//! One settings writer, with a bounded wake-up queue and current snapshots.
use std::sync::{
    Arc, RwLock,
    mpsc::{self, SyncSender},
};
use std::thread::JoinHandle;
use swifttunnel_core::settings::AppSettings;

enum SaveRequest {
    Changed,
    Flush(SyncSender<Result<(), String>>),
}

pub struct SaveSignal(SyncSender<SaveRequest>);
impl SaveSignal {
    pub fn try_send(&self, _: ()) -> Result<(), mpsc::TrySendError<()>> {
        self.0
            .try_send(SaveRequest::Changed)
            .map_err(|error| match error {
                mpsc::TrySendError::Full(_) => mpsc::TrySendError::Full(()),
                mpsc::TrySendError::Disconnected(_) => mpsc::TrySendError::Disconnected(()),
            })
    }

    /// Final snapshot barrier for the exit worker, never the window thread.
    /// Both admission to the bounded queue and completion share one deadline.
    pub fn flush(&self, timeout: std::time::Duration) -> Result<(), String> {
        let started = std::time::Instant::now();
        let (completed, done) = mpsc::sync_channel(1);
        let mut request = SaveRequest::Flush(completed);
        loop {
            match self.0.try_send(request) {
                Ok(()) => break,
                Err(mpsc::TrySendError::Disconnected(_)) => {
                    return Err("Settings saving has stopped.".into());
                }
                Err(mpsc::TrySendError::Full(unsent)) => request = unsent,
            }
            let remaining = timeout.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                return Err("Settings saving did not finish before closing.".into());
            }
            std::thread::sleep(remaining.min(std::time::Duration::from_millis(10)));
        }
        done.recv_timeout(timeout.saturating_sub(started.elapsed()))
            .map_err(|_| "Settings saving did not finish before closing.".to_string())?
    }
}

pub fn start(
    settings: Arc<RwLock<AppSettings>>,
    persist: impl Fn(&AppSettings) -> Result<(), String> + Send + 'static,
) -> std::io::Result<(SaveSignal, JoinHandle<()>)> {
    let (sender, receiver) = mpsc::sync_channel(1);
    let worker = std::thread::Builder::new()
        .name("lite-settings-save".into())
        .spawn(move || {
            while let Ok(request) = receiver.recv() {
                let snapshot = settings
                    .read()
                    .map(|settings| settings.clone())
                    .map_err(|_| "Could not read settings for saving".to_string());
                // No settings lock is held during disk IO. A queued wake-up reads
                // the latest state after this write, rather than an old UI snapshot.
                let result = snapshot.and_then(|snapshot| persist(&snapshot));
                if let Err(error) = &result {
                    log::warn!("Could not save settings: {error}");
                }
                if let SaveRequest::Flush(completed) = request {
                    let _ = completed.try_send(result);
                }
            }
        })?;
    Ok((SaveSignal(sender), worker))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn exit_barrier_waits_for_a_queued_latest_snapshot() {
        let settings = Arc::new(RwLock::new(AppSettings::default()));
        settings.write().unwrap().selected_region = "first".into();
        let (saved, received) = mpsc::channel();
        let (release, resume) = mpsc::channel();
        let first = std::sync::atomic::AtomicBool::new(true);
        let (signal, worker) = start(settings.clone(), move |snapshot| {
            saved.send(snapshot.selected_region.clone()).unwrap();
            if first.swap(false, std::sync::atomic::Ordering::SeqCst) {
                let _ = resume.recv_timeout(Duration::from_secs(3));
            }
            Ok(())
        })
        .unwrap();
        signal.try_send(()).unwrap();
        assert_eq!(
            received.recv_timeout(Duration::from_secs(2)).unwrap(),
            "first"
        );
        settings.write().unwrap().selected_region = "latest".into();
        signal.try_send(()).unwrap();
        let (completed, done) = mpsc::channel();
        let exiting = std::thread::spawn(move || {
            completed
                .send(signal.flush(Duration::from_secs(2)))
                .unwrap();
            signal
        });
        let waited = done.recv_timeout(Duration::from_millis(30)).is_err();
        release.send(()).unwrap();
        done.recv_timeout(Duration::from_secs(2)).unwrap().unwrap();
        drop(exiting.join().unwrap());
        worker.join().unwrap();
        assert!(
            waited,
            "Exit must wait while the first write and latest snapshot are pending"
        );
        assert_eq!(received.try_iter().last().as_deref(), Some("latest"));
    }

    #[test]
    fn exit_barrier_reports_a_failed_save_and_releases_a_disconnected_writer() {
        let (signal, worker) = start(Arc::new(RwLock::new(AppSettings::default())), |_| {
            Err("disk full".into())
        })
        .unwrap();
        assert_eq!(
            signal.flush(Duration::from_secs(2)).unwrap_err(),
            "disk full"
        );
        drop(signal);
        worker.join().unwrap();
        let (sender, receiver) = mpsc::sync_channel(1);
        drop(receiver);
        assert!(SaveSignal(sender).flush(Duration::from_secs(2)).is_err());
    }

    #[test]
    fn exit_barrier_bounds_both_queue_admission_and_save_completion() {
        for full in [false, true] {
            let (entered, ready) = mpsc::channel();
            let (release, resume) = mpsc::channel();
            let first = std::sync::atomic::AtomicBool::new(true);
            let (signal, worker) =
                start(Arc::new(RwLock::new(AppSettings::default())), move |_| {
                    if first.swap(false, std::sync::atomic::Ordering::SeqCst) {
                        entered.send(()).unwrap();
                        let _ = resume.recv_timeout(Duration::from_secs(3));
                    }
                    Ok(())
                })
                .unwrap();
            signal.try_send(()).unwrap();
            ready.recv_timeout(Duration::from_secs(2)).unwrap();
            if full {
                signal.try_send(()).unwrap();
            }
            let at = std::time::Instant::now();
            let result = signal.flush(Duration::from_millis(30));
            let elapsed = at.elapsed();
            release.send(()).unwrap();
            drop(signal);
            worker.join().unwrap();
            assert!(result.is_err());
            assert!(elapsed < Duration::from_secs(1));
        }
    }

    #[test]
    fn bursts_coalesce_without_an_older_save_overwriting_the_latest_settings() {
        let settings = Arc::new(RwLock::new(AppSettings::default()));
        settings.write().unwrap().selected_region = "first".into();
        let (saved, results) = mpsc::channel();
        let (release, resume) = mpsc::channel();
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let (notify, worker) = start(settings.clone(), move |snapshot| {
            saved.send(snapshot.selected_region.clone()).unwrap();
            if calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                let _ = resume.recv_timeout(Duration::from_secs(3));
            }
            Ok(())
        })
        .unwrap();
        notify.try_send(()).unwrap();
        let first = results.recv_timeout(Duration::from_secs(2));
        let mut coalesced = 0;
        for index in 0..1000 {
            settings.write().unwrap().selected_region = format!("region-{index}");
            if matches!(notify.try_send(()), Err(mpsc::TrySendError::Full(()))) {
                coalesced += 1;
            }
        }
        let no_overlap = results.try_recv().is_err();
        release.send(()).unwrap();
        let last = results.recv_timeout(Duration::from_secs(2));
        drop(notify);
        worker.join().unwrap();
        assert_eq!(first.unwrap(), "first");
        assert_eq!(last.unwrap(), "region-999");
        assert!(coalesced > 0);
        assert!(no_overlap);
        assert!(results.try_recv().is_err());
    }
}
