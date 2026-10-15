//! One settings writer, with a bounded wake-up queue and current snapshots.
use std::sync::{
    Arc, RwLock,
    mpsc::{self, SyncSender},
};
use std::thread::JoinHandle;
use swifttunnel_core::settings::AppSettings;

pub fn start(
    settings: Arc<RwLock<AppSettings>>,
    persist: impl Fn(&AppSettings) + Send + 'static,
) -> std::io::Result<(SyncSender<()>, JoinHandle<()>)> {
    let (sender, receiver) = mpsc::sync_channel(1);
    let worker = std::thread::Builder::new()
        .name("lite-settings-save".into())
        .spawn(move || {
            while receiver.recv().is_ok() {
                let snapshot = match settings.read() {
                    Ok(settings) => settings.clone(),
                    Err(_) => {
                        log::warn!("Could not read settings for saving");
                        continue;
                    }
                };
                // No settings lock is held during disk IO. A queued wake-up reads
                // the latest state after this write, rather than an old UI snapshot.
                persist(&snapshot);
            }
        })?;
    Ok((sender, worker))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

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
