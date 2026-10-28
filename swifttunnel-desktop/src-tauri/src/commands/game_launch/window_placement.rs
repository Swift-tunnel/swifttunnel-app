//! A busy player's synchronous window messages must not accumulate workers.
use std::sync::{
    Arc, LazyLock,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

static WORKER: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(1)));

pub(super) async fn run<T: Send + 'static>(
    work: impl FnOnce(Arc<AtomicBool>) -> T + Send + 'static,
) -> Result<T, String> {
    // Keep native calls on Tauri's existing blocking pool rather than moving
    // uninterruptible work onto the separately owned connection runtime.
    bounded(
        WORKER.clone(),
        Duration::from_secs(2),
        tauri::async_runtime::handle().inner().clone(),
        work,
    )
    .await
}

struct Cancel(Arc<AtomicBool>);
impl Drop for Cancel {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

async fn bounded<T: Send + 'static>(
    slots: Arc<Semaphore>,
    timeout: Duration,
    pool: tokio::runtime::Handle,
    work: impl FnOnce(Arc<AtomicBool>) -> T + Send + 'static,
) -> Result<T, String> {
    let permit = slots.try_acquire_owned().map_err(|_| {
        "Roblox's window is still busy. Wait for it to respond, then try Play again.".to_string()
    })?;
    let current = Arc::new(AtomicBool::new(true));
    let _cancel = Cancel(current.clone());
    let deadline = Instant::now() + timeout;
    // Dropping JoinSet aborts a job that has not started. A running Windows
    // call retains admission until it returns; a timeout cannot interrupt it.
    let mut worker = tokio::task::JoinSet::new();
    worker.spawn_blocking_on(
        move || {
            let _permit = permit;
            (Instant::now() < deadline && current.load(Ordering::Acquire)).then(|| work(current))
        },
        &pool,
    );
    tokio::time::timeout(timeout, worker.join_next()).await
        .map_err(|_| "Roblox did not respond to its window settings. Wait for it to finish opening, then try Play again.".to_string())?
        .ok_or("Roblox's window settings could not finish. Try Play again.")?
        .map_err(|error| format!("Roblox's window settings could not finish. Try Play again. ({error})"))?
        .ok_or_else(|| "Roblox's window settings expired before they could start. Try Play again.".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    #[tokio::test]
    async fn timeout_and_cancellation_keep_a_stalled_worker_admitted_and_skip_late_steps() {
        for cancel in [false, true] {
            let slots = Arc::new(Semaphore::new(1));
            let (started, ready) = tokio::sync::oneshot::channel();
            let (release, resume) = mpsc::channel();
            let (finished, done) = tokio::sync::oneshot::channel();
            let worker_slots = slots.clone();
            let owner = tokio::spawn(async move {
                bounded(
                    worker_slots,
                    if cancel {
                        Duration::from_secs(5)
                    } else {
                        Duration::from_millis(50)
                    },
                    tokio::runtime::Handle::current(),
                    move |current| {
                        let _ = started.send(());
                        let _ = resume.recv_timeout(Duration::from_secs(3));
                        // Models the step after a blocked SetWindowLongPtr returns.
                        let _ = finished.send(current.load(Ordering::Acquire));
                    },
                )
                .await
            });
            tokio::time::timeout(Duration::from_secs(2), ready)
                .await
                .unwrap()
                .unwrap();
            if cancel {
                owner.abort();
                assert!(owner.await.unwrap_err().is_cancelled());
            } else {
                assert!(
                    owner
                        .await
                        .unwrap()
                        .unwrap_err()
                        .contains("did not respond")
                );
            }
            let duplicate = bounded(
                slots.clone(),
                Duration::from_secs(1),
                tokio::runtime::Handle::current(),
                |_| panic!("duplicate native worker"),
            )
            .await;
            let _ = release.send(());
            let still_current = tokio::time::timeout(Duration::from_secs(2), done)
                .await
                .unwrap()
                .unwrap();
            assert!(!still_current, "abandoned work must not continue to resize");
            assert!(duplicate.unwrap_err().contains("still busy"));
            // The sender can wake before the permit's destructor runs.
            let permit =
                tokio::time::timeout(Duration::from_secs(2), slots.clone().acquire_owned())
                    .await
                    .unwrap()
                    .unwrap();
            drop(permit);
            assert_eq!(
                bounded(
                    slots,
                    Duration::from_secs(1),
                    tokio::runtime::Handle::current(),
                    |_| 7
                )
                .await
                .unwrap(),
                7
            );
        }
    }

    #[test]
    fn expired_work_in_the_blocking_queue_never_changes_a_window() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .unwrap();
        let (started, ready) = mpsc::channel();
        let (release, resume) = mpsc::channel();
        let blocker = runtime.spawn_blocking(move || {
            let _ = started.send(());
            let _ = resume.recv_timeout(Duration::from_secs(3));
        });
        ready.recv_timeout(Duration::from_secs(2)).unwrap();
        let slots = Arc::new(Semaphore::new(1));
        let called = Arc::new(AtomicBool::new(false));
        let observed = called.clone();
        let result = runtime.block_on(bounded(
            slots.clone(),
            Duration::from_millis(20),
            runtime.handle().clone(),
            move |_| {
                observed.store(true, Ordering::Release);
            },
        ));
        let _ = release.send(());
        runtime.block_on(blocker).unwrap();
        runtime.block_on(async {
            let _permit = slots.acquire_owned().await.unwrap();
        });
        assert!(result.is_err());
        assert!(!called.load(Ordering::Acquire));
    }
}
