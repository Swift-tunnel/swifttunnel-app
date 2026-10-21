//! The engine can release its last shared owner from a runtime worker.

use std::ops::Deref;
use tokio::runtime::Runtime;

pub struct EngineRuntime(Option<Runtime>);

impl From<Runtime> for EngineRuntime {
    fn from(runtime: Runtime) -> Self {
        Self(Some(runtime))
    }
}

impl Deref for EngineRuntime {
    type Target = Runtime;

    fn deref(&self) -> &Runtime {
        self.0.as_ref().expect("the runtime is present until drop")
    }
}

impl Drop for EngineRuntime {
    fn drop(&mut self) {
        if let Some(runtime) = self.0.take() {
            // The explicit Quit path already awaits network cleanup. Final
            // ownership can then land on an async worker or the window thread;
            // neither may wait indefinitely for the runtime's blocking pool.
            // Existing blocking work may finish, but no new task is retained.
            runtime.shutdown_background();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::{Arc, mpsc},
        time::Duration,
    };

    fn runtime() -> EngineRuntime {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap()
            .into()
    }

    #[test]
    fn last_owner_can_be_released_by_its_own_async_worker() {
        let runtime = Arc::new(runtime());
        let last_owner = runtime.clone();
        let (release, ready) = tokio::sync::oneshot::channel();
        let (completed, result) = mpsc::channel();
        runtime.spawn(async move {
            let _ = ready.await;
            let dropped =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(last_owner)));
            let _ = completed.send(dropped.is_ok());
        });
        drop(runtime);
        release.send(()).unwrap();
        assert!(
            result.recv_timeout(Duration::from_secs(2)).unwrap(),
            "last runtime owner panicked on its own worker"
        );
    }

    #[test]
    fn final_drop_does_not_wait_on_an_unrelated_blocking_job() {
        let runtime = runtime();
        let (started, ready) = mpsc::channel();
        let (release, wait) = mpsc::channel();
        let (completed, done) = mpsc::channel();
        runtime.spawn_blocking(move || {
            started.send(()).unwrap();
            let _ = wait.recv_timeout(Duration::from_secs(3));
            let _ = completed.send(());
        });
        ready.recv_timeout(Duration::from_secs(2)).unwrap();
        let before = std::time::Instant::now();
        drop(runtime);
        let elapsed = before.elapsed();
        let _ = release.send(());
        done.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(
            elapsed < Duration::from_secs(1),
            "runtime drop waited for blocking work: {elapsed:?}"
        );
    }

    #[test]
    fn shutdown_releases_a_pending_async_task() {
        struct Dropped(mpsc::Sender<()>);
        impl Drop for Dropped {
            fn drop(&mut self) {
                let _ = self.0.send(());
            }
        }
        let runtime = runtime();
        let (started, ready) = mpsc::channel();
        let (dropped, done) = mpsc::channel();
        runtime.spawn(async move {
            let _guard = Dropped(dropped);
            let _ = started.send(());
            std::future::pending::<()>().await;
        });
        ready.recv_timeout(Duration::from_secs(2)).unwrap();
        drop(runtime);
        done.recv_timeout(Duration::from_secs(2)).unwrap();
    }
}
