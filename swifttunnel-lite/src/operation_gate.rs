//! A nonblocking reservation shared by UI actions and background workers.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

#[derive(Default)]
pub struct OperationGate(Arc<AtomicBool>);

impl OperationGate {
    pub fn is_busy(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }

    pub fn try_enter(&self) -> Option<OperationGuard> {
        self.0
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| OperationGuard(Arc::clone(&self.0)))
    }
}

pub struct OperationGuard(Arc<AtomicBool>);

impl Drop for OperationGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// Installer work must wait for successful network cleanup and run off the
/// async worker that disconnects VPN.
pub async fn after_disconnect(
    disconnect: impl std::future::Future<Output = Result<(), String>>,
    installer: impl FnOnce() -> Result<(), String> + Send + 'static,
) -> Result<(), String> {
    disconnect.await?;
    tokio::task::spawn_blocking(installer)
        .await
        .map_err(|_| "Could not prepare the installer. Try again.".to_string())?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn disconnect_finishes_before_the_installer_starts() {
        let finished = Arc::new(AtomicBool::new(false));
        let check = finished.clone();
        after_disconnect(
            async {
                tokio::task::yield_now().await;
                finished.store(true, Ordering::SeqCst);
                Ok(())
            },
            move || {
                assert!(check.load(Ordering::SeqCst));
                Ok(())
            },
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn failed_disconnect_prevents_installer_work() {
        let result = after_disconnect(async { Err("disconnect failed".into()) }, || {
            panic!("must not start installer work")
        })
        .await;
        assert_eq!(result.unwrap_err(), "disconnect failed");
    }

    #[tokio::test]
    async fn an_installer_worker_failure_returns_an_actionable_error() {
        let result = after_disconnect(async { Ok(()) }, || {
            panic!("owned simulated installer failure")
        })
        .await;
        assert_eq!(
            result.unwrap_err(),
            "Could not prepare the installer. Try again."
        );
    }

    #[test]
    fn an_installer_reservation_excludes_connect_and_reconnect_until_it_finishes() {
        let gate = Arc::new(OperationGate::default());
        let install = gate.try_enter().unwrap();
        let contenders: Vec<_> = (0..32)
            .map(|_| {
                let gate = Arc::clone(&gate);
                std::thread::spawn(move || gate.try_enter().is_none())
            })
            .collect();
        for contender in contenders {
            assert!(contender.join().unwrap());
        }
        assert!(gate.is_busy());
        drop(install);
        assert!(!gate.is_busy());
        assert!(gate.try_enter().is_some());
    }

    #[test]
    fn a_panicking_operation_releases_its_reservation() {
        let gate = OperationGate::default();
        let result = std::panic::catch_unwind(|| {
            let _operation = gate.try_enter().unwrap();
            panic!("owned simulated worker failure");
        });
        assert!(result.is_err());
        assert!(!gate.is_busy());
        assert!(gate.try_enter().is_some());
    }

    #[tokio::test]
    async fn cancelling_an_owned_task_releases_its_operation_reservation() {
        let gate = OperationGate::default();
        let operation = gate.try_enter().unwrap();
        let task = tokio::spawn(async move {
            let _operation = operation;
            std::future::pending::<()>().await;
        });
        tokio::task::yield_now().await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(gate.try_enter().is_some());
    }
}
