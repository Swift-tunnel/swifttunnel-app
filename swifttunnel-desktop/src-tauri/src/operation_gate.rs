//! Own admitted work through completion and drain it before exit restoration.
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum AdmissionError {
    Busy,
    Closing,
}

pub(crate) struct OperationGate {
    closing: AtomicBool,
    slot: Arc<Semaphore>,
}

impl OperationGate {
    pub(crate) fn new() -> Self {
        Self {
            closing: AtomicBool::new(false),
            slot: Arc::new(Semaphore::new(1)),
        }
    }

    fn admit(&self, permit: OwnedSemaphorePermit) -> Result<OwnedSemaphorePermit, AdmissionError> {
        // Check after acquisition too. Shutdown can close admission while an
        // earlier waiter is asleep, or between a caller's check and acquire.
        if self.closing.load(Ordering::Acquire) {
            Err(AdmissionError::Closing)
        } else {
            Ok(permit)
        }
    }

    pub(crate) fn try_begin(&self) -> Result<OwnedSemaphorePermit, AdmissionError> {
        if self.closing.load(Ordering::Acquire) {
            return Err(AdmissionError::Closing);
        }
        self.admit(
            self.slot
                .clone()
                .try_acquire_owned()
                .map_err(|_| AdmissionError::Busy)?,
        )
    }

    pub(crate) async fn wait(&self) -> Result<OwnedSemaphorePermit, AdmissionError> {
        if self.closing.load(Ordering::Acquire) {
            return Err(AdmissionError::Closing);
        }
        self.admit(
            self.slot
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| AdmissionError::Closing)?,
        )
    }

    pub(crate) fn close_admission(&self) {
        self.closing.store(true, Ordering::Release);
    }

    pub(crate) async fn drain(&self) -> OwnedSemaphorePermit {
        // Unlike Semaphore::close, the latch lets shutdown wait for existing
        // permits. Keep that permit through restoration, not just a busy check.
        self.slot
            .clone()
            .acquire_owned()
            .await
            .expect("private operation semaphore is never closed")
    }
}

pub(crate) async fn drain_for_shutdown(
    network: &OperationGate,
    config: &OperationGate,
) -> (OwnedSemaphorePermit, OwnedSemaphorePermit) {
    // Close both before waiting for either. An in-flight operation must not
    // admit another kind of edit while shutdown is draining its first gate.
    network.close_admission();
    config.close_admission();
    let network = network.drain().await;
    let config = config.drain().await;
    (network, config)
}

/// Quitting cannot wait forever on admitted work. A native call that never
/// returns would otherwise keep a windowless process alive, and the exit
/// restoration after it would never run. Admission stays closed either way.
pub(crate) async fn drain_for_shutdown_within(
    network: &OperationGate,
    config: &OperationGate,
    limit: std::time::Duration,
) -> Option<(OwnedSemaphorePermit, OwnedSemaphorePermit)> {
    tokio::time::timeout(limit, drain_for_shutdown(network, config))
        .await
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn shutdown_waits_for_the_worker_and_refuses_previously_queued_work() {
        let gate = OperationGate::new();
        let active = gate.try_begin().unwrap();
        let mut queued = Box::pin(gate.wait());
        assert!(
            tokio::time::timeout(Duration::from_millis(5), &mut queued)
                .await
                .is_err()
        );
        gate.close_admission();
        assert_eq!(gate.try_begin().unwrap_err(), AdmissionError::Closing);
        let mut shutdown = Box::pin(gate.drain());
        assert!(
            tokio::time::timeout(Duration::from_millis(5), &mut shutdown)
                .await
                .is_err()
        );
        drop(active);
        assert_eq!(queued.await.unwrap_err(), AdmissionError::Closing);
        let restoration = shutdown.await;
        assert_eq!(gate.wait().await.unwrap_err(), AdmissionError::Closing);
        drop(restoration);
        assert_eq!(gate.try_begin().unwrap_err(), AdmissionError::Closing);
    }

    #[tokio::test]
    async fn exit_stops_waiting_for_work_that_never_finishes_and_admits_nothing_new() {
        let network = OperationGate::new();
        let config = OperationGate::new();
        let stuck = network.try_begin().unwrap();
        assert!(
            drain_for_shutdown_within(&network, &config, Duration::from_millis(5))
                .await
                .is_none()
        );
        assert_eq!(network.try_begin().unwrap_err(), AdmissionError::Closing);
        assert_eq!(config.try_begin().unwrap_err(), AdmissionError::Closing);
        drop(stuck);
        assert!(
            drain_for_shutdown_within(&network, &config, Duration::from_secs(3))
                .await
                .is_some()
        );
    }

    #[tokio::test]
    async fn exit_closes_both_kinds_of_admission_before_restoring_either() {
        let network = OperationGate::new();
        let config = OperationGate::new();
        let repairing = network.try_begin().unwrap();
        let applying = config.try_begin().unwrap();
        let mut exit = Box::pin(drain_for_shutdown(&network, &config));
        assert!(
            tokio::time::timeout(Duration::from_millis(5), &mut exit)
                .await
                .is_err()
        );
        assert_eq!(network.try_begin().unwrap_err(), AdmissionError::Closing);
        assert_eq!(config.try_begin().unwrap_err(), AdmissionError::Closing);
        // Ending one kind of work must not allow restoration to race the other.
        drop(repairing);
        assert!(
            tokio::time::timeout(Duration::from_millis(5), &mut exit)
                .await
                .is_err()
        );
        drop(applying);
        let restored = exit.await;
        assert_eq!(network.wait().await.unwrap_err(), AdmissionError::Closing);
        assert_eq!(config.wait().await.unwrap_err(), AdmissionError::Closing);
        drop(restored);
    }
}
