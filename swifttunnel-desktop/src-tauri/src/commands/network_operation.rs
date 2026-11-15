//! Keep connection setup and destructive network work mutually exclusive.
use crate::operation_gate::{AdmissionError, OperationGate};
use std::sync::{Arc, LazyLock};
use tokio::sync::OwnedSemaphorePermit;

static OPERATIONS: LazyLock<OperationGate> = LazyLock::new(OperationGate::new);

#[derive(Clone)]
pub(super) struct Permit {
    // Cloning keeps admission with blocking work after its caller is cancelled.
    _guard: Arc<OwnedSemaphorePermit>,
}

fn begin_on(gate: &OperationGate) -> Result<Permit, String> {
    let guard = gate.try_begin().map_err(|error| {
        match error {
            AdmissionError::Closing => "SwiftTunnel is closing. Reopen it to connect or repair the network.",
            AdmissionError::Busy => "A connection or network repair is already in progress. Wait for it to finish, then try again.",
        }.to_string()
    })?;
    Ok(Permit {
        _guard: Arc::new(guard),
    })
}

pub(super) fn begin() -> Result<Permit, String> {
    begin_on(&OPERATIONS)
}

pub(super) fn gate() -> &'static OperationGate {
    &OPERATIONS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cancelled_request_cannot_admit_connect_while_native_work_continues() {
        let gate = OperationGate::new();
        let request = begin_on(&gate).unwrap();
        let worker_permit = request.clone();
        let (entered, started) = std::sync::mpsc::channel();
        let (release, resume) = std::sync::mpsc::channel();
        let worker = tokio::task::spawn_blocking(move || {
            let _permit = worker_permit;
            entered.send(()).unwrap();
            resume
                .recv_timeout(std::time::Duration::from_secs(3))
                .unwrap();
            Err::<(), _>("fixture repair failure")
        });
        started
            .recv_timeout(std::time::Duration::from_secs(3))
            .unwrap();
        drop(request);
        let while_running = begin_on(&gate);
        // Release our fixture before asserting so a failure cannot strand it.
        release.send(()).unwrap();
        assert!(worker.await.unwrap().is_err());
        assert!(while_running.is_err());
        assert!(begin_on(&gate).is_ok());
    }

    #[test]
    fn active_setup_rejects_maintenance_without_waiting_or_queuing_it() {
        let gate = OperationGate::new();
        let connection = begin_on(&gate).unwrap();
        assert!(begin_on(&gate).is_err());
        drop(connection);
        assert!(begin_on(&gate).is_ok());
    }
}
