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

#[derive(Clone)]
pub(super) struct MaintenancePermit {
    _network: Permit,
    // A cancelled uninstall request must not let an optimizer run while its
    // blocking cleanup worker still restores the same persisted originals.
    _config: Arc<OwnedSemaphorePermit>,
}

fn begin_maintenance_on(
    gate: &OperationGate,
    config: impl FnOnce() -> Result<OwnedSemaphorePermit, String>,
) -> Result<MaintenancePermit, String> {
    let network = begin_on(gate)?;
    Ok(MaintenancePermit {
        _network: network,
        _config: Arc::new(config()?),
    })
}

pub(super) fn begin_maintenance() -> Result<MaintenancePermit, String> {
    begin_maintenance_on(&OPERATIONS, super::optimizer::begin_config_change)
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

    #[test]
    fn repair_and_uninstall_own_settings_admission_until_their_last_worker_finishes() {
        let network = OperationGate::new();
        let config = OperationGate::new();
        let applying = config.try_begin().unwrap();
        let reserve_config = || config.try_begin().map_err(|_| "settings busy".into());
        assert!(begin_maintenance_on(&network, reserve_config).is_err());
        // Refusal must release network admission rather than wedging Connect.
        assert!(begin_on(&network).is_ok());
        drop(applying);
        let request = begin_maintenance_on(&network, reserve_config).unwrap();
        let native_worker = request.clone();
        drop(request);
        assert!(begin_on(&network).is_err());
        assert!(config.try_begin().is_err());
        drop(native_worker);
        assert!(begin_on(&network).is_ok());
        assert!(config.try_begin().is_ok());
    }
}
