//! Coordination between trace setup and a concurrent stop request.

use std::sync::atomic::{AtomicBool, Ordering};
use windows::Win32::Foundation::{
    ERROR_ACTIVE_CONNECTIONS, ERROR_MORE_DATA, ERROR_SUCCESS, ERROR_WMI_INSTANCE_NOT_FOUND,
    WIN32_ERROR,
};

/// Byte capacity for a native properties header followed by UTF-16 names.
/// A Vec<u8> does not promise the alignment required for header field access.
pub(crate) fn trace_properties_storage(bytes: usize) -> Vec<u64> {
    use std::mem::{align_of, size_of};
    use windows::Win32::System::Diagnostics::Etw::EVENT_TRACE_PROPERTIES;
    const {
        assert!(align_of::<EVENT_TRACE_PROPERTIES>() <= align_of::<u64>());
    }
    vec![
        0;
        bytes
            .max(size_of::<EVENT_TRACE_PROPERTIES>())
            .div_ceil(size_of::<u64>())
    ]
}

/// Keep failure evidence before a caller waits for its trace worker to retire.
/// MORE_DATA still means the session stopped; ACTIVE_CONNECTIONS means stopping
/// is already underway. Neither should be presented as a failed stop.
pub(crate) fn report_trace_stop_result(session: &str, result: WIN32_ERROR) {
    if !matches!(
        result,
        ERROR_SUCCESS | ERROR_WMI_INSTANCE_NOT_FOUND | ERROR_MORE_DATA | ERROR_ACTIVE_CONNECTIONS
    ) {
        log::warn!(
            "Windows did not confirm stopping ETW session '{}' (0x{:08X})",
            session,
            result.0
        );
    }
}

/// Call only after the trace session and consumer have both been opened.
/// The caller must still close the consumer and stop its session on return.
pub(crate) fn process_trace_unless_stopped(
    stop: &AtomicBool,
    process: impl FnOnce() -> WIN32_ERROR,
) -> WIN32_ERROR {
    // stop() may have run before StartTrace created the session. In that case
    // its ControlTrace call could not stop this new session. Do not enter an
    // indefinite ProcessTrace wait; let the caller clean up the opened handles.
    // If stop happens after this check, the session already exists and the
    // normal ControlTrace stop can interrupt it.
    if stop.load(Ordering::SeqCst) {
        ERROR_SUCCESS
    } else {
        process()
    }
}

/// A controller outside this worker can end a trace successfully. Only our
/// own stop request means the supervisor should retire instead of retrying.
pub(crate) fn trace_session_result(stop: &AtomicBool, result: WIN32_ERROR) -> Result<(), String> {
    if stop.load(Ordering::SeqCst) {
        Ok(())
    } else if result == ERROR_SUCCESS {
        Err("The ETW trace ended without a stop request".into())
    } else {
        Err(format!("ProcessTrace failed: 0x{:08X}", result.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, atomic::Ordering, mpsc};
    use std::time::Duration;
    use windows::Win32::Foundation::ERROR_SUCCESS;

    #[test]
    fn properties_storage_is_aligned_zeroed_and_covers_the_trailing_name() {
        use std::mem::{align_of, size_of};
        use windows::Win32::System::Diagnostics::Etw::EVENT_TRACE_PROPERTIES;
        for trailing in 0..32 {
            let requested = size_of::<EVENT_TRACE_PROPERTIES>() + trailing;
            let storage = trace_properties_storage(requested);
            assert_eq!(
                storage.as_ptr() as usize % align_of::<EVENT_TRACE_PROPERTIES>(),
                0
            );
            assert!(size_of_val(storage.as_slice()) >= requested);
            assert!(size_of_val(storage.as_slice()) < requested + size_of::<u64>());
            assert!(storage.iter().all(|unit| *unit == 0));
        }
    }

    #[test]
    fn etw_shutdown_before_session_creation_cannot_enter_blocking_trace() {
        let stop = Arc::new(AtomicBool::new(false));
        let entered = Arc::new(AtomicBool::new(false));
        let (starting_tx, starting_rx) = mpsc::channel();
        let (setup_tx, setup_rx) = mpsc::channel();
        let (rescue_tx, rescue_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let worker_stop = stop.clone();
        let worker_entered = entered.clone();
        let worker = std::thread::spawn(move || {
            assert!(!worker_stop.load(Ordering::Acquire));
            starting_tx.send(()).unwrap();
            setup_rx.recv().unwrap();
            let result = process_trace_unless_stopped(&worker_stop, || {
                worker_entered.store(true, Ordering::Release);
                // Simulate ProcessTrace waiting for another session-stop call.
                rescue_rx.recv().unwrap();
                ERROR_SUCCESS
            });
            done_tx.send(result).unwrap();
        });
        starting_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        // stop() ran while no session existed, so its native stop was a no-op.
        stop.store(true, Ordering::SeqCst);
        setup_tx.send(()).unwrap();
        let completed = done_rx.recv_timeout(Duration::from_secs(1));
        // Always release a buggy worker before asserting, leaving no stuck thread.
        let _ = rescue_tx.send(());
        worker.join().unwrap();
        assert!(
            completed.is_ok(),
            "shutdown waited on a trace created after stop"
        );
        assert!(!entered.load(Ordering::Acquire));
    }

    #[test]
    fn a_trace_stopped_elsewhere_must_not_disable_the_supervisor() {
        let stop = AtomicBool::new(false);
        assert!(trace_session_result(&stop, ERROR_SUCCESS).is_err());
        assert!(trace_session_result(&stop, WIN32_ERROR(123)).is_err());
        stop.store(true, Ordering::SeqCst);
        assert!(trace_session_result(&stop, ERROR_SUCCESS).is_ok());
        assert!(trace_session_result(&stop, WIN32_ERROR(123)).is_ok());
    }

    #[test]
    fn etw_running_trace_preserves_its_result() {
        let stop = AtomicBool::new(false);
        assert_eq!(
            process_trace_unless_stopped(&stop, || WIN32_ERROR(123)),
            WIN32_ERROR(123)
        );
    }
}
