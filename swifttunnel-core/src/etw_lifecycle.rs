//! Coordination between trace setup and a concurrent stop request.

use std::sync::atomic::{AtomicBool, Ordering};
use windows::Win32::Foundation::{ERROR_SUCCESS, WIN32_ERROR};

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, atomic::Ordering, mpsc};
    use std::time::Duration;
    use windows::Win32::Foundation::ERROR_SUCCESS;

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
    fn etw_running_trace_preserves_its_result() {
        let stop = AtomicBool::new(false);
        assert_eq!(
            process_trace_unless_stopped(&stop, || WIN32_ERROR(123)),
            WIN32_ERROR(123)
        );
    }
}
