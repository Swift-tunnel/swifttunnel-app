//! Own one diagnostic at a time, including cancellation before its IPC starts.

use parking_lot::Mutex;
use std::collections::VecDeque;
use std::future::Future;
use tokio::sync::watch;

const CANCELLED_RUNS: usize = 64;
const STOPPED: &str = "Network test stopped.";

#[derive(Default)]
pub(super) struct NetworkTestControl {
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    active: Option<(String, watch::Sender<bool>)>,
    cancelled: VecDeque<String>,
}

struct Running<'a> {
    control: &'a NetworkTestControl,
    id: String,
}

impl Drop for Running<'_> {
    fn drop(&mut self) {
        let mut state = self.control.state.lock();
        if state.active.as_ref().is_some_and(|(id, _)| *id == self.id) {
            state.active = None;
        }
    }
}

fn validate_id(id: &str) -> Result<(), String> {
    if id.is_empty() || id.len() > 96 || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err("Invalid network test request.".into());
    }
    Ok(())
}

impl NetworkTestControl {
    pub(super) fn cancel(&self, id: &str) -> Result<(), String> {
        validate_id(id)?;
        let mut state = self.state.lock();
        // IPC can deliver Stop before Start. Remember it without an unbounded
        // map; the UI retains its run permit until the Start reply settles.
        if !state.cancelled.iter().any(|cancelled| cancelled == id) {
            if state.cancelled.len() == CANCELLED_RUNS {
                state.cancelled.pop_front();
            }
            state.cancelled.push_back(id.into());
        }
        if let Some((active_id, stop)) = &state.active
            && active_id == id
        {
            let _ = stop.send(true);
        }
        Ok(())
    }

    pub(super) async fn run<T>(
        &self,
        id: String,
        work: impl Future<Output = Result<T, String>>,
    ) -> Result<T, String> {
        validate_id(&id)?;
        let (mut stop, _running) = {
            let mut state = self.state.lock();
            if state.cancelled.contains(&id) {
                return Err(STOPPED.into());
            }
            if state.active.is_some() {
                return Err("Another network test is running. Wait for it to finish.".into());
            }
            let (send, receive) = watch::channel(false);
            state.active = Some((id.clone(), send));
            (receive, Running { control: self, id })
        };
        // Dropping Core's diagnostic futures aborts their owned load workers.
        // Keep the run lease until that future is dropped, never just until
        // the caller asks to cancel it.
        tokio::select! {
            biased;
            _ = stop.changed() => Err(STOPPED.into()),
            result = work => result,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct Work(Arc<AtomicBool>);
    impl Drop for Work {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn stop_drops_owned_work_and_releases_the_exclusive_run() {
        let control = Arc::new(NetworkTestControl::default());
        let dropped = Arc::new(AtomicBool::new(false));
        let (started, ready) = tokio::sync::oneshot::channel();
        let worker_control = control.clone();
        let worker_dropped = dropped.clone();
        let task = tokio::spawn(async move {
            worker_control
                .run("first".into(), async move {
                    let _work = Work(worker_dropped);
                    let _ = started.send(());
                    std::future::pending::<Result<(), String>>().await
                })
                .await
        });
        ready.await.unwrap();
        assert!(
            control
                .run("overlap".into(), async { Ok(()) })
                .await
                .is_err()
        );
        control.cancel("first").unwrap();
        assert_eq!(task.await.unwrap(), Err(STOPPED.into()));
        assert!(dropped.load(Ordering::SeqCst));
        assert_eq!(control.run("next".into(), async { Ok(42) }).await, Ok(42));
    }

    #[tokio::test]
    async fn stop_before_start_never_polls_work_and_stale_stop_cannot_cancel_a_new_run() {
        let control = NetworkTestControl::default();
        control.cancel("old").unwrap();
        let polled = AtomicBool::new(false);
        assert_eq!(
            control
                .run("old".into(), async {
                    polled.store(true, Ordering::SeqCst);
                    Ok(())
                })
                .await,
            Err(STOPPED.into())
        );
        assert!(!polled.load(Ordering::SeqCst));
        assert_eq!(
            control
                .run("new".into(), async {
                    control.cancel("old").unwrap();
                    tokio::task::yield_now().await;
                    Ok(7)
                })
                .await,
            Ok(7)
        );
    }

    #[tokio::test]
    async fn dropping_the_caller_releases_work_without_losing_the_gate() {
        let control = Arc::new(NetworkTestControl::default());
        let (started, ready) = tokio::sync::oneshot::channel();
        let worker_control = control.clone();
        let task = tokio::spawn(async move {
            worker_control
                .run("first".into(), async {
                    let _ = started.send(());
                    std::future::pending::<Result<(), String>>().await
                })
                .await
        });
        ready.await.unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(control.run("second".into(), async { Ok(()) }).await, Ok(()));
    }

    #[test]
    fn cancelled_request_history_is_bounded_and_invalid_ids_are_rejected() {
        let control = NetworkTestControl::default();
        assert!(control.cancel("").is_err());
        assert!(control.cancel(&"x".repeat(97)).is_err());
        for id in 0..1000 {
            control.cancel(&format!("run-{id}")).unwrap();
        }
        assert_eq!(control.state.lock().cancelled.len(), CANCELLED_RUNS);
    }
}
