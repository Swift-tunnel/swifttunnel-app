//! A new game supersedes the previous session's optional metadata lookup.

use std::future::Future;

#[derive(Default)]
pub(crate) struct SessionMetadataTask(Option<tokio::task::JoinHandle<()>>);

impl SessionMetadataTask {
    pub fn replace(
        &mut self,
        runtime: &tokio::runtime::Handle,
        name: impl Future<Output = ()> + Send + 'static,
        location: impl Future<Output = ()> + Send + 'static,
    ) {
        self.cancel();
        // Name/thumbnail traffic must not delay the server-location result.
        // These are owned futures, not detached child tasks: cancellation of
        // this session drops both operations together.
        self.0 = Some(runtime.spawn(async move {
            tokio::join!(name, location);
        }));
    }

    pub fn cancel(&mut self) {
        if let Some(task) = self.0.take() {
            task.abort();
        }
    }
}

impl Drop for SessionMetadataTask {
    fn drop(&mut self) {
        self.cancel();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::sync::oneshot;

    struct Dropped(Option<oneshot::Sender<()>>);
    impl Drop for Dropped {
        fn drop(&mut self) {
            if let Some(sender) = self.0.take() {
                let _ = sender.send(());
            }
        }
    }
    async fn pending(started: oneshot::Sender<()>, dropped: oneshot::Sender<()>) {
        let _guard = Dropped(Some(dropped));
        let _ = started.send(());
        std::future::pending::<()>().await;
    }

    #[tokio::test]
    async fn a_new_session_releases_the_old_lookup_and_owner_drop_releases_the_current_one() {
        let mut task = SessionMetadataTask::default();
        let (first_tx, first_rx) = oneshot::channel();
        let (first_drop_tx, first_drop_rx) = oneshot::channel();
        task.replace(
            &tokio::runtime::Handle::current(),
            pending(first_tx, first_drop_tx),
            std::future::ready(()),
        );
        first_rx.await.unwrap();
        let rescue_first = task.0.as_ref().unwrap().abort_handle();
        let (second_tx, second_rx) = oneshot::channel();
        let (second_drop_tx, second_drop_rx) = oneshot::channel();
        task.replace(
            &tokio::runtime::Handle::current(),
            std::future::ready(()),
            pending(second_tx, second_drop_tx),
        );
        second_rx.await.unwrap();
        let rescue_second = task.0.as_ref().unwrap().abort_handle();
        let first_finished = tokio::time::timeout(Duration::from_secs(1), first_drop_rx).await;
        drop(task);
        let second_finished = tokio::time::timeout(Duration::from_secs(1), second_drop_rx).await;
        rescue_first.abort();
        rescue_second.abort();
        assert!(
            matches!(first_finished, Ok(Ok(()))),
            "replaced metadata was detached instead of cancelled"
        );
        assert!(
            matches!(second_finished, Ok(Ok(()))),
            "lookup outlived its owner"
        );
    }

    #[tokio::test]
    async fn leaving_a_session_cancels_its_lookup_and_repeated_cancel_is_safe() {
        let mut task = SessionMetadataTask::default();
        let (started_tx, started_rx) = oneshot::channel();
        let (dropped_tx, dropped_rx) = oneshot::channel();
        task.replace(
            &tokio::runtime::Handle::current(),
            pending(started_tx, dropped_tx),
            std::future::ready(()),
        );
        started_rx.await.unwrap();
        let rescue = task.0.as_ref().unwrap().abort_handle();
        task.cancel();
        task.cancel();
        let finished = tokio::time::timeout(Duration::from_secs(1), dropped_rx).await;
        rescue.abort();
        assert!(matches!(finished, Ok(Ok(()))));
    }

    #[tokio::test]
    async fn a_stalled_name_request_does_not_block_the_current_location() {
        let mut task = SessionMetadataTask::default();
        let (name_tx, name_rx) = oneshot::channel();
        let (drop_tx, drop_rx) = oneshot::channel();
        let (location_tx, location_rx) = oneshot::channel();
        task.replace(
            &tokio::runtime::Handle::current(),
            pending(name_tx, drop_tx),
            async {
                let _ = location_tx.send(());
            },
        );
        name_rx.await.unwrap();
        let rescue = task.0.as_ref().unwrap().abort_handle();
        let location_finished = tokio::time::timeout(Duration::from_secs(1), location_rx).await;
        task.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(1), drop_rx).await;
        rescue.abort();
        assert!(
            matches!(location_finished, Ok(Ok(()))),
            "location waited for game-name metadata"
        );
    }
}
