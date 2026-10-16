//! Presence is a snapshot, so keep only the newest pending update while IPC is busy.

use super::state::DiscordActivity;
use parking_lot::{Condvar, Mutex};
use std::time::{Duration, Instant};

#[derive(Default)]
struct Pending {
    activity: Option<DiscordActivity>,
    shutdown: bool,
}

#[derive(Default)]
pub(super) struct ActivityMailbox {
    pending: Mutex<Pending>,
    changed: Condvar,
}

impl ActivityMailbox {
    pub fn publish(&self, activity: DiscordActivity) {
        let mut pending = self.pending.lock();
        if pending.shutdown {
            return;
        }
        pending.shutdown = matches!(activity, DiscordActivity::Shutdown);
        pending.activity = Some(activity);
        self.changed.notify_one();
    }

    /// None means the refresh deadline elapsed without a new snapshot.
    pub fn receive(&self, timeout: Option<Duration>) -> Option<DiscordActivity> {
        let deadline = timeout.map(|duration| Instant::now() + duration);
        let mut pending = self.pending.lock();
        loop {
            if let Some(activity) = pending.activity.take() {
                return Some(activity);
            }
            if pending.shutdown {
                return Some(DiscordActivity::Shutdown);
            }
            if let Some(deadline) = deadline {
                let remaining = deadline.checked_duration_since(Instant::now())?;
                self.changed.wait_for(&mut pending, remaining);
            } else {
                self.changed.wait(&mut pending);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discord_rpc::DiscordState;
    use std::sync::{Arc, mpsc};

    #[test]
    fn a_stalled_consumer_gets_only_the_latest_of_a_large_burst() {
        let mailbox = ActivityMailbox::default();
        for index in 0..10_000 {
            mailbox.publish(DiscordActivity::SetActivity(DiscordState::Connecting {
                region: index.to_string(),
            }));
        }
        assert!(matches!(
            mailbox.receive(Some(Duration::ZERO)),
            Some(DiscordActivity::SetActivity(DiscordState::Connecting { region })) if region == "9999"
        ));
        assert!(mailbox.receive(Some(Duration::ZERO)).is_none());
    }

    #[test]
    fn clear_replaces_stale_presence_and_can_be_followed_by_a_new_enable() {
        let mailbox = ActivityMailbox::default();
        mailbox.publish(DiscordActivity::SetActivity(DiscordState::Idle));
        mailbox.publish(DiscordActivity::Clear);
        assert!(matches!(
            mailbox.receive(Some(Duration::ZERO)),
            Some(DiscordActivity::Clear)
        ));
        mailbox.publish(DiscordActivity::Clear);
        mailbox.publish(DiscordActivity::SetActivity(DiscordState::Idle));
        assert!(matches!(
            mailbox.receive(Some(Duration::ZERO)),
            Some(DiscordActivity::SetActivity(DiscordState::Idle))
        ));
    }

    #[test]
    fn shutdown_discards_pending_work_and_cannot_be_overwritten() {
        let mailbox = ActivityMailbox::default();
        mailbox.publish(DiscordActivity::SetActivity(DiscordState::Idle));
        mailbox.publish(DiscordActivity::Shutdown);
        mailbox.publish(DiscordActivity::Clear);
        assert!(matches!(
            mailbox.receive(None),
            Some(DiscordActivity::Shutdown)
        ));
        assert!(matches!(
            mailbox.receive(None),
            Some(DiscordActivity::Shutdown)
        ));
    }

    #[test]
    fn publish_wakes_an_idle_worker_without_a_polling_loop() {
        let mailbox = Arc::new(ActivityMailbox::default());
        let worker_mailbox = Arc::clone(&mailbox);
        let (tx, rx) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let _ = tx.send(worker_mailbox.receive(None));
        });
        mailbox.publish(DiscordActivity::Clear);
        let received = rx.recv_timeout(Duration::from_secs(2));
        // Always release the owned worker, even if the assertion fails.
        mailbox.publish(DiscordActivity::Shutdown);
        worker.join().unwrap();
        assert!(matches!(received, Ok(Some(DiscordActivity::Clear))));
    }
}
