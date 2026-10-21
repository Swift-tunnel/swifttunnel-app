//! Bound native notification work even if Windows' toast service stalls.

use super::NotificationIcon;
use parking_lot::Mutex;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

const MAX_PENDING: usize = 4;
const MAX_AGE: Duration = Duration::from_secs(30);

pub(super) struct Notice {
    pub title: String,
    pub message: String,
    pub icon: NotificationIcon,
    created: Instant,
}

impl Notice {
    pub fn new(title: &str, message: &str, icon: NotificationIcon) -> Self {
        Self {
            title: title.chars().take(256).collect(),
            message: message.chars().take(2048).collect(),
            icon,
            created: Instant::now(),
        }
    }
}

#[derive(Default)]
struct Pending {
    items: VecDeque<Notice>,
    running: bool,
}

#[derive(Default)]
pub(super) struct ToastQueue(Arc<Mutex<Pending>>);

impl ToastQueue {
    pub fn submit(
        &self,
        notice: Notice,
        mut deliver: impl FnMut(Notice) + Send + 'static,
    ) -> std::io::Result<()> {
        let mut pending = self.0.lock();
        if let Some(existing) = pending.items.iter_mut().find(|item| {
            item.title == notice.title && item.message == notice.message && item.icon == notice.icon
        }) {
            *existing = notice;
            return Ok(());
        }
        if pending.items.len() == MAX_PENDING {
            // Prefer current alerts to a backlog of obsolete connection changes.
            pending.items.pop_front();
        }
        pending.items.push_back(notice);
        if pending.running {
            return Ok(());
        }
        pending.running = true;
        let shared = self.0.clone();
        let worker = std::thread::Builder::new()
            .name("windows-toast".into())
            .spawn(move || {
                loop {
                    let notice = {
                        let mut pending = shared.lock();
                        let Some(notice) = pending.items.pop_front() else {
                            pending.running = false;
                            return;
                        };
                        notice
                    };
                    if notice.created.elapsed() > MAX_AGE {
                        continue;
                    }
                    // A failed toast must not strand the queue in its running state.
                    if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| deliver(notice)))
                        .is_err()
                    {
                        log::warn!("Windows notification worker could not display a toast");
                    }
                }
            });
        if let Err(error) = worker {
            // Failed thread creation stays retryable on the next notification.
            pending.running = false;
            pending.items.clear();
            return Err(error);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    #[test]
    fn a_stalled_service_keeps_one_worker_and_only_four_recent_pending_alerts() {
        let queue = ToastQueue::default();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (resume_tx, resume_rx) = mpsc::channel();
        let (shown_tx, shown_rx) = mpsc::channel();
        let mut first = true;
        queue
            .submit(Notice::new("0", "", NotificationIcon::App), move |notice| {
                if first {
                    first = false;
                    entered_tx.send(()).unwrap();
                    let _ = resume_rx.recv_timeout(Duration::from_secs(5));
                }
                shown_tx.send(notice.title).unwrap();
            })
            .unwrap();
        entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        for number in 1..=10_000 {
            queue
                .submit(
                    Notice::new(&number.to_string(), "", NotificationIcon::App),
                    |_| {
                        panic!("must not create a second notification worker while one is stalled");
                    },
                )
                .unwrap();
        }
        let retained = queue.0.lock().items.len();
        // Release the owned worker before assertions, including on a failure.
        resume_tx.send(()).unwrap();
        let shown: Vec<_> = (0..5)
            .map(|_| shown_rx.recv_timeout(Duration::from_secs(2)).unwrap())
            .collect();
        assert_eq!(retained, MAX_PENDING);
        assert_eq!(shown, ["0", "9997", "9998", "9999", "10000"]);
    }

    #[test]
    fn stale_alerts_are_skipped_and_a_panicking_delivery_does_not_strand_new_alerts() {
        let queue = ToastQueue::default();
        let mut stale = Notice::new("stale", "", NotificationIcon::App);
        stale.created = Instant::now() - MAX_AGE - Duration::from_secs(1);
        {
            let mut pending = queue.0.lock();
            pending.items.push_back(stale);
            pending
                .items
                .push_back(Notice::new("failed", "", NotificationIcon::App));
        }
        let (shown_tx, shown_rx) = mpsc::channel();
        queue
            .submit(
                Notice::new("current", "", NotificationIcon::App),
                move |notice| {
                    if notice.title == "failed" {
                        panic!("simulated toast service failure");
                    }
                    shown_tx.send(notice.title).unwrap();
                },
            )
            .unwrap();
        assert_eq!(
            shown_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            "current"
        );
    }

    #[test]
    fn pending_duplicates_are_coalesced_and_text_is_bounded_on_unicode_boundaries() {
        let queue = ToastQueue::default();
        // Model an already busy worker without starting native notification APIs.
        queue.0.lock().running = true;
        let title = "🎮".repeat(300);
        let body = "好".repeat(3000);
        for _ in 0..1000 {
            queue
                .submit(
                    Notice::new(&title, &body, NotificationIcon::App),
                    |_| unreachable!(),
                )
                .unwrap();
        }
        let pending = queue.0.lock();
        assert_eq!(pending.items.len(), 1);
        assert_eq!(pending.items[0].title.chars().count(), 256);
        assert_eq!(pending.items[0].message.chars().count(), 2048);
    }
}
