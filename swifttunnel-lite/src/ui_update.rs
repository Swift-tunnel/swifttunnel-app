//! Coalesce snapshot-change notifications while the window thread is busy.

use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Default)]
pub struct UiUpdate(AtomicBool);

impl UiUpdate {
    pub fn post(&self, send: impl FnOnce() -> bool) {
        if self.0.swap(true, Ordering::AcqRel) {
            return;
        }
        if !send() {
            self.0.store(false, Ordering::Release);
        }
    }

    /// Acknowledge before reading the snapshot. A change during that read can
    /// then schedule one more pass instead of being lost.
    pub fn acknowledge(&self) {
        self.0.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, atomic::AtomicUsize};

    #[test]
    fn concurrent_updates_queue_one_snapshot_read_until_the_window_consumes_it() {
        let update = Arc::new(UiUpdate::default());
        let posts = Arc::new(AtomicUsize::new(0));
        for _ in 0..2 {
            let workers: Vec<_> = (0..4)
                .map(|_| {
                    let update = update.clone();
                    let posts = posts.clone();
                    std::thread::spawn(move || {
                        for _ in 0..2500 {
                            update.post(|| {
                                posts.fetch_add(1, Ordering::SeqCst);
                                true
                            });
                        }
                    })
                })
                .collect();
            for worker in workers {
                worker.join().unwrap();
            }
            update.acknowledge();
        }
        assert_eq!(posts.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn failed_post_can_retry_and_changes_during_snapshot_read_get_another_pass() {
        let update = UiUpdate::default();
        let posts = AtomicUsize::new(0);
        update.post(|| false);
        update.post(|| {
            posts.fetch_add(1, Ordering::SeqCst);
            true
        });
        update.acknowledge();
        // The UI is now reading the snapshot, while another worker changes it.
        update.post(|| {
            posts.fetch_add(1, Ordering::SeqCst);
            true
        });
        update.post(|| panic!("another read was already queued"));
        assert_eq!(posts.load(Ordering::SeqCst), 2);
    }
}
