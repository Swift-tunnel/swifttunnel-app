//! Shared Desktop/Lite countdown and native warnings. Authorization remains server-side.
use crate::auth::types::RelayTicketResponse;
use parking_lot::Mutex;
use std::sync::LazyLock;
use std::time::Instant;

static QUOTA: LazyLock<Mutex<QuotaClock>> = LazyLock::new(|| Mutex::new(QuotaClock::default()));

#[derive(Default)]
struct QuotaClock {
    remaining: Option<i64>,
    limit: Option<i64>,
    grace: Option<i64>,
    resets_at: Option<i64>,
    sampled: Option<Instant>,
    active: bool,
    warned: u8,
}

pub(crate) struct Notice {
    pub title: String,
    pub body: String,
}

impl QuotaClock {
    fn record(
        &mut self,
        remaining: Option<i64>,
        limit: Option<i64>,
        grace: Option<i64>,
        resets_at: Option<i64>,
        now: Instant,
    ) {
        if self.resets_at != resets_at || self.limit != limit {
            self.warned = 0;
        }
        self.remaining = remaining.filter(|v| *v >= 0);
        self.limit = limit.filter(|v| *v > 0);
        self.grace = grace.filter(|v| *v >= 0);
        self.resets_at = resets_at;
        self.sampled = Some(now);
    }

    fn values(&self, now: Instant, unix: i64) -> (Option<i64>, Option<i64>, Option<i64>) {
        if self.remaining.is_none() {
            return (None, self.limit, None);
        }
        if self
            .resets_at
            .is_some_and(|reset| reset > 0 && unix >= reset)
        {
            // A fresh connect still asks the server. Never create a local authorization.
            return (self.limit, self.limit, None);
        }
        let elapsed = if self.active {
            self.sampled
                .map(|at| {
                    now.saturating_duration_since(at)
                        .as_secs()
                        .min(i64::MAX as u64) as i64
                })
                .unwrap_or(0)
        } else {
            0
        };
        (
            self.remaining.map(|v| v.saturating_sub(elapsed).max(0)),
            self.limit,
            self.grace.map(|v| v.saturating_sub(elapsed).max(0)),
        )
    }

    fn set_active(&mut self, active: bool, now: Instant, unix: i64) {
        if self.active == active {
            return;
        }
        let (remaining, _, grace) = self.values(now, unix);
        self.remaining = remaining;
        self.grace = grace;
        self.sampled = Some(now);
        self.active = active;
    }

    fn next_notice(&mut self, now: Instant, unix: i64) -> Option<Notice> {
        if !self.active {
            return None;
        }
        let (Some(left), Some(limit), grace) = self.values(now, unix) else {
            return None;
        };
        let used = limit.saturating_sub(left).max(0) as i128;
        let percent = used * 100 / i128::from(limit);
        let stage = if left == 0 {
            4
        } else if left <= 60 {
            3
        } else if percent >= 90 {
            2
        } else if percent >= 50 {
            1
        } else {
            0
        };
        if stage <= self.warned {
            return None;
        }
        self.warned = stage;
        let (title, body) = match stage {
            4 if grace.is_some_and(|v| v > 0) => ("Free time used up".into(), format!("The server granted {} of extra connection time.", duration(grace.unwrap()))),
            4 => ("Free time used up".into(), "Your free allowance is exhausted. SwiftTunnel is disconnecting. Your allowance will return at its scheduled reset.".into()),
            3 => ("1 minute remaining".into(), format!("{} remaining before SwiftTunnel disconnects. Finish your match or disconnect now.", duration(left))),
            stage => {
                let threshold = if stage == 1 { 50 } else { 90 };
                (format!("{threshold}% of free time used"), format!("{} remaining before SwiftTunnel disconnects.", duration(left)))
            }
        };
        Some(Notice { title, body })
    }

    fn exhausted(&self, now: Instant, unix: i64) -> bool {
        let (remaining, limit, grace) = self.values(now, unix);
        self.active && limit.is_some() && remaining == Some(0) && grace.is_none_or(|v| v <= 0)
    }
}

fn duration(seconds: i64) -> String {
    if seconds >= 3600 {
        format!("{}h {}m", seconds / 3600, seconds % 3600 / 60)
    } else if seconds >= 60 {
        format!("{}m {}s", seconds / 60, seconds % 60)
    } else {
        format!("{seconds}s")
    }
}

pub(crate) fn record(ticket: &RelayTicketResponse) {
    QUOTA.lock().record(
        ticket.remaining_seconds,
        ticket.limit_seconds,
        ticket.grace_seconds,
        ticket.resets_at.map(|t| t.timestamp()),
        Instant::now(),
    );
}

pub(crate) fn values() -> (Option<i64>, Option<i64>, Option<i64>) {
    QUOTA
        .lock()
        .values(Instant::now(), chrono::Utc::now().timestamp())
}

pub(crate) fn set_active(active: bool) {
    QUOTA
        .lock()
        .set_active(active, Instant::now(), chrono::Utc::now().timestamp());
}

pub(crate) fn clear_reading() {
    let mut quota = QUOTA.lock();
    quota.remaining = None;
    quota.grace = None;
    quota.active = false;
}

pub(crate) fn tick() -> (Option<Notice>, bool) {
    let mut quota = QUOTA.lock();
    let now = Instant::now();
    let unix = chrono::Utc::now().timestamp();
    let notice = quota.next_notice(now, unix);
    let exhausted = quota.exhausted(now, unix);
    (notice, exhausted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    fn clock(left: i64) -> (QuotaClock, Instant) {
        let now = Instant::now();
        let mut clock = QuotaClock::default();
        clock.record(Some(left), Some(10800), None, Some(86400), now);
        clock.set_active(true, now, 0);
        (clock, now)
    }
    #[test]
    fn thresholds_and_one_minute_are_accurate_and_deduplicated() {
        let (mut q, now) = clock(10800);
        for (elapsed, title, remaining) in [
            (5400, "50%", "1h 30m"),
            (9720, "90%", "18m 0s"),
            (10740, "1 minute", "1m 0s"),
            (10800, "Free time used up", "disconnecting"),
        ] {
            let at = now + Duration::from_secs(elapsed);
            let notice = q.next_notice(at, elapsed as i64).unwrap();
            assert!(notice.title.starts_with(title));
            assert!(notice.body.contains(remaining));
            assert!(q.next_notice(at, elapsed as i64).is_none());
            if elapsed == 9720 {
                // Crossing 99% or reaching 61 seconds must not warn early.
                for elapsed in [10692, 10739] {
                    assert!(
                        q.next_notice(now + Duration::from_secs(elapsed), elapsed as i64)
                            .is_none()
                    );
                }
            }
        }
    }
    #[test]
    fn late_start_only_shows_most_urgent_warning() {
        let (mut q, now) = clock(50);
        assert!(q.next_notice(now, 0).unwrap().title.starts_with("1 minute"));
        assert!(q.next_notice(now, 0).is_none());
    }
    #[test]
    fn elapsed_snapshot_does_not_jump_back_when_read_again() {
        let (q, now) = clock(6840);
        assert_eq!(q.values(now + Duration::from_secs(60), 60).0, Some(6780));
        assert_eq!(q.values(now + Duration::from_secs(61), 61).0, Some(6779));
    }
    #[test]
    fn disconnect_pauses_and_reconnect_does_not_repeat_warning() {
        let (mut q, now) = clock(5400);
        assert!(q.next_notice(now, 0).is_some());
        q.set_active(false, now + Duration::from_secs(10), 10);
        assert_eq!(q.values(now + Duration::from_secs(100), 100).0, Some(5390));
        assert!(q.next_notice(now + Duration::from_secs(100), 100).is_none());
        q.record(
            Some(5390),
            Some(10800),
            None,
            Some(86400),
            now + Duration::from_secs(100),
        );
        q.set_active(true, now + Duration::from_secs(100), 100);
        assert!(q.next_notice(now + Duration::from_secs(100), 100).is_none());
    }
    #[test]
    fn reset_rearms_but_unlimited_and_unknown_never_warn() {
        let (mut q, now) = clock(5400);
        assert!(q.next_notice(now, 0).is_some());
        assert_eq!(q.values(now, 86400), (Some(10800), Some(10800), None));
        q.record(Some(5400), Some(10800), None, Some(172800), now);
        assert!(q.next_notice(now, 86400).is_some());
        for (left, limit) in [
            (None, None),
            (None, Some(10800)),
            (Some(0), None),
            (Some(0), Some(0)),
        ] {
            q.record(left, limit, None, None, now);
            assert!(q.next_notice(now, 0).is_none());
        }
    }
    #[test]
    fn no_grace_is_invented_and_legacy_grace_counts_down() {
        let (mut q, now) = clock(0);
        assert_eq!(q.values(now, 0).2, None);
        assert!(!q.next_notice(now, 0).unwrap().body.contains("extra"));
        q.record(Some(0), Some(10800), Some(30), Some(86401), now);
        assert_eq!(q.values(now + Duration::from_secs(31), 31).2, Some(0));
        assert!(!q.exhausted(now, 0));
        assert!(q.exhausted(now + Duration::from_secs(31), 31));
    }
    #[test]
    fn exhaustion_is_exact_does_not_wait_for_a_ticket_and_respects_reset() {
        let (mut q, now) = clock(61);
        assert!(!q.exhausted(now + Duration::from_secs(60), 60));
        assert!(q.exhausted(now + Duration::from_secs(61), 61));
        assert!(q.exhausted(now + Duration::from_secs(120), 120));
        assert!(!q.exhausted(now + Duration::from_secs(86400), 86400));
        q.set_active(false, now + Duration::from_secs(61), 61);
        assert!(!q.exhausted(now + Duration::from_secs(120), 120));
    }
}
