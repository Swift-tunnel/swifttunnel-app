//! Space automatic reconnect failures without delaying manual Connect.
use std::time::{Duration, Instant};

const INITIAL_DELAY: Duration = Duration::from_secs(5);
const MAX_DELAY: Duration = Duration::from_secs(60);

pub struct ReconnectBackoff {
    due: Option<Instant>,
    delay: Duration,
}

impl Default for ReconnectBackoff {
    fn default() -> Self {
        Self {
            due: None,
            delay: INITIAL_DELAY,
        }
    }
}

impl ReconnectBackoff {
    pub fn ready(&self, now: Instant) -> bool {
        self.due.is_none_or(|due| now >= due)
    }

    pub fn failed(&mut self, now: Instant) -> Duration {
        let wait = self.delay;
        self.due = Some(now + wait);
        self.delay = (wait * 2).min(MAX_DELAY);
        wait
    }

    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quick_failures_back_off_from_completion_and_a_healthy_session_resets_it() {
        let mut retry = ReconnectBackoff::default();
        let mut now = Instant::now();
        assert!(retry.ready(now));
        for wait in [5, 10, 20, 40, 60, 60] {
            // A slow connection attempt must not consume its own quiet period.
            now += Duration::from_secs(30);
            assert_eq!(retry.failed(now), Duration::from_secs(wait));
            assert!(!retry.ready(now));
            assert!(!retry.ready(now + Duration::from_secs(wait) - Duration::from_millis(1)));
            now += Duration::from_secs(wait);
            assert!(retry.ready(now));
        }
        retry.failed(now);
        assert!(!retry.ready(now));
        retry.reset();
        assert!(retry.ready(now));
        assert_eq!(retry.failed(now), INITIAL_DELAY);
    }
}
