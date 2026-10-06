//! Bounded, observational support telemetry. Never used to authorize, route,
//! or disconnect traffic. Counter samples are approximate, not packet captures.

use std::net::SocketAddr;
use std::time::Instant;

pub(super) struct AuthAttempt {
    diagnostic: u64,
    target: SocketAddr,
    phase: &'static str,
    started: Instant,
    pub outcome: &'static str,
    pub attempts: usize,
}

impl AuthAttempt {
    pub fn new(diagnostic: u64, target: SocketAddr, phase: &'static str) -> Self {
        Self {
            diagnostic,
            target,
            phase,
            started: Instant::now(),
            outcome: "cancelled_or_unwound",
            attempts: 0,
        }
    }
}

impl Drop for AuthAttempt {
    fn drop(&mut self) {
        log::info!(
            "Relay authentication: diagnostic={:016x} endpoint={} phase={} outcome={} attempts={} elapsed_ms={}",
            self.diagnostic,
            self.target,
            self.phase,
            self.outcome,
            self.attempts,
            self.started.elapsed().as_millis()
        );
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Sample {
    pub at: Instant,
    pub endpoint: SocketAddr,
    pub route_epoch: Option<Instant>,
    pub switch_grace: bool,
    pub enqueued: u64,
    pub received: u64,
    pub pongs: u64,
    pub ping_enabled: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct Interval {
    pub elapsed_ms: u128,
    pub enqueued: u64,
    pub received: u64,
    pub pongs: u64,
    pub observation: &'static str,
}

impl Sample {
    pub fn since(self, previous: Option<Self>) -> Option<Interval> {
        let previous = previous?;
        // Cumulative data counters survive a relay switch, while ping counters
        // reset. Do not attribute mixed endpoints or reset counters to a relay.
        if self.endpoint != previous.endpoint
            || self.route_epoch != previous.route_epoch
            || self.switch_grace
            || previous.switch_grace
            || self.ping_enabled != previous.ping_enabled
        {
            return None;
        }
        let enqueued = self.enqueued.checked_sub(previous.enqueued)?;
        let received = self.received.checked_sub(previous.received)?;
        let pongs = self.pongs.checked_sub(previous.pongs)?;
        let observation = match (enqueued > 0, received > 0, pongs > 0) {
            (true, true, _) => "data_in_both_directions",
            (true, false, true) => "control_replies_without_return_data",
            (true, false, false) => "outbound_without_return_data",
            (false, true, _) => "return_data_only",
            (false, false, _) => "no_game_data_in_interval",
        };
        Some(Interval {
            elapsed_ms: self.at.saturating_duration_since(previous.at).as_millis(),
            enqueued,
            received,
            pongs,
            observation,
        })
    }
}

/// Keep examples of abnormal packets/errors without a log write per packet.
/// Totals remain available in periodic summaries even when examples are skipped.
pub(super) fn log_counter_example(count: u64) -> bool {
    (1..=3).contains(&count) || count.is_power_of_two()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn sample() -> Sample {
        Sample {
            at: Instant::now(),
            endpoint: "127.0.0.1:51821".parse().unwrap(),
            route_epoch: None,
            switch_grace: false,
            enqueued: 10,
            received: 2,
            pongs: 3,
            ping_enabled: true,
        }
    }

    #[test]
    fn interval_uses_new_activity_not_old_success() {
        let previous = sample();
        let now = Sample {
            at: previous.at + Duration::from_secs(60),
            enqueued: 100,
            pongs: 7,
            ..previous
        };
        assert_eq!(
            now.since(Some(previous)),
            Some(Interval {
                elapsed_ms: 60_000,
                enqueued: 90,
                received: 0,
                pongs: 4,
                observation: "control_replies_without_return_data",
            })
        );
        assert_eq!(
            Sample { received: 4, ..now }
                .since(Some(previous))
                .unwrap()
                .observation,
            "data_in_both_directions"
        );
        assert_eq!(
            Sample { pongs: 3, ..now }
                .since(Some(previous))
                .unwrap()
                .observation,
            "outbound_without_return_data"
        );
    }

    #[test]
    fn idle_and_return_only_do_not_claim_failure() {
        let previous = sample();
        assert_eq!(
            previous.since(Some(previous)).unwrap().observation,
            "no_game_data_in_interval"
        );
        assert_eq!(
            Sample {
                received: 3,
                ..previous
            }
            .since(Some(previous))
            .unwrap()
            .observation,
            "return_data_only"
        );
    }

    #[test]
    fn switch_and_counter_reset_start_a_new_baseline() {
        let previous = sample();
        assert!(previous.since(None).is_none());
        // A -> B -> A and old-relay grace traffic must not look like success
        // on the currently selected relay.
        assert!(
            Sample {
                route_epoch: Some(Instant::now()),
                ..previous
            }
            .since(Some(previous))
            .is_none()
        );
        let grace = Sample {
            switch_grace: true,
            ..previous
        };
        assert!(grace.since(Some(previous)).is_none());
        assert!(previous.since(Some(grace)).is_none());
        assert!(
            Sample {
                endpoint: "127.0.0.2:51821".parse().unwrap(),
                ..previous
            }
            .since(Some(previous))
            .is_none()
        );
        assert!(
            Sample {
                pongs: 0,
                ..previous
            }
            .since(Some(previous))
            .is_none()
        );
        assert!(
            Sample {
                enqueued: 0,
                ..previous
            }
            .since(Some(previous))
            .is_none()
        );
        assert!(
            Sample {
                ping_enabled: false,
                ..previous
            }
            .since(Some(previous))
            .is_none()
        );
    }

    #[test]
    fn error_flood_keeps_examples_bounded() {
        assert!(!log_counter_example(0));
        let examples: Vec<_> = (1..=1_000_000)
            .filter(|&n| log_counter_example(n))
            .collect();
        assert_eq!(&examples[..5], &[1, 2, 3, 4, 8]);
        assert!(examples.len() <= 22);
    }
}
