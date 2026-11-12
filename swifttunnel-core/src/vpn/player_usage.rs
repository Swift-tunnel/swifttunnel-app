//! Sampled Player peak for one connection. No destinations or process identity
//! leave this module. Sampling never runs on a packet or UI thread.
use parking_lot::{Condvar, Mutex};
use serde::Serialize;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

const SAMPLE_INTERVAL: Duration = Duration::from_secs(5);
// An OS enumeration that stalls must not accumulate more enumerations on
// repeated reconnects. A busy census is unknown, never a zero-player sample.
static CENSUS: StdMutex<()> = StdMutex::new(());

#[derive(Default)]
pub(crate) struct PlayerUsage {
    state: Mutex<State>,
    changed: Condvar,
}
#[derive(Default)]
struct State {
    enabled: bool,
    enable_revision: u64,
    stopped: bool,
    session_id: Option<String>,
    peak_players: Option<u32>,
    samples: u32,
    failures: u32,
}
#[derive(Serialize, Debug, PartialEq, Eq)]
pub(crate) struct Report {
    schema: u8,
    session_id: String,
    peak_players: Option<u32>,
    samples: u32,
    failures: u32,
}
impl PlayerUsage {
    pub(crate) fn set_enabled(&self, enabled: bool) {
        let mut state = self.state.lock();
        if state.enabled != enabled {
            state.enabled = enabled;
            state.enable_revision = state.enable_revision.wrapping_add(1);
            self.changed.notify_one();
        }
    }
    pub(crate) fn bind(&self, session_id: String) {
        let mut state = self.state.lock();
        // An auto route keeps the same relay session. Rebinding is not a new
        // observation period and must not erase a high peak.
        if state.session_id.is_none() {
            state.session_id = Some(session_id);
        }
    }
    fn wait_for_sample(&self, earliest: Instant) -> Option<u64> {
        let mut state = self.state.lock();
        while !state.stopped {
            if !state.enabled {
                self.changed.wait(&mut state);
                continue;
            }
            let delay = earliest.saturating_duration_since(Instant::now());
            if delay.is_zero() {
                return Some(state.enable_revision);
            }
            self.changed.wait_for(&mut state, delay);
        }
        None
    }

    fn stop(&self) {
        self.state.lock().stopped = true;
        self.changed.notify_one();
    }

    fn sample(&self, revision: u64, count: Result<usize, ()>) {
        let mut state = self.state.lock();
        if state.stopped || !state.enabled || state.enable_revision != revision {
            return;
        }
        match count {
            Ok(count) if count <= 32768 => {
                state.peak_players = Some(state.peak_players.unwrap_or(0).max(count as u32));
                state.samples = state.samples.saturating_add(1);
            }
            _ => state.failures = state.failures.saturating_add(1),
        }
    }
    pub(crate) fn report(&self) -> Option<Report> {
        let state = self.state.try_lock()?;
        if !state.enabled {
            return None;
        }
        Some(Report {
            schema: 1,
            session_id: state.session_id.clone()?,
            peak_players: state.peak_players,
            samples: state.samples,
            failures: state.failures,
        })
    }
}

pub(crate) struct Observer(Arc<PlayerUsage>);
impl Observer {
    pub(crate) fn start(
        usage: Arc<PlayerUsage>,
        connection: Arc<tokio::sync::watch::Sender<super::connection::ConnectionState>>,
    ) -> Option<Self> {
        usage.state.lock().session_id.as_ref()?; // Custom relays have no hosted session to measure.
        let observed = usage.clone();
        std::thread::Builder::new()
            .name("player-usage".into())
            .spawn(move || {
                let usage = observed;
                let Some(mut revision) = usage.wait_for_sample(Instant::now()) else {
                    return;
                };
                #[cfg(windows)]
                unsafe {
                    use windows::Win32::System::Threading::{
                        GetCurrentThread, SetThreadPriority, THREAD_PRIORITY_BELOW_NORMAL,
                    };
                    if SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL).is_err()
                    {
                        usage.sample(revision, Err(()));
                        return;
                    }
                }
                loop {
                    if !connection.borrow().is_connected() {
                        break;
                    }
                    let count = match CENSUS.try_lock() {
                        Ok(_guard) => {
                            #[cfg(windows)]
                            {
                                crate::process_snapshot::count_named(
                                    crate::process_names::ROBLOX_PLAYER_PROCESS_NAMES,
                                )
                                .map_err(|_| ())
                            }
                            #[cfg(not(windows))]
                            {
                                Err(())
                            }
                        }
                        Err(_) => Err(()),
                    };
                    if connection.borrow().is_connected() {
                        usage.sample(revision, count);
                    }
                    let Some(next) = usage.wait_for_sample(Instant::now() + SAMPLE_INTERVAL) else {
                        break;
                    };
                    revision = next;
                }
            })
            .ok()?;
        Some(Self(usage))
    }
}
impl Drop for Observer {
    fn drop(&mut self) {
        self.0.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(windows)]
    #[test]
    #[ignore = "manual local native process-census timing, no network or game launch"]
    fn native_count_cost() {
        let mut samples = Vec::new();
        for _ in 0..25 {
            let start = std::time::Instant::now();
            let count = crate::process_snapshot::count_named(
                crate::process_names::ROBLOX_PLAYER_PROCESS_NAMES,
            )
            .unwrap();
            samples.push(start.elapsed().as_secs_f64() * 1000.0);
            std::hint::black_box(count);
        }
        samples.sort_by(f64::total_cmp);
        println!(
            "native_player_census_ms: median={:.3}, p96={:.3}, max={:.3}; 25 local samples",
            samples[12], samples[23], samples[24]
        );
    }
    #[test]
    fn sampled_peak_survives_rebinds_and_errors_are_not_zero() {
        let usage = PlayerUsage::default();
        assert!(usage.report().is_none());
        usage.bind("0123456789abcdef".into());
        assert!(usage.report().is_none());
        usage.set_enabled(true);
        let revision = usage.wait_for_sample(Instant::now()).unwrap();
        assert_eq!(usage.report().unwrap().peak_players, None);
        usage.sample(revision, Err(()));
        assert_eq!(usage.report().unwrap().peak_players, None);
        usage.sample(revision, Ok(2));
        usage.bind("different-relay".into());
        usage.sample(revision, Ok(0));
        let report = usage.report().unwrap();
        assert_eq!(report.peak_players, Some(2));
        assert_eq!(report.samples, 2);
        assert_eq!(report.failures, 1);
        assert_eq!(report.session_id, "0123456789abcdef");
        assert_eq!(PlayerUsage::default().report(), None);
        let json = serde_json::to_value(report).unwrap();
        assert_eq!(json.as_object().unwrap().len(), 5);
        usage.set_enabled(false);
        assert!(usage.report().is_none());
    }

    #[test]
    fn disabled_sampler_waits_for_enable_or_stop_and_discards_in_flight_counts() {
        use std::sync::mpsc;
        let usage = Arc::new(PlayerUsage::default());
        usage.bind("session".into());
        let observed = usage.clone();
        let (results, result) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let _ = results.send(observed.wait_for_sample(Instant::now()));
            let _ =
                results.send(observed.wait_for_sample(Instant::now() + Duration::from_secs(30)));
        });
        assert!(result.recv_timeout(Duration::from_millis(25)).is_err());
        usage.set_enabled(true);
        let revision = result
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .unwrap();
        usage.set_enabled(false);
        usage.set_enabled(true);
        usage.sample(revision, Ok(99));
        // `report` gives up instead of waiting when the sampler thread holds
        // the lock for an instant, which it does here while it goes back to
        // sleep. Asking once made this test fail about one run in three.
        let report = (0..500)
            .find_map(|_| {
                usage.report().or_else(|| {
                    std::thread::sleep(Duration::from_millis(1));
                    None
                })
            })
            .unwrap();
        assert_eq!(report.peak_players, None);
        usage.set_enabled(false);
        usage.stop();
        assert_eq!(result.recv_timeout(Duration::from_secs(2)).unwrap(), None);
        worker.join().unwrap();
    }
}
