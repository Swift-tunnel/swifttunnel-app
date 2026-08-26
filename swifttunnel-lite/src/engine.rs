//! The machinery behind the window.
//!
//! The window paints and posts actions; everything that can be slow (an HTTP
//! fetch, an ICMP round trip, reading Roblox's settings file) happens on a
//! background thread, so the Win32 message loop never blocks.
//!
//! Everything real is borrowed from `swifttunnel-core`. Lite reimplements no
//! behaviour, because a second implementation of the relay list, the ping or
//! the frame cap would drift from the full app and the two would end up
//! disagreeing about the same machine.
//!
//! # No frame counter
//!
//! There was one, and it was removed on purpose. Reading a game's frame rate
//! means running a real-time ETW trace of DXGI present events, and those events
//! are logged in the context of whichever process is presenting. A client whose
//! entire reason to exist is not costing you frames should not tax every program
//! that draws in order to display a number.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use swifttunnel_core::roblox_optimizer::RobloxOptimizer;
use swifttunnel_core::structs::RobloxSettingsConfig;
use swifttunnel_core::vpn::servers;

/// Frame cap written when the unlock is switched on.
///
/// Not unlimited. An uncapped client will happily render thousands of frames a
/// second on a menu screen, which heats the GPU and buys nothing a monitor can
/// display. 240 clears every refresh rate a player is realistically on while
/// still being a cap.
const UNLOCKED_TARGET_FPS: u32 = 240;

/// Roblox's own default. Anything at or below this counts as still capped.
const DEFAULT_FRAME_CAP: u32 = 60;

/// How often the relays are re-pinged.
///
/// Slow on purpose. A ping that moves while you are reading it is harder to
/// judge than one that holds still, and the full app measures once on connect
/// for the same reason.
const PING_INTERVAL: Duration = Duration::from_secs(30);

/// One row of the region list.
#[derive(Debug, Clone)]
pub struct RegionRow {
    pub id: String,
    pub name: String,
    /// Two-letter code for the badge, e.g. `IN`.
    pub country: String,
    pub relays: usize,
    /// Round trip to the best relay in the region, or `None` while unmeasured.
    pub ping_ms: Option<u32>,
}

impl RegionRow {
    /// Bars out of three, matching how the app grades a connection.
    ///
    /// Thresholds are gaming ones, not general networking ones: 60ms is already
    /// noticeable in a shooter, and past 140 the region is a fallback rather
    /// than a choice.
    pub fn bars(&self) -> u8 {
        match self.ping_ms {
            None => 0,
            Some(ms) if ms <= 60 => 3,
            Some(ms) if ms <= 140 => 2,
            Some(_) => 1,
        }
    }
}

pub struct Engine {
    regions: Arc<RwLock<Vec<RegionRow>>>,
    stop: Arc<AtomicBool>,
}

impl Engine {
    pub fn new() -> Self {
        let regions: Arc<RwLock<Vec<RegionRow>>> = Arc::new(RwLock::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));

        spawn_region_watcher(regions.clone(), stop.clone());

        Self { regions, stop }
    }

    /// The region list, empty until the first fetch lands.
    pub fn regions(&self) -> Vec<RegionRow> {
        self.regions.read().map(|r| r.clone()).unwrap_or_default()
    }

    /// Best measured round trip across every region, for the summary readout.
    pub fn best_ping(&self) -> Option<u32> {
        self.regions().iter().filter_map(|r| r.ping_ms).min()
    }

    pub fn roblox_running(&self) -> bool {
        RobloxOptimizer::new().is_roblox_running()
    }

    /// Whether Roblox is currently allowed to run above its default frame cap.
    ///
    /// Read from Roblox's own settings file rather than remembered here, so the
    /// switch reflects reality even when the cap was changed by the full app,
    /// by another tool, or by the player editing the file.
    pub fn fps_unlocked(&self) -> bool {
        RobloxOptimizer::new()
            .read_current_settings()
            .map(|settings| settings.fps_cap > DEFAULT_FRAME_CAP)
            .unwrap_or(false)
    }

    /// The frame cap Roblox is currently set to.
    pub fn frame_cap(&self) -> u32 {
        RobloxOptimizer::new()
            .read_current_settings()
            .map(|settings| settings.fps_cap)
            .unwrap_or(DEFAULT_FRAME_CAP)
    }

    /// Raise or restore Roblox's frame cap.
    ///
    /// Goes through `apply_optimizations` rather than writing the settings file
    /// directly. That function owns the file's format, its permissions repair
    /// and the backup taken before the first change, none of which is worth
    /// reimplementing and all of which a player would miss if Lite wrote the
    /// file itself.
    pub fn set_fps_unlocked(&self, unlocked: bool) -> Result<(), String> {
        let optimizer = RobloxOptimizer::new();

        if !optimizer.is_roblox_installed() {
            return Err("Roblox is not installed on this PC.".to_string());
        }

        let config = RobloxSettingsConfig {
            unlock_fps: unlocked,
            target_fps: if unlocked {
                UNLOCKED_TARGET_FPS
            } else {
                DEFAULT_FRAME_CAP
            },
            ..RobloxSettingsConfig::default()
        };

        optimizer
            .apply_optimizations(&config)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// Fetch the fleet once, then keep its round trips fresh.
///
/// The list comes from the same endpoint the full app uses, so Lite never has
/// its own idea of which relays exist, and the ping is core's own ICMP probe
/// rather than a second implementation that could disagree with the app's
/// numbers on the same network.
fn spawn_region_watcher(regions: Arc<RwLock<Vec<RegionRow>>>, stop: Arc<AtomicBool>) {
    std::thread::Builder::new()
        .name("lite-regions".to_string())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    log::error!("could not start the region watcher: {error}");
                    return;
                }
            };

            // Addresses to ping, alongside the row they belong to.
            let mut targets: Vec<(usize, String)> = Vec::new();

            match runtime.block_on(servers::fetch_server_list()) {
                Ok(list) => {
                    let mut rows = Vec::new();
                    for region in &list.regions {
                        // Only relays the API is currently offering. A region
                        // whose relays are all withdrawn should not be listed
                        // as somewhere you can go.
                        let members: Vec<&servers::DynamicServerInfo> = list
                            .servers
                            .iter()
                            .filter(|s| region.servers.contains(&s.region) && s.relay_available)
                            .collect();

                        let Some(first) = members.first() else {
                            continue;
                        };

                        targets.push((rows.len(), first.ip.clone()));
                        rows.push(RegionRow {
                            id: region.id.clone(),
                            name: region.name.clone(),
                            country: region.country_code.to_uppercase(),
                            relays: members.len(),
                            ping_ms: None,
                        });
                    }

                    log::info!("region list: {} regions", rows.len());
                    if let Ok(mut guard) = regions.write() {
                        *guard = rows;
                    }
                }
                Err(error) => {
                    log::warn!("could not fetch the region list: {error}");
                    return;
                }
            }

            while !stop.load(Ordering::Relaxed) {
                for (index, ip) in &targets {
                    if stop.load(Ordering::Relaxed) {
                        return;
                    }
                    let measured = servers::measure_latency_icmp(ip);
                    if let Ok(mut guard) = regions.write()
                        && let Some(row) = guard.get_mut(*index)
                    {
                        row.ping_ms = measured;
                    }
                }

                // Sleep in slices so quitting does not wait out the interval.
                let slice = Duration::from_millis(250);
                let mut left = PING_INTERVAL;
                while left > Duration::ZERO && !stop.load(Ordering::Relaxed) {
                    let nap = slice.min(left);
                    std::thread::sleep(nap);
                    left -= nap;
                }
            }
        })
        .expect("region watcher thread");
}
