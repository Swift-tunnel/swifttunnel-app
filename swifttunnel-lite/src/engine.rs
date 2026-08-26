//! The machinery behind the window.
//!
//! The window itself is a painting surface and nothing more: it reads values
//! from here and posts actions back. Keeping the two apart means the Win32
//! message loop never blocks on work that can be slow (reading Roblox's
//! settings file, walking the process list) and the UI stays responsive while
//! the tunnel is coming up.
//!
//! Everything real is borrowed from `swifttunnel-core`. Lite reimplements no
//! behaviour, because a second implementation of the frame cap or the FPS
//! reading would drift from the full app and the two would disagree about the
//! same machine.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Duration;

use swifttunnel_core::fps_monitor::FpsMonitor;
use swifttunnel_core::performance_monitor::PerformanceMonitor;
use swifttunnel_core::roblox_optimizer::RobloxOptimizer;
use swifttunnel_core::structs::RobloxSettingsConfig;

/// Frame cap written when the unlock is switched on.
///
/// Not unlimited. An uncapped client will happily render thousands of frames a
/// second on a menu screen, which heats the GPU and buys nothing a monitor can
/// display. 240 clears every refresh rate a player is realistically on while
/// still being a cap.
const UNLOCKED_TARGET_FPS: u32 = 240;

/// Roblox's own default. Anything at or below this counts as still capped.
const DEFAULT_FRAME_CAP: u32 = 60;

/// How often to look for the game.
///
/// Two seconds is far more often than a player launches Roblox, and the check
/// is a process-list walk, so it costs nothing measurable. Faster would only
/// make the FPS card appear a moment sooner.
const GAME_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Sentinel for "no game", since `AtomicU32` has no null and PID 0 is never a
/// real user process.
const NO_PID: u32 = 0;

pub struct Engine {
    fps: Arc<FpsMonitor>,
    /// PID of the running Roblox client, or [`NO_PID`].
    roblox_pid: Arc<AtomicU32>,
    stop: Arc<AtomicBool>,
}

impl Engine {
    pub fn new() -> Self {
        let fps = Arc::new(FpsMonitor::new());
        let roblox_pid = Arc::new(AtomicU32::new(NO_PID));
        let stop = Arc::new(AtomicBool::new(false));

        spawn_game_watcher(fps.clone(), roblox_pid.clone(), stop.clone());

        Self {
            fps,
            roblox_pid,
            stop,
        }
    }

    /// The game's current frame rate, or `None` when there is no game to
    /// measure.
    ///
    /// `None` and `Some(0)` are deliberately the same answer to the caller.
    /// The monitor reports 0 both before the first full sampling window and
    /// when the trace could not start, and showing a confident "0 FPS" for
    /// either would be a worse lie than showing nothing.
    pub fn fps(&self) -> Option<u32> {
        if !self.roblox_running() {
            return None;
        }
        match self.fps.current_fps() {
            0 => None,
            value => Some(value),
        }
    }

    pub fn roblox_running(&self) -> bool {
        self.roblox_pid.load(Ordering::Relaxed) != NO_PID
    }

    /// Whether Roblox is currently running above its default frame cap.
    ///
    /// Read from Roblox's own settings file rather than remembered here, so
    /// the switch reflects reality even when the cap was changed by the full
    /// app, by another tool, or by the player editing the file.
    pub fn fps_unlocked(&self) -> bool {
        RobloxOptimizer::new()
            .read_current_settings()
            .map(|settings| settings.fps_cap > DEFAULT_FRAME_CAP)
            .unwrap_or(false)
    }

    /// Raise or restore Roblox's frame cap.
    ///
    /// Goes through `apply_optimizations` rather than writing the settings
    /// file directly. That function owns the file's format, its permissions
    /// repair and the backup taken before the first change, none of which is
    /// worth reimplementing here and all of which a player would miss if Lite
    /// wrote the file itself.
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
        // Leaves no ETW session behind. The trace is a machine-wide resource
        // and an abandoned one keeps costing every process that presents a
        // frame, which on this app of all apps would be the wrong exit.
        self.fps.set_enabled(false);
    }
}

/// Watch for the game and point the FPS monitor at it.
///
/// The monitor is switched off whenever Roblox is not running, which matters
/// more than it looks: it reads frame rate from a real-time ETW trace of DXGI
/// present events, and those events are logged in the context of whichever
/// process is presenting. Leaving that running with no game to measure would
/// mean a tool people install to gain frames quietly taxing every other
/// program that draws.
fn spawn_game_watcher(fps: Arc<FpsMonitor>, roblox_pid: Arc<AtomicU32>, stop: Arc<AtomicBool>) {
    std::thread::Builder::new()
        .name("lite-game-watcher".to_string())
        .spawn(move || {
            let mut monitor = PerformanceMonitor::new();
            let mut tracked = NO_PID;

            while !stop.load(Ordering::Relaxed) {
                let current = monitor.get_roblox_pid().unwrap_or(NO_PID);

                if current != tracked {
                    tracked = current;
                    roblox_pid.store(current, Ordering::Relaxed);

                    if current == NO_PID {
                        fps.set_enabled(false);
                        log::info!("Roblox closed; FPS trace stopped");
                    } else {
                        fps.set_target_pid(current);
                        fps.set_enabled(true);
                        log::info!("Roblox found at pid {current}; measuring FPS");
                    }
                }

                std::thread::sleep(GAME_POLL_INTERVAL);
            }
        })
        .expect("game watcher thread");
}
