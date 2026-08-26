//! The machinery behind the window.
//!
//! The window paints and posts actions; everything that can be slow (reading
//! Roblox's settings file, bringing the tunnel up) happens here, so the Win32
//! message loop never blocks.
//!
//! Everything real is borrowed from `swifttunnel-core`. Lite reimplements no
//! behaviour, because a second implementation of the frame cap or the tunnel
//! would drift from the full app and the two would end up disagreeing about the
//! same machine.
//!
//! # No frame counter
//!
//! There was one, and it was removed on purpose. Reading a game's frame rate
//! means running a real-time ETW trace of DXGI present events, and those events
//! are logged in the context of whichever process is presenting. A client whose
//! entire reason to exist is not costing you frames should not be taxing every
//! program that draws in order to tell you how many frames you have.

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

pub struct Engine;

impl Engine {
    pub const fn new() -> Self {
        Self
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
