//! Discord Rich Presence manager
//!
//! Runs a background thread that maintains the Discord IPC connection
//! and updates presence based on VPN state.

use super::state::{
    DISCORD_BRAND_IMAGE_KEY, DiscordActivity, DiscordState, game_display_name, game_icon_key,
    region_display_label, region_flag_key,
};
use discord_rich_presence::{DiscordIpc, DiscordIpcClient, activity};
use log::{debug, info, warn};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// SwiftTunnel Discord application ID.
const DISCORD_APP_ID: &str = "1467394500476538920";

/// Interval to retry Discord connection if not connected
const RECONNECT_INTERVAL: Duration = Duration::from_secs(30);

/// Manages Discord Rich Presence in a background thread
pub struct DiscordManager {
    /// Channel to send activity updates
    tx: Sender<DiscordActivity>,
    /// Stored receiver for lazy thread spawn (only used when starting disabled)
    pending_rx: Option<Receiver<DiscordActivity>>,
    /// Handle to the background thread
    thread_handle: Option<JoinHandle<()>>,
    /// Whether RPC is enabled (user setting)
    enabled: bool,
    /// Current state for comparison (avoid duplicate updates)
    current_state: Option<DiscordState>,
    /// When the VPN connection was established (for elapsed time)
    connected_at: Option<Instant>,
}

impl DiscordManager {
    /// Create a new Discord manager. Only spawns the background thread when enabled.
    pub fn new(enabled: bool) -> Self {
        let (tx, rx) = mpsc::channel::<DiscordActivity>();

        // Only spawn thread if enabled — saves one thread + IPC connection attempts when disabled
        let (thread_handle, pending_rx) = if enabled {
            (Self::spawn_rpc_thread(rx), None)
        } else {
            (None, Some(rx))
        };

        Self {
            tx,
            pending_rx,
            thread_handle,
            enabled,
            current_state: None,
            connected_at: None,
        }
    }

    /// Spawn the background thread that handles Discord IPC
    fn spawn_rpc_thread(rx: Receiver<DiscordActivity>) -> Option<JoinHandle<()>> {
        match thread::Builder::new()
            .name("discord-rpc".to_string())
            .spawn(move || {
                Self::rpc_thread_main(rx);
            }) {
            Ok(handle) => Some(handle),
            Err(error) => {
                warn!("Discord presence worker could not start: {error}");
                None
            }
        }
    }

    /// Main loop for the Discord RPC background thread
    fn rpc_thread_main(rx: Receiver<DiscordActivity>) {
        info!("Discord RPC thread started");

        let mut client: Option<DiscordIpcClient> = None;
        let mut last_connect_attempt = Instant::now() - RECONNECT_INTERVAL;
        let mut latest_state: Option<DiscordState> = None;

        loop {
            // Unchanged GUI state no longer floods the pipe. A low-frequency
            // refresh still reconnects if Discord starts/restarts later.
            let message = if let Some(state) = &latest_state {
                match rx.recv_timeout(RECONNECT_INTERVAL) {
                    Ok(activity) => Ok(activity),
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        Ok(DiscordActivity::SetActivity(state.clone()))
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => Err(mpsc::RecvError),
                }
            } else {
                rx.recv()
            };
            match message {
                Ok(activity) => {
                    // Shutdown must not start a fresh pipe connection first.
                    if matches!(activity, DiscordActivity::Shutdown) {
                        if let Some(ref mut c) = client {
                            let _ = c.clear_activity();
                            let _ = c.close();
                        }
                        return;
                    }
                    // Clearing a disabled/unavailable presence must not open
                    // a new Discord pipe just to clear it again.
                    if matches!(activity, DiscordActivity::Clear) {
                        latest_state = None;
                        if let Some(ref mut c) = client
                            && c.clear_activity().is_err()
                        {
                            client = None;
                        }
                        continue;
                    }
                    if let DiscordActivity::SetActivity(state) = &activity {
                        latest_state = Some(state.clone());
                    }
                    // Try to connect if not connected and enough time has passed
                    if client.is_none() && last_connect_attempt.elapsed() >= RECONNECT_INTERVAL {
                        last_connect_attempt = Instant::now();
                        match Self::try_connect() {
                            Ok(c) => {
                                info!("Connected to Discord IPC");
                                client = Some(c);
                            }
                            Err(e) => {
                                debug!("Discord not available: {}", e);
                            }
                        }
                    }

                    match activity {
                        DiscordActivity::Shutdown => unreachable!("handled before connecting"),
                        DiscordActivity::Clear => unreachable!("handled before connecting"),
                        DiscordActivity::SetActivity(state) => {
                            if let Some(ref mut c) = client
                                && let Err(e) = Self::set_activity(c, &state)
                            {
                                warn!("Failed to set Discord activity: {}", e);
                                client = None;
                            }
                        }
                    }
                }
                Err(mpsc::RecvError) => {
                    info!("Discord RPC channel closed, shutting down");
                    if let Some(ref mut c) = client {
                        let _ = c.clear_activity();
                        let _ = c.close();
                    }
                    return;
                }
            }
        }
    }

    /// Try to connect to Discord IPC
    fn try_connect() -> Result<DiscordIpcClient, String> {
        let mut client = DiscordIpcClient::new(DISCORD_APP_ID)
            .map_err(|e| format!("Failed to create Discord client: {}", e))?;

        client
            .connect()
            .map_err(|e| format!("Failed to connect to Discord: {}", e))?;

        Ok(client)
    }

    /// Create Discord activity buttons (Get SwiftTunnel + Join Discord)
    fn create_buttons() -> Vec<activity::Button<'static>> {
        vec![
            activity::Button::new("Get SwiftTunnel", "https://swifttunnel.net"),
            activity::Button::new("Join our Discord!", "https://swifttunnel.net/discord"),
        ]
    }

    /// Set Discord activity based on state
    fn set_activity(client: &mut DiscordIpcClient, state: &DiscordState) -> Result<(), String> {
        // Build and send activity based on state
        // Each branch creates its own owned strings to avoid lifetime issues
        match state {
            DiscordState::Idle => {
                let payload = activity::Activity::new()
                    .state("Idle")
                    .details("VPN Disconnected")
                    .assets(
                        activity::Assets::new()
                            .large_image(DISCORD_BRAND_IMAGE_KEY)
                            .large_text("SwiftTunnel"),
                    )
                    .buttons(Self::create_buttons());
                client
                    .set_activity(payload)
                    .map_err(|e| format!("Failed to set activity: {}", e))?;
            }
            DiscordState::Connecting { region } => {
                let region_name = region_display_label(region);
                let state_str = format!("Connecting to {}...", region_name.as_ref());
                let payload = activity::Activity::new()
                    .state(&state_str)
                    .details("Establishing VPN")
                    .assets(
                        activity::Assets::new()
                            .large_image(DISCORD_BRAND_IMAGE_KEY)
                            .large_text("SwiftTunnel")
                            .small_image(region_flag_key(region))
                            .small_text(region_name.as_ref()),
                    )
                    .buttons(Self::create_buttons());
                client
                    .set_activity(payload)
                    .map_err(|e| format!("Failed to set activity: {}", e))?;
            }
            DiscordState::Connected {
                region,
                connected_at,
            } => {
                let region_name = region_display_label(region);
                let elapsed_secs = connected_at.elapsed().as_secs();
                // Use Unix timestamp for Discord's elapsed time display
                let start_timestamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64 - elapsed_secs as i64)
                    .unwrap_or(0);
                let state_str = format!("Connected to {}", region_name.as_ref());

                let payload = activity::Activity::new()
                    .state(&state_str)
                    .details("VPN Active")
                    .assets(
                        activity::Assets::new()
                            .large_image(DISCORD_BRAND_IMAGE_KEY)
                            .large_text("SwiftTunnel")
                            .small_image(region_flag_key(region))
                            .small_text(region_name.as_ref()),
                    )
                    .timestamps(activity::Timestamps::new().start(start_timestamp))
                    .buttons(Self::create_buttons());
                client
                    .set_activity(payload)
                    .map_err(|e| format!("Failed to set activity: {}", e))?;
            }
            DiscordState::PlayingGame {
                game_name,
                region,
                connected_at,
            } => {
                let region_name = region_display_label(region);
                let display_name = game_display_name(game_name);
                let elapsed_secs = connected_at.elapsed().as_secs();
                let start_timestamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64 - elapsed_secs as i64)
                    .unwrap_or(0);
                let state_str = format!("Connected to {}", region_name.as_ref());
                let details_str = format!("Playing {}", display_name);

                let payload = activity::Activity::new()
                    .state(&state_str)
                    .details(&details_str)
                    .assets(
                        activity::Assets::new()
                            .large_image(game_icon_key(game_name))
                            .large_text(display_name)
                            .small_image(DISCORD_BRAND_IMAGE_KEY)
                            .small_text("SwiftTunnel VPN"),
                    )
                    .timestamps(activity::Timestamps::new().start(start_timestamp))
                    .buttons(Self::create_buttons());
                client
                    .set_activity(payload)
                    .map_err(|e| format!("Failed to set activity: {}", e))?;
            }
        }

        debug!("Discord activity updated: {:?}", state);
        Ok(())
    }

    /// Update the Discord presence based on current state
    /// Call this from the main GUI update loop
    pub fn update_state(&mut self, state: DiscordState) {
        if self.current_state.as_ref() == Some(&state) {
            return;
        }

        // Track connected_at for elapsed time calculation
        match &state {
            DiscordState::Connected { connected_at, .. }
            | DiscordState::PlayingGame { connected_at, .. } => {
                if self.connected_at.is_none() {
                    self.connected_at = Some(*connected_at);
                }
            }
            DiscordState::Idle | DiscordState::Connecting { .. } => {
                self.connected_at = None;
            }
        }

        self.current_state = Some(state.clone());
        if self.enabled {
            let _ = self.tx.send(DiscordActivity::SetActivity(state));
        }
    }

    /// Set idle state
    pub fn set_idle(&mut self) {
        self.update_state(DiscordState::Idle);
    }

    /// Set connecting state
    pub fn set_connecting(&mut self, region: &str) {
        self.update_state(DiscordState::Connecting {
            region: region.to_string(),
        });
    }

    /// Set connected state
    pub fn set_connected(&mut self, region: &str) {
        let connected_at = self.connected_at.unwrap_or_else(Instant::now);
        self.connected_at = Some(connected_at);
        self.update_state(DiscordState::Connected {
            region: region.to_string(),
            connected_at,
        });
    }

    /// Set playing game state
    pub fn set_playing_game(&mut self, game_name: &str, region: &str) {
        let connected_at = self.connected_at.unwrap_or_else(Instant::now);
        self.update_state(DiscordState::PlayingGame {
            game_name: game_name.to_string(),
            region: region.to_string(),
            connected_at,
        });
    }

    /// Enable or disable Discord RPC
    pub fn set_enabled(&mut self, enabled: bool) {
        let was_enabled = self.enabled;
        self.enabled = enabled;

        if !enabled && was_enabled {
            // Clear presence when disabled (but keep current_state for later restore)
            let _ = self.tx.send(DiscordActivity::Clear);
        } else if enabled
            && (!was_enabled || self.thread_handle.as_ref().is_none_or(|h| h.is_finished()))
        {
            // Lazy-spawn the thread if it hasn't been started yet
            if self.thread_handle.as_ref().is_none_or(|h| h.is_finished()) {
                if let Some(handle) = self.thread_handle.take() {
                    let _ = handle.join();
                }
                let rx = self.pending_rx.take().unwrap_or_else(|| {
                    let (tx, rx) = mpsc::channel();
                    self.tx = tx;
                    rx
                });
                self.thread_handle = Self::spawn_rpc_thread(rx);
            }
            // Restore state when re-enabled
            if let Some(state) = self.current_state.clone() {
                let _ = self.tx.send(DiscordActivity::SetActivity(state));
            } else {
                self.set_idle();
            }
        }
    }

    /// Check if Discord RPC is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Clear presence (e.g., on logout)
    pub fn clear(&mut self) {
        self.current_state = None;
        self.connected_at = None;
        if self.thread_handle.is_some() {
            let _ = self.tx.send(DiscordActivity::Clear);
        }
    }
}

impl Drop for DiscordManager {
    fn drop(&mut self) {
        // Signal shutdown to the background thread
        let _ = self.tx.send(DiscordActivity::Shutdown);

        // A stalled Discord named pipe must not hang exit or a repair restart.
        if let Some(handle) = self.thread_handle.take() {
            let deadline = Instant::now() + Duration::from_millis(500);
            while !handle.is_finished() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(10));
            }
            if handle.is_finished() {
                match handle.join() {
                    Ok(()) => debug!("Discord RPC thread shut down cleanly"),
                    Err(_) => warn!("Discord RPC thread panicked during shutdown"),
                }
            } else {
                // Dropping the handle detaches it; do not create another waiter.
                warn!("Discord RPC shutdown exceeded 500ms; continuing app shutdown");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drop_does_not_wait_forever_for_a_stalled_rpc_worker() {
        let (release_tx, release_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let mut manager = DiscordManager::new(false);
        manager.thread_handle = Some(thread::spawn(move || {
            let _ = release_rx.recv();
        }));
        let dropper = thread::spawn(move || {
            drop(manager);
            let _ = done_tx.send(());
        });
        let completed = done_rx.recv_timeout(Duration::from_secs(2)).is_ok();
        // Release even on failure, so the old implementation fails rather than hanging tests.
        let _ = release_tx.send(());
        dropper.join().unwrap();
        assert!(
            completed,
            "Discord shutdown waited indefinitely for a blocked pipe worker"
        );
    }

    #[test]
    fn test_manager_creation() {
        // Just test that it doesn't panic
        let _manager = DiscordManager::new(false);
    }

    #[test]
    fn test_state_transitions() {
        let mut manager = DiscordManager::new(false);
        // Exercise the mailbox without connecting to the user's Discord.
        let rx = manager.pending_rx.take().unwrap();
        manager.thread_handle = Some(thread::spawn(move || {
            while let Ok(message) = rx.recv() {
                if matches!(message, DiscordActivity::Shutdown) {
                    break;
                }
            }
        }));
        manager.set_idle();
        assert!(matches!(manager.current_state, Some(DiscordState::Idle)));

        manager.set_enabled(true);
        manager.set_idle();
        assert!(manager.current_state.is_some());

        manager.set_connecting("singapore");
        manager.set_connected("singapore");
        manager.set_playing_game("roblox", "singapore");
    }

    #[test]
    fn duplicate_states_do_not_send_more_ipc_and_disabled_states_stay_current() {
        let mut manager = DiscordManager::new(false);
        let (tx, rx) = mpsc::channel();
        manager.tx = tx;
        manager.enabled = true;
        manager.set_connected("mumbai");
        manager.set_connected("mumbai");
        assert!(matches!(rx.try_recv(), Ok(DiscordActivity::SetActivity(_))));
        assert!(rx.try_recv().is_err());
        manager.set_enabled(false);
        assert!(matches!(rx.try_recv(), Ok(DiscordActivity::Clear)));
        manager.set_idle();
        assert!(rx.try_recv().is_err());
        assert!(matches!(manager.current_state, Some(DiscordState::Idle)));
    }
}
