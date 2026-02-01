//! Discord Rich Presence manager
//!
//! Runs a background thread that maintains the Discord IPC connection
//! and updates presence based on VPN state.

use super::state::{DiscordActivity, DiscordState, region_display_name, region_flag_key, game_display_name, game_icon_key};
use discord_rich_presence::{activity, DiscordIpc, DiscordIpcClient};
use std::sync::mpsc::{self, Sender, Receiver};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use log::{debug, error, info, warn};

/// Discord Application ID (create at https://discord.com/developers)
/// This should be replaced with the actual SwiftTunnel application ID
const DISCORD_APP_ID: &str = "1336440050925322240";

/// Interval to retry Discord connection if not connected
const RECONNECT_INTERVAL: Duration = Duration::from_secs(30);

/// Manages Discord Rich Presence in a background thread
pub struct DiscordManager {
    /// Channel to send activity updates
    tx: Sender<DiscordActivity>,
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
    /// Create a new Discord manager and start the background thread
    pub fn new(enabled: bool) -> Self {
        let (tx, rx) = mpsc::channel::<DiscordActivity>();

        let thread_handle = if enabled {
            Some(Self::spawn_rpc_thread(rx))
        } else {
            // Start thread but it will just wait for enable signal
            Some(Self::spawn_rpc_thread(rx))
        };

        Self {
            tx,
            thread_handle,
            enabled,
            current_state: None,
            connected_at: None,
        }
    }

    /// Spawn the background thread that handles Discord IPC
    fn spawn_rpc_thread(rx: Receiver<DiscordActivity>) -> JoinHandle<()> {
        thread::Builder::new()
            .name("discord-rpc".to_string())
            .spawn(move || {
                Self::rpc_thread_main(rx);
            })
            .expect("Failed to spawn Discord RPC thread")
    }

    /// Main loop for the Discord RPC background thread
    fn rpc_thread_main(rx: Receiver<DiscordActivity>) {
        info!("Discord RPC thread started");

        let mut client: Option<DiscordIpcClient> = None;
        let mut last_connect_attempt = Instant::now() - RECONNECT_INTERVAL;

        loop {
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

            // Check for activity updates with timeout
            match rx.recv_timeout(Duration::from_millis(500)) {
                Ok(activity) => {
                    match activity {
                        DiscordActivity::Shutdown => {
                            info!("Discord RPC thread shutting down");
                            if let Some(ref mut c) = client {
                                let _ = c.clear_activity();
                                let _ = c.close();
                            }
                            return;
                        }
                        DiscordActivity::Clear => {
                            if let Some(ref mut c) = client {
                                match c.clear_activity() {
                                    Ok(_) => debug!("Discord presence cleared"),
                                    Err(e) => {
                                        warn!("Failed to clear Discord presence: {}", e);
                                        // Connection may be broken, reset
                                        client = None;
                                    }
                                }
                            }
                        }
                        DiscordActivity::SetActivity(state) => {
                            if let Some(ref mut c) = client {
                                if let Err(e) = Self::set_activity(c, &state) {
                                    warn!("Failed to set Discord activity: {}", e);
                                    // Connection may be broken, try to reconnect
                                    client = None;
                                }
                            }
                        }
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    // Normal timeout, continue loop
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
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

        client.connect()
            .map_err(|e| format!("Failed to connect to Discord: {}", e))?;

        Ok(client)
    }

    /// Create Discord activity buttons (Get SwiftTunnel + Join Discord)
    fn create_buttons() -> activity::Buttons<'static> {
        activity::Buttons::new(vec![
            activity::Button::new("Get SwiftTunnel", "https://swifttunnel.net"),
            activity::Button::new("Join our Discord!", "https://swifttunnel.net/discord"),
        ])
    }

    /// Set Discord activity based on state
    fn set_activity(client: &mut DiscordIpcClient, state: &DiscordState) -> Result<(), String> {
        let payload = match state {
            DiscordState::Idle => {
                activity::Activity::new()
                    .state("Idle")
                    .details("VPN Disconnected")
                    .assets(
                        activity::Assets::new()
                            .large_image("swifttunnel_logo")
                            .large_text("SwiftTunnel")
                    )
                    .buttons(Self::create_buttons())
            }
            DiscordState::Connecting { region } => {
                let region_name = region_display_name(region);
                activity::Activity::new()
                    .state(&format!("Connecting to {}...", region_name))
                    .details("Establishing VPN")
                    .assets(
                        activity::Assets::new()
                            .large_image("swifttunnel_logo")
                            .large_text("SwiftTunnel")
                            .small_image(region_flag_key(region))
                            .small_text(region_name)
                    )
                    .buttons(Self::create_buttons())
            }
            DiscordState::Connected { region, connected_at } => {
                let region_name = region_display_name(region);
                let elapsed_secs = connected_at.elapsed().as_secs();
                // Use Unix timestamp for Discord's elapsed time display
                let start_timestamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64 - elapsed_secs as i64)
                    .unwrap_or(0);

                activity::Activity::new()
                    .state(&format!("Connected to {}", region_name))
                    .details("VPN Active")
                    .assets(
                        activity::Assets::new()
                            .large_image("swifttunnel_logo")
                            .large_text("SwiftTunnel")
                            .small_image(region_flag_key(region))
                            .small_text(region_name)
                    )
                    .timestamps(
                        activity::Timestamps::new()
                            .start(start_timestamp)
                    )
                    .buttons(Self::create_buttons())
            }
            DiscordState::PlayingGame { game_name, region, connected_at } => {
                let region_name = region_display_name(region);
                let display_name = game_display_name(game_name);
                let elapsed_secs = connected_at.elapsed().as_secs();
                let start_timestamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64 - elapsed_secs as i64)
                    .unwrap_or(0);

                activity::Activity::new()
                    .state(&format!("Connected to {}", region_name))
                    .details(&format!("Playing {}", display_name))
                    .assets(
                        activity::Assets::new()
                            .large_image(game_icon_key(game_name))
                            .large_text(display_name)
                            .small_image("swifttunnel_logo")
                            .small_text("SwiftTunnel VPN")
                    )
                    .timestamps(
                        activity::Timestamps::new()
                            .start(start_timestamp)
                    )
                    .buttons(Self::create_buttons())
            }
        };

        client.set_activity(payload)
            .map_err(|e| format!("Failed to set activity: {}", e))?;

        debug!("Discord activity updated: {:?}", state);
        Ok(())
    }

    /// Update the Discord presence based on current state
    /// Call this from the main GUI update loop
    pub fn update_state(&mut self, state: DiscordState) {
        if !self.enabled {
            return;
        }

        // Track connected_at for elapsed time calculation
        match &state {
            DiscordState::Connected { connected_at, .. } |
            DiscordState::PlayingGame { connected_at, .. } => {
                if self.connected_at.is_none() {
                    self.connected_at = Some(*connected_at);
                }
            }
            DiscordState::Idle | DiscordState::Connecting { .. } => {
                self.connected_at = None;
            }
        }

        self.current_state = Some(state.clone());
        let _ = self.tx.send(DiscordActivity::SetActivity(state));
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
            // Clear presence when disabled
            let _ = self.tx.send(DiscordActivity::Clear);
            self.current_state = None;
        } else if enabled && !was_enabled {
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
        let _ = self.tx.send(DiscordActivity::Clear);
    }
}

impl Drop for DiscordManager {
    fn drop(&mut self) {
        // Signal shutdown to the background thread
        let _ = self.tx.send(DiscordActivity::Shutdown);

        // Wait for thread to finish (with timeout)
        if let Some(handle) = self.thread_handle.take() {
            // Give thread time to clean up
            std::thread::sleep(Duration::from_millis(100));
            // Don't block forever
            let _ = handle.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_manager_creation() {
        // Just test that it doesn't panic
        let _manager = DiscordManager::new(false);
    }

    #[test]
    fn test_state_transitions() {
        let mut manager = DiscordManager::new(false);

        manager.set_idle();
        assert!(manager.current_state.is_none()); // Disabled, state not tracked

        manager.set_enabled(true);
        manager.set_idle();
        assert!(manager.current_state.is_some());

        manager.set_connecting("singapore");
        manager.set_connected("singapore");
        manager.set_playing_game("roblox", "singapore");
    }
}
