//! The machinery behind the window.
//!
//! The window paints and posts actions; everything that can be slow (an HTTP
//! fetch, an ICMP round trip, bringing the tunnel up, reading Roblox's settings
//! file) happens on a background thread and lands in a snapshot the window
//! copies on its next repaint. The Win32 message loop never blocks.
//!
//! Everything real is borrowed from `swifttunnel-core`. Lite reimplements no
//! behaviour, because a second implementation of the relay list, the ping, the
//! frame cap or the tunnel would drift from the full app, and the two would end
//! up disagreeing about the same machine. The settings file is the same file,
//! so a region picked here is picked in both.

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use windows::Win32::Foundation::{HWND, LPARAM, WPARAM};
use windows::Win32::UI::WindowsAndMessaging::{PostMessageW, WM_APP};

use swifttunnel_core::auth::types::AuthState;
use swifttunnel_core::autostart::{RUN_VALUE_LITE, sync_run_on_startup};
use swifttunnel_core::auth::{AuthManager, update_required_message};
use swifttunnel_core::discord_rpc::DiscordManager;
use swifttunnel_core::roblox_optimizer::RobloxOptimizer;
use swifttunnel_core::settings::{self, AdapterBindingMode, AppSettings};
use swifttunnel_core::structs::{GraphicsQuality, RobloxSettingsConfig};
use swifttunnel_core::vpn::connect_policy::{
    build_available_servers, current_binding_preference, resolve_initial_connect_region,
};
use swifttunnel_core::vpn::connection::{free_tier_grace_seconds, free_tier_quota};
use swifttunnel_core::vpn::parallel_interceptor::list_network_adapters;
use swifttunnel_core::vpn::servers::{self, DynamicServerList, ServerListSource};
use swifttunnel_core::vpn::split_tunnel::{GamePreset, get_apps_for_preset_set};
use swifttunnel_core::vpn::{ConnectionState, SplitTunnelDriver, VpnConnection};

use crate::state::{AdapterRow, Driver, Lockout, RegionRow, Roblox, State, Status, Tunnel};
use crate::view::{FieldId,Action, Flag};

/// Posted when a background job lands, so a finished connect or a fresh ping
/// shows up without waiting for the one-second heartbeat.
pub const WM_ENGINE_UPDATE: u32 = WM_APP + 1;

/// How often the relays are re-pinged.
///
/// Slow on purpose. A number that moves while you are reading it is harder to
/// judge than one that holds still, and the full app measures on connect for
/// the same reason.
const PING_INTERVAL: Duration = Duration::from_secs(30);

/// Roblox's own default. At or below this counts as still capped.
const DEFAULT_FRAME_CAP: u32 = 60;

/// What the background threads have found.
struct Snapshot {
    regions: Vec<RegionRow>,
    /// The fleet, in core's own container.
    ///
    /// Not a private copy: this is the type `connect_policy` takes, and the
    /// round trips measured below are written back into it, so the candidate
    /// list handed to `connect` carries the latency auto-routing sorts by.
    /// Lite used to build that list by hand with `None` for every latency,
    /// which left the router unable to tell one relay from another.
    server_list: DynamicServerList,
    adapters: Vec<AdapterRow>,
    roblox: Roblox,
    driver: Driver,
    lockout: Option<Lockout>,
    tunnel: Tunnel,
    email: Option<String>,
    signed_in: bool,
    free_tier_secs: Option<u32>,
    free_tier_spent: bool,
    /// A sign-in is in flight, and why the last one failed. Owned by the
    /// snapshot so the async result has somewhere to land.
    login_busy: bool,
    login_error: Option<String>,
}

struct Shared {
    runtime: tokio::runtime::Runtime,
    auth: Arc<tokio::sync::Mutex<AuthManager>>,
    vpn: Arc<tokio::sync::Mutex<VpnConnection>>,
    settings: RwLock<AppSettings>,
    /// Rich Presence, driven from the same tunnel state the window shows.
    ///
    /// Its own lock rather than living in the snapshot: the manager talks to
    /// Discord's IPC socket, which can block, and the poller must not hold the
    /// snapshot open while it does.
    discord: std::sync::Mutex<DiscordManager>,
    snapshot: RwLock<Snapshot>,
    /// Set once the window exists. Stored as an isize because HWND is not Send.
    hwnd: AtomicIsize,
    stop: AtomicBool,
    /// Guards against a second connect being started while one is in flight.
    busy: AtomicBool,
    /// Set when the user pressed Disconnect, so auto-reconnect knows the
    /// tunnel went down on purpose and leaves it down.
    intentional_disconnect: AtomicBool,
    /// Whether the tunnel has been up at least once, so a failed first connect
    /// is not retried forever behind a dialog nobody asked for.
    was_connected: AtomicBool,
}

impl Shared {
    /// The window, for anything that needs an owner.
    ///
    /// Null until `attach`, which a modal dialog reads as "no owner" and shows
    /// itself anyway rather than failing.
    fn hwnd(&self) -> HWND {
        HWND(self.hwnd.load(Ordering::Relaxed) as *mut std::ffi::c_void)
    }

    /// Nudge the window to re-read the snapshot.
    fn notify(&self) {
        let raw = self.hwnd.load(Ordering::Relaxed);
        if raw == 0 {
            return;
        }
        // SAFETY: posting to a window handle published by `run`. A stale
        // handle after the window closed makes PostMessageW fail, which is
        // exactly the harmless outcome wanted.
        unsafe {
            let _ = PostMessageW(
                Some(HWND(raw as *mut std::ffi::c_void)),
                WM_ENGINE_UPDATE,
                WPARAM(0),
                LPARAM(0),
            );
        }
    }

    fn edit<T>(&self, f: impl FnOnce(&mut Snapshot) -> T) -> Option<T> {
        self.snapshot.write().ok().map(|mut s| f(&mut s))
    }
}

pub struct Engine {
    shared: Arc<Shared>,
}

impl Engine {
    pub fn new() -> Result<Self, String> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|e| format!("could not start the runtime: {e}"))?;

        // Loads the stored session, so anyone signed in to the full app is
        // already signed in here: both read the same machine-bound file.
        let auth = AuthManager::new().map_err(|e| format!("auth: {e}"))?;
        let signed_in = auth.is_logged_in();
        let email = auth.get_user().map(|u| u.email);
        let auth_state = auth.get_state();
        let banned_reason = auth.get_user().and_then(|u| u.banned_reason);

        let mut loaded = settings::load_settings();
        loaded.sanitize_in_place();
        let roblox_intent = loaded.config.roblox_settings.clone();
        let discord_enabled = loaded.enable_discord_rpc;

        let shared = Arc::new(Shared {
            runtime,
            auth: Arc::new(tokio::sync::Mutex::new(auth)),
            vpn: Arc::new(tokio::sync::Mutex::new(VpnConnection::new())),
            discord: std::sync::Mutex::new(DiscordManager::new(discord_enabled)),
            settings: RwLock::new(loaded),
            snapshot: RwLock::new(Snapshot {
                signed_in,
                email,
                roblox: read_roblox(&roblox_intent),
                driver: read_driver(),
                lockout: lockout_of(&auth_state, banned_reason.clone()),
                server_list: DynamicServerList::new_empty(),
                regions: Vec::new(),
                adapters: Vec::new(),
                tunnel: Tunnel::default(),
                free_tier_secs: None,
                free_tier_spent: false,
                login_busy: false,
                login_error: None,
            }),
            hwnd: AtomicIsize::new(0),
            stop: AtomicBool::new(false),
            busy: AtomicBool::new(false),
            intentional_disconnect: AtomicBool::new(false),
            was_connected: AtomicBool::new(false),
        });

        spawn_regions(shared.clone());
        spawn_poller(shared.clone());

        // The profile is re-fetched once at startup, because a ban applied
        // since the last session is only visible on the server until
        // something asks.
        {
            let shared = shared.clone();
            shared.runtime.spawn({
                let shared = shared.clone();
                async move {
                    let auth = shared.auth.lock().await;
                    let _ = auth.refresh_profile().await;
                    let state = auth.get_state();
                    let reason = auth.get_user().and_then(|u| u.banned_reason);
                    drop(auth);
                    shared.edit(|s| s.lockout = lockout_of(&state, reason));
                    shared.notify();
                }
            });
        }

        // Once at startup, so the Settings row can put a name to a saved GUID
        // rather than showing "Manual" until somebody opens the picker.
        {
            let shared = shared.clone();
            std::thread::spawn(move || {
                let rows = list_adapters();
                shared.edit(|s| s.adapters = rows);
                shared.notify();
            });
        }

        Ok(Engine { shared })
    }

    /// Publish the window handle so background work can ask for a repaint.
    pub fn attach(&self, hwnd: isize) {
        self.shared.hwnd.store(hwnd, Ordering::Relaxed);
    }

    /// Copy everything the screens read out of the snapshot and the settings.
    pub fn fill(&self, state: &mut State) {
        if let Ok(snapshot) = self.shared.snapshot.read() {
            state.regions = snapshot.regions.clone();
            state.adapters = snapshot.adapters.clone();
            state.roblox = snapshot.roblox.clone();
            state.lockout = snapshot.lockout.clone();
            state.driver = snapshot.driver.clone();
            state.tunnel = snapshot.tunnel.clone();
            state.email = snapshot.email.clone();
            state.signed_in = snapshot.signed_in;
            state.free_tier_secs = snapshot.free_tier_secs;
            state.free_tier_spent = snapshot.free_tier_spent;
            // The text stays whatever is being typed; only the result of a
            // submit comes back from the engine.
            state.login.busy = snapshot.login_busy;
            state.login.error = snapshot.login_error.clone();
        }
        if let Ok(s) = self.shared.settings.read() {
            state.selected_region = s.selected_region.clone();
            state.auto_routing = s.auto_routing_enabled;
            state.route_assist = s.enable_api_tunneling;
            state.country_ban = s.enable_country_ban;
            state.run_on_startup = s.run_on_startup;
            state.close_to_tray = s.minimize_to_tray;
            state.auto_reconnect = s.auto_reconnect;
            state.adapter_guid = s.preferred_physical_adapter_guid.clone();
            state.discord_rpc = s.enable_discord_rpc;
            state.standalone = matches!(
                crate::uninstall::how_installed(),
                crate::uninstall::Installed::Standalone(_)
            );
        }
    }

    pub fn refresh_regions(&self) {
        // The list is already kept fresh by its own thread; this only matters
        // on the first open, when it may not have landed yet.
        self.shared.notify();
    }

    pub fn refresh_adapters(&self) {
        let shared = self.shared.clone();
        std::thread::spawn(move || {
            let rows = list_adapters();
            shared.edit(|s| s.adapters = rows);
            shared.notify();
        });
    }

    /// Carry out one action from the window.
    pub fn dispatch(&self, action: Action, state: &mut State) {
        match action {
            Action::Primary => self.primary(state),

            Action::PickAutoRegion => {
                self.settings(|s| s.auto_routing_enabled = true);
            }
            Action::PickRegion(id) => {
                self.settings(|s| {
                    s.selected_region = id.clone();
                    s.auto_routing_enabled = false;
                });
            }
            Action::PickAdapter(guid) => {
                self.settings(|s| {
                    s.preferred_physical_adapter_guid = guid.clone();
                    s.adapter_binding_mode = if guid.is_some() {
                        AdapterBindingMode::Manual
                    } else {
                        AdapterBindingMode::SmartAuto
                    };
                });
            }

            Action::Toggle(flag) => self.toggle(flag, state),
            Action::SetQuality(level) => state.edit_roblox(|d| d.quality = level),
            Action::Focus(id) => {
                state.focus = Some(id);
                // Land the caret at the end, which is where clicking into a
                // text box puts it everywhere else.
                match id {
                    FieldId::Email => {
                        let end = state.login.email.len();
                        state.login.email.move_to(end, false);
                    }
                    FieldId::Password => {
                        let end = state.login.password.len();
                        state.login.password.move_to(end, false);
                    }
                    FieldId::FpsCap => {}
                }
            }
            Action::ImportFflags => self.import_fflags(state),
            Action::ApplyRoblox => self.apply_roblox(state),

            Action::SignOut => {
                let shared = self.shared.clone();
                shared.runtime.spawn({
                    let shared = shared.clone();
                    async move {
                        let auth = shared.auth.lock().await;
                        let _ = auth.logout();
                        drop(auth);
                        if let Ok(mut discord) = shared.discord.lock() {
                            discord.clear();
                        }
                        // Same as the full app's auth_logout: a signed-out
                        // client must not bring the tunnel back on its own.
                        if let Ok(mut settings) = shared.settings.write() {
                            settings.auto_reconnect = false;
                            settings.resume_vpn_on_startup = false;
                            let snapshot = settings.clone();
                            drop(settings);
                            if let Err(error) =
                                swifttunnel_core::settings::save_settings(&snapshot)
                            {
                                log::warn!("could not persist logout settings: {error}");
                            }
                        }
                        refresh_auth(&shared).await;
                        shared.notify();
                    }
                });
            }
            Action::SignIn => self.sign_in(),
            Action::SubmitLogin => self.submit_login(state),
            Action::RepairDriver => self.repair_driver(),
            Action::OpenLogs => open_logs(),
            Action::Uninstall => self.uninstall(state),

            // Handled by the window: they change what is on screen, not what
            // the machine is doing.
            Action::Tab(_)
            | Action::Back
            | Action::OpenRegions
            | Action::OpenAdapters
            | Action::Minimise
            | Action::Close => {}
        }

        self.fill(state);
    }

    /// Connect, or disconnect if already up.
    fn primary(&self, state: &State) {
        // A connect with no allowance left would be refused by the server
        // anyway; refusing it here saves a pointless round trip and gives a
        // reason instead of a generic failure.
        if state.free_tier_spent && state.tunnel.status != Status::Connected {
            return;
        }
        if self.shared.busy.load(Ordering::Relaxed) || state.lockout.is_some() {
            return;
        }
        let connected = state.tunnel.status == Status::Connected;
        let shared = self.shared.clone();
        shared.busy.store(true, Ordering::Relaxed);
        shared
            .intentional_disconnect
            .store(connected, Ordering::Relaxed);

        shared.edit(|s| {
            s.tunnel.status = Status::Working;
            s.tunnel.detail = if connected {
                "Disconnecting".into()
            } else {
                "Connecting".into()
            };
        });
        shared.notify();

        shared.runtime.spawn({
            let shared = shared.clone();
            async move {
                let outcome = if connected {
                    let mut vpn = shared.vpn.lock().await;
                    vpn.disconnect()
                        .await
                        .map_err(|e| swifttunnel_core::vpn::user_friendly_error(&e))
                } else {
                    connect(&shared).await
                };

                if let Err(error) = outcome {
                    shared.edit(|s| {
                        s.tunnel.status = Status::Error;
                        s.tunnel.detail = error;
                    });
                }
                shared.busy.store(false, Ordering::Relaxed);
                shared.notify();
            }
        });
    }

    fn toggle(&self, flag: Flag, state: &mut State) {
        match flag {
            Flag::RouteAssist => self.settings(|s| s.enable_api_tunneling = !s.enable_api_tunneling),
            Flag::CountryBan => self.settings(|s| s.enable_country_ban = !s.enable_country_ban),
            Flag::RunOnStartup => {
                // Written to the registry, not just to the settings file. This
                // switch saved a boolean and did nothing else for as long as it
                // has existed.
                let enabled = !self
                    .shared
                    .settings
                    .read()
                    .map(|s| s.run_on_startup)
                    .unwrap_or(false);
                if let Err(error) = sync_run_on_startup(RUN_VALUE_LITE, enabled) {
                    log::warn!("could not change the startup entry: {error}");
                    return;
                }
                self.settings(|s| s.run_on_startup = enabled);
            }
            Flag::CloseToTray => self.settings(|s| s.minimize_to_tray = !s.minimize_to_tray),
            Flag::AutoReconnect => self.settings(|s| s.auto_reconnect = !s.auto_reconnect),
            Flag::DiscordRpc => {
                let on = !self
                    .shared
                    .settings
                    .read()
                    .map(|s| s.enable_discord_rpc)
                    .unwrap_or(false);
                self.settings(|s| s.enable_discord_rpc = on);
                if let Ok(mut discord) = self.shared.discord.lock() {
                    discord.set_enabled(on);
                }
            }

            // The Roblox switches edit the draft. Nothing reaches disk
            // until Apply, so a run of clicks is one write rather than a
            // race between several.
            Flag::UnlockFps => state.edit_roblox(|d| {
                d.unlock_fps = !d.unlock_fps;
                // Turning it off writes Roblox's own default back, or the
                // client keeps running at whatever it was raised to.
                if !d.unlock_fps {
                    d.fps_text = DEFAULT_FRAME_CAP.to_string();
                } else if d.fps().is_none_or(|v| v <= DEFAULT_FRAME_CAP) {
                    d.fps_text = "240".to_string();
                }
            }),
            Flag::Ultraboost => state.edit_roblox(|d| {
                d.ultraboost = !d.ultraboost;
                // Core refuses both at once, so the UI cannot offer both.
                if d.ultraboost {
                    d.custom_fflags = false;
                }
            }),
            Flag::CustomFflags => state.edit_roblox(|d| {
                d.custom_fflags = !d.custom_fflags;
                if d.custom_fflags {
                    d.ultraboost = false;
                } else {
                    d.fflag_note = None;
                }
            }),
            Flag::Fullscreen => state.edit_roblox(|d| d.fullscreen = !d.fullscreen),
        }
    }

    /// Write the pending Roblox edits, then restart the game if it is up.
    ///
    /// The only path in this client that touches Roblox's files.
    fn apply_roblox(&self, state: &mut State) {
        let draft = state.roblox_view();
        if !draft.ready() {
            return;
        }
        state.roblox_draft = None;
        state.focus = None;

        let config = RobloxSettingsConfig {
            unlock_fps: draft.unlock_fps,
            target_fps: draft.fps().unwrap_or(DEFAULT_FRAME_CAP),
            graphics_quality: quality_of(draft.quality),
            window_fullscreen: draft.fullscreen,
            ultraboost: draft.ultraboost,
            custom_fflags_enabled: draft.custom_fflags,
            custom_fflags_json: draft.custom_json.clone(),
            ..RobloxSettingsConfig::default()
        };
        let restart = state.roblox.running;
        let shared = self.shared.clone();

        std::thread::spawn(move || {
            let optimizer = RobloxOptimizer::new();
            let mut error = optimizer
                .apply_optimizations(&config)
                .err()
                .map(|e| e.to_string());

            // The intent for both FFlag paths is kept in the shared settings
            // file, because neither can be read back off Roblox's own config
            // in full: all core can tell is whether the flags are present.
            if error.is_none()
                && let Ok(mut guard) = shared.settings.write()
            {
                let roblox = &mut guard.config.roblox_settings;
                roblox.ultraboost = config.ultraboost;
                roblox.custom_fflags_enabled = config.custom_fflags_enabled;
                roblox.custom_fflags_json.clone_from(&config.custom_fflags_json);
                let snapshot = guard.clone();
                drop(guard);
                let _ = settings::save_settings(&snapshot);
            }

            if error.is_none() && restart {
                error = restart_roblox().err();
            }

            let intent = shared
                .settings
                .read()
                .map(|s| s.config.roblox_settings.clone())
                .unwrap_or_default();
            shared.edit(|s| {
                s.roblox = read_roblox(&intent);
                s.roblox.error = error;
            });
            shared.notify();
        });
    }

    /// Reinstall the split tunnel driver.
    ///
    /// Lite had no way to do this at all, which meant a machine whose driver
    /// was missing or broken showed a connect that failed with a raw error and
    /// no route out of it except opening the full app.
    ///
    /// Force-reinstalls rather than installing only when absent: the cases
    /// worth having a button for are the ones where something is present and
    /// wrong, which a conditional install would skip. Needs admin, which this
    /// build already has from its manifest.
    fn repair_driver(&self) {
        if self
            .shared
            .snapshot
            .read()
            .map(|s| s.driver.repairing)
            .unwrap_or(false)
        {
            return;
        }

        let shared = self.shared.clone();
        shared.edit(|s| {
            s.driver.repairing = true;
            s.driver.note = None;
        });
        shared.notify();

        std::thread::spawn(move || {
            let exe_dir = std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|d| d.to_path_buf()));
            let program_files = std::path::PathBuf::from(
                std::env::var("ProgramFiles").unwrap_or_else(|_| "C:\\Program Files".to_string()),
            );

            let note = match SplitTunnelDriver::install_driver_from_bundled_package(
                None,
                exe_dir.as_deref(),
                &program_files,
                true,
            ) {
                Ok(()) => "Driver reinstalled. Try connecting again.".to_string(),
                Err(error) => error,
            };

            let mut driver = read_driver();
            driver.note = Some(note);
            shared.edit(|s| s.driver = driver);
            shared.notify();
        });
    }

    /// Google sign-in, start to finish.
    ///
    /// The first version opened the browser and stopped there: nothing ever
    /// collected the callback, so the flow began and never completed, and the
    /// window sat on "Signed out" while the browser said it had worked.
    ///
    /// Core owns all of it, including the loopback server the callback lands
    /// on. This starts the flow, waits for the token, and completes it.
    /// Sign in with the email and password in the form.
    ///
    /// The same core call the full app's auth_login makes, so the two clients
    /// cannot drift on what counts as a valid sign-in.
    fn submit_login(&self, state: &mut State) {
        if state.login.busy {
            return;
        }
        let email = state.login.email.text.trim().to_string();
        let password = state.login.password.text.clone();
        if email.is_empty() || password.is_empty() {
            return;
        }

        state.login.busy = true;
        state.login.error = None;
        state.focus = None;
        self.shared.edit(|s| {
            s.login_busy = true;
            s.login_error = None;
        });

        let shared = self.shared.clone();
        shared.runtime.spawn({
            let shared = shared.clone();
            async move {
                let result = {
                    let auth = shared.auth.lock().await;
                    auth.sign_in(&email, &password).await
                };
                if result.is_ok() {
                    refresh_auth(&shared).await;
                }
                shared.edit(|s| {
                    s.login_busy = false;
                    s.login_error = match &result {
                        Ok(()) => None,
                        Err(error) => Some(friendly_auth_error(error)),
                    };
                });
                shared.notify();
            }
        });
    }

    /// Load custom FFlags from a file the user picks.
    ///
    /// A file rather than the clipboard: an exported flag list is a file to
    /// begin with, and pasting means opening it in something first and hoping
    /// nothing is trimmed on the way through.
    ///
    /// The dialog is modal on purpose. It runs on the UI thread, so nothing
    /// can repaint underneath it, and the file is small enough that reading it
    /// is not worth a thread.
    fn import_fflags(&self, state: &mut State) {
        let owner = self.shared.hwnd();
        match crate::picker::read_fflag_file(owner) {
            // Cancelled. Saying anything here would be noise.
            Ok(None) => {}
            Ok(Some(text)) => apply_fflag_text(state, text),
            Err(reason) => state.edit_roblox(|d| {
                d.fflag_ok = false;
                d.fflag_note = Some(reason);
            }),
        }
    }

    fn sign_in(&self) {
        let shared = self.shared.clone();
        shared.runtime.spawn({
            let shared = shared.clone();
            async move {
                let url = {
                    let auth = shared.auth.lock().await;
                    match auth.start_google_sign_in() {
                        Ok(url) => url,
                        Err(error) => {
                            log::warn!("could not start sign-in: {error}");
                            return;
                        }
                    }
                };
                open_in_browser(&url);

                // The loopback server is already listening; this waits for it.
                // Ten minutes matches the expiry core enforces on the flow.
                let deadline = Instant::now() + Duration::from_secs(600);
                let callback = loop {
                    if Instant::now() > deadline || shared.stop.load(Ordering::Relaxed) {
                        let auth = shared.auth.lock().await;
                        auth.cancel_oauth();
                        log::warn!("sign-in was not completed in time");
                        return;
                    }
                    let found = {
                        let auth = shared.auth.lock().await;
                        auth.poll_oauth_callback()
                    };
                    if let Some(data) = found {
                        break data;
                    }
                    tokio::time::sleep(Duration::from_millis(400)).await;
                };

                let auth = shared.auth.lock().await;
                if let Err(error) = auth
                    .complete_oauth_callback(&callback.token, &callback.state)
                    .await
                {
                    log::warn!("sign-in failed: {error}");
                    return;
                }
                drop(auth);
                refresh_auth(&shared).await;
                shared.notify();
            }
        });
    }

    /// Change a setting and write the file.
    ///
    /// Saved immediately rather than debounced: the file is shared with the
    /// full app, and a Lite that held changes in memory would lose them to
    /// whichever client saved last.
    fn settings(&self, edit: impl FnOnce(&mut AppSettings)) {
        let snapshot = {
            let Ok(mut guard) = self.shared.settings.write() else {
                return;
            };
            edit(&mut guard);
            guard.clone()
        };
        std::thread::spawn(move || {
            if let Err(error) = settings::save_settings(&snapshot) {
                log::warn!("could not save settings: {error}");
            }
        });
    }

}


impl Drop for Engine {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::Relaxed);
    }
}

// ── Connecting ──────────────────────────────────────────────────────────────

/// Bring the tunnel up, with the same arguments the full app passes.
///
/// The one thing Lite decides differently is the app list: it is always the
/// Roblox preset, because that is the only thing this client is for.
async fn connect(shared: &Arc<Shared>) -> Result<(), String> {
    let mut settings = shared
        .settings
        .read()
        .map(|s| s.clone())
        .map_err(|_| "settings unavailable".to_string())?;

    // Which adapter to bind. This was `None`, which meant the adapter the user
    // picked in Settings was read, saved, displayed, and then ignored at the
    // one moment it mattered. It also refuses a saved adapter that has since
    // gone down or turned into a tunnel, before the connection is attempted.
    let binding = current_binding_preference(&mut settings)?;

    let token = {
        let auth = shared.auth.lock().await;
        auth.get_access_token()
            .await
            .map_err(|e| format!("Sign in again: {e}"))?
    };

    // The fleet with its measured round trips, and the region auto-routing
    // would actually pick, both from core's own policy rather than from a
    // second opinion held here.
    let (available, region) = {
        let snapshot = shared
            .snapshot
            .read()
            .map_err(|_| "server list unavailable".to_string())?;
        (
            build_available_servers(&snapshot.server_list),
            resolve_initial_connect_region(
                &snapshot.server_list,
                &settings.selected_region,
                settings.auto_routing_enabled,
                &settings.forced_servers,
            ),
        )
    };

    // Always the Roblox preset, because that is the only thing this client
    // is for. The full app builds this from a saved list of games.
    let apps = get_apps_for_preset_set(&HashSet::from([GamePreset::Roblox]));

    // An empty custom relay means "use the fleet", which is what the full app
    // does with the same field.
    let custom_relay = (!settings.custom_relay_server.is_empty())
        .then(|| settings.custom_relay_server.clone());
    // A custom relay and auto-routing contradict each other; the full app
    // drops auto-routing for the session, so this does too.
    let auto_routing = settings.auto_routing_enabled && custom_relay.is_none();

    let mut vpn = shared.vpn.lock().await;
    vpn.set_auth_manager(shared.auth.clone());
    vpn.connect(
        &token,
        &region,
        apps,
        custom_relay,
        auto_routing,
        available,
        settings.whitelisted_regions.clone(),
        settings.forced_servers.clone(),
        binding,
        settings.game_process_performance,
        settings.enable_api_tunneling,
        settings.enable_country_ban,
    )
    .await
    .map_err(|e| swifttunnel_core::vpn::user_friendly_error(&e))
}

// ── Background threads ──────────────────────────────────────────────────────

/// Fetch the fleet once, then keep its round trips fresh.
fn spawn_regions(shared: Arc<Shared>) {
    std::thread::Builder::new()
        .name("lite-regions".into())
        .spawn(move || {
            let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                log::error!("could not start the region watcher");
                return;
            };

            // (relay id, address to ping).
            let mut targets: Vec<(String, String)> = Vec::new();

            match runtime.block_on(servers::fetch_server_list()) {
                Ok(list) => {
                    let mut rows = Vec::new();
                    for region in &list.regions {
                        // Only relays the API is currently offering. A region
                        // whose relays are all withdrawn should not be listed
                        // as somewhere you can go.
                        let Some(first) = list
                            .servers
                            .iter()
                            .find(|s| region.servers.contains(&s.region) && s.relay_available)
                        else {
                            continue;
                        };
                        // The relay id, not the region id: latency is keyed by
                        // server in core's list, and `get_region_best_latency`
                        // reads it back out per region.
                        targets.push((first.region.clone(), first.ip.clone()));
                        rows.push(RegionRow {
                            id: region.id.clone(),
                            name: region.name.clone(),
                            country: region.country_code.to_uppercase(),
                            ping_ms: None,
                        });
                    }
                    log::info!("region list: {} regions", rows.len());
                    shared.edit(|s| {
                        s.regions = rows;
                        s.server_list.update(
                            list.servers.clone(),
                            list.regions.clone(),
                            ServerListSource::Api,
                        );
                    });
                    shared.notify();
                }
                Err(error) => {
                    log::warn!("could not fetch the region list: {error}");
                    return;
                }
            }

            while !shared.stop.load(Ordering::Relaxed) {
                for (server_id, ip) in &targets {
                    if shared.stop.load(Ordering::Relaxed) {
                        return;
                    }
                    let measured = servers::measure_latency_icmp(ip);
                    shared.edit(|s| {
                        // Into core's list, so a later connect hands the same
                        // numbers to auto-routing, and back out per region for
                        // the rows the picker draws.
                        s.server_list.set_latency(server_id, measured);
                        for row in s.regions.iter_mut() {
                            row.ping_ms = s.server_list.get_region_best_latency(&row.id);
                        }
                    });
                }
                shared.notify();

                // Slept in slices so quitting does not wait out the interval.
                let mut left = PING_INTERVAL;
                while left > Duration::ZERO && !shared.stop.load(Ordering::Relaxed) {
                    let nap = Duration::from_millis(250).min(left);
                    std::thread::sleep(nap);
                    left -= nap;
                }
            }
        })
        .expect("region watcher thread");
}

/// Keep the tunnel readout and the Roblox switches honest.
///
/// # Why this is careful about doing nothing
///
/// The first version polled once a second and posted a repaint every time,
/// which redrew a 340x356 window sixty times a minute to show the same
/// pixels, and measured 2.6% of a core with the tunnel down and nobody
/// looking. For a client whose whole argument is that it does not cost you
/// frames, that is the one number that must not be wrong.
///
/// So: the interval stretches when there is nothing moving, the process scan
/// runs at a fraction of the poll rate, and a repaint is only asked for when
/// the snapshot actually differs from what the window already has.
fn spawn_poller(shared: Arc<Shared>) {
    std::thread::Builder::new()
        .name("lite-poll".into())
        .spawn(move || {
            let mut since: Option<Instant> = None;
            let mut roblox_tick: u32 = 0;
            let mut running = false;

            while !shared.stop.load(Ordering::Relaxed) {
                // A second while the session timer is ticking, five when the
                // only thing that could change is somebody launching Roblox.
                let idle = !matches!(
                    shared
                        .snapshot
                        .read()
                        .map(|s| s.tunnel.status)
                        .unwrap_or(Status::Disconnected),
                    Status::Connected | Status::Working
                );
                let period = if idle { 5 } else { 1 };
                for _ in 0..period * 4 {
                    if shared.stop.load(Ordering::Relaxed) {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(250));
                }

                let (state, throughput) = shared.runtime.block_on(async {
                    let vpn = shared.vpn.lock().await;
                    (
                        vpn.state_handle().borrow().clone(),
                        vpn.get_throughput_stats(),
                    )
                });

                let mut tunnel = Tunnel::default();
                match &state {
                    ConnectionState::Disconnected => {
                        since = None;
                        tunnel.detail = "Ready to connect".into();
                    }
                    ConnectionState::Error(message) => {
                        since = None;
                        tunnel.status = Status::Error;
                        let (detail, hint) = split_message(message);
                        tunnel.detail = detail;
                        tunnel.hint = hint;
                    }
                    ConnectionState::Connected {
                        since: started,
                        server_region,
                        ..
                    } => {
                        shared.was_connected.store(true, Ordering::Relaxed);
                        since = Some(*started);
                        tunnel.status = Status::Connected;
                        tunnel.region = Some(server_region.clone());
                        tunnel.elapsed = started.elapsed().as_secs();
                    }
                    ConnectionState::Disconnecting => {
                        tunnel.status = Status::Working;
                        tunnel.detail = "Disconnecting".into();
                    }
                    other => {
                        tunnel.status = Status::Working;
                        tunnel.detail = describe(other);
                    }
                }
                if let Some(started) = since {
                    tunnel.elapsed = started.elapsed().as_secs();
                }
                if let Some(stats) = throughput {
                    tunnel.bytes_up = stats.bytes_tx.load(Ordering::Relaxed);
                    tunnel.bytes_down = stats.bytes_rx.load(Ordering::Relaxed);
                }

                // The free-tier allowance. Read from core, which is where it
                // is recorded as each relay ticket is issued and where the
                // limit is actually enforced, so this is a readout of the
                // server's decision rather than a second opinion about it.
                let locked = update_required_message().map(Lockout::UpdateRequired);
                let spent = free_tier_spent();

                let free_tier = match free_tier_grace_seconds() {
                    Some(grace) => Some(grace.max(0) as u32),
                    None => free_tier_quota().0.map(|left| left.max(0) as u32),
                };

                // Reconciled against what SwiftTunnel last asked for, since
                // the FFlag switches cannot be read back off Roblox's config
                // on their own.
                // Cheap, and the answer changes when Windows updates or
                // another VPN installs its own copy of the same driver.
                let driver = (roblox_tick % 20 == 0).then(read_driver);

                let roblox_intent = shared
                    .settings
                    .read()
                    .map(|s| s.config.roblox_settings.clone())
                    .unwrap_or_default();

                // Neither of these is free. "Is Roblox running" walks the
                // process table and settings means reading a file off disk,
                // and both answer a question that changes when a person does
                // something, not several times a second.
                roblox_tick += 1;
                if roblox_tick % 4 == 0 || roblox_tick == 1 {
                    running = RobloxOptimizer::new().is_roblox_running();
                }
                let refresh = roblox_tick % 20 == 0;

                let changed = shared
                    .edit(|s| {
                        let before = (
                            s.tunnel.clone(),
                            s.roblox.clone(),
                            s.free_tier_secs,
                            s.lockout.clone(),
                        );

                        // A connect in flight owns the readout: the state
                        // watch still says Disconnected for the first second
                        // or two, and letting it overwrite "Connecting" makes
                        // the button flick.
                        if !shared.busy.load(Ordering::Relaxed) {
                            s.tunnel = tunnel;
                        } else {
                            s.tunnel.bytes_up = tunnel.bytes_up;
                            s.tunnel.bytes_down = tunnel.bytes_down;
                        }
                        s.free_tier_secs = free_tier;
                        if let Some(fresh) = driver.clone()
                            && !s.driver.repairing
                        {
                            s.driver = Driver {
                                note: s.driver.note.clone(),
                                ..fresh
                            };
                        }
                        if let Some(locked) = locked.clone() {
                            s.lockout = Some(locked);
                        }
                        s.free_tier_spent = spent;
                        s.roblox.running = running;
                        if refresh {
                            let fresh = read_roblox(&roblox_intent);
                            s.roblox = Roblox {
                                running,
                                error: s.roblox.error.clone(),
                                ..fresh
                            };
                        }

                        before
                            != (
                                s.tunnel.clone(),
                                s.roblox.clone(),
                                s.free_tier_secs,
                                s.lockout.clone(),
                            )
                    })
                    .unwrap_or(false);

                // Only when something is actually different. The window's own
                // one-second heartbeat keeps the session timer moving while
                // connected; this is for everything else, and asking for a
                // repaint that changes no pixels is pure waste.
                if changed {
                    shared.notify();
                }

                update_discord(&shared);
                maybe_reconnect(&shared);
            }
        })
        .expect("poller thread");
}

// ── Reading the machine ─────────────────────────────────────────────────────

/// Split one of core's messages into a status line and the advice under it.
///
/// Core writes failures for a dialog: a short first paragraph, a blank line,
/// then what to do. Drawn as one line those ran together into "Couldn't
/// connect.Check your internet connection" with the advice cut off at the
/// window edge. The first paragraph is the what and fits on the status line;
/// the remainder is the what-to-do and goes to a note that wraps.
fn split_message(message: &str) -> (String, String) {
    let mut parts = message.splitn(2, "

");
    let head = parts.next().unwrap_or_default();
    let rest = parts.next().unwrap_or_default();
    (flatten(head), flatten(rest))
}

/// Collapse every run of whitespace, newlines included, into one space.
fn flatten(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Keep Rich Presence in step with the tunnel.
///
/// Driven from the snapshot the window already reads rather than from the
/// connect path, so it cannot disagree with what is on screen, and so a tunnel
/// that dropped on its own is reflected without anything having to remember to
/// tell Discord about it.
fn update_discord(shared: &Arc<Shared>) {
    let Ok(mut discord) = shared.discord.try_lock() else {
        return;
    };
    if !discord.is_enabled() {
        return;
    }

    let Ok(snapshot) = shared.snapshot.read() else {
        return;
    };
    let status = snapshot.tunnel.status;
    // The relay region core reports, falling back to whatever is selected
    // so a connecting state still names somewhere.
    let region = snapshot
        .tunnel
        .region
        .clone()
        .unwrap_or_else(|| "auto".to_string());
    drop(snapshot);

    match status {
        Status::Connected => discord.set_connected(&region),
        Status::Working => discord.set_connecting(&region),
        _ => discord.set_idle(),
    }
}

/// Bring the tunnel back up if it dropped on its own.
///
/// Only when it had been up, only when the user did not ask for it to go down,
/// and never while a connect is already in flight. The retry is one attempt
/// per poll: core's own candidate rotation handles a relay that is refusing,
/// so hammering it from here would add nothing but load.
fn maybe_reconnect(shared: &Arc<Shared>) {
    if shared.busy.load(Ordering::Relaxed)
        || shared.intentional_disconnect.load(Ordering::Relaxed)
        || !shared.was_connected.load(Ordering::Relaxed)
    {
        return;
    }

    let wants = shared
        .settings
        .read()
        .map(|s| s.auto_reconnect)
        .unwrap_or(false);
    if !wants {
        return;
    }

    let down = shared
        .snapshot
        .read()
        .map(|s| matches!(s.tunnel.status, Status::Disconnected | Status::Error))
        .unwrap_or(false);
    if !down {
        return;
    }

    // A lockout means the server will refuse the ticket anyway.
    if shared
        .snapshot
        .read()
        .map(|s| s.lockout.is_some())
        .unwrap_or(false)
    {
        return;
    }

    log::info!("tunnel dropped on its own; reconnecting");
    shared.busy.store(true, Ordering::Relaxed);
    shared.edit(|s| {
        s.tunnel.status = Status::Working;
        s.tunnel.detail = "Reconnecting".into();
    });
    shared.notify();

    let shared = shared.clone();
    shared.runtime.spawn({
        let shared = shared.clone();
        async move {
            if let Err(error) = connect(&shared).await {
                shared.edit(|s| {
                    s.tunnel.status = Status::Error;
                    s.tunnel.detail = error;
                });
            }
            shared.busy.store(false, Ordering::Relaxed);
            shared.notify();
        }
    });
}

/// What core's health check says about the split tunnel driver.
fn read_driver() -> Driver {
    let health = SplitTunnelDriver::health_check();
    Driver {
        ready: health.ready,
        status: if health.ready {
            "Installed and bound".to_string()
        } else {
            health.message.clone()
        },
        repairing: false,
        note: None,
    }
}

/// A ban is a lockout; an outdated build is decided separately, by the API.
fn lockout_of(state: &AuthState, banned_reason: Option<String>) -> Option<Lockout> {
    if let Some(message) = update_required_message() {
        return Some(Lockout::UpdateRequired(message));
    }
    match state {
        AuthState::Banned(_) => Some(Lockout::Banned(banned_reason.unwrap_or_default())),
        AuthState::LoggedIn { .. } => None,
        // Everything else means no usable session, which the full app treats as
        // "show the login screen and nothing else".
        _ => Some(Lockout::SignedOut),
    }
}

/// Whether the free-tier allowance, and any grace after it, is spent.
///
/// `free_tier_grace_seconds` is `Some` only once the allowance has run out, so
/// grace being present is itself the signal that it has; the number only says
/// how much borrowed time is left. With no grace recorded, a remaining count of
/// zero means the same thing.
fn free_tier_spent() -> bool {
    match free_tier_grace_seconds() {
        Some(grace) => grace <= 0,
        None => matches!(free_tier_quota().0, Some(0)),
    }
}

/// Copy the auth manager's view of the world into the snapshot.
///
/// Every path that changes who is signed in has to call this. Nothing else
/// refreshes `signed_in` or the lockout: the poller does not read auth state,
/// so a sign-in that skipped this left a valid session sitting behind a login
/// screen, and a sign-out left the app fully usable until it was restarted.
async fn refresh_auth(shared: &Arc<Shared>) {
    let auth = shared.auth.lock().await;
    let signed_in = auth.is_logged_in();
    let email = auth.get_user().map(|u| u.email);
    let auth_state = auth.get_state();
    let reason = auth.get_user().and_then(|u| u.banned_reason);
    drop(auth);

    shared.edit(|s| {
        s.signed_in = signed_in;
        s.email = email;
        s.lockout = lockout_of(&auth_state, reason);
    });
}

/// Turn a core auth error into something worth showing on the sign-in screen.
///
/// The raw Display of these leaks HTTP wording, and "error sending request for
/// url" is not a thing to tell somebody whose password was wrong.
fn friendly_auth_error(error: &swifttunnel_core::auth::AuthError) -> String {
    use swifttunnel_core::auth::AuthError;
    match error {
        // A wrong password comes back as a 400 from the API, so the text is
        // the only thing that separates it from a real server fault.
        AuthError::ApiError(message) => {
            let lowered = message.to_lowercase();
            if lowered.contains("invalid")
                || lowered.contains("credential")
                || lowered.contains("password")
            {
                "Wrong email or password.".to_string()
            } else {
                message.clone()
            }
        }
        AuthError::NetworkError(_) => {
            "Could not reach SwiftTunnel. Check your connection.".to_string()
        }
        AuthError::UserBanned(_) => "This account cannot use SwiftTunnel.".to_string(),
        AuthError::RateLimited(secs) => {
            format!("Too many attempts. Try again in {secs}s.")
        }
        other => other.to_string(),
    }
}

fn describe(state: &ConnectionState) -> String {
    match state {
        ConnectionState::FetchingConfig => "Resolving relay".into(),
        ConnectionState::ConfiguringSplitTunnel => "Configuring split tunnel".into(),
        _ => "Connecting".into(),
    }
}


fn quality_of(level: u32) -> GraphicsQuality {
    match level {
        0 => GraphicsQuality::Automatic,
        1 => GraphicsQuality::Level1,
        10 => GraphicsQuality::Level10,
        _ => GraphicsQuality::Automatic,
    }
}

/// Roblox stores the quality level as a number, so this is its own scale
/// rather than the enum the writer takes. 0 is automatic.
fn level_of(quality: i32) -> u32 {
    match quality {
        1 => 1,
        10 => 10,
        _ => 0,
    }
}

/// Close Roblox, wait for it to actually go, and start it again.
///
/// The same sequence the full app runs. Roblox reads its settings once at
/// launch, so a change made while it is open does nothing until it restarts.
fn restart_roblox() -> Result<(), String> {
    let roblox = RobloxOptimizer::new();
    roblox
        .close_running_instances()
        .map_err(|e| format!("Could not close Roblox: {e}"))?;

    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if !roblox.is_roblox_running() {
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    if roblox.is_roblox_running() {
        return Err("Roblox did not exit in time. Try again.".into());
    }

    roblox
        .reopen_client()
        .map_err(|e| format!("Could not relaunch Roblox: {e}"))
}

/// Read Roblox's own settings rather than remembering them, so the switches
/// reflect reality even when the full app or the player changed them.
/// What is actually applied to the Roblox client.
///
/// The frame cap, the quality level and fullscreen are read back out of
/// Roblox's own settings, so a cap the player changed in Roblox itself shows
/// up here. The FFlag switches cannot be fully read back (all core can tell
/// is whether the flags are present), so the saved intent is passed in and
/// reconciled against reality by `effective_roblox_config`.
fn read_roblox(intent: &RobloxSettingsConfig) -> Roblox {
    let optimizer = RobloxOptimizer::new();
    let installed = optimizer.is_roblox_installed();
    let running = optimizer.is_roblox_running();

    // Turns the saved intent into what is really in force: it clears
    // ultraboost when the flags are not in ClientAppSettings.json, and clears
    // the unlock when the cap has fallen back to 60.
    let effective = optimizer.effective_roblox_config(intent);

    let Ok(current) = optimizer.read_current_settings() else {
        return Roblox {
            installed,
            running,
            ultraboost: effective.ultraboost,
            custom_fflags: effective.custom_fflags_enabled,
            custom_json: effective.custom_fflags_json.clone(),
            target_fps: DEFAULT_FRAME_CAP,
            ..Roblox::default()
        };
    };

    Roblox {
        installed,
        running,
        unlock_fps: current.fps_cap > DEFAULT_FRAME_CAP,
        target_fps: current.fps_cap,
        quality: level_of(current.graphics_quality),
        ultraboost: effective.ultraboost,
        custom_fflags: effective.custom_fflags_enabled,
        custom_json: effective.custom_fflags_json,
        fullscreen: current.fullscreen,
        error: None,
    }
}

/// Take a custom FFlag payload off the clipboard and check it.
///
/// Checked here rather than at apply time so a bad paste is refused where it
/// happened. The rules are core's, not this window's: valid JSON, a non-empty
/// object under 8KB, and every key on Roblox's local client allowlist. Nothing
/// outside that list can be written whatever is pasted.
fn apply_fflag_text(state: &mut State, text: String) {
    match RobloxOptimizer::validate_custom_fflags(&text) {
        Ok(count) => state.edit_roblox(|d| {
            d.custom_json = text;
            d.fflag_ok = true;
            d.fflag_note = Some(format!(
                "{count} allowlisted flag{} ready. Apply to write them.",
                if count == 1 { "" } else { "s" }
            ));
        }),
        Err(reason) => state.edit_roblox(|d| {
            d.fflag_ok = false;
            d.fflag_note = Some(reason);
        }),
    }
}

fn list_adapters() -> Vec<AdapterRow> {
    list_network_adapters()
        .unwrap_or_default()
        .into_iter()
        .filter(|a| a.is_up && a.kind != "loopback" && a.kind != "tunnel")
        .map(|a| AdapterRow {
            name: if a.friendly_name.is_empty() {
                a.description.clone()
            } else {
                a.friendly_name.clone()
            },
            detail: if a.is_default_route {
                "Default route".into()
            } else {
                a.kind.clone()
            },
            guid: a.guid,
        })
        .collect()
}

impl Engine {
/// Hand over to Lite's own uninstaller.
///
/// Disconnects first. Pulling the tunnel down after the driver bindings have
/// been removed leaves a machine that looks like it only has internet when
/// SwiftTunnel is installed, which is the state people uninstall to escape.
fn uninstall(&self, state: &mut State) {
    let crate::uninstall::Installed::Standalone(product_code) =
        crate::uninstall::how_installed()
    else {
        state.uninstall_note =
            Some("Lite came with SwiftTunnel. Uninstall SwiftTunnel to remove it.".into());
        return;
    };

    // Drop the tunnel before the driver bindings go. Removing them under a
    // live session leaves a machine that looks like it only has internet when
    // SwiftTunnel is installed, which is the state people uninstall to escape.
    if state.tunnel.status == Status::Connected {
        self.primary(state);
    }

    if let Err(error) = crate::uninstall::start(product_code) {
        state.uninstall_note = Some(error);
    }
}

}

/// Show the log file in Explorer, selected.
///
/// Not opened in a text editor: the file is hundreds of kilobytes and what
/// somebody actually needs to do with it is attach it to a message, which
/// means finding it in a folder.
fn open_logs() {
    let Some(path) = crate::log_path() else {
        return;
    };
    let _ = std::process::Command::new("explorer")
        .arg(format!("/select,{}", path.display()))
        .spawn();
}

/// Hand a URL to the default browser.
///
/// ShellExecuteW rather than `cmd /C start`: cmd.exe is a console program, so
/// spawning it flashes a console window on screen every time sign-in opens the
/// browser. This is the same thing without the window.
fn open_in_browser(url: &str) {
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
    use windows::core::HSTRING;

    let verb = HSTRING::from("open");
    let target = HSTRING::from(url);
    // SAFETY: both strings outlive the call, and a null hwnd/parameters/dir is
    // what the API expects for "just open this".
    unsafe {
        ShellExecuteW(
            None,
            &verb,
            &target,
            None,
            None,
            SW_SHOWNORMAL,
        );
    }
}
