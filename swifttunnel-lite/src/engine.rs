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
use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use windows::Win32::Foundation::{HWND, LPARAM, WPARAM};
use windows::Win32::UI::WindowsAndMessaging::{PostMessageW, WM_APP};

use swifttunnel_core::auth::types::AuthState;
use swifttunnel_core::auth::{AuthManager, update_required_message};
use swifttunnel_core::autostart::{RUN_VALUE_LITE, sync_run_on_startup};
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
use swifttunnel_core::vpn::split_tunnel::{
    DriverHealthStatus, GamePreset, SplitTunnelDriverHealth, get_apps_for_preset_set,
};
use swifttunnel_core::vpn::{ConnectionState, SplitTunnelDriver, VpnConnection};

use crate::operation_gate::OperationGate;
use crate::state::{
    AdapterRow, Driver, Lockout, RegionRow, ResetState, Roblox, State, Status, Tunnel, UpdateState,
};
use crate::view::{Action, FieldId, Flag};

/// Posted when a background job lands, so a finished connect or a fresh ping
/// shows up without waiting for the one-second heartbeat.
pub const WM_ENGINE_UPDATE: u32 = WM_APP + 1;
pub const WM_ENGINE_QUIT_READY: u32 = WM_APP + 3;

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
    startup_failure: Option<(bool, String)>,
    installation: Option<crate::uninstall::Installed>,
    uninstall_note: Option<String>,
    uninstall_busy: bool,
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
    adapter_error: Option<String>,
    roblox: Roblox,
    /// The reset row's two-press flow, and what the last reset found.
    ///
    /// Here rather than only in the window's own `State` because `fill` copies
    /// this way at the end of every dispatch, so anything the window sets
    /// directly is overwritten a moment later, and because the worker thread
    /// finishing has nowhere else to report to.
    roblox_reset: ResetState,
    roblox_reset_note: Option<String>,
    driver: Driver,
    lockout: Option<Lockout>,
    /// Progress of the in-app update, shown on the update-required screen.
    update: UpdateState,
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
    runtime: crate::runtime::EngineRuntime,
    auth: Arc<tokio::sync::Mutex<AuthManager>>,
    vpn: Arc<tokio::sync::Mutex<VpnConnection>>,
    settings: Arc<RwLock<AppSettings>>,
    settings_save_signal: crate::settings_writer::SaveSignal,
    /// Rich Presence, driven from the same tunnel state the window shows.
    ///
    /// Its own lock rather than living in the snapshot: the manager talks to
    /// Discord's IPC socket, which can block, and the poller must not hold the
    /// snapshot open while it does.
    discord: std::sync::Mutex<DiscordManager>,
    snapshot: RwLock<Snapshot>,
    /// Set once the window exists. Stored as an isize because HWND is not Send.
    hwnd: AtomicIsize,
    ui_update: crate::ui_update::UiUpdate,
    stop: AtomicBool,
    /// Serializes connect, disconnect, uninstall and installer handoff.
    busy: OperationGate,
    /// One update check/download at a time, whether manual or automatic.
    update_busy: OperationGate,
    roblox_edits: OperationGate,
    startup_edits: OperationGate,
    adapter_scan: OperationGate,
    roblox_revision: AtomicU64,
    /// Set when the user pressed Disconnect, so auto-reconnect knows the
    /// tunnel went down on purpose and leaves it down.
    intentional_disconnect: AtomicBool,
    /// Whether the tunnel has been up at least once, so a failed first connect
    /// is not retried forever behind a dialog nobody asked for.
    was_connected: AtomicBool,
    /// Automatic reconnects that failed since the tunnel was last up, and the
    /// earliest time the next one may start.
    reconnect_backoff: std::sync::Mutex<ReconnectBackoff>,
}

/// Paces automatic reconnects. Without it a reconnect that kept failing (no
/// network, relay fleet down, broken driver) restarted every 5 s poll for as
/// long as Lite stayed open, re-running auth, fleet and driver setup each time.
#[derive(Debug, Default)]
struct ReconnectBackoff {
    failures: u32,
    next_attempt: Option<Instant>,
}

impl ReconnectBackoff {
    const FIRST_DELAY: Duration = Duration::from_secs(5);
    const MAX_DELAY: Duration = Duration::from_secs(120);

    fn due(&self, now: Instant) -> bool {
        self.next_attempt.is_none_or(|at| now >= at)
    }

    fn failed(&mut self, now: Instant) {
        let delay = Self::FIRST_DELAY
            .saturating_mul(1 << self.failures.min(5))
            .min(Self::MAX_DELAY);
        self.failures = self.failures.saturating_add(1);
        self.next_attempt = Some(now + delay);
    }

    fn reset(&mut self) {
        *self = Self::default();
    }
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
        if self.stop.load(Ordering::Relaxed) {
            return;
        }
        let raw = self.hwnd.load(Ordering::Relaxed);
        if raw == 0 {
            return;
        }
        // SAFETY: posting to a window handle published by `run`. A stale
        // handle after the window closed makes PostMessageW fail, which is
        // exactly the harmless outcome wanted.
        self.ui_update.post(|| unsafe {
            PostMessageW(
                Some(HWND(raw as *mut std::ffi::c_void)),
                WM_ENGINE_UPDATE,
                WPARAM(0),
                LPARAM(0),
            )
            .is_ok()
        });
    }

    fn edit<T>(&self, f: impl FnOnce(&mut Snapshot) -> T) -> Option<T> {
        self.snapshot.write().ok().map(|mut s| f(&mut s))
    }

    // Called after reserving busy, so a new connect cannot race this check.
    fn connection_is_idle(&self) -> bool {
        !self.stop.load(Ordering::Relaxed)
            && self.vpn.try_lock().is_ok_and(|vpn| {
                matches!(
                    &*vpn.state_handle().borrow(),
                    ConnectionState::Disconnected | ConnectionState::Error(_)
                )
            })
    }

    fn automatic_updates_allowed(&self) -> bool {
        !self.stop.load(Ordering::Relaxed)
            && settings::settings_load_error().is_none()
            && self
                .settings
                .read()
                .is_ok_and(|settings| settings.update_settings.auto_check)
            // Roblox can be running directly while the tunnel is disconnected.
            // Check afresh before checking/downloading and at installer handoff;
            // the UI snapshot can be up to twenty seconds behind while idle.
            && !RobloxOptimizer::player_is_running()
    }

    // Called only on exit/update workers, never the GUI thread.
    fn flush_settings_before_exit(&self) {
        if let Err(error) = self.settings_save_signal.flush(Duration::from_secs(3)) {
            log::warn!("Could not finish settings saving before exit: {error}");
        }
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

        let settings = Arc::new(RwLock::new(loaded));
        let (settings_save_signal, settings_writer) =
            crate::settings_writer::start(settings.clone(), settings::save_settings)
                .map_err(|error| format!("Could not start settings saving: {error}"))?;
        // The writer owns only the settings and receiver, not Shared/runtime.
        // It finishes when Shared drops its sender, without blocking the GUI.
        drop(settings_writer);

        let shared = Arc::new(Shared {
            runtime: runtime.into(),
            auth: Arc::new(tokio::sync::Mutex::new(auth)),
            vpn: Arc::new(tokio::sync::Mutex::new(VpnConnection::new())),
            discord: std::sync::Mutex::new(DiscordManager::new(discord_enabled)),
            settings,
            settings_save_signal,
            snapshot: RwLock::new(Snapshot {
                startup_failure: None,
                installation: None,
                uninstall_note: None,
                uninstall_busy: false,
                signed_in,
                email,
                roblox: read_roblox(&roblox_intent),
                roblox_reset: ResetState::default(),
                roblox_reset_note: None,
                driver: read_driver(),
                lockout: lockout_of(&auth_state, banned_reason.clone()),
                update: UpdateState::default(),
                server_list: DynamicServerList::new_empty(),
                regions: Vec::new(),
                adapters: Vec::new(),
                adapter_error: None,
                tunnel: Tunnel::default(),
                free_tier_secs: None,
                free_tier_spent: false,
                login_busy: false,
                login_error: None,
            }),
            hwnd: AtomicIsize::new(0),
            ui_update: crate::ui_update::UiUpdate::default(),
            stop: AtomicBool::new(false),
            busy: OperationGate::default(),
            update_busy: OperationGate::default(),
            roblox_edits: OperationGate::default(),
            startup_edits: OperationGate::default(),
            adapter_scan: OperationGate::default(),
            roblox_revision: AtomicU64::new(0),
            intentional_disconnect: AtomicBool::new(false),
            was_connected: AtomicBool::new(false),
            reconnect_backoff: std::sync::Mutex::new(ReconnectBackoff::default()),
        });

        // Own shutdown before launching workers. A later startup failure must
        // signal already-started workers instead of abandoning their owners.
        let engine = Engine {
            shared: shared.clone(),
        };
        spawn_regions(shared.clone())?;
        spawn_game_logs(shared.clone())?;
        spawn_poller(shared.clone())?;
        if let Err(error) = spawn_auto_update(shared.clone()) {
            log::warn!("Automatic update checks could not start: {error}");
        }
        spawn_installation_lookup(shared.clone());

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
                    drop(auth);
                    // Refresh can revoke the saved login or clear a previous
                    // ban. Publish all account fields from the latest state.
                    refresh_auth(&shared).await;
                    shared.notify();
                }
            });
        }

        // Recovery is independent of adapter discovery. A slow recovery must
        // not hold up the picker or start another scan when it opens.
        {
            let shared = shared.clone();
            if let Err(error) = std::thread::Builder::new()
                .name("lite-gpu-recovery".into())
                .spawn(move || {
                    if let Err(error) =
                        swifttunnel_core::vpn::process_performance::recover_gpu_preferences()
                    {
                        log::warn!("Runtime GPU recovery has pending originals: {error}");
                    }
                    shared.notify();
                })
            {
                log::warn!("Could not start runtime GPU recovery: {error}");
            }
        }

        engine.refresh_adapters();
        Ok(engine)
    }

    /// Publish the window handle so background work can ask for a repaint.
    pub fn attach(&self, hwnd: isize) {
        self.shared.hwnd.store(hwnd, Ordering::Relaxed);
        // Workers can finish between the window's initial snapshot read and
        // publication of its handle. Their earlier notifications had no
        // recipient; always request one current snapshot after attachment.
        self.shared.notify();
    }

    pub fn acknowledge_update(&self) {
        self.shared.ui_update.acknowledge();
    }

    /// Copy everything the screens read out of the snapshot and the settings.
    pub fn fill(&self, state: &mut State) {
        state.startup_busy = self.shared.startup_edits.is_busy();
        state.adapter_busy = self.shared.adapter_scan.is_busy();
        let load_error = settings::settings_load_error();
        state.settings_reload_required = load_error.is_some();
        state.settings_warning = load_error
            .or_else(|| self.shared.settings_save_signal.warning())
            .map(str::to_owned);
        if let Ok(snapshot) = self.shared.snapshot.read() {
            if state.settings_warning.is_none() {
                state.settings_warning = snapshot
                    .startup_failure
                    .as_ref()
                    .map(|(_, message)| message.clone());
            }
            state.uninstall_note = snapshot.uninstall_note.clone();
            state.standalone = matches!(
                snapshot.installation,
                Some(crate::uninstall::Installed::Standalone(_))
            );
            state.installation_unknown = snapshot.installation.is_none()
                || matches!(
                    snapshot.installation,
                    Some(crate::uninstall::Installed::Unknown(_))
                );
            if state.uninstall_note.is_none() {
                match &snapshot.installation {
                    None => state.uninstall_note = Some("Checking installation...".into()),
                    Some(crate::uninstall::Installed::Unknown(message)) => {
                        state.uninstall_note = Some(message.clone())
                    }
                    _ => {}
                }
            }
            state.uninstall_busy = snapshot.uninstall_busy;
            state.regions = snapshot.regions.clone();
            state.adapters = snapshot.adapters.clone();
            state.adapter_error = snapshot.adapter_error.clone();
            state.roblox = snapshot.roblox.clone();
            state.roblox_reset = snapshot.roblox_reset;
            state.roblox_reset_note = snapshot.roblox_reset_note.clone();
            state.lockout = snapshot.lockout.clone();
            state.update = snapshot.update.clone();
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
            state.manual_relay = s.manual_relay.clone();
            state.custom_relay = !s.custom_relay_server.is_empty();
            state.auto_routing = s.auto_routing_enabled;
            state.route_assist = s.enable_api_tunneling;
            state.country_ban = s.enable_country_ban;
            state.run_on_startup = s.run_on_startup;
            state.close_to_tray = s.minimize_to_tray;
            state.auto_reconnect = s.auto_reconnect;
            state.adapter_guid = s.preferred_physical_adapter_guid.clone();
            state.discord_rpc = s.enable_discord_rpc;
        }
        // A removed saved city must not remain the picker label while core
        // chooses a surviving location for the next connection.
        if state.manual_relay.is_none()
            && !state.regions.is_empty()
            && !state
                .regions
                .iter()
                .any(|row| row.id == state.selected_region)
        {
            if let Ok(snapshot) = self.shared.snapshot.read() {
                state.selected_region = resolve_initial_connect_region(
                    &snapshot.server_list,
                    &state.selected_region,
                    false,
                );
            }
        }
        state.sync_roblox_busy(self.shared.roblox_edits.is_busy());
        state.finish_flag_import(self.shared.roblox_revision.load(Ordering::Acquire));
    }

    pub fn refresh_regions(&self) {
        // The list is refreshed periodically by its own thread; this only matters
        // on the first open, when it may not have landed yet.
        self.shared.notify();
    }

    pub fn refresh_adapters(&self) {
        let shared = self.shared.clone();
        let notify = self.shared.clone();
        let result = spawn_adapter_scan(
            &self.shared.adapter_scan,
            list_adapters,
            move |result| {
                shared.edit(|s| match result {
                    Ok(rows) => {
                        s.adapters = rows;
                        s.adapter_error = None;
                    }
                    Err(error) => {
                        log::warn!("Could not list Lite network adapters: {error}");
                        s.adapter_error = Some(ADAPTER_SCAN_ERROR.into());
                    }
                });
            },
            move || notify.notify(),
        );
        if let Err(error) = result {
            log::warn!("Could not start Lite adapter discovery: {error}");
            self.shared
                .edit(|s| s.adapter_error = Some(ADAPTER_SCAN_ERROR.into()));
        }
        self.shared.notify();
    }

    /// Carry out one action from the window.
    pub fn dispatch(&self, action: Action, state: &mut State) {
        if self.shared.stop.load(Ordering::Relaxed) {
            return;
        }
        // Doing anything else disarms the reset row. A half-pressed destructive
        // control must not sit there waiting behind a screen change, so that
        // coming back to Roblox and tapping the row once wipes the flags.
        if state.roblox_reset == ResetState::Armed && action != Action::ResetRoblox {
            self.shared.edit(|s| s.roblox_reset = ResetState::Idle);
        }

        match action {
            Action::Primary => self.primary(state),

            Action::RetrySettingsSave => {
                let _ = self.shared.settings_save_signal.try_send(());
                let pending = self
                    .shared
                    .snapshot
                    .read()
                    .ok()
                    .and_then(|s| s.startup_failure.as_ref().map(|(enabled, _)| *enabled));
                if let Some(enabled) = pending {
                    self.change_startup(enabled);
                }
            }

            Action::PickAutoRegion => {
                if matches!(state.tunnel.status, Status::Connected | Status::Working) {
                    return;
                }
                self.settings(|s| {
                    s.auto_routing_enabled = !s.auto_routing_enabled;
                    s.manual_relay = None;
                    if s.auto_routing_enabled {
                        s.enable_api_tunneling = false;
                        s.enable_country_ban = false;
                    }
                });
            }
            Action::PickRegion(id) => {
                if state.auto_routing
                    || matches!(state.tunnel.status, Status::Connected | Status::Working)
                {
                    return;
                }
                self.settings(|s| {
                    s.selected_region = id.clone();
                    s.manual_relay = None;
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

            Action::PickRelay(id) => {
                if state.auto_routing
                    || state.custom_relay
                    || matches!(state.tunnel.status, Status::Connected | Status::Working)
                {
                    return;
                }
                let manual = match id {
                    None => None,
                    Some(id) => {
                        let Some(relay) = state
                            .selected()
                            .and_then(|r| r.relays.iter().find(|r| r.id == id && r.available))
                        else {
                            return;
                        };
                        Some(swifttunnel_core::settings::ManualRelay {
                            region: state.selected_region.clone(),
                            server_id: id,
                            ip: relay.ip.clone(),
                            port: relay.port,
                        })
                    }
                };
                self.settings(|s| {
                    s.selected_region = state.selected_region.clone();
                    s.manual_relay = manual;
                    s.auto_routing_enabled = false;
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
            Action::ResetRoblox => self.reset_roblox(state),

            Action::SignOut => self.sign_out(),
            Action::SignIn => self.sign_in(),
            Action::SubmitLogin => self.submit_login(state),
            Action::RepairDriver => self.repair_driver(),
            Action::UpdateNow => self.update_now(),
            Action::OpenLogs => open_logs(),
            Action::Uninstall => self.uninstall(state),

            // Handled by the window: they change what is on screen, not what
            // the machine is doing.
            Action::Tab(_)
            | Action::Back
            | Action::OpenRegions
            | Action::OpenRelays
            | Action::OpenAdapters
            | Action::Minimise
            | Action::Close => {}
        }

        self.fill(state);
    }

    /// Connect, or disconnect if already up.
    fn primary(&self, state: &State) {
        // A cached zero can outlive an admin reset or a window refill. A fresh
        // explicit attempt must reach the authoritative server quota check.
        if state.lockout.is_some() {
            return;
        }
        let Some(operation) = self.shared.busy.try_enter() else {
            return;
        };
        let connected = state.tunnel.status == Status::Connected;
        let shared = self.shared.clone();
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
                let operation = operation;
                let full_ban = shared
                    .settings
                    .read()
                    .is_ok_and(|settings| settings.enable_country_ban);
                let outcome = if connected {
                    let mut vpn = shared.vpn.lock().await;
                    vpn.disconnect()
                        .await
                        .map_err(|e| swifttunnel_core::vpn::user_friendly_error(&e))
                } else if let Some(message) =
                    full_ban_connect_refusal(full_ban, RobloxOptimizer::player_is_running)
                {
                    Err(message.to_string())
                } else {
                    connect(&shared).await
                };

                if let Err(error) = outcome {
                    shared.edit(|s| {
                        s.tunnel.status = Status::Error;
                        s.tunnel.detail = error;
                    });
                }
                drop(operation);
                shared.notify();
            }
        });
    }

    fn toggle(&self, flag: Flag, state: &mut State) {
        match flag {
            Flag::RouteAssist => self.settings(|s| {
                s.enable_api_tunneling = !s.enable_api_tunneling;
                if s.enable_api_tunneling {
                    s.auto_routing_enabled = false;
                }
            }),
            Flag::CountryBan => self.settings(toggle_country_ban),
            Flag::RunOnStartup => {
                self.change_startup(!state.run_on_startup);
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
    /// Put Roblox back to stock, whoever changed it.
    ///
    /// Wider than turning our own switches off, on purpose. Somebody reaching
    /// for this has a Roblox that renders wrong and no way to tell which of
    /// SwiftTunnel, a bootstrapper or a flag list they copied is responsible,
    /// and the flag that ruins render distance looks exactly like the one that
    /// unlocks frames. Core deletes all of them, and the important half is the
    /// launcher's own copy: a strap writes it back into the game at every
    /// launch, which is why resetting Roblox's own files never clears anything.
    ///
    /// The first press only arms the row. This is the second.
    fn reset_roblox(&self, state: &mut State) {
        if state.fflag_import.is_busy() {
            return;
        }
        match state.roblox_reset {
            ResetState::Running => return,
            ResetState::Idle => {
                self.shared.edit(|s| {
                    s.roblox_reset = ResetState::Armed;
                    s.roblox_reset_note = None;
                });
                return;
            }
            ResetState::Armed => {}
        }
        let Some(operation) = self.shared.busy.try_enter() else {
            self.shared.edit(|s| {
                s.roblox_reset_note =
                    Some("Wait for the current operation to finish, then retry the reset.".into())
            });
            return;
        };
        let Some(edit) = self.shared.roblox_edits.try_enter() else {
            return;
        };
        self.shared.roblox_revision.fetch_add(1, Ordering::AcqRel);
        state.roblox_busy = true;

        self.shared.edit(|s| {
            s.roblox_reset = ResetState::Running;
            s.roblox_reset_note = None;
        });
        // Pending edits describe a client that is about to stop existing.
        state.focus = None;

        let shared = self.shared.clone();
        let spawned = std::thread::Builder::new()
            .name("lite-roblox-reset".into())
            .spawn(move || {
                let report = match crate::roblox_changes::run_edit(|| {
                    Ok(RobloxOptimizer::new().reset_client_to_default())
                }) {
                    Ok(report) => report,
                    Err(error) => {
                        shared.edit(|s| {
                            s.roblox_reset = ResetState::Idle;
                            s.roblox_reset_note = Some(error);
                        });
                        drop(edit);
                        drop(operation);
                        shared.notify();
                        return;
                    }
                };

                // The saved intent has to follow the client, or the switches come
                // straight back on over a Roblox with no flags left in it.
                if let Ok(mut guard) = shared.settings.write() {
                    let changed = crate::roblox_changes::reset_saved_intent(
                        &report,
                        &mut guard.config.roblox_settings,
                    );
                    drop(guard);
                    if changed {
                        let _ = shared.settings_save_signal.try_send(());
                    }
                }

                // Roblox usually outlives its own window, so somebody who believes
                // they closed it long ago still had it running. Saying it was
                // closed stops a deliberate kill reading as a crash.
                let closed = if report.roblox_was_running {
                    "Roblox closed. "
                } else {
                    ""
                };
                let note = if !report.failures.is_empty() {
                    "Some files were locked. Try again.".to_string()
                } else if report.flag_files_removed == 0 {
                    format!("{closed}Roblox was already clean, nothing to remove.")
                } else {
                    format!(
                        "{closed}Removed {} flag file{} from {}.",
                        report.flag_files_removed,
                        if report.flag_files_removed == 1 {
                            ""
                        } else {
                            "s"
                        },
                        report.sources.join(", ")
                    )
                };

                let intent = shared
                    .settings
                    .read()
                    .map(|s| s.config.roblox_settings.clone())
                    .unwrap_or_default();
                let roblox = read_roblox(&intent);
                shared.edit(|s| {
                    s.roblox = roblox;
                    s.roblox_reset = ResetState::Idle;
                    s.roblox_reset_note = Some(note);
                });
                drop(edit);
                drop(operation);
                shared.notify();
            });
        match spawned {
            Ok(_) => state.roblox_draft = None,
            Err(error) => {
                log::warn!("Lite Roblox reset worker could not start: {error}");
                self.shared.edit(|s| {
                    s.roblox_reset = ResetState::Idle;
                    s.roblox_reset_note = Some("Could not start the reset. Try again.".into());
                });
                self.shared.notify();
            }
        }
    }

    fn apply_roblox(&self, state: &mut State) {
        if state.fflag_import.is_busy() {
            return;
        }
        let draft = state.roblox_view();
        if !draft.ready() || !state.roblox_dirty() {
            return;
        }
        let Some(operation) = self.shared.busy.try_enter() else {
            self.shared.edit(|s| {
                s.roblox.error = Some(
                    "Wait for the current operation to finish, then apply your changes.".into(),
                )
            });
            return;
        };
        let Some(edit) = self.shared.roblox_edits.try_enter() else {
            return;
        };
        self.shared.roblox_revision.fetch_add(1, Ordering::AcqRel);
        state.roblox_busy = true;
        state.focus = None;

        let config = RobloxSettingsConfig {
            // Always write the cap: see `frame_cap_to_write`.
            unlock_fps: true,
            target_fps: frame_cap_to_write(draft.unlock_fps, draft.fps()),
            graphics_quality: quality_of(draft.quality),
            window_fullscreen: draft.fullscreen,
            ultraboost: draft.ultraboost,
            custom_fflags_enabled: draft.custom_fflags,
            custom_fflags_json: draft.custom_json.clone(),
            ..RobloxSettingsConfig::default()
        };
        let restart = state.roblox.running;
        let shared = self.shared.clone();

        let spawned = std::thread::Builder::new().name("lite-roblox-apply".into()).spawn(move || {
            let optimizer = RobloxOptimizer::new();
            let result = crate::roblox_changes::run_edit(|| crate::roblox_changes::apply_in_order(
                || {
                    if restart {
                        close_roblox_for_changes(&optimizer).map(Some)
                    } else if optimizer.is_roblox_running() {
                        Err("Roblox opened while you were editing. Close it, then apply your changes.".into())
                    } else {
                        Ok(None)
                    }
                },
                || {
                    // Read after Roblox has closed, since it saves its window on exit.
                    let mut config = config.clone();
                    keep_current_window_size(
                        &mut config,
                        optimizer.read_current_settings().ok().and_then(|current| current.window_size),
                    );
                    let mut warnings = optimizer.apply_optimizations(&config).map_err(|e| e.to_string())?;
                    if let Ok(mut guard) = shared.settings.write() {
                        let roblox = &mut guard.config.roblox_settings;
                        roblox.ultraboost = config.ultraboost;
                        roblox.custom_fflags_enabled = config.custom_fflags_enabled;
                        roblox.custom_fflags_json.clone_from(&config.custom_fflags_json);
                        drop(guard);
                        let _ = shared.settings_save_signal.try_send(());
                    } else {
                        warnings.push("Roblox changed, but SwiftTunnel could not remember these settings. Try again.".into());
                    }
                    Ok(warnings)
                },
                |player| optimizer.reopen_client(&player).map_err(|e| e.to_string()),
            ));
            let error = match result {
                Ok(warnings) if warnings.is_empty() => None,
                Ok(warnings) => Some(warnings.join("\n")),
                Err(error) => Some(error),
            };

            let intent = shared
                .settings
                .read()
                .map(|s| s.config.roblox_settings.clone())
                .unwrap_or_default();
                let roblox = read_roblox(&intent);
                shared.edit(|s| {
                    s.roblox = roblox;
                s.roblox.error = error;
            });
            drop(edit);
            drop(operation);
            shared.notify();
        });
        if let Err(error) = spawned {
            log::warn!("Lite Roblox apply worker could not start: {error}");
            self.shared.edit(|s| {
                s.roblox.error = Some("Could not start applying your changes. Try again.".into())
            });
            self.shared.notify();
        }
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
    /// Fetch, verify and run the newest Lite.
    ///
    /// The only route out of the update-required screen, which replaces the
    /// whole window, so every failure has to end somewhere the user can act on
    /// rather than a button that silently does nothing.
    ///
    /// Nothing here decides whether the download is genuine. Core verifies the
    /// signed manifest and then the installer's hash against it, and returns an
    /// error if either fails; this only reports what happened.
    fn update_now(&self) {
        let Some(update_job) = self.shared.update_busy.try_enter() else {
            return;
        };
        let Some(operation) = self.shared.busy.try_enter() else {
            self.shared.edit(|s| {
                s.update = UpdateState::Failed(
                    "Wait for the current operation to finish, then retry updating.".into(),
                )
            });
            self.shared.notify();
            return;
        };
        let shared = self.shared.clone();
        shared.edit(|s| s.update = UpdateState::Working("Checking...".to_string()));
        shared.notify();

        let spawned = std::thread::Builder::new()
            .name("lite-manual-update".into())
            .spawn(move || {
                let _update_job = update_job;
                let _operation = operation;
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        log::error!("update: could not start a runtime: {error}");
                        shared.edit(|s| {
                            s.update =
                                UpdateState::Failed("Could not start the update.".to_string())
                        });
                        shared.notify();
                        return;
                    }
                };

                let outcome = runtime.block_on(async {
                    let update =
                        swifttunnel_core::lite_update::check_for_update(env!("CARGO_PKG_VERSION"))
                            .await?
                            .ok_or_else(|| {
                                // The server refused this build but the newest release is
                                // not newer than it. Nothing here can fix that, and saying
                                // so is better than a spinner that never resolves.
                                "This is already the newest SwiftTunnel Lite.".to_string()
                            })?;

                    log::info!(
                        "update: {} available ({} bytes)",
                        update.version,
                        update.size()
                    );
                    shared.edit(|s| s.update = UpdateState::Working("Downloading...".to_string()));
                    shared.notify();

                    let path = swifttunnel_core::lite_update::download_verified(&update).await?;
                    if shared.stop.load(Ordering::Relaxed) {
                        return Err("Update cancelled because SwiftTunnel Lite closed.".into());
                    }
                    // The forced-update screen has no separate Disconnect
                    // button. An explicit update must clean up an active
                    // tunnel before exiting, rather than trap that screen or
                    // kill the process with networking still configured.
                    let launch_shared = Arc::clone(&shared);
                    crate::operation_gate::after_disconnect(
                        async {
                            if !shared.connection_is_idle() {
                                shared.edit(|s| s.update = UpdateState::Working("Disconnecting...".into()));
                                shared.notify();
                                shared.intentional_disconnect.store(true, Ordering::Relaxed);
                                shared.vpn.lock().await.disconnect().await.map_err(|_| {
                                    "Could not disconnect safely. Retry updating SwiftTunnel Lite.".to_string()
                                })?;
                            }
                            Ok(())
                        },
                        move || {
                            if launch_shared.stop.load(Ordering::Relaxed) {
                                return Err("Update cancelled because SwiftTunnel Lite closed.".into());
                            }
                            launch_shared.edit(|s| {
                                s.update = UpdateState::Working("Starting installer...".to_string())
                            });
                            launch_shared.notify();
                            swifttunnel_core::lite_update::launch_installer(&path)
                        },
                    ).await
                });

                match outcome {
                    Ok(()) => {
                        // msiexec cannot replace files this process is holding
                        // open, so it has to be the last thing we do.
                        log::info!(
                            "update: installer started, closing so it can replace this build"
                        );
                        shared.stop.store(true, Ordering::Relaxed);
                        shared.flush_settings_before_exit();
                        std::process::exit(0);
                    }
                    Err(error) => {
                        log::error!("update failed: {error}");
                        shared.edit(|s| s.update = UpdateState::Failed(error));
                        shared.notify();
                    }
                }
            });
        if let Err(error) = spawned {
            log::warn!("Lite update worker could not start: {error}");
            self.shared.edit(|s| {
                s.update = UpdateState::Failed("Could not start the update. Try again.".into())
            });
            self.shared.notify();
        }
    }

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
        let Some(operation) = self.shared.busy.try_enter() else {
            self.shared.edit(|s| {
                s.driver.note =
                    Some("Wait for the current operation to finish, then retry the repair.".into())
            });
            self.shared.notify();
            return;
        };

        let shared = self.shared.clone();
        shared.edit(|s| {
            s.driver.repairing = true;
            s.driver.note = None;
        });
        shared.notify();

        let spawned = std::thread::Builder::new()
            .name("lite-driver-repair".into())
            .spawn(move || {
                let operation = operation;
                let repair_shared = shared.clone();
                let result = shared
                    .runtime
                    .block_on(crate::operation_gate::after_disconnect(
                        async {
                            if shared.stop.load(Ordering::Relaxed) {
                                return Err(
                                    "Repair cancelled because SwiftTunnel Lite closed.".into()
                                );
                            }
                            shared.intentional_disconnect.store(true, Ordering::Relaxed);
                            shared.vpn.lock().await.disconnect().await.map_err(|_| {
                                "Could not disconnect safely. Retry the driver repair.".to_string()
                            })
                        },
                        move || {
                            if repair_shared.stop.load(Ordering::Relaxed) {
                                return Err(
                                    "Repair cancelled because SwiftTunnel Lite closed.".into()
                                );
                            }
                            let exe_dir = std::env::current_exe()
                                .ok()
                                .and_then(|p| p.parent().map(|d| d.to_path_buf()));
                            let program_files = std::path::PathBuf::from(
                                std::env::var("ProgramFiles")
                                    .unwrap_or_else(|_| "C:\\Program Files".to_string()),
                            );
                            SplitTunnelDriver::install_driver_from_bundled_package(
                                None,
                                exe_dir.as_deref(),
                                &program_files,
                                true,
                            )
                            .map_err(|error| {
                                log::warn!("Lite driver reinstall failed: {error}");
                                swifttunnel_core::vpn::error_messages::driver_repair_error(&error)
                            })
                        },
                    ));
                let mut driver = read_driver();
                driver.note = Some(match result {
                    Ok(()) => "Driver reinstalled. Try connecting again.".into(),
                    Err(error) => error,
                });
                shared.edit(|s| s.driver = driver);
                drop(operation);
                shared.notify();
            });
        if let Err(error) = spawned {
            log::warn!("Lite driver repair worker could not start: {error}");
            self.shared.edit(|s| {
                s.driver.repairing = false;
                s.driver.note = Some("Could not start the driver repair. Try again.".into());
            });
            self.shared.notify();
        }
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
    fn sign_out(&self) {
        if self.shared.edit(|s| {
            if s.login_busy {
                return false;
            }
            s.login_busy = true;
            s.login_error = None;
            true
        }) != Some(true)
        {
            return;
        }
        self.shared.notify();
        let shared = self.shared.clone();
        shared.runtime.spawn({
            let shared = shared.clone();
            async move {
                let manager = shared.auth.clone();
                // Credential deletion can wait for disk or the Windows vault.
                // Keep it off the two asynchronous engine workers too.
                let result =
                    tokio::task::spawn_blocking(move || manager.blocking_lock().logout()).await;
                let failure = match result {
                    Ok(Ok(())) => None,
                    Ok(Err(error)) => {
                        log::warn!("Could not sign out: {error}");
                        Some("Could not remove your saved login. Try signing out again.")
                    }
                    Err(error) => {
                        log::warn!("Sign-out worker stopped: {error}");
                        Some("Could not finish signing out. Try again.")
                    }
                };
                if let Some(message) = failure {
                    shared.edit(|s| {
                        s.login_busy = false;
                        s.login_error = Some(message.into());
                    });
                    shared.notify();
                    return;
                }
                if let Ok(mut discord) = shared.discord.lock() {
                    discord.clear();
                }
                // A successfully signed-out client must not reconnect on its own.
                if let Ok(mut settings) = shared.settings.write() {
                    settings.auto_reconnect = false;
                    settings.resume_vpn_on_startup = false;
                    drop(settings);
                    let _ = shared.settings_save_signal.try_send(());
                }
                refresh_auth(&shared).await;
                shared.edit(|s| {
                    s.login_busy = false;
                    s.login_error = None;
                });
                shared.notify();
            }
        });
    }

    fn submit_login(&self, state: &mut State) {
        if state.login.busy
            || self
                .shared
                .snapshot
                .read()
                .map(|s| s.login_busy)
                .unwrap_or(true)
        {
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
                // A rejected login can still publish a confirmed ban in Core.
                // Keep its account details and the lockout in sync on errors too.
                refresh_auth(&shared).await;
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
    /// Windows owns the modal picker; disk access and validation run separately.
    /// The UI keeps one pending read and discards a result after newer flag edits.
    fn import_fflags(&self, state: &mut State) {
        if state.fflag_import.pending() || state.roblox_busy || !state.roblox_view().custom_fflags {
            return;
        }
        let Some(path) = crate::picker::pick_fflag_file(self.shared.hwnd()) else {
            return;
        };
        let baseline = state.roblox_view();
        if self.shared.roblox_edits.is_busy() || !baseline.custom_fflags {
            return;
        }
        let revision = self.shared.roblox_revision.load(Ordering::Acquire);
        let shared = self.shared.clone();
        if let Err(reason) = state.fflag_import.start(
            baseline,
            revision,
            move || {
                let text = crate::picker::read_fflag_path(&path)?;
                let count = RobloxOptimizer::validate_custom_fflags(&text)?;
                Ok(crate::flag_import::ImportedFlags { text, count })
            },
            move || shared.notify(),
        ) {
            state.edit_roblox(|draft| draft.fflag_note = Some(reason));
        } else {
            state.edit_roblox(|draft| draft.fflag_note = None);
        }
    }

    fn sign_in(&self) {
        // Share the email form's busy state. A second poller must not consume
        // the first attempt's callback or cancel its replacement at timeout.
        if self.shared.edit(|s| {
            if s.login_busy {
                return false;
            }
            s.login_busy = true;
            s.login_error = None;
            true
        }) != Some(true)
        {
            return;
        }
        self.shared.notify();
        let shared = self.shared.clone();
        shared.runtime.spawn({
            let shared = shared.clone();
            async move {
                use swifttunnel_core::auth::AuthError;
                let result: Result<(), AuthError> = async {
                    let manager = shared.auth.clone();
                    let expected_state = tokio::task::spawn_blocking(move || {
                        manager.blocking_lock().start_google_sign_in()
                    })
                    .await
                    .map_err(|_| {
                        AuthError::ApiError("Could not open browser sign-in. Try again.".into())
                    })??;
                    // Core already opened the browser. Its return value is the
                    // random state, not another URL to pass to ShellExecute.
                    let deadline = Instant::now() + Duration::from_secs(600);
                    let callback = loop {
                        if Instant::now() >= deadline || shared.stop.load(Ordering::Relaxed) {
                            if let Ok(auth) = shared.auth.try_lock()
                                && auth.get_pending_oauth_state().as_deref()
                                    == Some(expected_state.as_str())
                            {
                                auth.cancel_oauth();
                            }
                            return Err(AuthError::ApiError(
                                "Sign-in timed out. Try again.".into(),
                            ));
                        }
                        // A profile refresh can hold this mutex during HTTP.
                        // Keep the deadline running instead of queuing on it.
                        if let Ok(auth) = shared.auth.try_lock() {
                            if auth.get_pending_oauth_state().as_deref()
                                != Some(expected_state.as_str())
                            {
                                return Ok(());
                            }
                            if let Some(callback) = auth.poll_oauth_callback() {
                                break callback;
                            }
                        }
                        tokio::time::sleep(Duration::from_millis(400)).await;
                    };
                    let auth = shared.auth.lock().await;
                    if auth.get_pending_oauth_state().as_deref() != Some(expected_state.as_str()) {
                        return Ok(());
                    }
                    auth.complete_oauth_callback(&callback.token, &callback.state)
                        .await
                }
                .await;
                shared.edit(|s| {
                    s.login_busy = false;
                    s.login_error = result.as_ref().err().map(friendly_auth_error);
                });
                refresh_auth(&shared).await;
                shared.notify();
            }
        });
    }

    fn change_startup(&self, enabled: bool) {
        let Some(operation) = self.shared.startup_edits.try_enter() else {
            return;
        };
        self.shared.notify();
        let shared = self.shared.clone();
        let spawned = std::thread::Builder::new()
            .name("lite-startup-settings".into())
            .spawn(move || {
                if shared.stop.load(Ordering::Relaxed) { return; }
                let result = apply_startup_preference(&shared.settings, enabled, |value| {
                    sync_run_on_startup(RUN_VALUE_LITE, value)
                });
                match result {
                    Ok(()) => {
                        let _ = shared.settings_save_signal.try_send(());
                        shared.edit(|s| s.startup_failure = None);
                    }
                    Err(error) => {
                        log::warn!("Could not change the startup entry: {error}");
                        shared.edit(|s| s.startup_failure = Some((enabled,
                            "Couldn't finish Windows startup setup. Retry settings, or restart SwiftTunnel.".into())));
                    }
                }
                drop(operation);
                shared.notify();
            });
        if let Err(error) = spawned {
            log::warn!("Could not start the startup-settings worker: {error}");
            self.shared.edit(|s| {
                s.startup_failure = Some((
                    enabled,
                    "Couldn't start Windows startup setup. Retry settings.".into(),
                ))
            });
            self.shared.notify();
        }
    }

    /// Change a setting and write the file.
    ///
    /// Wake one writer immediately. Changes while a save is running collapse
    /// into its next snapshot instead of creating competing threads/writes.
    fn settings(&self, edit: impl FnOnce(&mut AppSettings)) {
        {
            let Ok(mut guard) = self.shared.settings.write() else {
                return;
            };
            edit(&mut guard);
        }
        let _ = self.shared.settings_save_signal.try_send(());
    }
}

fn apply_startup_preference(
    settings: &RwLock<AppSettings>,
    enabled: bool,
    apply: impl FnOnce(bool) -> Result<(), String>,
) -> Result<(), String> {
    // Confirm the shared snapshot can be read, but never hold it during an OS
    // call. A failed registration must not publish a successful checkbox.
    drop(
        settings
            .read()
            .map_err(|_| "Could not read startup preferences.")?,
    );
    apply(enabled)?;
    settings
        .write()
        .map_err(|_| "Could not update startup preferences.")?
        .run_on_startup = enabled;
    Ok(())
}

impl Drop for Engine {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::Relaxed);
    }
}

impl Engine {
    /// Quit only after the same network cleanup as Disconnect. The window's
    /// message loop stays responsive while an in-flight connect finishes and
    /// the driver restores its state. Do not rely on process exit to run Drop
    /// for Arc-owned background resources.
    pub fn request_quit(&self) -> Result<(), String> {
        let shared = self.shared.clone();
        let hwnd = shared.hwnd.load(Ordering::Relaxed);
        spawn_exit_cleanup(
            move || {
                shared.stop.store(true, Ordering::Relaxed);
                shared.intentional_disconnect.store(true, Ordering::Relaxed);
                shared.was_connected.store(false, Ordering::Relaxed);
                // Repair/install may be past its disconnect phase while still
                // changing the shared driver. Do not exit underneath it.
                let _operation = shared.busy.enter_for_shutdown();
                let _startup_settings = shared.startup_edits.enter_for_shutdown();
                let result = shared.runtime.block_on(async {
                    let mut vpn = shared.vpn.lock().await;
                    let idle =
                        matches!(*vpn.state_handle().borrow(), ConnectionState::Disconnected)
                            && vpn.split_tunnel_handle().is_none();
                    if !idle {
                        vpn.disconnect().await.map_err(|error| error.to_string())?;
                    }
                    Ok(())
                });
                // The detached settings worker must get its final snapshot before
                // the GUI exits. A broken disk cannot hold shutdown indefinitely.
                shared.flush_settings_before_exit();
                // The GUI still owns Engine here. Release the worker's Arc before
                // posting the message that destroys it, keeping final runtime
                // destruction out of this cleanup worker.
                drop(shared);
                result
            },
            move |success| unsafe {
                let _ = PostMessageW(
                    Some(HWND(hwnd as *mut std::ffi::c_void)),
                    WM_ENGINE_QUIT_READY,
                    WPARAM(usize::from(success)),
                    LPARAM(0),
                );
            },
        )
        .map(|_| ())
        .map_err(|error| {
            format!("Could not start exit cleanup. Try closing SwiftTunnel again. ({error})")
        })
    }
}

fn spawn_exit_cleanup(
    cleanup: impl FnOnce() -> Result<(), String> + Send + 'static,
    completed: impl FnOnce(bool) + Send + 'static,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name("lite-exit-cleanup".into())
        .spawn(move || {
            let success = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(cleanup)) {
                Ok(Ok(())) => true,
                Ok(Err(error)) => {
                    log::warn!("Could not finish Lite exit cleanup: {error}");
                    false
                }
                Err(_) => {
                    log::error!("Lite exit cleanup panicked; keeping the window open for retry");
                    false
                }
            };
            completed(success);
        })
}

// ── Connecting ──────────────────────────────────────────────────────────────

/// Bring the tunnel up, with the same arguments the full app passes.
///
/// The one thing Lite decides differently is the app list: it is always the
/// Roblox preset, because that is the only thing this client is for.
async fn connect(shared: &Arc<Shared>) -> Result<(), String> {
    if shared.stop.load(Ordering::Relaxed) {
        return Err("SwiftTunnel is closing.".into());
    }
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
            .map_err(|error| friendly_auth_error(&error))?
    };

    if settings.custom_relay_server.is_empty() {
        if let Err(error) = refresh_fleet(shared).await {
            log::warn!("Fleet refresh before connect failed; retaining last list: {error}");
        }
    }

    // The fleet with its measured round trips, and the region auto-routing
    // would actually pick, both from core's own policy rather than from a
    // second opinion held here.
    let (available, region) = {
        let snapshot = shared
            .snapshot
            .read()
            .map_err(|_| "server list unavailable".to_string())?;
        let (region, available) = swifttunnel_core::vpn::connect_policy::connect_candidates(
            &snapshot.server_list,
            &settings.selected_region,
            settings.auto_routing_enabled,
            settings
                .manual_relay
                .as_ref()
                .filter(|_| settings.custom_relay_server.is_empty()),
        )?;
        (available, region)
    };

    // Always the Roblox preset, because that is the only thing this client
    // is for. The full app builds this from a saved list of games.
    let apps = get_apps_for_preset_set(&HashSet::from([GamePreset::Roblox]));

    // An empty custom relay means "use the fleet", which is what the full app
    // does with the same field.
    let custom_relay =
        (!settings.custom_relay_server.is_empty()).then(|| settings.custom_relay_server.clone());
    // A custom relay and auto-routing contradict each other; the full app
    // drops auto-routing for the session, so this does too.
    let auto_routing = settings.auto_routing_enabled && custom_relay.is_none();

    let mut vpn = shared.vpn.lock().await;
    // Auth/fleet reads above can finish after Quit already checked the idle
    // connection. Recheck under this lock so no late connect starts afterward.
    if shared.stop.load(Ordering::Relaxed) {
        return Err("SwiftTunnel is closing.".into());
    }
    vpn.set_auth_manager(shared.auth.clone());
    vpn.set_regional_auto_scope(swifttunnel_core::vpn::connect_policy::regional_auto_scope(
        &settings,
        &settings.selected_region,
    ));
    vpn.connect(
        &token,
        &region,
        apps,
        custom_relay,
        auto_routing,
        available,
        settings.whitelisted_regions.clone(),
        binding,
        settings.game_process_performance,
        settings.enable_api_tunneling,
        settings.enable_country_ban,
    )
    .await
    .map_err(|e| swifttunnel_core::vpn::user_friendly_error(&e))
}

// ── Background threads ──────────────────────────────────────────────────────

/// MSI enumeration can stall, so discover installation identity off the window thread.
fn spawn_installation_lookup(shared: Arc<Shared>) {
    let failure_shared = shared.clone();
    let spawned = std::thread::Builder::new()
        .name("lite-installation-lookup".into())
        .spawn(move || {
            let installation = crate::uninstall::how_installed().clone();
            shared.edit(|s| s.installation = Some(installation));
            shared.notify();
        });
    if let Err(error) = spawned {
        log::warn!("Lite installation lookup worker could not start: {error}");
        failure_shared.edit(|s| {
            s.installation = Some(crate::uninstall::Installed::Unknown(
                "Could not check this installation. Use Windows Settings > Apps.".into(),
            ))
        });
        failure_shared.notify();
    }
}

/// Dropping this future stops its owned download when activity changes.
async fn download_while_idle<T>(
    download: impl std::future::Future<Output = T>,
    mut allowed: impl FnMut() -> bool,
    check_every: Duration,
) -> Option<T> {
    if !allowed() {
        return None;
    }
    tokio::pin!(download);
    loop {
        tokio::select! {
            result = &mut download => return Some(result),
            _ = tokio::time::sleep(check_every) => {
                if !allowed() { return None; }
            }
        }
    }
}

/// Check for automatic updates in the background and hand off only while idle.
/// How one pass of the automatic update worker ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UpdatePass {
    /// Checked: current, installed or not retried. Nothing to do for hours.
    Checked,
    /// Skipped before any network work: tunnel in use, Roblox open, another
    /// update running or updates switched off. Cheap to look again soon.
    Deferred,
    /// An update was found, but activity started during the download or
    /// handover. Retry once things are quiet, without re-downloading often.
    Interrupted,
    /// The check or download failed: offline, GitHub down, bad signature.
    Failed,
}

/// When the update worker looks again. Every outcome used to wait six hours,
/// so a player who was connected or had Roblox open 45 s after launch (the
/// usual case) went six hours without the update.
fn update_retry_after(pass: UpdatePass) -> Duration {
    match pass {
        UpdatePass::Checked => Duration::from_secs(6 * 60 * 60),
        UpdatePass::Deferred => Duration::from_secs(60),
        UpdatePass::Interrupted => Duration::from_secs(10 * 60),
        UpdatePass::Failed => Duration::from_secs(30 * 60),
    }
}

fn spawn_auto_update(shared: Arc<Shared>) -> Result<(), String> {
    // Long enough that a launch is not competing with a download, short enough
    // that somebody who opens Lite, updates, and plays is covered.
    const FIRST_CHECK_AFTER: Duration = Duration::from_secs(45);

    std::thread::Builder::new().name("lite-auto-update".into()).spawn(move || {
        let mut wait = FIRST_CHECK_AFTER;

        loop {
            // Wake often so a close is noticed promptly rather than after
            // hours.
            let deadline = Instant::now() + wait;
            while Instant::now() < deadline {
                if shared.stop.load(Ordering::Relaxed) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(500));
            }
            wait = update_retry_after(UpdatePass::Checked);

            if shared.stop.load(Ordering::Relaxed) {
                return;
            }
            if !shared.automatic_updates_allowed() {
                wait = update_retry_after(UpdatePass::Deferred);
                continue;
            }

            // Connected, or busy connecting: leave it alone and come back.
            let in_use = shared
                .snapshot
                .read()
                .map(|s| s.tunnel.status != Status::Disconnected)
                .unwrap_or(true);
            if in_use || shared.busy.is_busy() {
                log::debug!("auto-update: in use, deferring");
                wait = update_retry_after(UpdatePass::Deferred);
                continue;
            }

            let Some(_update_job) = shared.update_busy.try_enter() else {
                wait = update_retry_after(UpdatePass::Deferred);
                continue;
            };

            let found = shared.runtime.block_on(async {
                swifttunnel_core::lite_update::check_for_update(env!("CARGO_PKG_VERSION")).await
            });

            let update = match found {
                Ok(Some(update)) => update,
                Ok(None) => {
                    log::debug!("auto-update: already current");
                    continue;
                }
                // Offline, GitHub down, a release without Lite assets. None of
                // it is worth telling the user about, and all of it is worth
                // trying again later.
                Err(error) => {
                    log::info!("auto-update: could not check ({error})");
                    wait = update_retry_after(UpdatePass::Failed);
                    continue;
                }
            };

            if swifttunnel_core::lite_update::already_attempted(&update.version) {
                // We installed this once and came back as the old version, so
                // installing it again would only do the same. Left to the
                // button on the update screen, which reports what happened
                // rather than looping in the background.
                log::warn!(
                    "auto-update: {} was installed once already and this build is still {};                      not retrying automatically",
                    update.version,
                    env!("CARGO_PKG_VERSION")
                );
                continue;
            }

            if !shared.automatic_updates_allowed() {
                wait = update_retry_after(UpdatePass::Deferred);
                continue;
            }

            log::info!("auto-update: {} is available, fetching", update.version);
            shared.edit(|s| s.update = UpdateState::Working("Updating...".to_string()));
            shared.notify();

            let staged = shared.runtime.block_on(async {
                download_while_idle(
                    swifttunnel_core::lite_update::download_verified(&update),
                    || {
                        !shared.busy.is_busy()
                            && shared.connection_is_idle()
                            && shared.automatic_updates_allowed()
                    },
                    Duration::from_secs(2),
                )
                .await
            });

            let staged = match staged {
                Some(Ok(path)) => path,
                None => {
                    log::debug!("auto-update: activity or preferences changed, download cancelled");
                    shared.edit(|s| s.update = UpdateState::Idle);
                    shared.notify();
                    wait = update_retry_after(UpdatePass::Interrupted);
                    continue;
                }
                Some(Err(error)) => {
                    // Includes a failed signature or hash. Deliberately quiet:
                    // the build still works, and the update screen is there if
                    // the server ever refuses it.
                    log::warn!("auto-update: not applying it ({error})");
                    shared.edit(|s| s.update = UpdateState::Idle);
                    shared.notify();
                    wait = update_retry_after(UpdatePass::Failed);
                    continue;
                }
            };

            // Re-check rather than trusting the state from before the
            // download: a connect can start while several megabytes are in
            // flight, and closing then is exactly what this avoids.
            let Some(_operation) = shared.busy.try_enter() else {
                shared.edit(|s| s.update = UpdateState::Idle);
                shared.notify();
                wait = update_retry_after(UpdatePass::Interrupted);
                continue;
            };
            if !shared.connection_is_idle() || !shared.automatic_updates_allowed() {
                log::info!(
                    "auto-update: connection or preferences changed while downloading, deferring"
                );
                shared.edit(|s| s.update = UpdateState::Idle);
                shared.notify();
                wait = update_retry_after(UpdatePass::Interrupted);
                continue;
            }

            // Written before the handover: the process exits straight after
            // and gets no later chance.
            swifttunnel_core::lite_update::record_install_attempt(&update.version);

            match swifttunnel_core::lite_update::launch_installer(&staged) {
                Ok(()) => {
                    log::info!("auto-update: installer started, closing so it can replace us");
                    shared.stop.store(true, Ordering::Relaxed);
                    shared.flush_settings_before_exit();
                    std::process::exit(0);
                }
                Err(error) => {
                    log::warn!("auto-update: could not start the installer ({error})");
                    shared.edit(|s| s.update = UpdateState::Idle);
                    shared.notify();
                }
            }
        }
    }).map(|_| ()).map_err(|error| format!("Could not start the Lite update worker: {error}"))
}

fn region_rows(list: &DynamicServerList) -> Vec<RegionRow> {
    list.regions()
        .iter()
        .filter(|region| !list.servers_in_region(&region.id).is_empty())
        .map(|region| RegionRow {
            id: region.id.clone(),
            name: region.name.clone(),
            country: region.country_code.to_uppercase(),
            ping_ms: list.get_region_best_latency(&region.id),
            relays: list
                .servers()
                .iter()
                .filter(|s| region.servers.contains(&s.region))
                .map(|s| crate::state::RelayRow {
                    preview: None,
                    id: s.region.clone(),
                    ip: s.ip.clone(),
                    port: s.effective_relay_port(),
                    available: s.relay_available,
                    ping_ms: list.get_recent_latency(&s.region),
                })
                .collect(),
        })
        .collect()
}

/// The worker and connect path share the same list replacement logic.
async fn refresh_fleet(shared: &Arc<Shared>) -> Result<(), String> {
    let list = servers::fetch_server_list_for_connect().await?;
    shared.edit(|s| {
        s.server_list
            .update(list.servers, list.regions, ServerListSource::Api);
        s.regions = region_rows(&s.server_list);
    });
    // Updating candidates does not move the existing connection.
    if let Ok(vpn) = shared.vpn.try_lock() {
        if let Some(router) = vpn.auto_router() {
            if let Ok(s) = shared.snapshot.read() {
                router.set_available_servers(build_available_servers(&s.server_list));
            }
        }
    }
    shared.notify();
    Ok(())
}

fn spawn_game_logs(shared: Arc<Shared>) -> Result<(), String> {
    std::thread::Builder::new()
        .name("lite-game-logs".into())
        .spawn(move || {
            use swifttunnel_core::{
                roblox_watcher::{RobloxEvent, RobloxWatcher},
                vpn::game_destination::{self, ObservedGame},
            };
            let Some(watcher) = RobloxWatcher::new() else {
                return;
            };
            let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                return;
            };
            runtime.block_on(async {
                let mut game_started: Option<Instant> = None;
                let mut location = crate::game_location::GameLocation::default();
                while !shared.stop.load(Ordering::Relaxed) {
                    for event in watcher.poll() {
                        match event {
                            RobloxEvent::GameJoined {
                                ip,
                                place_id,
                                job_id,
                                ..
                            } => {
                                if !RobloxOptimizer::player_is_running() {
                                    continue;
                                }
                                location.clear();
                                if !game_destination::register(ObservedGame {
                                    ip,
                                    job_id: job_id.clone(),
                                    location: None,
                                    region: None,
                                    prelaunch: false,
                                }) {
                                    continue;
                                }
                                game_started = Some(Instant::now());
                                if !swifttunnel_core::geolocation::is_roblox_game_server_ip(ip) {
                                    location.replace(ip, place_id, job_id);
                                }
                            }
                            RobloxEvent::GameLeft { job_id } => {
                                if let Some(job_id) = job_id {
                                    location.clear_for_session(&job_id);
                                    if game_destination::clear_for_session(&job_id) {
                                        game_started = None;
                                    }
                                }
                            }
                            RobloxEvent::PlayerOpened | RobloxEvent::GameServerDetected { .. } => {}
                        }
                    }
                    let running = shared
                        .snapshot
                        .read()
                        .map(|s| s.roblox.running)
                        .unwrap_or(false);
                    if running
                        || game_started.is_some_and(|at| at.elapsed() < Duration::from_secs(8))
                    {
                        game_destination::refresh();
                    } else {
                        game_started = None;
                        location.clear();
                        game_destination::clear();
                    }
                    // Continue consuming joins/leaves even if the optional
                    // cloud-location service stalls. Only the newest session
                    // owns a lookup, and shutdown drops it with this loop.
                    if let Some(resolved) = location.advance(Duration::from_secs(1)).await {
                        if shared.stop.load(Ordering::Relaxed)
                            || !RobloxOptimizer::player_is_running()
                        {
                            continue;
                        }
                        let region = swifttunnel_core::geolocation::RobloxRegion::all_regions()
                            .iter()
                            .find(|region| {
                                region.best_swifttunnel_region()
                                    == resolved.center.relay_region.as_deref()
                            })
                            .cloned();
                        game_destination::update_location(
                            resolved.ip,
                            &resolved.job_id,
                            resolved.center.city,
                            region,
                        );
                    }
                }
                game_destination::clear();
            });
        })
        .map(|_| ())
        .map_err(|error| format!("Could not start the Lite game log worker: {error}"))
}

fn spawn_regions(shared: Arc<Shared>) -> Result<(), String> {
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

            let game_running = || {
                shared
                    .snapshot
                    .read()
                    .map(|s| s.roblox.running)
                    .unwrap_or(true)
            };
            let mut next_refresh = Instant::now();
            let mut until_round = Duration::ZERO;
            while wait_for_picker_round(&shared.stop, &game_running, until_round) {
                until_round = PING_INTERVAL;
                if Instant::now() >= next_refresh {
                    match runtime.block_on(refresh_fleet(&shared)) {
                        Ok(()) => next_refresh = Instant::now() + Duration::from_secs(5 * 60),
                        Err(error) => {
                            log::warn!("could not refresh the region list: {error}");
                            next_refresh = Instant::now() + PING_INTERVAL;
                        }
                    }
                }
                // Rebuild targets from the current snapshot. Connect can also
                // refresh the fleet while one of these probes is in flight.
                let targets = shared
                    .snapshot
                    .read()
                    .map(|s| {
                        s.server_list
                            .servers()
                            .iter()
                            .filter(|s| s.relay_available)
                            .map(|s| (s.region.clone(), s.ip.clone(), s.effective_relay_port()))
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                // All siblings need a first leg. Bound concurrent blocking ICMP work.
                let measured = runtime.block_on(async {
                    let mut tasks = tokio::task::JoinSet::new();
                    let mut measured = Vec::new();
                    for (id, ip, port) in targets {
                        if shared.stop.load(Ordering::Relaxed) || game_running() {
                            break;
                        }
                        if tasks.len() >= 8 {
                            if let Some(Ok(row)) = tasks.join_next().await {
                                measured.push(row);
                            }
                        }
                        tasks.spawn_blocking(move || {
                            let ping = servers::measure_latency_icmp(&ip);
                            (id, ip, port, ping)
                        });
                    }
                    while let Some(row) = tasks.join_next().await {
                        if let Ok(row) = row {
                            measured.push(row);
                        }
                    }
                    measured
                });
                if shared.stop.load(Ordering::Relaxed) {
                    break;
                }
                if game_running() {
                    until_round = Duration::ZERO;
                    continue;
                }
                let samples = runtime.block_on(swifttunnel_core::vpn::route_preview::fetch());
                shared.edit(|s| {
                    for (id, ip, port, ping) in measured {
                        s.server_list.set_endpoint_latency(&id, &ip, port, ping);
                    }
                    s.regions = region_rows(&s.server_list);
                    let previews = swifttunnel_core::vpn::route_preview::estimates(
                        &build_available_servers(&s.server_list),
                        &samples,
                        s.server_list.regions(),
                    );
                    for relay in s.regions.iter_mut().flat_map(|region| &mut region.relays) {
                        relay.preview = previews
                            .iter()
                            .find(|row| row.estimate.relay == relay.id)
                            .cloned();
                    }
                });
                // Feed the same recent first legs to join-time routing and the picker.
                if let Ok(vpn) = shared.vpn.try_lock() {
                    if let Some(router) = vpn.auto_router() {
                        if let Ok(s) = shared.snapshot.read() {
                            router.set_available_servers(build_available_servers(&s.server_list));
                        }
                    }
                }
                shared.notify();
            }
        })
        .map(|_| ())
        .map_err(|error| format!("Could not start the Lite region worker: {error}"))
}

/// Keep picker-only probes off the connection during play. A game opening
/// interrupts the idle cadence; its exit starts a fresh round immediately.
fn wait_for_picker_round(
    stop: &AtomicBool,
    game_running: impl Fn() -> bool,
    interval: Duration,
) -> bool {
    let mut due = Instant::now() + interval;
    loop {
        if stop.load(Ordering::Relaxed) {
            return false;
        }
        let now = Instant::now();
        if game_running() {
            due = now;
        } else if now >= due {
            return true;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
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
fn spawn_poller(shared: Arc<Shared>) -> Result<(), String> {
    std::thread::Builder::new()
        .name("lite-poll".into())
        .spawn(move || {
            let mut since: Option<Instant> = None;
            let mut roblox_tick: u32 = 0;
            let mut running = false;
            let mut last_settings_warning = None;

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

                let (state, throughput, game_route) = shared.runtime.block_on(async {
                    let mut vpn = shared.vpn.lock().await;
                    if vpn.take_terminal_cleanup_request() {
                        // Quota/auth termination is not a transient drop to auto-retry.
                        shared.was_connected.store(false, Ordering::Relaxed);
                        vpn.cleanup_after_terminal_error().await;
                    }
                    (
                        vpn.state_handle().borrow().clone(),
                        vpn.get_throughput_stats(),
                        vpn.auto_router().and_then(|r| r.game_route_status()),
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
                        shared
                            .reconnect_backoff
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .reset();
                        since = Some(*started);
                        tunnel.status = Status::Connected;
                        tunnel.game_route = game_route;
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

                let read_revision = shared.roblox_revision.load(Ordering::Acquire);
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
                    running = RobloxOptimizer::player_is_running();
                }
                let refresh = roblox_tick % 20 == 0;
                // File/process reads can stall. Never hold the snapshot lock
                // the Win32 thread needs while performing those reads.
                let refreshed_roblox = (refresh && !shared.roblox_edits.is_busy())
                    .then(|| read_roblox(&roblox_intent));

                let settings_warning = shared.settings_save_signal.warning();
                let settings_changed = settings_warning != last_settings_warning;
                last_settings_warning = settings_warning;
                let changed = shared
                    .edit(|s| {
                        let before = (
                            s.tunnel.clone(),
                            s.roblox.clone(),
                            s.driver.clone(),
                            s.free_tier_secs,
                            s.free_tier_spent,
                            s.lockout.clone(),
                        );

                        // A connect in flight owns the readout: the state
                        // watch still says Disconnected for the first second
                        // or two, and letting it overwrite "Connecting" makes
                        // the button flick.
                        if !shared.busy.is_busy() {
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
                        if let Some(fresh) = refreshed_roblox
                            && !shared.roblox_edits.is_busy()
                            && read_revision == shared.roblox_revision.load(Ordering::Acquire)
                        {
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
                                s.driver.clone(),
                                s.free_tier_secs,
                                s.free_tier_spent,
                                s.lockout.clone(),
                            )
                    })
                    .unwrap_or(false);

                // Elapsed session time and remaining allowance are part of
                // this comparison too. Notify for changed snapshots, without
                // a second timer rereading and repainting the same values.
                if changed || settings_changed {
                    shared.notify();
                }

                update_discord(&shared);
                maybe_reconnect(&shared);
            }
        })
        .map(|_| ())
        .map_err(|error| format!("Could not start the Lite state worker: {error}"))
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
    // Core writes failures as two paragraphs for a dialog, so a blank line is
    // the intended break.
    if let Some((head, rest)) = message.split_once("\n\n") {
        return (flatten(head), flatten(rest));
    }

    // The API's own messages arrive as one long paragraph, and the free-tier
    // one is the longest of them. Put the first sentence on the status line
    // and let the rest wrap, or the reader gets "...free SwiftTunnel time for
    // today, plu" and never learns it refills in a day.
    let flat = flatten(message);

    // What fits on the status line at this width. A head longer than this is
    // not shortened, it is cut, and the reader loses the end of a sentence
    // rather than the end of a paragraph.
    const FITS: usize = 46;

    if flat.chars().count() <= FITS {
        return (flat, String::new());
    }

    // Prefer the first sentence, when there is one and it fits.
    if let Some(at) = flat.find(". ")
        && flat[..=at].chars().count() <= FITS
    {
        let (head, rest) = flat.split_at(at + 1);
        return (head.trim().to_string(), rest.trim().to_string());
    }

    // Nothing short enough to lead with, so say the plain thing and let the
    // whole message wrap underneath, where there is room for it.
    ("Couldn't connect".to_string(), flat)
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
    if shared.busy.is_busy()
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

    if !shared
        .reconnect_backoff
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .due(Instant::now())
    {
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

    let Some(operation) = shared.busy.try_enter() else {
        return;
    };
    // A user action may have finished while the eligibility checks above ran.
    if shared.intentional_disconnect.load(Ordering::Relaxed) || !shared.connection_is_idle() {
        return;
    }
    log::info!("tunnel dropped on its own; reconnecting");
    shared.edit(|s| {
        s.tunnel.status = Status::Working;
        s.tunnel.detail = "Reconnecting".into();
    });
    shared.notify();

    let shared = shared.clone();
    shared.runtime.spawn({
        let shared = shared.clone();
        async move {
            let operation = operation;
            if let Err(error) = connect(&shared).await {
                shared
                    .reconnect_backoff
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .failed(Instant::now());
                shared.edit(|s| {
                    s.tunnel.status = Status::Error;
                    s.tunnel.detail = error;
                });
            }
            drop(operation);
            shared.notify();
        }
    });
}

/// What core's health check says about the split tunnel driver.
fn read_driver() -> Driver {
    driver_snapshot(SplitTunnelDriver::health_check())
}

fn driver_snapshot(health: SplitTunnelDriverHealth) -> Driver {
    Driver {
        ready: health.ready,
        status: if health.ready {
            "Installed and bound"
        } else if health.reboot_required {
            "Restart Windows to finish driver setup"
        } else {
            match health.status {
                DriverHealthStatus::Missing => "Use Reinstall driver below to install it",
                DriverHealthStatus::VersionTooOld => "Use Reinstall driver below to update it",
                DriverHealthStatus::NoAdapters => "Check your Wi-Fi or Ethernet connection",
                DriverHealthStatus::RebootRequired => "Restart Windows to finish driver setup",
                _ => "Use Reinstall driver below to repair it",
            }
        }
        .to_string(),
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

    // Retain account-action ordering through publication. A delayed refresh
    // must not overwrite a newer login/logout after releasing this lock.
    shared.edit(|s| {
        s.signed_in = signed_in;
        s.email = email;
        s.lockout = lockout_of(&auth_state, reason);
    });
}

/// Turn a core auth error into guidance for sign-in and connection attempts.
///
/// The raw Display of these leaks HTTP wording, and "error sending request for
/// url" is not a thing to tell somebody whose password was wrong.
fn friendly_auth_error(error: &swifttunnel_core::auth::AuthError) -> String {
    use swifttunnel_core::auth::AuthError;
    match error {
        AuthError::InvalidCredentials => "Wrong email or password.".to_string(),
        AuthError::NotAuthenticated | AuthError::RefreshTokenInvalid => {
            "Sign in to SwiftTunnel, then connect again.".to_string()
        }
        AuthError::ApiError(message) => message.clone(),
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

/// Full Country Ban only helps connections Roblox opens after the tunnel is
/// up: an already-running client keeps its login and game connections on the
/// blocked direct path. The full app refuses this connect; Lite now does too.
/// Only the Connect button checks it, not an automatic reconnect mid-game.
const FULL_BAN_ROBLOX_RUNNING: &str = "Close Roblox before connecting with Full Country Ban. Then connect SwiftTunnel and reopen Roblox so login and game traffic use the bypass.";

fn full_ban_connect_refusal(
    full_ban: bool,
    roblox_running: impl FnOnce() -> bool,
) -> Option<&'static str> {
    (full_ban && roblox_running()).then_some(FULL_BAN_ROBLOX_RUNNING)
}

/// The FramerateCap Lite writes. Lite keeps no unlock setting of its own: the
/// switch shows whether Roblox's cap is above 60, so switching it off has to
/// write 60. Passing `unlock_fps: false` instead tells core to leave the cap
/// alone, so Roblox kept the raised cap and the switch turned itself back on
/// after Apply.
fn frame_cap_to_write(unlock: bool, typed: Option<u32>) -> u32 {
    if unlock {
        typed.unwrap_or(DEFAULT_FRAME_CAP)
    } else {
        DEFAULT_FRAME_CAP
    }
}

/// Bypass and Auto contradict each other, so turning Bypass on turns Auto off,
/// as the full app does and as Route Assist already did here. Leaving both on
/// only lasted until the next launch, when loading the settings turned Auto
/// off without a word.
fn toggle_country_ban(settings: &mut AppSettings) {
    settings.enable_country_ban = !settings.enable_country_ban;
    if settings.enable_country_ban {
        settings.auto_routing_enabled = false;
    }
}

/// Lite's chips offer Auto, Low and Max, but a player may have picked any
/// level in Roblox's own menu. Both directions keep that level: collapsing 2..=9
/// to Automatic here made every Apply, even one that only changed the frame
/// cap, overwrite the player's graphics level with Automatic.
fn quality_of(level: u32) -> GraphicsQuality {
    if level > 10 {
        return GraphicsQuality::Automatic;
    }
    GraphicsQuality::from_level(level as i32)
}

/// Roblox stores the quality level as a number, so this is its own scale
/// rather than the enum the writer takes. 0 is automatic.
fn level_of(quality: i32) -> u32 {
    u32::try_from(quality)
        .ok()
        .filter(|level| *level <= 10)
        .unwrap_or(0)
}

/// Lite has no window-size control. Write back the size Roblox already has,
/// or every Apply reset the player's windowed size to the default.
fn keep_current_window_size(config: &mut RobloxSettingsConfig, current: Option<(u32, u32)>) {
    if let Some((width, height)) = current {
        config.window_width = width;
        config.window_height = height;
    }
}

/// Resolve the player's executable, close it, and wait before settings writes.
///
/// The same sequence the full app runs. Roblox reads its settings once at
/// launch, so a change made while it is open does nothing until it restarts.
fn close_roblox_for_changes(roblox: &RobloxOptimizer) -> Result<std::path::PathBuf, String> {
    let client = swifttunnel_core::roblox_native_launch::running_client()?.unwrap_or_default();
    let player = swifttunnel_core::roblox_native_launch::official_player_for(client)?;
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

    Ok(player)
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

const ADAPTER_SCAN_ERROR: &str = "Couldn't refresh network adapters. Reopen this picker to retry. If it keeps failing, restart SwiftTunnel.";

fn spawn_adapter_scan(
    gate: &OperationGate,
    scan: impl FnOnce() -> Result<Vec<AdapterRow>, String> + Send + 'static,
    publish: impl FnOnce(Result<Vec<AdapterRow>, String>) + Send + 'static,
    notify: impl FnOnce() + Send + 'static,
) -> std::io::Result<bool> {
    let Some(operation) = gate.try_enter() else {
        return Ok(false);
    };
    std::thread::Builder::new()
        .name("lite-adapters".into())
        .spawn(move || {
            publish(scan());
            drop(operation);
            notify();
        })?;
    Ok(true)
}

fn list_adapters() -> Result<Vec<AdapterRow>, String> {
    Ok(list_network_adapters()
        .map_err(|error| error.to_string())?
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
        .collect())
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
            self.shared.edit(|s| {
                s.uninstall_note =
                    Some("Use Windows Settings > Apps to select the installation to remove.".into())
            });
            return;
        };
        let Some(operation) = self.shared.busy.try_enter() else {
            self.shared.edit(|s| {
                s.uninstall_note =
                    Some("Wait for the current operation to finish, then retry uninstall.".into())
            });
            return;
        };
        let product_code = product_code.clone();
        self.shared
            .intentional_disconnect
            .store(true, Ordering::SeqCst);
        self.shared.edit(|s| {
            s.uninstall_busy = true;
            s.uninstall_note = Some("Disconnecting safely before uninstall...".into());
        });
        let shared = self.shared.clone();
        shared.runtime.spawn({
            let shared = shared.clone();
            async move {
                let operation = operation;
                let result = crate::operation_gate::after_disconnect(
                    async {
                        shared.vpn.lock().await.disconnect().await.map_err(|_| {
                            "Could not disconnect safely. Retry disconnecting before uninstalling."
                                .to_string()
                        })
                    },
                    move || crate::uninstall::start(&product_code),
                )
                .await;
                shared.edit(|s| {
                    s.uninstall_busy = false;
                    s.uninstall_note = Some(match result {
                        Ok(()) => "Windows Installer has opened. Follow its prompts to finish uninstalling.".into(),
                        Err(error) => error,
                    });
                });
                drop(operation);
                shared.notify();
            }
        });
        self.fill(state);
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
    let _ = swifttunnel_core::hidden_command("explorer")
        .arg(format!("/select,{}", path.display()))
        .spawn();
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_FRAME_CAP, FULL_BAN_ROBLOX_RUNNING, frame_cap_to_write, full_ban_connect_refusal,
        keep_current_window_size, level_of, quality_of, toggle_country_ban,
    };
    use swifttunnel_core::settings::AppSettings;
    use swifttunnel_core::structs::{GraphicsQuality, RobloxSettingsConfig};

    #[test]
    fn deferred_update_checks_come_back_soon_and_completed_ones_wait() {
        use super::{UpdatePass, update_retry_after};
        let deferred = update_retry_after(UpdatePass::Deferred);
        let interrupted = update_retry_after(UpdatePass::Interrupted);
        let failed = update_retry_after(UpdatePass::Failed);
        let checked = update_retry_after(UpdatePass::Checked);
        assert!(deferred.as_secs() <= 60);
        assert!(deferred < interrupted && interrupted < failed && failed < checked);
        assert_eq!(checked.as_secs(), 6 * 60 * 60);
    }

    #[test]
    fn failed_automatic_reconnects_back_off_up_to_two_minutes() {
        use super::ReconnectBackoff;
        use std::time::Instant;
        let start = Instant::now();
        let mut backoff = ReconnectBackoff::default();
        assert!(backoff.due(start));
        let mut delays = Vec::new();
        for _ in 0..8 {
            backoff.failed(start);
            let next = backoff.next_attempt.unwrap();
            assert!(!backoff.due(start));
            assert!(backoff.due(next));
            delays.push((next - start).as_secs());
        }
        assert_eq!(delays, [5, 10, 20, 40, 80, 120, 120, 120]);
        backoff.reset();
        assert!(backoff.due(start));
        assert_eq!(backoff.failures, 0);
    }

    #[test]
    fn full_ban_connect_is_refused_only_while_roblox_runs() {
        assert_eq!(
            full_ban_connect_refusal(true, || true),
            Some(FULL_BAN_ROBLOX_RUNNING)
        );
        assert_eq!(full_ban_connect_refusal(true, || false), None);
        // Without Full Country Ban the process check is not even made.
        assert_eq!(
            full_ban_connect_refusal(false, || panic!("checked Roblox")),
            None
        );
    }

    #[test]
    fn switching_unlock_off_writes_the_default_cap() {
        assert_eq!(frame_cap_to_write(false, Some(240)), DEFAULT_FRAME_CAP);
        assert_eq!(frame_cap_to_write(true, Some(240)), 240);
        assert_eq!(frame_cap_to_write(true, None), DEFAULT_FRAME_CAP);
        let config = RobloxSettingsConfig {
            unlock_fps: true,
            target_fps: frame_cap_to_write(false, Some(240)),
            ..RobloxSettingsConfig::default()
        };
        assert_eq!(
            config.checked_frame_cap(),
            Ok(Some(DEFAULT_FRAME_CAP as i32))
        );
    }

    #[test]
    fn enabling_country_ban_bypass_turns_auto_routing_off() {
        let mut settings = AppSettings {
            auto_routing_enabled: true,
            ..AppSettings::default()
        };
        toggle_country_ban(&mut settings);
        assert!(settings.enable_country_ban);
        assert!(!settings.auto_routing_enabled);
        toggle_country_ban(&mut settings);
        assert!(!settings.enable_country_ban);
        assert!(!settings.auto_routing_enabled);
    }

    #[test]
    fn every_roblox_quality_level_survives_a_read_and_apply() {
        for level in 0..=10 {
            assert_eq!(level_of(quality_of(level).to_level()), level, "{level}");
        }
        assert_eq!(quality_of(11), GraphicsQuality::Automatic);
        assert_eq!(level_of(-1), 0);
        assert_eq!(level_of(21), 0);
    }

    #[test]
    fn applying_keeps_the_window_size_roblox_already_has() {
        let mut config = RobloxSettingsConfig::default();
        keep_current_window_size(&mut config, Some((1600, 900)));
        assert_eq!((config.window_width, config.window_height), (1600, 900));
        let defaults = RobloxSettingsConfig::default();
        let mut unknown = defaults.clone();
        keep_current_window_size(&mut unknown, None);
        assert_eq!(unknown, defaults);
    }

    #[tokio::test]
    async fn automatic_download_is_not_polled_while_busy_and_a_new_game_drops_active_work() {
        use super::*;
        use std::sync::atomic::AtomicUsize;
        let called = AtomicUsize::new(0);
        let result = download_while_idle(
            async {
                called.fetch_add(1, Ordering::Relaxed);
            },
            || false,
            Duration::from_millis(10),
        )
        .await;
        assert!(result.is_none());
        assert_eq!(called.load(Ordering::Relaxed), 0);

        struct DropSignal(Arc<AtomicBool>);
        impl Drop for DropSignal {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }
        let allowed = Arc::new(AtomicBool::new(true));
        let dropped = Arc::new(AtomicBool::new(false));
        let (started, ready) = tokio::sync::oneshot::channel();
        let gate = allowed.clone();
        let signal = dropped.clone();
        let owner = tokio::spawn(async move {
            download_while_idle(
                async move {
                    let _signal = DropSignal(signal);
                    let _ = started.send(());
                    std::future::pending::<()>().await;
                },
                || gate.load(Ordering::Acquire),
                Duration::from_millis(10),
            )
            .await
        });
        tokio::time::timeout(Duration::from_secs(2), ready)
            .await
            .unwrap()
            .unwrap();
        allowed.store(false, Ordering::Release);
        assert!(
            tokio::time::timeout(Duration::from_secs(2), owner)
                .await
                .unwrap()
                .unwrap()
                .is_none()
        );
        assert!(
            dropped.load(Ordering::Acquire),
            "the download future must not remain detached"
        );
        assert_eq!(
            download_while_idle(
                async { Ok::<_, &str>("verified") },
                || true,
                Duration::from_millis(10)
            )
            .await,
            Some(Ok("verified"))
        );
        assert_eq!(
            download_while_idle(
                async { Err::<(), _>("signature mismatch") },
                || true,
                Duration::from_millis(10)
            )
            .await,
            Some(Err("signature mismatch"))
        );
    }

    #[test]
    fn adapter_scans_hold_one_reservation_through_publication_and_allow_retry() {
        use super::*;
        use std::sync::mpsc;
        let gate = OperationGate::default();
        let (started, waiting) = mpsc::channel();
        let (release, resume) = mpsc::channel();
        let (published, result) = mpsc::channel();
        let (finished, done) = mpsc::channel();
        assert!(
            spawn_adapter_scan(
                &gate,
                move || {
                    started.send(()).unwrap();
                    resume.recv_timeout(Duration::from_secs(3)).unwrap();
                    Err("private scan failure".into())
                },
                move |value| {
                    published.send(value).unwrap();
                },
                move || {
                    finished.send(()).unwrap();
                }
            )
            .unwrap()
        );
        waiting.recv_timeout(Duration::from_secs(2)).unwrap();
        let duplicate = spawn_adapter_scan(
            &gate,
            || panic!("duplicate scan"),
            |_| panic!("duplicate publication"),
            || panic!("duplicate completion"),
        )
        .unwrap();
        release.send(()).unwrap();
        assert!(
            result
                .recv_timeout(Duration::from_secs(2))
                .unwrap()
                .is_err()
        );
        done.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(!duplicate);
        assert!(!gate.is_busy());
        let (finished, done) = mpsc::channel();
        assert!(
            spawn_adapter_scan(
                &gate,
                || Ok(vec![]),
                |value| assert!(value.unwrap().is_empty()),
                move || {
                    finished.send(()).unwrap();
                }
            )
            .unwrap()
        );
        done.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(!gate.is_busy());
    }

    #[test]
    fn startup_setup_publishes_only_success_and_releases_settings_during_windows_work() {
        use super::*;
        let settings = RwLock::new(AppSettings::default());
        let before = settings.read().unwrap().run_on_startup;
        let requested = !before;
        let error = apply_startup_preference(&settings, requested, |enabled| {
            assert_eq!(enabled, requested);
            let mut concurrent = settings
                .try_write()
                .expect("Windows work must not hold the UI's settings lock");
            concurrent.minimize_to_tray = false;
            Err("private Windows registration failure".into())
        })
        .unwrap_err();
        assert!(error.contains("registration failure"));
        assert_eq!(settings.read().unwrap().run_on_startup, before);
        apply_startup_preference(&settings, requested, |enabled| {
            assert_eq!(enabled, requested);
            assert!(settings.try_write().is_ok());
            Ok(())
        })
        .unwrap();
        let published = settings.read().unwrap();
        assert_eq!(published.run_on_startup, requested);
        assert!(
            !published.minimize_to_tray,
            "preserve unrelated edits made during Windows work"
        );
    }

    #[test]
    fn driver_health_diagnostics_are_not_used_as_settings_copy() {
        use swifttunnel_core::vpn::{
            DriverHealthStatus, DriverRecommendedAction, SplitTunnelDriverHealth,
        };
        let health = SplitTunnelDriverHealth {
            installed: false,
            ready: false,
            status: DriverHealthStatus::Missing,
            message: "failed to open \\\\.\\NDISRD: 0x80070002".into(),
            version: None,
            reboot_required: false,
            recommended_action: DriverRecommendedAction::Install,
        };
        let missing = super::driver_snapshot(health.clone());
        assert!(!missing.ready);
        assert!(missing.status.contains("Reinstall driver"));
        assert!(!missing.status.contains("NDISRD"));
        assert!(!missing.status.contains("0x"));
        let reboot = super::driver_snapshot(SplitTunnelDriverHealth {
            reboot_required: true,
            ..health
        });
        assert!(reboot.status.contains("Restart Windows"));
    }

    use super::split_message;

    #[test]
    fn quit_waits_for_cleanup_without_blocking_the_requesting_thread() {
        use std::sync::mpsc;
        use std::time::Duration;
        let (started, ready) = mpsc::channel();
        let (release, resume) = mpsc::channel();
        let (notify, notified) = mpsc::channel();
        let worker = super::spawn_exit_cleanup(
            move || {
                started.send(()).unwrap();
                resume.recv_timeout(Duration::from_secs(3)).unwrap();
                Ok(())
            },
            move |success| {
                notify.send(success).unwrap();
            },
        )
        .unwrap();
        ready.recv_timeout(Duration::from_secs(2)).unwrap();
        let before_cleanup = notified.try_recv();
        release.send(()).unwrap();
        let after_cleanup = notified.recv_timeout(Duration::from_secs(2));
        worker.join().unwrap();
        assert!(
            before_cleanup.is_err(),
            "must not destroy the window during cleanup"
        );
        assert!(after_cleanup.unwrap());
    }

    #[test]
    fn failed_or_panicking_quit_cleanup_never_requests_window_destruction() {
        use std::sync::mpsc;
        for panic in [false, true] {
            let (notify, notified) = mpsc::channel();
            let worker = super::spawn_exit_cleanup(
                move || {
                    if panic {
                        panic!("owned simulated cleanup failure");
                    }
                    Err("cleanup failed".into())
                },
                move |success| {
                    notify.send(success).unwrap();
                },
            )
            .unwrap();
            worker.join().unwrap();
            assert!(!notified.recv().unwrap());
        }
    }

    #[test]
    fn picker_wait_pauses_during_play_and_wakes_on_exit_or_shutdown() {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
            mpsc,
        };
        use std::time::Duration;
        for shutdown in [false, true] {
            let stop = Arc::new(AtomicBool::new(false));
            let game = Arc::new(AtomicBool::new(true));
            let (checks, checked) = mpsc::sync_channel(1);
            let (done, finished) = mpsc::channel();
            let worker_stop = stop.clone();
            let worker_game = game.clone();
            let worker = std::thread::spawn(move || {
                done.send(super::wait_for_picker_round(
                    &worker_stop,
                    || {
                        let running = worker_game.load(Ordering::SeqCst);
                        let _ = checks.try_send(running);
                        running
                    },
                    Duration::from_secs(30),
                ))
                .unwrap();
            });
            assert!(checked.recv_timeout(Duration::from_secs(2)).unwrap());
            assert!(finished.try_recv().is_err(), "no picker round during play");
            if shutdown {
                stop.store(true, Ordering::SeqCst);
            } else {
                game.store(false, Ordering::SeqCst);
            }
            let result = finished.recv_timeout(Duration::from_secs(2));
            // Always retire an owned worker before asserting the deadline.
            stop.store(true, Ordering::SeqCst);
            worker.join().unwrap();
            assert_eq!(result.unwrap(), !shutdown);
        }
    }

    #[test]
    fn a_game_opening_during_the_idle_wait_does_not_leave_a_thirty_second_delay_after_exit() {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
            mpsc,
        };
        use std::time::Duration;
        let stop = Arc::new(AtomicBool::new(false));
        let game = Arc::new(AtomicBool::new(false));
        let (checks, checked) = mpsc::channel();
        let (done, finished) = mpsc::channel();
        let worker_stop = stop.clone();
        let worker_game = game.clone();
        let worker = std::thread::spawn(move || {
            let result = super::wait_for_picker_round(
                &worker_stop,
                || {
                    let running = worker_game.load(Ordering::SeqCst);
                    let _ = checks.send(running);
                    running
                },
                Duration::from_secs(30),
            );
            let _ = done.send(result);
        });
        assert!(!checked.recv_timeout(Duration::from_secs(2)).unwrap());
        game.store(true, Ordering::SeqCst);
        while !checked.recv_timeout(Duration::from_secs(2)).unwrap() {}
        game.store(false, Ordering::SeqCst);
        let result = finished.recv_timeout(Duration::from_secs(2));
        stop.store(true, Ordering::SeqCst);
        worker.join().unwrap();
        assert!(result.unwrap());
    }

    #[test]
    fn malformed_server_responses_are_not_reported_as_wrong_passwords() {
        use swifttunnel_core::auth::AuthError;
        assert_eq!(
            super::friendly_auth_error(&AuthError::InvalidCredentials),
            "Wrong email or password."
        );
        assert_eq!(
            super::friendly_auth_error(&AuthError::ApiError(
                "Invalid authentication response".into()
            )),
            "Invalid authentication response"
        );
        assert_eq!(
            super::friendly_auth_error(&AuthError::NetworkError("connection timed out".into())),
            "Could not reach SwiftTunnel. Check your connection."
        );
        assert_eq!(
            super::friendly_auth_error(&AuthError::RateLimited(67)),
            "Too many attempts. Try again in 67s."
        );
        assert!(super::friendly_auth_error(&AuthError::RefreshTokenInvalid).contains("Sign in"));
        assert!(super::friendly_auth_error(&AuthError::NotAuthenticated).contains("Sign in"));
    }

    #[test]
    fn region_picker_accepts_new_locations_and_removes_withdrawn_ones() {
        use super::{DynamicServerList, ServerListSource, region_rows, servers};
        let mut list = DynamicServerList::new_empty();
        let mut relays = Vec::new();
        let mut regions = Vec::new();
        for (id, name, country) in [("jakarta", "Jakarta", "id"), ("israel", "Israel", "il")] {
            let relay = format!("{id}-99");
            relays.push(
                serde_json::from_value(serde_json::json!({
                    "region": relay, "name": name, "country_code": country,
                    "ip": "192.0.2.1", "port": 51820, "phantun_available": false,
                    "relay_available": true
                }))
                .unwrap(),
            );
            regions.push(servers::DynamicGamingRegion {
                id: id.into(),
                name: name.into(),
                description: String::new(),
                country_code: country.into(),
                servers: vec![relay],
            });
        }
        list.update(relays, regions.clone(), ServerListSource::Api);
        let rows = region_rows(&list);
        assert_eq!(
            rows.iter()
                .map(|r| (r.name.as_str(), r.country.as_str()))
                .collect::<Vec<_>>(),
            vec![("Jakarta", "ID"), ("Israel", "IL")]
        );
        let mut remaining = list.servers.clone();
        remaining[0].relay_available = false;
        list.update(remaining, regions, ServerListSource::Api);
        assert_eq!(region_rows(&list).len(), 1);
        list.update(vec![], vec![], ServerListSource::Api);
        assert!(region_rows(&list).is_empty());
    }

    // The status line is one line and it clips. Every case below is really the
    // same assertion: whatever lands there has to fit, and nothing the reader
    // needs may be dropped on the way.
    const FITS: usize = 46;

    #[test]
    fn keeps_the_paragraph_break_core_intended() {
        let (head, hint) = split_message("Couldn't connect.\n\nCheck your adapter.");
        assert_eq!(head, "Couldn't connect.");
        assert_eq!(hint, "Check your adapter.");
    }

    #[test]
    fn short_message_stays_whole() {
        let (head, hint) = split_message("Adapter is offline.");
        assert_eq!(head, "Adapter is offline.");
        assert!(hint.is_empty());
    }

    #[test]
    fn leads_with_the_first_sentence_when_it_fits() {
        let (head, hint) = split_message(
            "Connection refused. The relay is at capacity right now, so try another region.",
        );
        assert_eq!(head, "Connection refused.");
        assert!(hint.starts_with("The relay is at capacity"));
    }

    #[test]
    fn long_first_sentence_is_not_cut_onto_the_status_line() {
        // The real free-tier body. Its first sentence is 85 characters, so
        // leading with it clipped at "...time for today, plu" and the reader
        // never learned the allowance refills.
        let body = "You've used your 3 hours of free SwiftTunnel time for today, plus \
                    the extra 20 minutes. It refills in about 24 hours.";
        let (head, hint) = split_message(body);
        assert_eq!(head, "Couldn't connect");
        assert!(hint.contains("refills in about 24 hours"));
        assert!(hint.contains("3 hours of free"));
    }

    #[test]
    fn nothing_ever_overflows_the_status_line() {
        let cases = [
            "Couldn't connect.\n\nCheck your adapter.",
            "Adapter is offline.",
            "Connection refused. The relay is at capacity, so try another region.",
            "You've used your 3 hours of free SwiftTunnel time for today, plus the \
             extra 20 minutes. It refills in about 24 hours.",
            "A single sentence with no full stop that runs well past the width of the line",
        ];
        for case in cases {
            let (head, _) = split_message(case);
            assert!(
                head.chars().count() <= FITS,
                "head of {head:?} is {} chars",
                head.chars().count()
            );
        }
    }

    #[test]
    fn collapses_the_newlines_core_wraps_at() {
        let (head, _) = split_message("Adapter\nis\noffline.");
        assert_eq!(head, "Adapter is offline.");
    }
}
