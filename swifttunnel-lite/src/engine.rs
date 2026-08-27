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
use swifttunnel_core::auth::{AuthManager, update_required_message};
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
use swifttunnel_core::vpn::{ConnectionState, VpnConnection};

use crate::state::{AdapterRow, Lockout, RegionRow, Roblox, State, Status, Tunnel};
use crate::view::{Action, Flag};

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
    lockout: Option<Lockout>,
    tunnel: Tunnel,
    email: Option<String>,
    signed_in: bool,
    free_tier_secs: Option<u32>,
}

struct Shared {
    runtime: tokio::runtime::Runtime,
    auth: Arc<tokio::sync::Mutex<AuthManager>>,
    vpn: Arc<tokio::sync::Mutex<VpnConnection>>,
    settings: RwLock<AppSettings>,
    snapshot: RwLock<Snapshot>,
    /// Set once the window exists. Stored as an isize because HWND is not Send.
    hwnd: AtomicIsize,
    stop: AtomicBool,
    /// Guards against a second connect being started while one is in flight.
    busy: AtomicBool,
}

impl Shared {
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
        let ultraboost = loaded.config.roblox_settings.ultraboost;

        let shared = Arc::new(Shared {
            runtime,
            auth: Arc::new(tokio::sync::Mutex::new(auth)),
            vpn: Arc::new(tokio::sync::Mutex::new(VpnConnection::new())),
            settings: RwLock::new(loaded),
            snapshot: RwLock::new(Snapshot {
                signed_in,
                email,
                roblox: read_roblox(ultraboost),
                lockout: lockout_of(&auth_state, banned_reason.clone()),
                server_list: DynamicServerList::new_empty(),
                regions: Vec::new(),
                adapters: Vec::new(),
                tunnel: Tunnel::default(),
                free_tier_secs: None,
            }),
            hwnd: AtomicIsize::new(0),
            stop: AtomicBool::new(false),
            busy: AtomicBool::new(false),
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
            state.tunnel = snapshot.tunnel.clone();
            state.email = snapshot.email.clone();
            state.signed_in = snapshot.signed_in;
            state.free_tier_secs = snapshot.free_tier_secs;
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

            Action::Toggle(flag) => self.toggle(flag),
            Action::SetFps(fps) => self.patch_roblox(move |c| {
                c.unlock_fps = fps > DEFAULT_FRAME_CAP;
                c.target_fps = fps;
            }),
            Action::SetQuality(level) => self.patch_roblox(move |c| {
                c.graphics_quality = quality_of(level);
            }),
            Action::RestartRoblox => {
                let shared = self.shared.clone();
                std::thread::spawn(move || {
                    let error = restart_roblox().err();
                    shared.edit(|s| s.roblox.error = error);
                    shared.notify();
                });
            }

            Action::SignOut => {
                let shared = self.shared.clone();
                shared.runtime.spawn({
                    let shared = shared.clone();
                    async move {
                        let auth = shared.auth.lock().await;
                        let _ = auth.logout();
                        drop(auth);
                        shared.edit(|s| {
                            s.signed_in = false;
                            s.email = None;
                        });
                        shared.notify();
                    }
                });
            }
            Action::SignIn => {
                // Signing in needs a browser round trip and a form. Rather
                // than build a second login UI, Lite hands off to the full
                // app's, which both clients already share a session file with.
                let shared = self.shared.clone();
                shared.runtime.spawn({
                    let shared = shared.clone();
                    async move {
                        let url = {
                            let auth = shared.auth.lock().await;
                            auth.start_google_sign_in().ok()
                        };
                        if let Some(url) = url {
                            open_in_browser(&url);
                        }
                    }
                });
            }

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
        if self.shared.busy.load(Ordering::Relaxed) || state.lockout.is_some() {
            return;
        }
        let connected = state.tunnel.status == Status::Connected;
        let shared = self.shared.clone();
        shared.busy.store(true, Ordering::Relaxed);

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

    fn toggle(&self, flag: Flag) {
        match flag {
            Flag::RouteAssist => self.settings(|s| s.enable_api_tunneling = !s.enable_api_tunneling),
            Flag::CountryBan => self.settings(|s| s.enable_country_ban = !s.enable_country_ban),
            Flag::RunOnStartup => self.settings(|s| s.run_on_startup = !s.run_on_startup),
            Flag::CloseToTray => self.settings(|s| s.minimize_to_tray = !s.minimize_to_tray),
            Flag::AutoReconnect => self.settings(|s| s.auto_reconnect = !s.auto_reconnect),

            Flag::UnlockFps => {
                let on = !self.snapshot_roblox().unlock_fps;
                self.patch_roblox(move |c| {
                    c.unlock_fps = on;
                    // Restoring the cap has to write the default back, or
                    // Roblox keeps running at whatever it was raised to.
                    if !on {
                        c.target_fps = DEFAULT_FRAME_CAP;
                    } else if c.target_fps <= DEFAULT_FRAME_CAP {
                        c.target_fps = 240;
                    }
                });
            }
            Flag::Ultraboost => {
                let on = !self.snapshot_roblox().ultraboost;
                self.patch_roblox(move |c| c.ultraboost = on);
            }
            Flag::Fullscreen => {
                let on = !self.snapshot_roblox().fullscreen;
                self.patch_roblox(move |c| c.window_fullscreen = on);
            }
        }
    }

    fn snapshot_roblox(&self) -> Roblox {
        self.shared
            .snapshot
            .read()
            .map(|s| s.roblox.clone())
            .unwrap_or_default()
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

    /// Write one Roblox setting through core and re-read what landed.
    ///
    /// Goes through `apply_optimizations` rather than editing the file
    /// directly, because that function owns the format, the permissions repair
    /// and the backup taken before the first change, none of which is worth a
    /// second implementation.
    fn patch_roblox(&self, edit: impl FnOnce(&mut RobloxSettingsConfig) + Send + 'static) {
        let shared = self.shared.clone();
        std::thread::spawn(move || {
            let optimizer = RobloxOptimizer::new();
            if !optimizer.is_roblox_installed() {
                shared.edit(|s| s.roblox.error = Some("Roblox is not installed.".into()));
                shared.notify();
                return;
            }

            let ultraboost_now = shared
                .settings
                .read()
                .map(|s| s.config.roblox_settings.ultraboost)
                .unwrap_or(false);
            let mut config = current_roblox_config(ultraboost_now);
            edit(&mut config);

            // Ultraboost is FFlags rather than a Roblox setting, so
            // nothing can read it back off disk. The intent is kept in
            // the shared settings file, where the full app keeps it too.
            if config.ultraboost != ultraboost_now {
                if let Ok(mut guard) = shared.settings.write() {
                    guard.config.roblox_settings.ultraboost = config.ultraboost;
                    let snapshot = guard.clone();
                    drop(guard);
                    let _ = settings::save_settings(&snapshot);
                }
            }

            let error = optimizer
                .apply_optimizations(&config)
                .err()
                .map(|e| e.to_string());

            let ultraboost = shared
                .settings
                .read()
                .map(|s| s.config.roblox_settings.ultraboost)
                .unwrap_or(config.ultraboost);
            shared.edit(|s| {
                s.roblox = read_roblox(ultraboost);
                s.roblox.error = error;
            });
            shared.notify();
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
                        tunnel.detail = message.clone();
                    }
                    ConnectionState::Connected {
                        since: started,
                        server_region,
                        ..
                    } => {
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

                let free_tier = match free_tier_grace_seconds() {
                    Some(grace) => Some(grace.max(0) as u32),
                    None => free_tier_quota().0.map(|left| left.max(0) as u32),
                };

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
                        if let Some(locked) = locked.clone() {
                            s.lockout = Some(locked);
                        }
                        s.roblox.running = running;
                        if refresh {
                            let fresh = read_roblox(s.roblox.ultraboost);
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
            }
        })
        .expect("poller thread");
}

// ── Reading the machine ─────────────────────────────────────────────────────

/// A ban is a lockout; an outdated build is decided separately, by the API.
fn lockout_of(state: &AuthState, banned_reason: Option<String>) -> Option<Lockout> {
    if let Some(message) = update_required_message() {
        return Some(Lockout::UpdateRequired(message));
    }
    match state {
        AuthState::Banned(_) => Some(Lockout::Banned(banned_reason.unwrap_or_default())),
        _ => None,
    }
}

fn describe(state: &ConnectionState) -> String {
    match state {
        ConnectionState::FetchingConfig => "Resolving relay".into(),
        ConnectionState::ConfiguringSplitTunnel => "Configuring split tunnel".into(),
        _ => "Connecting".into(),
    }
}

fn current_roblox_config(ultraboost: bool) -> RobloxSettingsConfig {
    let current = read_roblox(ultraboost);
    RobloxSettingsConfig {
        unlock_fps: current.unlock_fps,
        target_fps: current.target_fps,
        graphics_quality: quality_of(current.quality),
        ultraboost: current.ultraboost,
        window_fullscreen: current.fullscreen,
        ..RobloxSettingsConfig::default()
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
fn read_roblox(ultraboost: bool) -> Roblox {
    let optimizer = RobloxOptimizer::new();
    let installed = optimizer.is_roblox_installed();
    let running = optimizer.is_roblox_running();

    let Ok(current) = optimizer.read_current_settings() else {
        return Roblox {
            installed,
            running,
            ultraboost,
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
        ultraboost,
        fullscreen: current.fullscreen,
        error: None,
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

fn open_in_browser(url: &str) {
    let _ = std::process::Command::new("cmd")
        .args(["/C", "start", "", url])
        .spawn();
}
