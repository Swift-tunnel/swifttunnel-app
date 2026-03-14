use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};

use serde::Serialize;
use sysinfo::{Pid, ProcessesToUpdate, System};

use crate::commands::vpn::{
    build_binding_preflight, current_binding_preference, parse_game_presets,
};
use crate::state::AppState;
use swifttunnel_core::auth::AuthError;
use swifttunnel_core::settings::AdapterBindingMode;
use swifttunnel_core::vpn::BindingPreflightInfo;

const DEFAULT_REGION: &str = "singapore";
const DEFAULT_CONNECT_WAIT_MS: u64 = 3_000;
const SHELL_MONITOR_INTERVAL_MS: u64 = 50;

#[derive(Debug, Default)]
struct HarnessCli {
    report_path: Option<PathBuf>,
    region: Option<String>,
    adapter_guid: Option<String>,
    token: Option<String>,
    email: Option<String>,
    password: Option<String>,
    custom_relay_server: Option<String>,
    enable_api_tunneling: bool,
    connect: bool,
    connect_wait_ms: u64,
    game_presets: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
enum AuthSource {
    ProvidedToken,
    StoredSession,
    Credentials,
    None,
}

#[derive(Debug, Clone, Serialize)]
struct AuthSummary {
    logged_in_before: bool,
    logged_in_after: bool,
    refreshed_profile: bool,
    refresh_error: Option<String>,
    source: AuthSource,
}

#[derive(Debug, Clone, Serialize)]
struct ServerListSummary {
    server_count: usize,
    region_count: usize,
    source: String,
}

#[derive(Debug, Clone, Serialize)]
struct BindingPreflightSummary {
    status: String,
    reason: String,
    network_signature: String,
    recommended_guid: Option<String>,
    cached_override_used: bool,
    candidate_count: usize,
}

#[derive(Debug, Clone, Serialize)]
struct DiagnosticsSummary {
    adapter_name: Option<String>,
    adapter_guid: Option<String>,
    selected_if_index: Option<u32>,
    resolved_if_index: Option<u32>,
    binding_reason: String,
    binding_stage: String,
    packets_tunneled: u64,
    packets_bypassed: u64,
    last_validation_result: String,
}

#[derive(Debug, Clone, Serialize)]
struct ThroughputSummary {
    bytes_up: u64,
    bytes_down: u64,
}

#[derive(Debug, Clone, Serialize)]
struct ConnectSummary {
    requested_region: String,
    game_presets: Vec<String>,
    connected_region: Option<String>,
    server_endpoint: Option<String>,
    assigned_ip: Option<String>,
    relay_auth_mode: Option<String>,
    split_tunnel_active: bool,
    tunneled_processes: Vec<String>,
    diagnostics: Option<DiagnosticsSummary>,
    throughput: Option<ThroughputSummary>,
    disconnected: bool,
}

#[derive(Debug, Clone, Serialize)]
struct ObservedShellProcess {
    pid: u32,
    parent_pid: Option<u32>,
    name: String,
    first_seen_ms: u128,
}

#[derive(Debug, Clone, Serialize)]
struct ShellMonitorSummary {
    spawned_shells: Vec<ObservedShellProcess>,
    console_host_seen: bool,
}

#[derive(Debug, Clone, Serialize)]
struct HarnessTimings {
    total_ms: u128,
}

#[derive(Debug, Clone, Serialize)]
pub struct HarnessReport {
    version: String,
    pid: u32,
    is_admin: bool,
    driver_available: bool,
    adapter_count: usize,
    timings: HarnessTimings,
    server_list: Option<ServerListSummary>,
    auth: AuthSummary,
    binding_preflight: Option<BindingPreflightSummary>,
    connect: Option<ConnectSummary>,
    shell_monitor: ShellMonitorSummary,
    errors: Vec<String>,
    success: bool,
}

struct ShellMonitorHandle {
    stop: Arc<AtomicBool>,
    join: thread::JoinHandle<Vec<ObservedShellProcess>>,
}

impl ShellMonitorHandle {
    fn start(root_pid: u32) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let stop_flag = Arc::clone(&stop);

        let join = thread::spawn(move || {
            let root_pid = Pid::from_u32(root_pid);
            let started = Instant::now();
            let mut system = System::new();
            let mut seen = BTreeMap::<u32, ObservedShellProcess>::new();

            loop {
                system.refresh_processes(ProcessesToUpdate::All, true);

                for (pid, process) in system.processes() {
                    let name = process.name().to_string_lossy().to_ascii_lowercase();
                    if !is_shell_process(&name) || !is_descendant_process(&system, *pid, root_pid) {
                        continue;
                    }

                    seen.entry(pid.as_u32())
                        .or_insert_with(|| ObservedShellProcess {
                            pid: pid.as_u32(),
                            parent_pid: process.parent().map(|value| value.as_u32()),
                            name,
                            first_seen_ms: started.elapsed().as_millis(),
                        });
                }

                if stop_flag.load(Ordering::Relaxed) {
                    break;
                }

                thread::sleep(Duration::from_millis(SHELL_MONITOR_INTERVAL_MS));
            }

            seen.into_values().collect()
        });

        Self { stop, join }
    }

    fn stop(self) -> Vec<ObservedShellProcess> {
        self.stop.store(true, Ordering::Relaxed);
        self.join.join().unwrap_or_default()
    }
}

pub fn run_testbench_harness(raw_args: &[String]) -> i32 {
    if let Err(err) = init_logging() {
        eprintln!("Failed to initialize harness logging: {err}");
    }

    let cli = match parse_cli(raw_args) {
        Ok(cli) => cli,
        Err(ParseOutcome::Help) => {
            print_help();
            return 0;
        }
        Err(ParseOutcome::Error(err)) => {
            eprintln!("{err}");
            eprintln!();
            print_help();
            return 2;
        }
    };

    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => Arc::new(runtime),
        Err(err) => {
            eprintln!("Failed to create Tokio runtime: {err}");
            return 1;
        }
    };

    let monitor = ShellMonitorHandle::start(std::process::id());
    let started = Instant::now();

    let harness_runtime = Arc::clone(&runtime);
    let mut report = runtime.block_on(run_harness(harness_runtime, &cli));
    let observed_shells = monitor.stop();

    let console_host_seen = observed_shells.iter().any(|process| {
        let name = process.name.as_str();
        name == "conhost.exe" || name == "conhost"
    });

    report.timings.total_ms = started.elapsed().as_millis();
    report.shell_monitor = ShellMonitorSummary {
        spawned_shells: observed_shells,
        console_host_seen,
    };

    if console_host_seen {
        report.errors.push(
            "Observed conhost.exe as a descendant process during harness execution".to_string(),
        );
    }

    report.success = report.errors.is_empty();

    let json = match serde_json::to_string_pretty(&report) {
        Ok(json) => json,
        Err(err) => {
            eprintln!("Failed to serialize harness report: {err}");
            return 1;
        }
    };

    println!("{json}");

    if let Some(path) = &cli.report_path {
        if let Err(err) = write_report(path, &json) {
            eprintln!(
                "Failed to write harness report to {}: {err}",
                path.display()
            );
            return 1;
        }
    }

    if report.success { 0 } else { 1 }
}

async fn run_harness(runtime: Arc<tokio::runtime::Runtime>, cli: &HarnessCli) -> HarnessReport {
    let mut errors = Vec::new();
    let mut server_list = None;
    let mut binding_preflight = None;
    let mut connect = None;

    swifttunnel_core::roblox_proxy::hosts::recover_stale();

    let state = match AppState::new(Arc::clone(&runtime)) {
        Ok(state) => state,
        Err(err) => {
            return HarnessReport {
                version: env!("CARGO_PKG_VERSION").to_string(),
                pid: std::process::id(),
                is_admin: swifttunnel_core::is_administrator(),
                driver_available: false,
                adapter_count: 0,
                timings: HarnessTimings { total_ms: 0 },
                server_list: None,
                auth: AuthSummary {
                    logged_in_before: false,
                    logged_in_after: false,
                    refreshed_profile: false,
                    refresh_error: None,
                    source: AuthSource::None,
                },
                binding_preflight: None,
                connect: None,
                shell_monitor: ShellMonitorSummary {
                    spawned_shells: Vec::new(),
                    console_host_seen: false,
                },
                errors: vec![format!("Failed to initialize app state: {err}")],
                success: false,
            };
        }
    };

    state.network_booster.lock().recover_from_snapshot();
    swifttunnel_core::vpn::recover_tso_on_startup();
    swifttunnel_core::vpn::recover_ipv6_on_startup();

    let auth = collect_auth_summary(&state, cli).await;

    match load_server_list_summary(&state).await {
        Ok(summary) => server_list = Some(summary),
        Err(err) => errors.push(err),
    }

    let adapter_count = match swifttunnel_core::vpn::list_network_adapters() {
        Ok(adapters) => adapters.len(),
        Err(err) => {
            errors.push(format!("Failed to list network adapters: {err}"));
            0
        }
    };

    let driver_available = swifttunnel_core::vpn::SplitTunnelDriver::is_available();

    match collect_binding_preflight(&state, cli) {
        Ok(preflight) => binding_preflight = Some(preflight),
        Err(err) => errors.push(err),
    }

    if cli.connect {
        match run_connect_flow(&state, cli).await {
            Ok(summary) => connect = Some(summary),
            Err(err) => errors.push(err),
        }
    }

    HarnessReport {
        version: env!("CARGO_PKG_VERSION").to_string(),
        pid: std::process::id(),
        is_admin: swifttunnel_core::is_administrator(),
        driver_available,
        adapter_count,
        timings: HarnessTimings { total_ms: 0 },
        server_list,
        auth,
        binding_preflight,
        connect,
        shell_monitor: ShellMonitorSummary {
            spawned_shells: Vec::new(),
            console_host_seen: false,
        },
        errors,
        success: false,
    }
}

async fn collect_auth_summary(state: &AppState, cli: &HarnessCli) -> AuthSummary {
    let auth = state.auth_manager.lock().await;
    let logged_in_before = auth.is_logged_in();
    let mut refreshed_profile = false;
    let mut refresh_error = None;

    if logged_in_before {
        match auth.refresh_profile().await {
            Ok(_) => refreshed_profile = true,
            Err(err) => refresh_error = Some(err.to_string()),
        }
    }

    let source = if cli.token.is_some() {
        AuthSource::ProvidedToken
    } else if logged_in_before {
        AuthSource::StoredSession
    } else if cli.email.is_some() && cli.password.is_some() {
        AuthSource::Credentials
    } else {
        AuthSource::None
    };

    let logged_in_after = auth.is_logged_in();
    drop(auth);

    AuthSummary {
        logged_in_before,
        logged_in_after,
        refreshed_profile,
        refresh_error,
        source,
    }
}

async fn load_server_list_summary(state: &AppState) -> Result<ServerListSummary, String> {
    let (servers, regions, source) = swifttunnel_core::vpn::servers::load_server_list()
        .await
        .map_err(|err| format!("Failed to load server list: {err}"))?;

    let server_count = servers.len();
    let region_count = regions.len();
    let source_label = source.to_string();

    {
        let mut server_list = state.server_list.lock();
        server_list.update(servers, regions, source);
    }

    Ok(ServerListSummary {
        server_count,
        region_count,
        source: source_label,
    })
}

fn collect_binding_preflight(
    state: &AppState,
    cli: &HarnessCli,
) -> Result<BindingPreflightSummary, String> {
    let mut settings = state.settings.lock();
    apply_adapter_override(&mut settings, cli);
    let preflight = build_binding_preflight(&mut settings)?;
    Ok(summarize_preflight(&preflight))
}

fn summarize_preflight(preflight: &BindingPreflightInfo) -> BindingPreflightSummary {
    BindingPreflightSummary {
        status: preflight.status.clone(),
        reason: preflight.reason.clone(),
        network_signature: preflight.network_signature.clone(),
        recommended_guid: preflight.recommended_guid.clone(),
        cached_override_used: preflight.cached_override_used,
        candidate_count: preflight.candidates.len(),
    }
}

fn apply_adapter_override(
    settings: &mut swifttunnel_core::settings::AppSettings,
    cli: &HarnessCli,
) {
    if let Some(guid) = &cli.adapter_guid {
        settings.adapter_binding_mode = AdapterBindingMode::Manual;
        settings.preferred_physical_adapter_guid = Some(guid.clone());
    }
}

async fn run_connect_flow(state: &AppState, cli: &HarnessCli) -> Result<ConnectSummary, String> {
    let requested_region = cli
        .region
        .clone()
        .or_else(|| state.settings.lock().last_connected_region.clone())
        .unwrap_or_else(|| DEFAULT_REGION.to_string());

    let (
        custom_relay,
        auto_routing,
        relay_qos_enabled,
        whitelisted_regions,
        forced_servers,
        binding_preference,
        game_process_performance,
        enable_api_tunneling,
    ) = {
        let mut settings = state.settings.lock();
        apply_adapter_override(&mut settings, cli);
        let preflight = build_binding_preflight(&mut settings)?;
        if preflight.status != "ok" {
            return Err(format!(
                "Binding preflight rejected connect attempt: {}",
                preflight.reason
            ));
        }

        let binding_preference = current_binding_preference(&mut settings)?;
        let snapshot = settings.clone();
        drop(settings);

        (
            cli.custom_relay_server.clone().or_else(|| {
                if snapshot.custom_relay_server.is_empty() {
                    None
                } else {
                    Some(snapshot.custom_relay_server.clone())
                }
            }),
            snapshot.auto_routing_enabled,
            snapshot.config.network_settings.gaming_qos,
            snapshot.whitelisted_regions.clone(),
            snapshot.forced_servers.clone(),
            binding_preference,
            snapshot.game_process_performance,
            cli.enable_api_tunneling || snapshot.enable_api_tunneling,
        )
    };

    let available_servers = {
        let server_list = state.server_list.lock();
        server_list
            .servers()
            .iter()
            .filter_map(|server| {
                let addr = format!("{}:{}", server.ip, 51821).parse().ok()?;
                let latency = server_list.get_latency(&server.region);
                Some((server.region.clone(), addr, latency))
            })
            .collect::<Vec<_>>()
    };

    if available_servers.is_empty() {
        return Err("Server list is empty, cannot run connect harness".to_string());
    }

    let access_token = resolve_access_token(state, cli).await?;
    let preset_set = parse_game_presets(&cli.game_presets);
    let tunnel_apps = swifttunnel_core::vpn::get_apps_for_preset_set(&preset_set);

    {
        let mut vpn = state.vpn_connection.lock().await;
        vpn.connect(
            &access_token,
            &requested_region,
            tunnel_apps,
            custom_relay,
            auto_routing,
            relay_qos_enabled,
            available_servers,
            whitelisted_regions,
            forced_servers,
            binding_preference,
            game_process_performance,
            enable_api_tunneling,
        )
        .await
        .map_err(|err| swifttunnel_core::vpn::user_friendly_error(&err))?;
    }

    tokio::time::sleep(Duration::from_millis(cli.connect_wait_ms)).await;

    let (
        connected_region,
        server_endpoint,
        assigned_ip,
        relay_auth_mode,
        split_tunnel_active,
        tunneled_processes,
    ) = {
        let vpn = state.vpn_connection.lock().await;
        match vpn.state().await {
            swifttunnel_core::vpn::ConnectionState::Connected {
                server_region,
                server_endpoint,
                assigned_ip,
                relay_auth_mode,
                split_tunnel_active,
                tunneled_processes,
                ..
            } => (
                Some(server_region),
                Some(server_endpoint),
                Some(assigned_ip),
                Some(relay_auth_mode),
                split_tunnel_active,
                tunneled_processes,
            ),
            other => {
                return Err(format!(
                    "Harness connect did not reach connected state: {:?}",
                    other
                ));
            }
        }
    };

    let diagnostics = {
        let vpn = state.vpn_connection.lock().await;
        vpn.get_split_tunnel_diagnostics()
            .map(|diag| DiagnosticsSummary {
                adapter_name: diag.adapter_name,
                adapter_guid: diag.adapter_guid,
                selected_if_index: diag.selected_if_index,
                resolved_if_index: diag.resolved_if_index,
                binding_reason: diag.binding_reason,
                binding_stage: diag.binding_stage,
                packets_tunneled: diag.packets_tunneled,
                packets_bypassed: diag.packets_bypassed,
                last_validation_result: diag.last_validation_result,
            })
    };

    let throughput = {
        let vpn = state.vpn_connection.lock().await;
        vpn.get_throughput_stats().map(|stats| ThroughputSummary {
            bytes_up: stats.get_bytes_tx(),
            bytes_down: stats.get_bytes_rx(),
        })
    };

    {
        let mut vpn = state.vpn_connection.lock().await;
        vpn.disconnect()
            .await
            .map_err(|err| swifttunnel_core::vpn::user_friendly_error(&err))?;
    }

    Ok(ConnectSummary {
        requested_region,
        game_presets: cli.game_presets.clone(),
        connected_region,
        server_endpoint,
        assigned_ip,
        relay_auth_mode,
        split_tunnel_active,
        tunneled_processes,
        diagnostics,
        throughput,
        disconnected: true,
    })
}

async fn resolve_access_token(state: &AppState, cli: &HarnessCli) -> Result<String, String> {
    if let Some(token) = &cli.token {
        return Ok(token.clone());
    }

    let auth = state.auth_manager.lock().await;
    match auth.get_access_token().await {
        Ok(token) => return Ok(token),
        Err(AuthError::NotAuthenticated) => {}
        Err(err) => return Err(format!("Failed to resolve stored access token: {err}")),
    }

    if let (Some(email), Some(password)) = (&cli.email, &cli.password) {
        auth.sign_in(email, password)
            .await
            .map_err(|err| format!("Harness sign-in failed: {err}"))?;
        return auth
            .get_access_token()
            .await
            .map_err(|err| format!("Failed to fetch access token after sign-in: {err}"));
    }

    Err("No access token, stored session, or email/password credentials available".to_string())
}

fn init_logging() -> Result<(), log::SetLoggerError> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .try_init()
}

fn write_report(path: &PathBuf, json: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| err.to_string())?;
    }
    fs::write(path, json).map_err(|err| err.to_string())
}

fn is_shell_process(name: &str) -> bool {
    matches!(
        name,
        "powershell.exe"
            | "powershell"
            | "pwsh.exe"
            | "pwsh"
            | "cmd.exe"
            | "cmd"
            | "conhost.exe"
            | "conhost"
    )
}

fn is_descendant_process(system: &System, pid: Pid, root_pid: Pid) -> bool {
    let mut cursor = Some(pid);
    let mut visited = BTreeSet::new();

    while let Some(current) = cursor {
        if current == root_pid {
            return true;
        }

        if !visited.insert(current.as_u32()) {
            return false;
        }

        cursor = system.process(current).and_then(|process| process.parent());
    }

    false
}

enum ParseOutcome {
    Help,
    Error(String),
}

fn parse_cli(raw_args: &[String]) -> Result<HarnessCli, ParseOutcome> {
    let mut cli = HarnessCli {
        connect_wait_ms: DEFAULT_CONNECT_WAIT_MS,
        ..HarnessCli::default()
    };

    let mut idx = 0usize;
    while idx < raw_args.len() {
        let flag = &raw_args[idx];
        idx += 1;

        let next = |name: &str, idx: &mut usize| -> Result<String, ParseOutcome> {
            let Some(value) = raw_args.get(*idx) else {
                return Err(ParseOutcome::Error(format!("Missing value for {name}")));
            };
            *idx += 1;
            Ok(value.clone())
        };

        match flag.as_str() {
            "--help" | "-h" => return Err(ParseOutcome::Help),
            "--report" => cli.report_path = Some(PathBuf::from(next(flag, &mut idx)?)),
            "--region" | "-r" => cli.region = Some(next(flag, &mut idx)?),
            "--adapter-guid" => cli.adapter_guid = Some(next(flag, &mut idx)?),
            "--token" | "-t" => cli.token = Some(next(flag, &mut idx)?),
            "--email" => cli.email = Some(next(flag, &mut idx)?),
            "--password" => cli.password = Some(next(flag, &mut idx)?),
            "--custom-relay" => cli.custom_relay_server = Some(next(flag, &mut idx)?),
            "--enable-api-tunneling" => cli.enable_api_tunneling = true,
            "--connect" => cli.connect = true,
            "--connect-wait-ms" => {
                let value = next(flag, &mut idx)?;
                cli.connect_wait_ms = value.parse::<u64>().map_err(|_| {
                    ParseOutcome::Error(format!("Invalid integer for --connect-wait-ms: {value}"))
                })?;
            }
            "--game-preset" | "--game" => cli.game_presets.push(next(flag, &mut idx)?),
            other => {
                return Err(ParseOutcome::Error(format!("Unknown argument: {other}")));
            }
        }
    }

    Ok(cli)
}

fn print_help() {
    println!("SwiftTunnel desktop testbench harness");
    println!();
    println!("Usage:");
    println!("  desktop_testbench_harness [options]");
    println!();
    println!("Options:");
    println!("  --report <path>           Write the JSON harness report to a file");
    println!("  --region, -r <region>     Region to use for connect tests");
    println!(
        "  --adapter-guid <guid>     Override the preferred adapter GUID for preflight/connect"
    );
    println!("  --token, -t <token>       Use an explicit access token");
    println!("  --email <email>           Sign in with email when connect testing");
    println!("  --password <password>     Sign in with password when connect testing");
    println!("  --custom-relay <host:port>  Override the relay endpoint for connect tests");
    println!("  --enable-api-tunneling      Force TCP/API tunneling on for connect tests");
    println!("  --connect                 Run a connect/disconnect smoke flow");
    println!("  --connect-wait-ms <ms>    Wait time after connect before collecting diagnostics");
    println!("  --game-preset <name>      Include a game preset for connect tests (repeatable)");
}
