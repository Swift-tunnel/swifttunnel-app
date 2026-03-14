use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::path::PathBuf;
use std::time::Duration;

use swifttunnel_core::auth::{AuthError, AuthManager};
use swifttunnel_core::settings::AppSettings;
use swifttunnel_core::vpn::{
    AdapterBindingPreference, BindingPreferenceSource, BindingPreflightInfo, DynamicServerInfo,
    SplitTunnelDiagnostics, VpnConnection, load_server_list, preflight_binding,
};

pub const DEFAULT_REGION: &str = "singapore";
pub const DEFAULT_UDP_PROBE_TARGET: &str = "128.116.1.1:49152";
pub const DEFAULT_UDP_PROBE_COUNT: usize = 32;
pub const DEFAULT_UDP_PROBE_STARTUP_DELAY_MS: u64 = 1500;

#[derive(Debug, Clone, Default)]
pub struct CommonCliOptions {
    pub region: Option<String>,
    pub adapter_guid: Option<String>,
    pub token: Option<String>,
    pub email: Option<String>,
    pub password: Option<String>,
    pub test_exe: Option<PathBuf>,
    pub udp_target: Option<String>,
    pub udp_count: Option<usize>,
    pub custom_relay_server: Option<String>,
    pub enable_api_tunneling: bool,
}

pub fn init_logging() {
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .try_init();
}

pub fn parse_common_cli_options(args: &[String]) -> Result<CommonCliOptions, String> {
    let mut opts = CommonCliOptions::default();
    let mut idx = 0usize;

    while idx < args.len() {
        let flag = &args[idx];
        idx += 1;

        let next = |name: &str, idx: &mut usize| -> Result<String, String> {
            let Some(value) = args.get(*idx) else {
                return Err(format!("Missing value for {}", name));
            };
            *idx += 1;
            Ok(value.clone())
        };

        match flag.as_str() {
            "--region" | "-r" => opts.region = Some(next(flag, &mut idx)?),
            "--adapter-guid" => opts.adapter_guid = Some(next(flag, &mut idx)?),
            "--token" | "-t" => opts.token = Some(next(flag, &mut idx)?),
            "--email" => opts.email = Some(next(flag, &mut idx)?),
            "--password" => opts.password = Some(next(flag, &mut idx)?),
            "--test-exe" | "-e" => opts.test_exe = Some(PathBuf::from(next(flag, &mut idx)?)),
            "--udp-target" => opts.udp_target = Some(next(flag, &mut idx)?),
            "--udp-count" => {
                let raw = next(flag, &mut idx)?;
                let count = raw
                    .parse::<usize>()
                    .map_err(|_| format!("Invalid integer for {}: {}", flag, raw))?;
                opts.udp_count = Some(count);
            }
            "--custom-relay" => opts.custom_relay_server = Some(next(flag, &mut idx)?),
            "--enable-api-tunneling" => opts.enable_api_tunneling = true,
            "--help" | "-h" => return Err("help".to_string()),
            other => return Err(format!("Unknown argument: {}", other)),
        }
    }

    Ok(opts)
}

pub fn resolve_region(opts: &CommonCliOptions) -> String {
    opts.region
        .clone()
        .or_else(|| std::env::var("SWIFTTUNNEL_TEST_REGION").ok())
        .unwrap_or_else(|| DEFAULT_REGION.to_string())
}

fn parse_env_flag(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

pub fn resolve_custom_relay_server(
    opts: &CommonCliOptions,
    settings: &AppSettings,
) -> Option<String> {
    opts.custom_relay_server
        .clone()
        .or_else(|| {
            std::env::var("SWIFTTUNNEL_TEST_CUSTOM_RELAY")
                .ok()
                .filter(|value| !value.trim().is_empty())
        })
        .or_else(|| {
            let custom = settings.custom_relay_server.trim();
            (!custom.is_empty()).then(|| custom.to_string())
        })
}

pub fn resolve_enable_api_tunneling(opts: &CommonCliOptions, settings: &AppSettings) -> bool {
    opts.enable_api_tunneling
        || parse_env_flag("SWIFTTUNNEL_TEST_ENABLE_API_TUNNELING")
        || settings.enable_api_tunneling
}

pub fn resolve_binding_preference(
    opts: &CommonCliOptions,
) -> Result<(Option<AdapterBindingPreference>, BindingPreflightInfo), String> {
    let preferred_guid = opts
        .adapter_guid
        .clone()
        .or_else(|| std::env::var("SWIFTTUNNEL_TEST_ADAPTER_GUID").ok());

    let preference = preferred_guid.map(|guid| AdapterBindingPreference {
        guid,
        source: BindingPreferenceSource::Manual,
        network_signature: None,
    });

    let preflight = preflight_binding(preference.clone()).map_err(|e| e.to_string())?;
    Ok((preference, preflight))
}

pub fn print_preflight_summary(preflight: &BindingPreflightInfo) {
    println!("Binding preflight: {}", preflight.status);
    println!("  Reason: {}", preflight.reason);
    println!("  Network signature: {}", preflight.network_signature);
    println!(
        "  Recommended adapter: {}",
        preflight.recommended_guid.as_deref().unwrap_or("<none>")
    );
    println!("  Cached override used: {}", preflight.cached_override_used);
    if !preflight.candidates.is_empty() {
        println!("  Candidates:");
        for candidate in &preflight.candidates {
            println!(
                "    - {} [{}] ifIndex={} stage={} score={}",
                candidate.friendly_name,
                candidate.guid,
                candidate
                    .if_index
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "?".to_string()),
                candidate.stage,
                candidate.score
            );
        }
    }
}

pub async fn resolve_access_token(opts: &CommonCliOptions) -> Result<String, String> {
    if let Some(token) = opts
        .token
        .clone()
        .or_else(|| std::env::var("SWIFTTUNNEL_TEST_ACCESS_TOKEN").ok())
    {
        return Ok(token);
    }

    let manager = AuthManager::new().map_err(|e| e.to_string())?;
    match manager.get_access_token().await {
        Ok(token) => return Ok(token),
        Err(AuthError::NotAuthenticated) => {}
        Err(err) => {
            log::warn!("Stored session unavailable for testbench auth: {}", err);
        }
    }

    let email = opts
        .email
        .clone()
        .or_else(|| std::env::var("SWIFTTUNNEL_TEST_EMAIL").ok());
    let password = opts
        .password
        .clone()
        .or_else(|| std::env::var("SWIFTTUNNEL_TEST_PASSWORD").ok());

    if let (Some(email), Some(password)) = (email, password) {
        match manager.sign_in(&email, &password).await {
            Ok(()) => {
                return manager
                    .get_access_token()
                    .await
                    .map_err(|e| format!("Failed to get access token after sign in: {}", e));
            }
            Err(err) => {
                log::warn!(
                    "Testbench sign-in failed ({}); continuing with relay legacy fallback",
                    err
                );
            }
        }
    } else {
        log::warn!("No auth session or testbench credentials found; using relay legacy fallback");
    }

    Ok("testbench-legacy-fallback".to_string())
}

pub async fn load_available_servers() -> Result<Vec<(String, SocketAddr, Option<u32>)>, String> {
    let (servers, _, source) = load_server_list().await?;
    println!("Loaded {} servers from {}", servers.len(), source);
    Ok(to_available_servers(&servers))
}

fn to_available_servers(servers: &[DynamicServerInfo]) -> Vec<(String, SocketAddr, Option<u32>)> {
    servers
        .iter()
        .filter_map(|server| {
            let addr = format!("{}:{}", server.ip, 51821).parse().ok()?;
            Some((server.region.clone(), addr, None))
        })
        .collect()
}

pub fn resolve_test_exe(opts: &CommonCliOptions) -> Result<PathBuf, String> {
    if let Some(path) = opts.test_exe.clone() {
        return Ok(path);
    }

    let current = std::env::current_exe()
        .map_err(|e| format!("Failed to resolve current executable path: {}", e))?;
    let Some(dir) = current.parent() else {
        return Err("Current executable has no parent directory".to_string());
    };
    Ok(dir.join("ip_checker.exe"))
}

pub fn get_public_ip() -> Result<String, String> {
    let services = [
        ("api.ipify.org", "/"),
        ("ifconfig.me", "/ip"),
        ("icanhazip.com", "/"),
    ];

    let mut last_error = None;
    for (host, path) in services {
        match check_ip_via_http(host, path) {
            Ok(ip) => return Ok(ip),
            Err(err) => last_error = Some(format!("{}: {}", host, err)),
        }
    }

    Err(last_error.unwrap_or_else(|| "No IP check service succeeded".to_string()))
}

fn check_ip_via_http(host: &str, path: &str) -> Result<String, String> {
    let addr = format!("{}:80", host)
        .to_socket_addrs()
        .map_err(|e| format!("DNS resolution failed: {}", e))?
        .next()
        .ok_or_else(|| "No addresses found".to_string())?;

    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5))
        .map_err(|e| format!("Connect failed: {}", e))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| format!("Set read timeout failed: {}", e))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| format!("Set write timeout failed: {}", e))?;

    let mut stream = stream;
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: SwiftTunnel-Testbench/1.0\r\n\r\n",
        path, host
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("Write failed: {}", e))?;

    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|e| format!("Read failed: {}", e))?;

    let body_start = response
        .find("\r\n\r\n")
        .ok_or_else(|| "Malformed HTTP response".to_string())?;
    let ip = response[body_start + 4..].trim().to_string();
    if ip.is_empty() {
        return Err("Empty response body".to_string());
    }
    Ok(ip)
}

pub fn run_udp_probe(
    target: &str,
    count: usize,
    startup_delay_ms: u64,
    port_file: Option<&std::path::Path>,
) -> Result<(), String> {
    let addr: SocketAddr = target
        .parse()
        .map_err(|e| format!("Invalid UDP target '{}': {}", target, e))?;
    let socket =
        UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("Failed to bind UDP socket: {}", e))?;
    socket
        .set_write_timeout(Some(Duration::from_secs(1)))
        .map_err(|e| format!("Failed to set UDP timeout: {}", e))?;

    let local_port = socket
        .local_addr()
        .map_err(|e| format!("Failed to query UDP local address: {}", e))?
        .port();

    if let Some(path) = port_file {
        std::fs::write(path, local_port.to_string())
            .map_err(|e| format!("Failed to write UDP port file '{}': {}", path.display(), e))?;
    }

    // Give the parent process time to register the helper PID and local port
    // before any UDP packets are emitted.
    std::thread::sleep(Duration::from_millis(startup_delay_ms));

    for idx in 0..count {
        let payload = format!("SwiftTunnel UDP probe {}", idx);
        socket
            .send_to(payload.as_bytes(), addr)
            .map_err(|e| format!("UDP send failed: {}", e))?;
        std::thread::sleep(Duration::from_millis(30));
    }

    std::thread::sleep(Duration::from_millis(500));

    Ok(())
}

pub async fn connect_vpn(
    vpn: &mut VpnConnection,
    opts: &CommonCliOptions,
    settings: &AppSettings,
    binding_preference: Option<AdapterBindingPreference>,
) -> Result<(), String> {
    let access_token = resolve_access_token(opts).await?;
    let region = resolve_region(opts);
    let available_servers = load_available_servers().await?;

    vpn.connect(
        &access_token,
        &region,
        vec!["ip_checker.exe".to_string()],
        resolve_custom_relay_server(opts, settings),
        false,
        settings.config.network_settings.gaming_qos,
        available_servers,
        settings.whitelisted_regions.clone(),
        settings.forced_servers.clone(),
        binding_preference,
        settings.game_process_performance,
        resolve_enable_api_tunneling(opts, settings),
    )
    .await
    .map_err(|e| swifttunnel_core::vpn::user_friendly_error(&e))
}

pub fn print_diagnostics(diag: &SplitTunnelDiagnostics) {
    println!("Diagnostics:");
    println!(
        "  Adapter: {} ({})",
        diag.adapter_name.as_deref().unwrap_or("<unknown>"),
        diag.adapter_guid.as_deref().unwrap_or("<unknown>")
    );
    println!(
        "  Route ifIndex: selected={:?} resolved={:?}",
        diag.selected_if_index, diag.resolved_if_index
    );
    println!("  Binding reason: {}", diag.binding_reason);
    println!("  Binding stage: {}", diag.binding_stage);
    println!("  Cached override used: {}", diag.cached_override_used);
    println!(
        "  Network signature: {}",
        diag.network_signature.as_deref().unwrap_or("<none>")
    );
    println!("  Last validation result: {}", diag.last_validation_result);
    println!("  Packets tunneled: {}", diag.packets_tunneled);
    println!("  Packets bypassed: {}", diag.packets_bypassed);
}
