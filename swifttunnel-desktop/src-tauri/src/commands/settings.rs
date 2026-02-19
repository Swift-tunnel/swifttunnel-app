use serde::Serialize;
use std::path::PathBuf;
use std::process::Output;
use tauri::{AppHandle, Manager, State};

use crate::state::AppState;

#[derive(Serialize)]
pub struct SettingsResponse {
    pub json: String,
}

#[derive(Serialize)]
pub struct NetworkDiagnosticsBundleResponse {
    pub file_path: String,
    pub folder_path: String,
}

#[derive(Debug, Clone)]
struct DiagnosticsCommand {
    title: &'static str,
    program: &'static str,
    args: Vec<String>,
}

#[derive(Debug, Clone)]
struct CommandCapture {
    stdout: String,
    stderr: String,
    status_code: Option<i32>,
    success: bool,
    execution_error: Option<String>,
}

#[derive(Debug, Clone)]
struct BundleContext {
    generated_at: String,
    app_version: String,
    platform: String,
    settings: swifttunnel_core::settings::AppSettings,
    vpn_state: swifttunnel_core::vpn::ConnectionState,
    split_tunnel_diag: Option<(Option<String>, bool, u64, u64)>,
}

#[tauri::command]
pub fn settings_load(state: State<'_, AppState>) -> Result<SettingsResponse, String> {
    let settings = state.settings.lock();
    let json = serde_json::to_string(&*settings).map_err(|e| format!("Serialize error: {}", e))?;
    Ok(SettingsResponse { json })
}

#[tauri::command]
pub fn settings_save(
    state: State<'_, AppState>,
    app: AppHandle,
    settings_json: String,
) -> Result<(), String> {
    let mut new_settings: swifttunnel_core::settings::AppSettings =
        serde_json::from_str(&settings_json)
            .map_err(|e| format!("Invalid settings JSON: {}", e))?;

    new_settings.sanitize_in_place();
    swifttunnel_core::settings::save_settings(&new_settings)?;

    {
        let mut discord = state.discord_manager.lock();
        discord.set_enabled(new_settings.enable_discord_rpc);
    }

    let mut settings = state.settings.lock();
    *settings = new_settings;
    let run_on_startup = settings.run_on_startup;
    drop(settings);

    if let Err(e) = crate::autostart::sync_run_on_startup(&app, run_on_startup) {
        log::warn!(
            "Failed to sync startup registration after settings save: {}",
            e
        );
    }

    Ok(())
}

fn current_timestamp_utc() -> String {
    chrono::Utc::now().to_rfc3339()
}

fn current_filename_timestamp() -> String {
    chrono::Local::now().format("%Y%m%d_%H%M%S").to_string()
}

fn build_diagnostics_filename_from_timestamp(timestamp: &str) -> String {
    format!("SwiftTunnel_NetworkDiagnostics_{timestamp}.txt")
}

fn build_diagnostics_filename() -> String {
    build_diagnostics_filename_from_timestamp(&current_filename_timestamp())
}

fn resolve_output_dir(app: &AppHandle) -> PathBuf {
    app.path()
        .desktop_dir()
        .or_else(|_| app.path().download_dir())
        .unwrap_or_else(|_| std::env::temp_dir())
}

fn format_section(title: &str, body: &str) -> String {
    let mut section = String::new();
    section.push_str("## ");
    section.push_str(title);
    section.push('\n');
    section.push_str(body.trim_end());
    section.push('\n');
    section
}

fn capture_from_output(result: Result<Output, std::io::Error>) -> CommandCapture {
    match result {
        Ok(output) => CommandCapture {
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            status_code: output.status.code(),
            success: output.status.success(),
            execution_error: None,
        },
        Err(e) => CommandCapture {
            stdout: String::new(),
            stderr: String::new(),
            status_code: None,
            success: false,
            execution_error: Some(e.to_string()),
        },
    }
}

fn format_command_section(title: &str, capture: &CommandCapture) -> String {
    let mut body = String::new();

    if let Some(error) = &capture.execution_error {
        body.push_str(&format!("Execution error: {error}\n"));
        return format_section(title, &body);
    }

    if !capture.success {
        match capture.status_code {
            Some(code) => body.push_str(&format!("Command failed (exit code: {code})\n")),
            None => body.push_str("Command failed (unknown exit code)\n"),
        }
    }

    if !capture.stdout.trim().is_empty() {
        body.push_str(&capture.stdout);
        if !capture.stdout.ends_with('\n') {
            body.push('\n');
        }
    }

    if !capture.stderr.trim().is_empty() {
        if !body.is_empty() {
            body.push('\n');
        }
        body.push_str("[stderr]\n");
        body.push_str(&capture.stderr);
        if !capture.stderr.ends_with('\n') {
            body.push('\n');
        }
    }

    if body.trim().is_empty() {
        body.push_str("(no output)\n");
    }

    format_section(title, &body)
}

fn run_diagnostics_command(command: &DiagnosticsCommand) -> CommandCapture {
    let mut process = swifttunnel_core::hidden_command(command.program);
    for arg in &command.args {
        process.arg(arg);
    }
    capture_from_output(process.output())
}

fn run_windows_diagnostics_sections() -> Vec<String> {
    #[cfg(windows)]
    {
        windows_diagnostics_commands()
            .into_iter()
            .map(|command| {
                let capture = run_diagnostics_command(&command);
                format_command_section(command.title, &capture)
            })
            .collect()
    }

    #[cfg(not(windows))]
    {
        vec![format_section(
            "Windows Diagnostics",
            "Windows-specific diagnostics are unavailable on this platform.",
        )]
    }
}

fn isp_lookup_script() -> &'static str {
    "$ErrorActionPreference='Stop'; \
     $ProgressPreference='SilentlyContinue'; \
     Invoke-RestMethod -Uri 'https://ipinfo.io/json' -TimeoutSec 6 | ConvertTo-Json -Depth 8"
}

#[cfg(windows)]
fn windows_diagnostics_commands() -> Vec<DiagnosticsCommand> {
    vec![
        DiagnosticsCommand {
            title: "Get-NetAdapter",
            program: "powershell",
            args: vec![
                "-NoProfile".to_string(),
                "-Command".to_string(),
                "Get-NetAdapter | Format-Table Name,InterfaceDescription,ifIndex,Status,MacAddress,LinkSpeed -AutoSize | Out-String -Width 220".to_string(),
            ],
        },
        DiagnosticsCommand {
            title: "Get-NetIPInterface",
            program: "powershell",
            args: vec![
                "-NoProfile".to_string(),
                "-Command".to_string(),
                "Get-NetIPInterface | Sort-Object InterfaceMetric | Format-Table InterfaceAlias,InterfaceIndex,AddressFamily,NlMtu,InterfaceMetric,ConnectionState -AutoSize | Out-String -Width 220".to_string(),
            ],
        },
        DiagnosticsCommand {
            title: "Get-NetRoute Default Routes",
            program: "powershell",
            args: vec![
                "-NoProfile".to_string(),
                "-Command".to_string(),
                "Get-NetRoute -DestinationPrefix '0.0.0.0/0','::/0' | Sort-Object RouteMetric,InterfaceMetric | Format-Table DestinationPrefix,NextHop,InterfaceIndex,RouteMetric,InterfaceMetric -AutoSize | Out-String -Width 220".to_string(),
            ],
        },
        DiagnosticsCommand {
            title: "Get-DnsClientServerAddress",
            program: "powershell",
            args: vec![
                "-NoProfile".to_string(),
                "-Command".to_string(),
                "Get-DnsClientServerAddress | Format-Table InterfaceAlias,AddressFamily,ServerAddresses -AutoSize | Out-String -Width 220".to_string(),
            ],
        },
        DiagnosticsCommand {
            title: "Get-NetOffloadGlobalSetting",
            program: "powershell",
            args: vec![
                "-NoProfile".to_string(),
                "-Command".to_string(),
                "Get-NetOffloadGlobalSetting | Out-String -Width 220".to_string(),
            ],
        },
        DiagnosticsCommand {
            title: "Get-NetAdapterAdvancedProperty (offload/checksum)",
            program: "powershell",
            args: vec![
                "-NoProfile".to_string(),
                "-Command".to_string(),
                "Get-NetAdapterAdvancedProperty | Where-Object { $_.DisplayName -match 'offload|checksum|large send|udp|tcp' } | Format-Table Name,DisplayName,DisplayValue -AutoSize | Out-String -Width 260".to_string(),
            ],
        },
        DiagnosticsCommand {
            title: "ipconfig /all",
            program: "ipconfig",
            args: vec!["/all".to_string()],
        },
        DiagnosticsCommand {
            title: "route print -4",
            program: "route",
            args: vec!["print".to_string(), "-4".to_string()],
        },
        DiagnosticsCommand {
            title: "route print -6",
            program: "route",
            args: vec!["print".to_string(), "-6".to_string()],
        },
        DiagnosticsCommand {
            title: "External ISP Lookup (ipinfo.io)",
            program: "powershell",
            args: vec![
                "-NoProfile".to_string(),
                "-Command".to_string(),
                isp_lookup_script().to_string(),
            ],
        },
    ]
}

#[cfg(not(windows))]
fn windows_diagnostics_commands() -> Vec<DiagnosticsCommand> {
    Vec::new()
}

fn format_settings_snapshot(settings: &swifttunnel_core::settings::AppSettings) -> String {
    let selected_games = if settings.selected_game_presets.is_empty() {
        "none".to_string()
    } else {
        settings.selected_game_presets.join(", ")
    };
    let whitelisted_regions = if settings.whitelisted_regions.is_empty() {
        "none".to_string()
    } else {
        settings.whitelisted_regions.join(", ")
    };
    let custom_relay = if settings.custom_relay_server.trim().is_empty() {
        "auto".to_string()
    } else {
        settings.custom_relay_server.trim().to_string()
    };

    format!(
        "selected_region: {}\nselected_game_presets: {}\nauto_routing_enabled: {}\nwhitelisted_regions: {}\nupdate_channel: {:?}\ncustom_relay_server: {}",
        settings.selected_region,
        selected_games,
        settings.auto_routing_enabled,
        whitelisted_regions,
        settings.update_channel,
        custom_relay
    )
}

fn format_vpn_snapshot(vpn_state: &swifttunnel_core::vpn::ConnectionState) -> String {
    match vpn_state {
        swifttunnel_core::vpn::ConnectionState::Disconnected => "state: disconnected".to_string(),
        swifttunnel_core::vpn::ConnectionState::FetchingConfig => {
            "state: fetching_config".to_string()
        }
        swifttunnel_core::vpn::ConnectionState::ConfiguringSplitTunnel => {
            "state: configuring_split_tunnel".to_string()
        }
        swifttunnel_core::vpn::ConnectionState::Connected {
            server_region,
            server_endpoint,
            assigned_ip,
            relay_auth_mode,
            split_tunnel_active,
            tunneled_processes,
            ..
        } => {
            let tunneled = if tunneled_processes.is_empty() {
                "none".to_string()
            } else {
                tunneled_processes.join(", ")
            };
            format!(
                "state: connected\nserver_region: {server_region}\nserver_endpoint: {server_endpoint}\nassigned_ip: {assigned_ip}\nrelay_auth_mode: {relay_auth_mode}\nsplit_tunnel_active: {split_tunnel_active}\ntunneled_processes: {tunneled}"
            )
        }
        swifttunnel_core::vpn::ConnectionState::Disconnecting => "state: disconnecting".to_string(),
        swifttunnel_core::vpn::ConnectionState::Error(message) => {
            format!("state: error\nerror: {message}")
        }
    }
}

fn format_split_tunnel_snapshot(diag: Option<(Option<String>, bool, u64, u64)>) -> String {
    match diag {
        Some((adapter_name, has_default_route, packets_tunneled, packets_bypassed)) => format!(
            "adapter_name: {}\nhas_default_route: {}\npackets_tunneled: {}\npackets_bypassed: {}",
            adapter_name.unwrap_or_else(|| "unknown".to_string()),
            has_default_route,
            packets_tunneled,
            packets_bypassed
        ),
        None => "split tunnel diagnostics unavailable".to_string(),
    }
}

fn compose_bundle_text(context: &BundleContext, command_sections: &[String]) -> String {
    let mut content = String::new();
    content.push_str("SwiftTunnel Network Diagnostics Bundle\n");
    content.push_str("====================================\n\n");

    content.push_str(&format_section(
        "App Metadata",
        &format!(
            "generated_at: {}\napp_version: {}\nplatform: {}",
            context.generated_at, context.app_version, context.platform
        ),
    ));
    content.push('\n');
    content.push_str(&format_section(
        "Settings Snapshot",
        &format_settings_snapshot(&context.settings),
    ));
    content.push('\n');
    content.push_str(&format_section(
        "VPN Snapshot",
        &format_vpn_snapshot(&context.vpn_state),
    ));
    content.push('\n');
    content.push_str(&format_section(
        "Split Tunnel Diagnostics",
        &format_split_tunnel_snapshot(context.split_tunnel_diag.clone()),
    ));
    content.push('\n');

    for (idx, section) in command_sections.iter().enumerate() {
        content.push_str(section);
        if idx + 1 != command_sections.len() {
            content.push('\n');
        }
    }

    content
}

#[tauri::command]
pub async fn settings_generate_network_diagnostics_bundle(
    state: State<'_, AppState>,
    app: AppHandle,
) -> Result<NetworkDiagnosticsBundleResponse, String> {
    let settings = state.settings.lock().clone();

    let (vpn_state, split_tunnel_diag) = {
        let vpn = state.vpn_connection.lock().await;
        let snapshot = vpn.state().await;
        let diagnostics = vpn.get_split_tunnel_diagnostics();
        (snapshot, diagnostics)
    };

    let bundle_context = BundleContext {
        generated_at: current_timestamp_utc(),
        app_version: env!("CARGO_PKG_VERSION").to_string(),
        platform: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
        settings,
        vpn_state,
        split_tunnel_diag,
    };

    let command_sections = run_windows_diagnostics_sections();
    let bundle_text = compose_bundle_text(&bundle_context, &command_sections);

    let output_dir = resolve_output_dir(&app);
    std::fs::create_dir_all(&output_dir)
        .map_err(|e| format!("Failed to create diagnostics output directory: {e}"))?;

    let file_path = output_dir.join(build_diagnostics_filename());
    std::fs::write(&file_path, bundle_text)
        .map_err(|e| format!("Failed to write diagnostics bundle: {e}"))?;

    Ok(NetworkDiagnosticsBundleResponse {
        file_path: file_path.to_string_lossy().to_string(),
        folder_path: output_dir.to_string_lossy().to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn build_diagnostics_filename_has_expected_format() {
        let fixed = build_diagnostics_filename_from_timestamp("20260219_154500");
        assert_eq!(fixed, "SwiftTunnel_NetworkDiagnostics_20260219_154500.txt");

        let generated = build_diagnostics_filename();
        assert!(generated.starts_with("SwiftTunnel_NetworkDiagnostics_"));
        assert!(generated.ends_with(".txt"));

        let stamp = generated
            .trim_start_matches("SwiftTunnel_NetworkDiagnostics_")
            .trim_end_matches(".txt");
        assert_eq!(stamp.len(), 15);
        assert_eq!(&stamp[8..9], "_");
        assert!(stamp.chars().enumerate().all(|(idx, ch)| {
            if idx == 8 {
                ch == '_'
            } else {
                ch.is_ascii_digit()
            }
        }));
    }

    #[test]
    fn compose_bundle_text_contains_required_sections() {
        let mut settings = swifttunnel_core::settings::AppSettings::default();
        settings.selected_region = "mumbai".to_string();
        settings.selected_game_presets = vec!["roblox".to_string(), "valorant".to_string()];
        settings.auto_routing_enabled = true;
        settings.custom_relay_server = "relay.example.com:51821".to_string();

        let context = BundleContext {
            generated_at: "2026-02-19T15:45:00Z".to_string(),
            app_version: "1.15.25".to_string(),
            platform: "windows-x86_64".to_string(),
            settings,
            vpn_state: swifttunnel_core::vpn::ConnectionState::Connected {
                since: Instant::now(),
                server_region: "mumbai".to_string(),
                server_endpoint: "1.2.3.4:51821".to_string(),
                assigned_ip: "100.64.0.12".to_string(),
                relay_auth_mode: "preflight-ok".to_string(),
                split_tunnel_active: true,
                tunneled_processes: vec!["robloxplayerbeta.exe".to_string()],
            },
            split_tunnel_diag: Some((Some("Ethernet".to_string()), true, 77, 12)),
        };

        let bundle = compose_bundle_text(
            &context,
            &[format_section("Get-NetAdapter", "sample adapter output")],
        );

        assert!(bundle.contains("## App Metadata"));
        assert!(bundle.contains("## Settings Snapshot"));
        assert!(bundle.contains("## VPN Snapshot"));
        assert!(bundle.contains("## Split Tunnel Diagnostics"));
        assert!(bundle.contains("selected_region: mumbai"));
        assert!(bundle.contains("state: connected"));
        assert!(bundle.contains("packets_tunneled: 77"));
        assert!(bundle.contains("## Get-NetAdapter"));
    }

    #[test]
    fn command_section_includes_errors_without_panicking() {
        let capture = CommandCapture {
            stdout: String::new(),
            stderr: "Access is denied".to_string(),
            status_code: Some(1),
            success: false,
            execution_error: None,
        };

        let section = format_command_section("Get-NetAdapter", &capture);
        assert!(section.contains("Command failed (exit code: 1)"));
        assert!(section.contains("[stderr]"));
        assert!(section.contains("Access is denied"));
    }

    #[test]
    fn isp_lookup_script_targets_ipinfo() {
        let script = isp_lookup_script();
        assert!(script.contains("ipinfo.io/json"));
        assert!(script.contains("Invoke-RestMethod"));
    }
}
