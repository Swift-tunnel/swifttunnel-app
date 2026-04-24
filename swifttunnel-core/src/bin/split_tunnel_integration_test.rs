mod testbench_shared;

use std::path::Path;
use std::process::Command;
use std::time::Duration;

use swifttunnel_core::settings::load_settings;
use swifttunnel_core::vpn::{SplitTunnelDiagnostics, VpnConnection};
use testbench_shared::{
    DEFAULT_TCP_PROBE_COUNT, DEFAULT_TCP_PROBE_TARGET, DEFAULT_UDP_PROBE_COUNT,
    DEFAULT_UDP_PROBE_STARTUP_DELAY_MS, DEFAULT_UDP_PROBE_TARGET, connect_vpn, get_public_ip,
    init_logging, parse_common_cli_options, print_diagnostics, print_preflight_summary,
    resolve_binding_preference, resolve_enable_api_tunneling, resolve_region, resolve_test_exe,
};

fn print_usage() {
    println!("SwiftTunnel split tunnel integration test");
    println!();
    println!("Usage:");
    println!("  split_tunnel_integration_test.exe --token ACCESS_TOKEN [--region singapore]");
    println!("  split_tunnel_integration_test.exe --email you@example.com --password secret");
    println!(
        "  split_tunnel_integration_test.exe --test-exe path\\to\\ip_checker.exe --udp-target {} --udp-count {}",
        DEFAULT_UDP_PROBE_TARGET, DEFAULT_UDP_PROBE_COUNT
    );
    println!("  split_tunnel_integration_test.exe --custom-relay 45.32.115.254:51821");
    println!();
    println!("Environment:");
    println!("  SWIFTTUNNEL_TEST_ACCESS_TOKEN");
    println!("  SWIFTTUNNEL_TEST_EMAIL");
    println!("  SWIFTTUNNEL_TEST_PASSWORD");
    println!("  SWIFTTUNNEL_TEST_REGION");
    println!("  SWIFTTUNNEL_TEST_ADAPTER_GUID");
    println!("  SWIFTTUNNEL_TEST_CUSTOM_RELAY");
    println!("  SWIFTTUNNEL_TEST_ENABLE_API_TUNNELING");
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    init_logging();

    let raw_args: Vec<String> = std::env::args().skip(1).collect();
    let options = match parse_common_cli_options(&raw_args) {
        Ok(opts) => opts,
        Err(err) if err == "help" => {
            print_usage();
            return;
        }
        Err(err) => {
            eprintln!("{}", err);
            print_usage();
            std::process::exit(2);
        }
    };

    println!("=== SwiftTunnel Split Tunnel Integration Test ===");
    println!("Region: {}", resolve_region(&options));

    let (binding_preference, preflight) = match resolve_binding_preference(&options) {
        Ok(value) => value,
        Err(err) => {
            eprintln!("Preflight failed: {}", err);
            std::process::exit(1);
        }
    };
    print_preflight_summary(&preflight);
    if preflight.status != "ok" {
        eprintln!(
            "FAIL: split tunnel binding preflight returned {}",
            preflight.status
        );
        std::process::exit(1);
    }

    let baseline_ip = match get_public_ip() {
        Ok(ip) => ip,
        Err(err) => {
            eprintln!("FAIL: could not determine baseline public IP: {}", err);
            std::process::exit(1);
        }
    };
    println!("Baseline IP: {}", baseline_ip);

    let settings = load_settings();
    let api_tunneling_enabled = resolve_enable_api_tunneling(&options, &settings);
    let mut vpn = VpnConnection::new();
    if let Err(err) = connect_vpn(&mut vpn, &options, &settings, binding_preference).await {
        eprintln!("FAIL: vpn connect failed: {}", err);
        std::process::exit(1);
    }

    let result =
        run_connected_checks(&mut vpn, &options, &baseline_ip, api_tunneling_enabled).await;

    if let Err(err) = vpn.disconnect().await {
        eprintln!("WARN: vpn disconnect failed: {}", err);
    }

    if let Err(err) = result {
        eprintln!("FAIL: {}", err);
        std::process::exit(1);
    }

    println!("PASS: split tunnel integration test succeeded");
}

async fn run_connected_checks(
    vpn: &mut VpnConnection,
    options: &testbench_shared::CommonCliOptions,
    baseline_ip: &str,
    api_tunneling_enabled: bool,
) -> Result<(), String> {
    tokio::time::sleep(Duration::from_secs(2)).await;

    let connected_ip = get_public_ip()?;
    println!("Post-connect IP (current process): {}", connected_ip);
    if connected_ip != baseline_ip {
        return Err(format!(
            "current process should bypass tunnel, but IP changed from {} to {}",
            baseline_ip, connected_ip
        ));
    }

    let before = vpn
        .get_split_tunnel_diagnostics()
        .ok_or_else(|| "missing split tunnel diagnostics after connect".to_string())?;
    print_diagnostics(&before);

    let test_exe = resolve_test_exe(options)?;
    if !test_exe.exists() {
        return Err(format!("test executable not found: {}", test_exe.display()));
    }

    let udp_target = options
        .udp_target
        .clone()
        .unwrap_or_else(|| DEFAULT_UDP_PROBE_TARGET.to_string());
    let udp_count = options.udp_count.unwrap_or(DEFAULT_UDP_PROBE_COUNT);
    let startup_delay_ms = DEFAULT_UDP_PROBE_STARTUP_DELAY_MS.to_string();
    let port_file = std::env::temp_dir().join(format!(
        "swifttunnel-probe-port-{}-{}.txt",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or_default()
    ));
    let port_file_arg = port_file.display().to_string();
    let _ = std::fs::remove_file(&port_file);

    println!(
        "Running tunneled UDP probe via {} to {} ({} packets)",
        test_exe.display(),
        udp_target,
        udp_count
    );
    let child = Command::new(&test_exe)
        .args([
            "--udp-probe",
            "--target",
            &udp_target,
            "--count",
            &udp_count.to_string(),
            "--startup-delay-ms",
            &startup_delay_ms,
            "--port-file",
            &port_file_arg,
        ])
        .spawn()
        .map_err(|e| format!("failed to spawn probe executable: {}", e))?;

    let child_pid = child.id();
    println!("Probe helper PID: {}", child_pid);
    vpn.register_tunnel_process(child_pid, "ip_checker.exe")
        .await
        .map_err(|e| format!("failed to register probe process for tunneling: {}", e))?;

    let local_port = wait_for_probe_port(&port_file)?;
    println!("Probe helper local UDP port: {}", local_port);
    vpn.register_tunnel_udp_port(local_port)
        .await
        .map_err(|e| format!("failed to register probe UDP port for tunneling: {}", e))?;

    let output = child
        .wait_with_output()
        .map_err(|e| format!("failed to wait for probe executable: {}", e))?;
    let _ = std::fs::remove_file(&port_file);

    if !output.status.success() {
        return Err(format!(
            "probe executable failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    if !output.stdout.is_empty() {
        println!("{}", String::from_utf8_lossy(&output.stdout).trim());
    }

    tokio::time::sleep(Duration::from_secs(2)).await;

    let after = vpn
        .get_split_tunnel_diagnostics()
        .ok_or_else(|| "missing split tunnel diagnostics after UDP probe".to_string())?;
    print_diagnostics(&after);

    if after.packets_tunneled <= before.packets_tunneled {
        return Err(format!(
            "expected tunneled packet counter to increase (before={}, after={})",
            before.packets_tunneled, after.packets_tunneled
        ));
    }

    if api_tunneling_enabled {
        run_tcp_api_probe_check(vpn, options, &after).await?;
    } else {
        println!("Skipping TCP/API probe because API tunneling is disabled");
    }

    Ok(())
}

async fn run_tcp_api_probe_check(
    vpn: &mut VpnConnection,
    options: &testbench_shared::CommonCliOptions,
    before: &SplitTunnelDiagnostics,
) -> Result<(), String> {
    let test_exe = resolve_test_exe(options)?;
    let startup_delay_ms = DEFAULT_UDP_PROBE_STARTUP_DELAY_MS.to_string();
    let port_file = std::env::temp_dir().join(format!(
        "swifttunnel-probe-tcp-port-{}-{}.txt",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or_default()
    ));
    let port_file_arg = port_file.display().to_string();
    let _ = std::fs::remove_file(&port_file);

    println!(
        "Running tunneled TCP/API probe via {} to {} ({} writes)",
        test_exe.display(),
        DEFAULT_TCP_PROBE_TARGET,
        DEFAULT_TCP_PROBE_COUNT
    );
    let child = Command::new(&test_exe)
        .args([
            "--tcp-probe",
            "--target",
            DEFAULT_TCP_PROBE_TARGET,
            "--count",
            &DEFAULT_TCP_PROBE_COUNT.to_string(),
            "--startup-delay-ms",
            &startup_delay_ms,
            "--port-file",
            &port_file_arg,
        ])
        .spawn()
        .map_err(|e| format!("failed to spawn TCP probe executable: {}", e))?;

    let child_pid = child.id();
    println!("TCP probe helper PID: {}", child_pid);
    vpn.register_tunnel_process(child_pid, "ip_checker.exe")
        .await
        .map_err(|e| format!("failed to register TCP probe process for tunneling: {}", e))?;

    let local_port = wait_for_probe_port(&port_file)?;
    println!("TCP probe helper local port: {}", local_port);

    let output = child
        .wait_with_output()
        .map_err(|e| format!("failed to wait for TCP probe executable: {}", e))?;
    let _ = std::fs::remove_file(&port_file);

    if !output.status.success() {
        return Err(format!(
            "TCP probe executable failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    if !output.stdout.is_empty() {
        println!("{}", String::from_utf8_lossy(&output.stdout).trim());
    }

    tokio::time::sleep(Duration::from_secs(2)).await;

    let after = vpn
        .get_split_tunnel_diagnostics()
        .ok_or_else(|| "missing split tunnel diagnostics after TCP probe".to_string())?;
    print_diagnostics(&after);

    if after.packets_tunneled <= before.packets_tunneled {
        return Err(format!(
            "expected TCP/API probe to increase tunneled packet counter (before={}, after={})",
            before.packets_tunneled, after.packets_tunneled
        ));
    }

    Ok(())
}

fn wait_for_probe_port(path: &Path) -> Result<u16, String> {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if let Ok(raw) = std::fs::read_to_string(path) {
            let trimmed = raw.trim();
            if !trimmed.is_empty() {
                return trimmed.parse::<u16>().map_err(|e| {
                    format!(
                        "probe port file '{}' contained invalid port '{}': {}",
                        path.display(),
                        trimmed,
                        e
                    )
                });
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    Err(format!(
        "timed out waiting for probe port file '{}'",
        path.display()
    ))
}
