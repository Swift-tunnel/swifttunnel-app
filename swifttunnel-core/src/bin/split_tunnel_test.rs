mod testbench_shared;

use swifttunnel_core::vpn::SplitTunnelDriver;
use testbench_shared::{
    init_logging, parse_common_cli_options, print_preflight_summary, resolve_binding_preference,
};

fn print_usage() {
    println!("SwiftTunnel split tunnel driver smoke test");
    println!();
    println!("Usage:");
    println!("  split_tunnel_test.exe");
    println!("  split_tunnel_test.exe --adapter-guid {{GUID}}");
    println!();
    println!("Environment:");
    println!("  SWIFTTUNNEL_TEST_ADAPTER_GUID");
}

fn main() {
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

    println!("=== SwiftTunnel Split Tunnel Smoke Test ===");
    println!();
    println!("[1] Checking WinpkFilter / NDISRD driver...");
    if !SplitTunnelDriver::check_driver_available() {
        eprintln!("  FAIL: WinpkFilter driver is not available");
        std::process::exit(1);
    }
    println!("  OK: Driver is available");

    println!();
    println!("[2] Running mandatory binding preflight...");
    let (_, preflight) = match resolve_binding_preference(&options) {
        Ok(value) => value,
        Err(err) => {
            eprintln!("  FAIL: {}", err);
            std::process::exit(1);
        }
    };
    print_preflight_summary(&preflight);

    if preflight.status != "ok" {
        eprintln!(
            "  FAIL: split tunnel binding preflight returned {}",
            preflight.status
        );
        std::process::exit(1);
    }

    println!();
    println!("PASS: driver and split tunnel binding preflight are healthy");
}
