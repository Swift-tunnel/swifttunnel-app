//! Driver Installer - Standalone binary for WinpkFilter/ndisapi driver installation
//!
//! This binary is invoked by the main SwiftTunnel app (or Velopack hooks) with
//! admin elevation to install the WinpkFilter NDIS driver. It runs silently,
//! prints status to stdout, and exits with code 0 (success) or 1 (failure).

use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    println!("[driver-installer] Starting WinpkFilter driver installation...");

    // Locate the MSI
    let msi_path = match find_msi() {
        Some(path) => {
            println!("[driver-installer] Found MSI: {}", path.display());
            path
        }
        None => {
            eprintln!("[driver-installer] ERROR: WinpkFilter-x64.msi not found");
            eprintln!("[driver-installer] Searched:");
            eprintln!("  - {{exe_dir}}\\drivers\\");
            eprintln!("  - %LOCALAPPDATA%\\SwiftTunnel\\drivers\\");
            eprintln!("  - {{exe_dir}}\\..\\drivers\\");
            return ExitCode::from(1);
        }
    };

    // Run msiexec to install silently
    println!("[driver-installer] Running msiexec /i ... /qn /norestart");
    let output = match std::process::Command::new("msiexec")
        .args([
            "/i",
            &msi_path.to_string_lossy(),
            "/qn", // Quiet, no UI
            "/norestart",
        ])
        .output()
    {
        Ok(output) => output,
        Err(e) => {
            eprintln!("[driver-installer] ERROR: Failed to run msiexec: {}", e);
            return ExitCode::from(1);
        }
    };

    let exit_code = output.status.code().unwrap_or(-1);
    match exit_code {
        0 => println!("[driver-installer] MSI installation completed successfully"),
        1638 => println!("[driver-installer] Driver already installed (different version)"),
        3010 => println!("[driver-installer] Installation succeeded (reboot recommended)"),
        code => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            eprintln!(
                "[driver-installer] ERROR: msiexec failed with code {}: {}",
                code, stderr
            );
            return ExitCode::from(1);
        }
    }

    // Wait for driver to become available
    println!("[driver-installer] Waiting for driver to initialize...");
    std::thread::sleep(std::time::Duration::from_secs(2));

    // Verify driver is available
    if verify_driver() {
        println!("[driver-installer] SUCCESS: NDISRD driver is available");
        ExitCode::from(0)
    } else {
        eprintln!("[driver-installer] WARNING: Driver installed but NDISRD not responding");
        eprintln!("[driver-installer] A reboot may be required");
        // Still return success since the MSI installed OK - driver may need reboot
        ExitCode::from(0)
    }
}

/// Search for WinpkFilter-x64.msi in known locations
fn find_msi() -> Option<PathBuf> {
    let candidates: Vec<PathBuf> = [
        // 1. Same directory as this exe: {exe_dir}\drivers\
        std::env::current_exe().ok().and_then(|p| {
            p.parent()
                .map(|d| d.join("drivers").join("WinpkFilter-x64.msi"))
        }),
        // 2. Velopack per-user install: %LOCALAPPDATA%\SwiftTunnel\drivers\
        std::env::var("LOCALAPPDATA").ok().map(|appdata| {
            PathBuf::from(appdata)
                .join("SwiftTunnel")
                .join("drivers")
                .join("WinpkFilter-x64.msi")
        }),
        // 3. Parent directory (for when exe is in a subdirectory): {exe_dir}\..\drivers\
        std::env::current_exe().ok().and_then(|p| {
            p.parent()
                .and_then(|d| d.parent())
                .map(|d| d.join("drivers").join("WinpkFilter-x64.msi"))
        }),
    ]
    .into_iter()
    .flatten()
    .collect();

    for path in candidates {
        if path.exists() {
            return Some(path);
        }
    }

    None
}

/// Verify that the NDISRD driver is available by trying to open it
fn verify_driver() -> bool {
    match ndisapi::Ndisapi::new("NDISRD") {
        Ok(_) => true,
        Err(_) => false,
    }
}
