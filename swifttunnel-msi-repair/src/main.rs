//! Command line front end for clearing an orphaned SwiftTunnel MSI
//! registration. See the library for why this exists.
//!
//! This is the hand-out tool for someone already stuck. The launcher
//! (`swifttunnel-setup`) does the same thing automatically before installing,
//! so most people should never need to run this.

use swifttunnel_msi_repair::{clear_registration, find_orphans};

fn main() {
    let dry_run = std::env::args().any(|a| a == "--dry-run");

    println!("SwiftTunnel MSI repair");
    println!("======================");

    let orphans = match find_orphans() {
        Ok(o) => o,
        Err(e) => {
            eprintln!("Could not read the installer registry: {e}");
            eprintln!("Try running this as Administrator.");
            std::process::exit(2);
        }
    };

    if orphans.is_empty() {
        println!();
        println!("Nothing to repair. Either SwiftTunnel is not installed, or its");
        println!("installer package is still present and upgrades will work normally.");
        return;
    }

    for orphan in &orphans {
        println!();
        println!("Found a broken registration:");
        println!(
            "  Product      : {} {}",
            orphan.display_name, orphan.display_version
        );
        println!("  Product code : {}", orphan.product_code);
        println!("  Missing file : {}", orphan.local_package);

        if dry_run {
            println!("  -> --dry-run given, leaving it alone.");
            continue;
        }

        match clear_registration(orphan) {
            Ok(()) => println!("  -> Cleared. Install SwiftTunnel again and it will work."),
            Err(e) => {
                eprintln!("  -> Failed: {e}");
                eprintln!("     This needs Administrator. Right-click and Run as administrator.");
                std::process::exit(3);
            }
        }
    }
}
