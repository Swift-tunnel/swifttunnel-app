//! Command line front end for clearing an orphaned SwiftTunnel MSI
//! registration. See the library for why this exists.
//!
//! This is the hand-out tool for someone already stuck. The launcher
//! (`swifttunnel-setup`) does the same thing automatically before installing,
//! so most people should never need to run this.

use swifttunnel_msi_repair::{clear_registration, find_orphans, preserve_installer_sources};

#[derive(Debug, PartialEq, Eq)]
enum Options {
    Repair { dry_run: bool },
    Help,
}

fn options(arguments: impl IntoIterator<Item = std::ffi::OsString>) -> Result<Options, String> {
    let mut dry_run = false;
    let mut help = false;
    for argument in arguments {
        if argument == "--dry-run" {
            dry_run = true;
        } else if argument == "--help" || argument == "-h" {
            help = true;
        } else {
            return Err(format!(
                "Unknown option: {}. Run with --help to see the available options.",
                argument.to_string_lossy()
            ));
        }
    }
    Ok(if help {
        Options::Help
    } else {
        Options::Repair { dry_run }
    })
}

fn main() {
    // Parse before any source preservation or registry access. Help and a
    // mistyped option must never fall through to a real repair.
    let dry_run = match options(std::env::args_os().skip(1)) {
        Ok(Options::Repair { dry_run }) => dry_run,
        Ok(Options::Help) => {
            println!("Usage: swifttunnel-msi-repair [--dry-run]\n\nWith no options, preserves available installer sources and clears confirmed orphaned SwiftTunnel registrations.\n--dry-run  List orphaned registrations without changing anything.\n--help, -h Show this help without running a repair.");
            return;
        }
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(2);
        }
    };

    println!("SwiftTunnel MSI repair");
    println!("======================");

    // Prevention before cure. A machine whose package is still cached gets a
    // durable copy now, so a cleanup tool later costs it nothing. Nothing to
    // do on a machine that is already broken, which the repair below handles.
    if !dry_run {
        match preserve_installer_sources() {
            Ok(kept) if !kept.is_empty() => {
                println!();
                for product in &kept {
                    println!("Kept a durable installer copy for {product}.");
                }
            }
            Ok(_) => {}
            Err(error) => eprintln!("Could not preserve the installer source: {error}"),
        }
    }

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
        println!("No confirmed orphaned SwiftTunnel registration was found.");
        println!("If Setup still fails, send support its error message and code.");
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

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Options, String> {
        options(args.iter().map(std::ffi::OsString::from))
    }

    #[test]
    fn help_and_invalid_options_never_select_a_repair() {
        assert_eq!(parse(&[]), Ok(Options::Repair { dry_run: false }));
        assert_eq!(parse(&["--dry-run"]), Ok(Options::Repair { dry_run: true }));
        for args in [vec!["--help"], vec!["-h"], vec!["--dry-run", "--help"]] {
            assert_eq!(parse(&args), Ok(Options::Help));
        }
        for args in [
            vec!["--help-me"],
            vec!["--dryrun"],
            vec!["--dry-run", "unknown"],
            vec!["--help", "unknown"],
        ] {
            assert!(parse(&args).is_err());
        }
    }

    #[cfg(windows)]
    #[test]
    fn a_non_unicode_argument_is_rejected_without_panicking() {
        use std::os::windows::ffi::OsStringExt;
        let arg = std::ffi::OsString::from_wide(&[0xd800]);
        assert!(options([arg]).is_err());
    }
}
