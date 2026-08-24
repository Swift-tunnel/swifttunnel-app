//! Embeds a manifest that requires administrator, and stages the MSI payload.
//!
//! The manifest is the entire reason the launcher exists. The repair has to
//! write HKLM before `msiexec` starts, and the MSI itself cannot arrange that:
//! an immediate custom action impersonates an unelevated user, and a deferred
//! one runs as SYSTEM but cannot be sequenced ahead of RemoveExistingProducts.

use std::path::PathBuf;

use embed_manifest::{embed_manifest, manifest::ExecutionLevel, new_manifest};

fn main() {
    if std::env::var_os("CARGO_CFG_WINDOWS").is_some() {
        embed_manifest(
            new_manifest("SwiftTunnel.Setup")
                .requested_execution_level(ExecutionLevel::RequireAdministrator),
        )
        .expect("failed to embed the setup manifest");
    }

    stage_payload();

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=SWIFTTUNNEL_SETUP_MSI");
}

/// Copy the MSI this launcher wraps into OUT_DIR so `include_bytes!` can find
/// it at a stable path.
///
/// Going through OUT_DIR rather than `include_bytes!(env!(..))` directly keeps
/// the crate compiling when the variable is absent, which matters because
/// `cargo test --workspace` and CI's `cargo check` build every member and
/// neither of them has an MSI to hand. A release build without a payload is a
/// different matter and is refused outright: shipping a launcher that installs
/// nothing would be worse than not shipping one.
fn stage_payload() {
    let out = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR is always set"));
    let dest = out.join("payload.msi");

    match std::env::var_os("SWIFTTUNNEL_SETUP_MSI") {
        Some(src) => {
            let src = PathBuf::from(src);
            let bytes = std::fs::read(&src)
                .unwrap_or_else(|e| panic!("could not read {}: {e}", src.display()));
            assert!(
                bytes.len() > 1_000_000,
                "{} is only {} bytes, which is not a SwiftTunnel MSI",
                src.display(),
                bytes.len()
            );
            std::fs::write(&dest, bytes).expect("could not stage the MSI payload");
            println!("cargo:rerun-if-changed={}", src.display());
        }
        None if std::env::var("PROFILE").as_deref() == Ok("release") => {
            panic!(
                "SWIFTTUNNEL_SETUP_MSI is not set. A release build of the setup launcher must \
                 point at the MSI it should install, for example \
                 target/x86_64-pc-windows-msvc/release/bundle/msi/SwiftTunnel_<version>_x64_en-US.msi"
            );
        }
        None => {
            // Debug or check build: an empty payload keeps the workspace
            // compiling, and main() refuses to run rather than pretending.
            std::fs::write(&dest, []).expect("could not write the placeholder payload");
        }
    }
}
