//! The installer the website hands out.
//!
//! It exists for one reason: to run the orphaned-registration repair *before*
//! `msiexec` starts. That ordering cannot be achieved from inside the MSI, and
//! without it an upgrade on a machine whose cached package is missing dies on
//! "The feature you are trying to use is on a network resource that is
//! unavailable" with no way forward.
//!
//! Everything else is deliberately boring. It unpacks the MSI it was built
//! around, hands it to `msiexec` with the normal installer UI, waits, and
//! returns whatever msiexec returned. The user sees the same install they
//! always did, one UAC prompt earlier.
//!
//! No console window: the manifest asks for administrator, so Windows prompts
//! at launch, and msiexec draws the only UI. A flashing console would look
//! like a script running against the machine, which is exactly the impression
//! an unsigned installer does not need.

#![windows_subsystem = "windows"]

use std::process::Command;

/// The installer payload, staged into OUT_DIR by build.rs.
///
/// Empty on a debug or `cargo check` build, where there is no MSI to embed. A
/// release build without one is refused by build.rs, so an empty payload here
/// can only mean somebody ran the debug binary.
const MSI_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/payload.msi"));

/// Name used for the unpacked copy. Windows records the path it installed from
/// as the source, so this deliberately looks like a real installer name rather
/// than a random temporary file.
const MSI_NAME: &str = env!("SWIFTTUNNEL_SETUP_NAME");

fn main() {
    std::process::exit(run());
}

fn run() -> i32 {
    if MSI_BYTES.is_empty() {
        // A debug build carries no installer. Refuse rather than write a
        // zero byte file and hand msiexec something meaningless.
        return 2;
    }

    // Best effort, and never fatal. A machine that is not broken finds nothing
    // to do here, and a repair that fails should still let the install be
    // attempted: the worst case is the old error the user would have had
    // anyway, rather than an installer that refuses to start.
    let _ = swifttunnel_msi_repair::repair();

    let msi_path = std::env::temp_dir().join(MSI_NAME);
    if std::fs::write(&msi_path, MSI_BYTES).is_err() {
        return 1;
    }

    let status = Command::new("msiexec").arg("/i").arg(&msi_path).status();

    // Leave no installer lying around. It is version specific, so keeping it
    // would not help a future upgrade anyway.
    let _ = std::fs::remove_file(&msi_path);

    match status {
        Ok(s) => s.code().unwrap_or(1),
        Err(_) => 1,
    }
}
