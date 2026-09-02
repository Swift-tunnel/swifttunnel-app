//! The installer the website hands out.
//!
//! It does two things the MSI cannot do for itself, and they are opposite ends
//! of the same failure.
//!
//! It runs the orphaned-registration repair *before* `msiexec` starts, which no
//! custom action inside an MSI can be sequenced to do. Without that, an upgrade
//! on a machine whose cached package is missing dies on "The feature you are
//! trying to use is on a network resource that is unavailable" with no way
//! forward. That is the cure.
//!
//! And it leaves the package it installed from somewhere permanent, so the next
//! upgrade has a source to fall back on when Windows' own cached copy is
//! deleted. That is the prevention, and it is the more important half: it used
//! to install out of `%TEMP%` and delete the file immediately afterwards, so
//! every install made here started out needing the repair.
//!
//! The rest is deliberately boring. It hands the MSI to `msiexec` with the
//! normal installer UI, waits, and returns whatever msiexec returned. The user
//! sees the same install they always did, one UAC prompt earlier.
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

    let Some(msi_path) = stage_payload() else {
        return 1;
    };

    let status = Command::new("msiexec").arg("/i").arg(&msi_path).status();

    // The installer stays where it is. See `stage_payload`.
    prune_old_payloads(&msi_path);

    match status {
        Ok(s) => s.code().unwrap_or(1),
        Err(_) => 1,
    }
}

/// Where the payload is unpacked before msiexec runs.
///
/// `%ProgramData%`, and it is left there afterwards. Both halves of that matter
/// and both used to be wrong.
///
/// Windows records the directory it installed from as the product's
/// installation source. Removing a product needs that product's own package,
/// because the package is what describes what to remove, and a major upgrade
/// removes the old version before installing the new one. Windows keeps its own
/// copy under `C:\Windows\Installer` for this, but cleanup tools delete it, and
/// the source is the only fallback left when they do.
///
/// This used to unpack into `%TEMP%` and then delete the file as soon as
/// msiexec returned, reasoning that a version specific installer could not help
/// a later upgrade. That is backwards: the version specific installer is
/// exactly what the next upgrade asks for, because it is the package for the
/// version being removed. So every install made here was born pointing at a
/// file that no longer existed, and stayed one cleanup tool away from
/// "the feature you are trying to use is on a network resource that is
/// unavailable", with nothing able to repair it from inside the MSI.
///
/// The name carries a tag derived from the payload so two versions never
/// collide. Overwriting one name would leave the older product's source
/// pointing at a newer package, which Windows rejects just as firmly as a
/// missing one.
fn stage_payload() -> Option<std::path::PathBuf> {
    let dir = std::env::var_os("ProgramData")
        .map(|base| {
            std::path::PathBuf::from(base)
                .join("SwiftTunnel")
                .join("installers")
        })
        // Somewhere is better than nowhere: a machine without ProgramData set
        // still gets an install, just without the durable source.
        .unwrap_or_else(std::env::temp_dir);
    let _ = std::fs::create_dir_all(&dir);

    let path = dir.join(payload_file_name(MSI_NAME, &payload_tag()));

    // Already staged by an earlier run of this same build, and byte for byte
    // the same file, so rewriting it would only risk breaking a source another
    // product is relying on.
    if std::fs::metadata(&path).is_ok_and(|meta| meta.len() == MSI_BYTES.len() as u64) {
        return Some(path);
    }

    std::fs::write(&path, MSI_BYTES).ok().map(|()| path)
}

/// The staged file's name: the installer's name with a payload tag before the
/// extension.
///
/// Separate and pure because the property that matters is easy to get wrong and
/// invisible when it is: two versions must never land on the same name. If they
/// did, installing the newer one would overwrite the file the older product
/// records as its source, and Windows refuses a source holding the wrong
/// package just as firmly as a missing one, which is the failure this staging
/// exists to prevent.
fn payload_file_name(msi_name: &str, tag: &str) -> String {
    match msi_name.rsplit_once('.') {
        Some((stem, extension)) => format!("{stem}-{tag}.{extension}"),
        None => format!("{msi_name}-{tag}"),
    }
}

/// A short tag that differs whenever the payload does.
///
/// FNV-1a, because this only has to separate one build's installer from
/// another's. Nothing security related rests on it.
fn payload_tag() -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in MSI_BYTES {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{hash:016x}")
}

/// Keep the newest few installers and remove the rest.
///
/// Only what this launcher installs, matched on the same stem, so the full app
/// never prunes Lite's package or the reverse. Three is enough to cover the
/// version being replaced while not letting a folder of 15MB installers grow
/// without limit.
fn prune_old_payloads(current: &std::path::Path) {
    const KEEP: usize = 3;

    let (Some(dir), Some(stem)) = (current.parent(), MSI_NAME.rsplit_once('.').map(|(s, _)| s))
    else {
        return;
    };

    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut ours: Vec<_> = entries
        .flatten()
        .filter(|entry| {
            let path = entry.path();
            path != current
                && path.extension().and_then(|e| e.to_str()) == Some("msi")
                && path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|name| name.starts_with(stem))
        })
        .collect();

    ours.sort_by_key(|entry| {
        entry
            .metadata()
            .and_then(|m| m.modified())
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
    });

    while ours.len() >= KEEP {
        let oldest = ours.remove(0);
        let _ = std::fs::remove_file(oldest.path());
    }
}

#[cfg(test)]
mod tests {
    use super::payload_file_name;

    /// Two builds must never stage to the same filename.
    ///
    /// The whole point of staging is that the older product's recorded source
    /// keeps holding the older package. Installing a newer version over the
    /// same name would replace it, and Windows rejects a source containing the
    /// wrong package exactly as it rejects a missing one, which is the error
    /// this was built to stop.
    #[test]
    fn two_payloads_never_share_a_file_name() {
        let older = payload_file_name("SwiftTunnel-Installer.msi", "1111111111111111");
        let newer = payload_file_name("SwiftTunnel-Installer.msi", "2222222222222222");
        assert_ne!(older, newer);
    }

    /// The tag goes before the extension, not after.
    ///
    /// msiexec dispatches on `.msi`, so a name ending in the tag would not be
    /// recognised as a package at all.
    #[test]
    fn the_name_still_ends_in_msi() {
        let name = payload_file_name("SwiftTunnel-Installer.msi", "abc123");
        assert_eq!(name, "SwiftTunnel-Installer-abc123.msi");
        assert!(name.ends_with(".msi"));
    }

    /// The two products keep separate names, since they share the directory
    /// and each prunes only its own.
    #[test]
    fn the_full_app_and_lite_do_not_collide() {
        let tag = "deadbeefdeadbeef";
        assert_ne!(
            payload_file_name("SwiftTunnel-Installer.msi", tag),
            payload_file_name("SwiftTunnelLite-Installer.msi", tag)
        );
    }

    #[test]
    fn a_name_without_an_extension_still_gets_a_tag() {
        assert_eq!(payload_file_name("installer", "abc"), "installer-abc");
    }
}
