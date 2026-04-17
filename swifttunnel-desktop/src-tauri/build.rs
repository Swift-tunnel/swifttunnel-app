use embed_manifest::manifest::ExecutionLevel;
use embed_manifest::{embed_manifest, new_manifest};

fn main() {
    // `requireAdministrator` so UAC fires at process start. Runtime self-
    // elevation via `ShellExecuteW("runas")` breaks for Standard User
    // accounts — over-the-shoulder UAC prompts for a different admin's
    // credentials, and the elevated copy then runs under that profile with
    // a different `%LOCALAPPDATA%`, which invalidates the AES-GCM-sealed
    // auth session (the key is derived from the data dir path).
    //
    // `embed_manifest` no-ops on non-Windows targets, so the unconditional
    // call is safe for macOS/Linux CI builds.
    embed_manifest(
        new_manifest("SwiftTunnel.Desktop")
            .requested_execution_level(ExecutionLevel::RequireAdministrator),
    )
    .expect("Failed to embed Windows application manifest");

    tauri_build::build();
}
