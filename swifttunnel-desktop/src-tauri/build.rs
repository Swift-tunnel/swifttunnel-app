// `requireAdministrator` so UAC fires at process start. Runtime self-elevation
// via `ShellExecuteW("runas")` breaks for Standard User accounts — over-the-
// shoulder UAC prompts for a different admin's credentials, and the elevated
// copy then runs under that profile with a different `%LOCALAPPDATA%`, which
// invalidates the AES-GCM-sealed auth session (the key is derived from the
// data dir path).
//
// We pass the manifest through tauri-build's own `WindowsAttributes::app_manifest`
// rather than a separate crate like `embed-manifest`, because tauri-build already
// embeds a default manifest via the MSVC resource compiler — stacking a second
// manifest produced `CVTRES CVT1100: duplicate resource type:MANIFEST` at link
// time. Replacing Tauri's default is the only collision-free route.
const APP_MANIFEST: &str = r#"<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <dependency>
    <dependentAssembly>
      <assemblyIdentity
        type="win32"
        name="Microsoft.Windows.Common-Controls"
        version="6.0.0.0"
        processorArchitecture="*"
        publicKeyToken="6595b64144ccf1df"
        language="*"
      />
    </dependentAssembly>
  </dependency>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="requireAdministrator" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
</assembly>"#;

/// Fail the build early if the bundled WinpkFilter MSIs are missing or too
/// small to be real. This matters because without the MSI in resources/drivers,
/// the runtime has to fall back to telling the user to manually download from
/// wiresock/ndisapi — which many users can't or won't do, and the installer
/// warning shows up silently in logs (see ferdi's support log 2026-04-19:
/// "Bundled runtime asset not found: WinpkFilter-x64.msi"). CI is supposed to
/// populate these via `.github/workflows/release.yml` "Prepare bundled driver
/// payloads", but a skipped guard or failed download can slip through. This
/// guard catches both CI and local-dev cases: if the MSI isn't present when
/// tauri-build runs, the build stops with a clear message.
fn check_bundled_driver_msis() {
    // Match the paths listed in tauri.conf.json's `bundle.resources`.
    // If anyone moves the MSIs, this path must move too.
    const MSI_FILES: &[&str] = &[
        "resources/drivers/WinpkFilter-x64.msi",
        "resources/drivers/WinpkFilter-arm64.msi",
    ];
    // Real Windows Packet Filter MSIs are ~1-2MB. Anything under 500KB is
    // either a stub, a 404 HTML page, or a corrupt partial download.
    const MIN_MSI_BYTES: u64 = 500_000;

    for rel in MSI_FILES {
        println!("cargo:rerun-if-changed={}", rel);
        let path = std::path::Path::new(rel);
        match std::fs::metadata(path) {
            Ok(meta) => {
                if !meta.is_file() {
                    panic!(
                        "Bundled driver resource `{}` exists but isn't a file. Did something \
                         stomp the resources/drivers directory?",
                        rel
                    );
                }
                if meta.len() < MIN_MSI_BYTES {
                    panic!(
                        "Bundled driver resource `{}` is suspiciously small ({} bytes, expected \
                         >= {}). Re-run `.github/workflows/release.yml` \"Prepare bundled driver \
                         payloads\" or fetch the MSIs manually from \
                         https://github.com/wiresock/ndisapi/releases/tag/v3.6.2",
                        rel,
                        meta.len(),
                        MIN_MSI_BYTES
                    );
                }
            }
            Err(err) => {
                panic!(
                    "Bundled driver resource `{}` is missing ({}). The installer ships without \
                     WinpkFilter if this file isn't present when tauri-build runs. Run the CI's \
                     \"Prepare bundled driver payloads\" step, or fetch the MSIs from \
                     https://github.com/wiresock/ndisapi/releases/tag/v3.6.2 and place them in \
                     resources/drivers/.",
                    rel, err
                );
            }
        }
    }
}

fn main() {
    // Only enforce the MSI payload check for Windows release builds.
    // CARGO_CFG_TARGET_OS gates out macOS/Linux hosts; PROFILE gates out
    // debug/check builds so CI's `cargo check -p swifttunnel-desktop` stays
    // green (the MSIs are only fetched in the release workflow).
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows")
        && std::env::var("PROFILE").as_deref() == Ok("release")
    {
        check_bundled_driver_msis();
    }

    let attrs = tauri_build::Attributes::new()
        .windows_attributes(tauri_build::WindowsAttributes::new().app_manifest(APP_MANIFEST));
    tauri_build::try_build(attrs).expect("Failed to run tauri-build");
}
