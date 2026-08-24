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
    const DRIVER_PACKAGE_FILES: &[(&str, u64)] = &[
        ("ndisrd_lwf.inf", 256),
        ("ndisrd.sys", 4 * 1024),
        ("ndisrd.cat", 256),
    ];

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

    for arch in ["x64", "arm64"] {
        let package_dir = std::path::Path::new("resources")
            .join("drivers")
            .join("winpkfilter")
            .join(arch)
            .join("win10");
        println!("cargo:rerun-if-changed={}", package_dir.display());

        if !package_dir.is_dir() {
            panic!(
                "Bundled driver package directory `{}` is missing. Extract the WinpkFilter \
                 MSI payload into resources/drivers/winpkfilter/{}/win10 before building.",
                package_dir.display(),
                arch
            );
        }

        for (name, min_bytes) in DRIVER_PACKAGE_FILES {
            let path = package_dir.join(name);
            println!("cargo:rerun-if-changed={}", path.display());
            match std::fs::metadata(&path) {
                Ok(meta) if meta.is_file() && meta.len() >= *min_bytes => {}
                Ok(meta) if meta.is_file() => {
                    panic!(
                        "Bundled driver package file `{}` is suspiciously small ({} bytes, \
                         expected >= {}). Re-extract the WinpkFilter MSI payload.",
                        path.display(),
                        meta.len(),
                        min_bytes
                    );
                }
                Ok(_) => {
                    panic!(
                        "Bundled driver package path `{}` exists but is not a file.",
                        path.display()
                    );
                }
                Err(err) => {
                    panic!(
                        "Bundled driver package file `{}` is missing ({}). Re-extract the \
                         WinpkFilter MSI payload into resources/drivers/winpkfilter/{}/win10.",
                        path.display(),
                        err,
                        arch
                    );
                }
            }
        }
    }
}

/// Fail release builds if the NVIDIA Profile Inspector helper was not staged.
///
/// Ultraboost can apply its Roblox FastFlags without this helper, but the
/// NVIDIA-only potato graphics profile depends on
/// `nvidiaProfileInspector.exe`. The release workflow downloads the helper
/// into resources/tools before Tauri bundles updater artifacts; this guard
/// catches skipped downloads before users receive an update without the new
/// payload.
fn check_bundled_nvidia_profile_inspector() {
    const NPI_FILES: &[(&str, u64, Option<&str>)] = &[
        (
            "resources/tools/nvidiaProfileInspector/nvidiaProfileInspector.exe",
            900_000,
            Some("61452518fdd2464313e08589dd6b6e9d00d3fd36c1622e1105884ab1ad7334d4"),
        ),
        (
            "resources/tools/nvidiaProfileInspector/Reference.xml",
            800_000,
            Some("fb19d0ed9a8f1b95caa3675a94f80e2e14ae891c8fe83f164e0bb62513c2bb3f"),
        ),
        (
            "resources/tools/nvidiaProfileInspector/nvidiaProfileInspector.exe.config",
            100,
            Some("051099983b896673909e01a1f631b6652abb88da95c9f06f3efef4be033091fa"),
        ),
        (
            "resources/tools/nvidiaProfileInspector/nvidiaProfileInspector.pdb",
            100_000,
            Some("68ab6fe22594a906e40bb414a76a30106fa1c8d95f778c910f07e194623e7070"),
        ),
    ];

    for (rel, min_bytes, expected_hash) in NPI_FILES {
        println!("cargo:rerun-if-changed={}", rel);
        let path = std::path::Path::new(rel);
        match std::fs::metadata(path) {
            Ok(meta) if meta.is_file() && meta.len() >= *min_bytes => {
                if let Some(expected_hash) = expected_hash {
                    let actual_hash = file_sha256_with_powershell(path).unwrap_or_else(|err| {
                        panic!(
                            "Failed to hash bundled NVIDIA Profile Inspector helper `{}`: {}",
                            rel, err
                        )
                    });
                    if actual_hash != *expected_hash {
                        panic!(
                            "Bundled NVIDIA Profile Inspector helper `{}` failed SHA-256 check: \
                             expected {}, got {}. Re-run the release workflow's pinned helper download \
                             step and do not ship an unverified third-party binary.",
                            rel, expected_hash, actual_hash
                        );
                    }
                }
            }
            Ok(meta) if meta.is_file() => {
                panic!(
                    "Bundled NVIDIA Profile Inspector helper `{}` is suspiciously small ({} bytes, \
                     expected >= {}). Re-run the release workflow's helper download step, or fetch \
                     nvidiaProfileInspector.zip from https://github.com/Orbmu2k/nvidiaProfileInspector/releases",
                    rel,
                    meta.len(),
                    min_bytes
                );
            }
            Ok(_) => {
                panic!(
                    "Bundled NVIDIA Profile Inspector helper path `{}` exists but is not a file.",
                    rel
                );
            }
            Err(err) => {
                panic!(
                    "Bundled NVIDIA Profile Inspector helper `{}` is missing ({}). The updater must \
                     ship the complete helper directory so existing Ultraboost users receive the \
                     NVIDIA potato profile without a separate manual install.",
                    rel, err
                );
            }
        }
    }
}

/// Fail release builds if the GoodbyeDPI helper payload was not staged.
///
/// The country-ban bypass starts `goodbyedpi.exe` with a generated Roblox
/// hostlist. The executable must ship beside its matching WinDivert files or
/// the toggle can be enabled but will be unavailable at connect time.
fn check_bundled_goodbyedpi_helper() {
    const GOODBYEDPI_FILES: &[(&str, u64, Option<&str>)] = &[
        (
            "resources/tools/goodbyedpi/x86/goodbyedpi.exe",
            10_000,
            Some("234e7c679c3d36885bb9214fb86e4a555754c8416e2c6773e4832834f73ae686"),
        ),
        (
            "resources/tools/goodbyedpi/x86/WinDivert.dll",
            10_000,
            Some("ab3cdd99d4c710821070568995ca4cb58fb4273e9c0516a16e3335218438efcc"),
        ),
        (
            "resources/tools/goodbyedpi/x86/WinDivert32.sys",
            10_000,
            Some("b2ef49a10d07df6db483e86516d2dfaaaa2f30f4a93dd152fa85f09f891cd049"),
        ),
        (
            "resources/tools/goodbyedpi/x86/WinDivert64.sys",
            10_000,
            Some("53ab28ec00be6e6f8aefa9ee76fc2735e94d7f3f9dbc06eb2b7ac8cd3084a6af"),
        ),
        (
            "resources/tools/goodbyedpi/x86_64/goodbyedpi.exe",
            10_000,
            Some("331ac6c1d22ba5a0a217f3f27d0d823051869cafc8b8ef7f2002fa2accebc74e"),
        ),
        (
            "resources/tools/goodbyedpi/x86_64/WinDivert.dll",
            10_000,
            Some("a97859785a2df1d4462e7d48d33ccbd89fedd40dac4970f4afd89e63f59ee1ec"),
        ),
        (
            "resources/tools/goodbyedpi/x86_64/WinDivert64.sys",
            10_000,
            Some("53ab28ec00be6e6f8aefa9ee76fc2735e94d7f3f9dbc06eb2b7ac8cd3084a6af"),
        ),
        (
            "resources/tools/goodbyedpi/licenses/LICENSE-goodbyedpi.txt",
            100,
            None,
        ),
        (
            "resources/tools/goodbyedpi/licenses/LICENSE-windivert.txt",
            100,
            None,
        ),
    ];

    for (rel, min_bytes, expected_hash) in GOODBYEDPI_FILES {
        println!("cargo:rerun-if-changed={}", rel);
        let path = std::path::Path::new(rel);
        match std::fs::metadata(path) {
            Ok(meta) if meta.is_file() && meta.len() >= *min_bytes => {
                if let Some(expected_hash) = expected_hash {
                    let actual_hash = file_sha256_with_powershell(path).unwrap_or_else(|err| {
                        panic!(
                            "Failed to hash bundled GoodbyeDPI helper payload `{}`: {}",
                            rel, err
                        )
                    });
                    if actual_hash != *expected_hash {
                        panic!(
                            "Bundled GoodbyeDPI helper payload `{}` failed SHA-256 check: \
                             expected {}, got {}. Re-run the release workflow's pinned \
                             GoodbyeDPI download step and do not ship an unverified third-party binary.",
                            rel, expected_hash, actual_hash
                        );
                    }
                }
            }
            Ok(meta) if meta.is_file() => {
                panic!(
                    "Bundled GoodbyeDPI helper payload `{}` is suspiciously small ({} bytes, \
                     expected >= {}). Re-run the release workflow's pinned GoodbyeDPI download step.",
                    rel,
                    meta.len(),
                    min_bytes
                );
            }
            Ok(_) => {
                panic!(
                    "Bundled GoodbyeDPI helper payload path `{}` exists but is not a file.",
                    rel
                );
            }
            Err(err) => {
                panic!(
                    "Bundled GoodbyeDPI helper payload `{}` is missing ({}). The updater/MSI must \
                     ship the complete GoodbyeDPI directory for Bypass country bans to work.",
                    rel, err
                );
            }
        }
    }
}

fn file_sha256_with_powershell(path: &std::path::Path) -> Result<String, String> {
    let path = path
        .canonicalize()
        .map_err(|e| format!("failed to canonicalize path: {e}"))?;
    let quoted = powershell_single_quoted(&path.to_string_lossy());
    let script = format!("(Get-FileHash -LiteralPath '{quoted}' -Algorithm SHA256).Hash.ToLower()");
    let output = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
        .map_err(|e| format!("failed to run powershell: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "Get-FileHash exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .trim()
        .to_ascii_lowercase())
}

fn powershell_single_quoted(value: &str) -> String {
    value.replace('\'', "''")
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
        check_bundled_nvidia_profile_inspector();
        check_bundled_goodbyedpi_helper();
    }

    let attrs = tauri_build::Attributes::new()
        .windows_attributes(tauri_build::WindowsAttributes::new().app_manifest(APP_MANIFEST));
    tauri_build::try_build(attrs).expect("Failed to run tauri-build");
}
