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

fn main() {
    let attrs = tauri_build::Attributes::new().windows_attributes(
        tauri_build::WindowsAttributes::new().app_manifest(APP_MANIFEST),
    );
    tauri_build::try_build(attrs).expect("Failed to run tauri-build");
}
