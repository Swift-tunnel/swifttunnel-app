//! Render the actual Desktop template with inert payloads for WiX table/ICE checks.
//! Output goes to the explicit scratch directory. Never install this fixture.
use std::path::PathBuf;

fn main() {
    let output = PathBuf::from(
        std::env::args_os()
            .nth(1)
            .expect("scratch output directory"),
    );
    std::fs::create_dir_all(&output).unwrap();
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf();
    let tauri = repo.join("swifttunnel-desktop/src-tauri");
    let template = std::fs::read_to_string(tauri.join("wix/main.wxs")).unwrap();
    let config: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(tauri.join("tauri.conf.json")).unwrap())
            .unwrap();
    let mut engine = handlebars::Handlebars::new();
    // Match the Tauri bundler's XML rendering behavior.
    engine.register_escape_fn(handlebars::no_escape);
    let data = serde_json::json!({
        "product_name": "SwiftTunnel", "manufacturer": "SwiftTunnel", "version": "3.1.5",
        "bundle_id": "net.swifttunnel.desktop", "allow_downgrades": true,
        "upgrade_code": config["bundle"]["windows"]["wix"]["upgradeCode"],
        "path_component_guid": "2C4BFFEA-DF0A-41E1-94EE-1B9A66C28BD2",
        "main_binary_path": std::env::current_exe().unwrap().display().to_string(),
        "icon_path": tauri.join("icons/icon.ico").display().to_string(),
        "component_group_refs": ["NsisMigration", "SwiftTunnelLite"],
        "deep_link_protocols": ["swifttunnel"]
    });
    let rendered = engine.render_template(&template, &data).unwrap();
    // This fixture uses the real upgrade family to verify authoring. Prevent an
    // accidental double-click from installing it or removing a real Desktop app.
    let rendered = rendered.replacen("<Media Id=", concat!(
        "<Condition Message=\"This is a sequence validation fixture and cannot be installed.\">0</Condition>\n",
        "<Media Id="
    ), 1);
    std::fs::write(output.join("main.wxs"), rendered).unwrap();
    std::fs::write(output.join("fixture.wxl"), r#"<WixLocalization Culture="en-us" xmlns="http://schemas.microsoft.com/wix/2006/localization">
<String Id="TauriLanguage">1033</String><String Id="TauriCodepage">1252</String>
<String Id="LaunchApp">Launch SwiftTunnel</String><String Id="InstallAppFeature">Install app</String>
<String Id="PathEnvVarFeature">PATH</String><String Id="DowngradeErrorMessage">Newer version installed</String>
</WixLocalization>"#).unwrap();
}
