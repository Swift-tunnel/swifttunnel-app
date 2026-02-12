fn main() {
    // Embed Windows application manifest for proper DPI awareness and admin elevation
    #[cfg(windows)]
    {
        // Embed manifest requesting asInvoker (no UAC prompt)
        let manifest = embed_manifest::new_manifest("SwiftTunnel")
            .requested_execution_level(embed_manifest::ExecutionLevel::AsInvoker);
        embed_manifest::embed_manifest(manifest).expect("Failed to embed manifest");

        // Embed icon and version info
        let mut res = winres::WindowsResource::new();
        res.set_icon("icons/icon.ico");
        res.set("ProductName", "SwiftTunnel");
        res.set("FileDescription", "SwiftTunnel Gaming VPN");
        res.set("ProductVersion", env!("CARGO_PKG_VERSION"));
        if let Err(e) = res.compile() {
            eprintln!("Warning: Failed to compile Windows resources: {}", e);
        }
    }

    tauri_build::build();
}
