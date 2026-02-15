use crate::hidden_command;
use crate::structs::*;
use log::{error, info, warn};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

#[cfg(windows)]
use std::os::windows::fs::MetadataExt;
#[cfg(windows)]
use windows::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_READONLY, SetFileAttributesW,
};

/// Current Roblox settings read from the XML file
#[derive(Debug, Clone)]
pub struct CurrentRobloxSettings {
    pub fps_cap: u32,
    pub graphics_quality: i32,
    pub fullscreen: bool,
}

pub struct RobloxOptimizer {
    settings_path: PathBuf,
    backup_path: PathBuf,
}

impl RobloxOptimizer {
    pub fn new() -> Self {
        // Find the GlobalBasicSettings XML file
        let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_default();
        let roblox_dir = PathBuf::from(&local_app_data).join("Roblox");

        // Find the GlobalBasicSettings file (could be numbered)
        let settings_path = Self::find_settings_file(&roblox_dir);

        Self {
            settings_path,
            backup_path: PathBuf::from("./roblox_settings_backup.xml"),
        }
    }

    /// Find the GlobalBasicSettings XML file
    fn find_settings_file(roblox_dir: &PathBuf) -> PathBuf {
        // Prefer any discovered GlobalBasicSettings_*.xml file and pick the highest index.
        let mut latest_indexed: Option<(u32, PathBuf)> = None;
        if let Ok(entries) = fs::read_dir(roblox_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_file() {
                    continue;
                }

                let Some(file_name) = path.file_name().and_then(|n| n.to_str()) else {
                    continue;
                };

                let Some(index) = Self::parse_settings_file_index(file_name) else {
                    continue;
                };

                if latest_indexed
                    .as_ref()
                    .map(|(best, _)| index > *best)
                    .unwrap_or(true)
                {
                    latest_indexed = Some((index, path));
                }
            }
        }

        if let Some((_, path)) = latest_indexed {
            info!("Found Roblox settings at: {:?}", path);
            return path;
        }

        // Try to find GlobalBasicSettings files with different numbers
        for i in (1..=20).rev() {
            let path = roblox_dir.join(format!("GlobalBasicSettings_{}.xml", i));
            if path.exists() {
                info!("Found Roblox settings at: {:?}", path);
                return path;
            }
        }

        // Fallback to standard name
        let standard_path = roblox_dir.join("GlobalBasicSettings_13.xml");
        info!("Using default settings path: {:?}", standard_path);
        standard_path
    }

    fn parse_settings_file_index(file_name: &str) -> Option<u32> {
        let prefix = "GlobalBasicSettings_";
        let suffix = ".xml";
        if !file_name.starts_with(prefix) || !file_name.ends_with(suffix) {
            return None;
        }

        let number_part = &file_name[prefix.len()..file_name.len() - suffix.len()];
        number_part.parse::<u32>().ok()
    }

    fn resolve_settings_path(&self) -> PathBuf {
        if self.settings_path.exists() {
            return self.settings_path.clone();
        }

        let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_default();
        let roblox_dir = PathBuf::from(&local_app_data).join("Roblox");
        Self::find_settings_file(&roblox_dir)
    }

    /// Get the path to the settings file
    pub fn get_settings_path(&self) -> &PathBuf {
        &self.settings_path
    }

    /// Read current Roblox settings from the XML file
    pub fn read_current_settings(&self) -> Result<CurrentRobloxSettings> {
        let settings_path = self.resolve_settings_path();
        if !settings_path.exists() {
            return Err(anyhow::anyhow!("Roblox settings file not found"));
        }

        let content = fs::read_to_string(&settings_path)?;

        // Parse FPS cap
        let fps_cap = Self::extract_int_value(&content, "FramerateCap").unwrap_or(60);

        // Parse graphics quality level
        let graphics_quality =
            Self::extract_int_value(&content, "GraphicsQualityLevel").unwrap_or(5);

        // Parse fullscreen
        let fullscreen = Self::extract_bool_value(&content, "Fullscreen").unwrap_or(false);

        Ok(CurrentRobloxSettings {
            fps_cap: fps_cap as u32,
            graphics_quality,
            fullscreen,
        })
    }

    /// Extract an integer value from XML content
    fn extract_int_value(content: &str, name: &str) -> Option<i32> {
        // Look for pattern: <int name="FieldName">value</int>
        let pattern = format!("<int name=\"{}\">", name);
        if let Some(start) = content.find(&pattern) {
            let value_start = start + pattern.len();
            if let Some(end) = content[value_start..].find("</int>") {
                let value_str = &content[value_start..value_start + end];
                return value_str.trim().parse().ok();
            }
        }

        // Also check for token type (used for SavedQualityLevel)
        let token_pattern = format!("<token name=\"{}\">", name);
        if let Some(start) = content.find(&token_pattern) {
            let value_start = start + token_pattern.len();
            if let Some(end) = content[value_start..].find("</token>") {
                let value_str = &content[value_start..value_start + end];
                return value_str.trim().parse().ok();
            }
        }

        None
    }

    /// Extract a boolean value from XML content
    fn extract_bool_value(content: &str, name: &str) -> Option<bool> {
        let pattern = format!("<bool name=\"{}\">", name);
        if let Some(start) = content.find(&pattern) {
            let value_start = start + pattern.len();
            if let Some(end) = content[value_start..].find("</bool>") {
                let value_str = &content[value_start..value_start + end]
                    .trim()
                    .to_lowercase();
                return Some(value_str == "true");
            }
        }
        None
    }

    /// Remove read-only attribute from a file (Windows only)
    #[cfg(windows)]
    fn remove_readonly(&self) -> Result<()> {
        Self::remove_readonly_path(&self.settings_path)
    }

    #[cfg(windows)]
    fn remove_readonly_path(path: &PathBuf) -> Result<()> {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;

        let path_wide: Vec<u16> = OsStr::new(path)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        unsafe {
            SetFileAttributesW(
                windows::core::PCWSTR::from_raw(path_wide.as_ptr()),
                FILE_ATTRIBUTE_NORMAL,
            )?;
        }

        info!("Removed read-only attribute from settings file");
        Ok(())
    }

    /// Set read-only attribute on a file (Windows only)
    #[cfg(windows)]
    fn set_readonly(&self) -> Result<()> {
        Self::set_readonly_path(&self.settings_path)
    }

    #[cfg(windows)]
    fn set_readonly_path(path: &PathBuf) -> Result<()> {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;

        let path_wide: Vec<u16> = OsStr::new(path)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        unsafe {
            SetFileAttributesW(
                windows::core::PCWSTR::from_raw(path_wide.as_ptr()),
                FILE_ATTRIBUTE_READONLY,
            )?;
        }

        info!("Set read-only attribute on settings file to prevent Roblox from overwriting");
        Ok(())
    }

    /// Check if file is read-only (Windows only)
    #[cfg(windows)]
    fn is_readonly(&self) -> bool {
        Self::is_readonly_path(&self.settings_path)
    }

    #[cfg(windows)]
    fn is_readonly_path(path: &PathBuf) -> bool {
        if let Ok(metadata) = fs::metadata(path) {
            // FILE_ATTRIBUTE_READONLY = 0x1
            (metadata.file_attributes() & 0x1) != 0
        } else {
            false
        }
    }

    #[cfg(not(windows))]
    fn remove_readonly(&self) -> Result<()> {
        Self::remove_readonly_path(&self.settings_path)
    }

    #[cfg(not(windows))]
    fn remove_readonly_path(path: &PathBuf) -> Result<()> {
        // On non-Windows, use permissions
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(0o644); // rw-r--r--
        fs::set_permissions(path, perms)?;
        Ok(())
    }

    #[cfg(not(windows))]
    fn set_readonly(&self) -> Result<()> {
        Self::set_readonly_path(&self.settings_path)
    }

    #[cfg(not(windows))]
    fn set_readonly_path(path: &PathBuf) -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(0o444); // r--r--r--
        fs::set_permissions(path, perms)?;
        Ok(())
    }

    #[cfg(not(windows))]
    fn is_readonly(&self) -> bool {
        Self::is_readonly_path(&self.settings_path)
    }

    #[cfg(not(windows))]
    fn is_readonly_path(path: &PathBuf) -> bool {
        if let Ok(metadata) = fs::metadata(path) {
            metadata.permissions().readonly()
        } else {
            false
        }
    }

    /// Apply Roblox-specific optimizations
    pub fn apply_optimizations(&self, config: &RobloxSettingsConfig) -> Result<()> {
        info!("Applying Roblox optimizations via GlobalBasicSettings");
        let settings_path = self.resolve_settings_path();

        if !settings_path.exists() {
            return Err(anyhow::anyhow!(
                "Roblox settings file not found. Please ensure Roblox is installed and has been run at least once."
            ));
        }

        // Remove read-only if it was set (so we can write)
        if Self::is_readonly_path(&settings_path) {
            info!("Settings file is read-only, removing attribute to apply changes...");
            if let Err(e) = Self::remove_readonly_path(&settings_path) {
                error!("Failed to remove read-only attribute: {}", e);
                return Err(anyhow::anyhow!(
                    "Cannot modify settings: file is read-only and we couldn't remove the attribute. Error: {}",
                    e
                ));
            }
        }

        // Backup current settings first
        self.backup_settings_for(&settings_path)?;

        // Read current content
        let mut content = fs::read_to_string(&settings_path)?;

        // Apply FPS cap
        if config.unlock_fps {
            content = self.set_xml_int_value(&content, "FramerateCap", config.target_fps as i32);
            info!("Set FPS cap to: {}", config.target_fps);
        }

        // Apply graphics quality
        let quality_value = self.graphics_quality_to_int(&config.graphics_quality);
        content = self.set_xml_int_value(&content, "GraphicsQualityLevel", quality_value);
        content = self.set_xml_token_value(&content, "SavedQualityLevel", quality_value);
        info!("Set graphics quality to level: {}", quality_value);

        // Write updated content back
        fs::write(&settings_path, &content)?;

        // Note: We no longer set the file to read-only. Setting it read-only
        // caused Roblox to fail with "Failed to apply critical settings" because
        // Roblox needs to write to this file during its startup sequence.
        // The FPS settings may be reset by Roblox, but the background monitor
        // will re-detect and re-apply them when needed.

        // Apply FFlag optimizations (shadows, post-processing, texture quality, dynamic render)
        if let Err(e) = self.apply_client_fflags(config) {
            warn!("Could not apply FFlag optimizations: {}", e);
        }

        info!("Roblox optimizations applied successfully");
        Ok(())
    }

    /// Convert GraphicsQuality enum to integer value
    fn graphics_quality_to_int(&self, quality: &GraphicsQuality) -> i32 {
        match quality {
            GraphicsQuality::Automatic => 0,
            GraphicsQuality::Manual => 0,
            GraphicsQuality::Level1 => 1,
            GraphicsQuality::Level2 => 2,
            GraphicsQuality::Level3 => 3,
            GraphicsQuality::Level4 => 4,
            GraphicsQuality::Level5 => 5,
            GraphicsQuality::Level6 => 6,
            GraphicsQuality::Level7 => 7,
            GraphicsQuality::Level8 => 8,
            GraphicsQuality::Level9 => 9,
            GraphicsQuality::Level10 => 10,
        }
    }

    /// Set an integer value in the XML content
    fn set_xml_int_value(&self, content: &str, name: &str, value: i32) -> String {
        let pattern = format!("<int name=\"{}\">", name);

        if let Some(start) = content.find(&pattern) {
            let value_start = start + pattern.len();
            if let Some(end_offset) = content[value_start..].find("</int>") {
                let before = &content[..value_start];
                let after = &content[value_start + end_offset..];
                return format!("{}{}{}", before, value, after);
            }
        }

        // If not found, return original content
        content.to_string()
    }

    /// Set a token value in the XML content
    fn set_xml_token_value(&self, content: &str, name: &str, value: i32) -> String {
        let pattern = format!("<token name=\"{}\">", name);

        if let Some(start) = content.find(&pattern) {
            let value_start = start + pattern.len();
            if let Some(end_offset) = content[value_start..].find("</token>") {
                let before = &content[..value_start];
                let after = &content[value_start + end_offset..];
                return format!("{}{}{}", before, value, after);
            }
        }

        content.to_string()
    }

    /// Set a boolean value in the XML content
    fn set_xml_bool_value(&self, content: &str, name: &str, value: bool) -> String {
        let pattern = format!("<bool name=\"{}\">", name);
        let value_str = if value { "true" } else { "false" };

        if let Some(start) = content.find(&pattern) {
            let value_start = start + pattern.len();
            if let Some(end_offset) = content[value_start..].find("</bool>") {
                let before = &content[..value_start];
                let after = &content[value_start + end_offset..];
                return format!("{}{}{}", before, value_str, after);
            }
        }

        content.to_string()
    }

    /// Backup current Roblox settings
    fn backup_settings(&self) -> Result<()> {
        self.backup_settings_for(&self.settings_path)
    }

    fn backup_settings_for(&self, settings_path: &PathBuf) -> Result<()> {
        if settings_path.exists() {
            info!("Creating backup of Roblox settings");
            fs::copy(settings_path, &self.backup_path)?;
            info!("Backup created at: {:?}", self.backup_path);
        }
        Ok(())
    }

    /// Restore original settings from backup
    pub fn restore_settings(&self) -> Result<()> {
        info!("Restoring original Roblox settings from backup");

        if !self.backup_path.exists() {
            warn!("No backup file found");
            return Ok(());
        }

        let settings_path = self.resolve_settings_path();

        // Remove read-only if set (so we can restore)
        if Self::is_readonly_path(&settings_path) {
            let _ = Self::remove_readonly_path(&settings_path);
        }

        fs::copy(&self.backup_path, &settings_path)?;

        // Remove all FFlag optimizations when restoring
        if let Err(e) = self.remove_all_fflags() {
            warn!("Could not remove FFlag optimizations during restore: {}", e);
        }

        // Don't set read-only after restore - user is disabling optimizations
        info!("Settings restored successfully");
        Ok(())
    }

    /// Check if Roblox is installed (settings file exists)
    pub fn is_roblox_installed(&self) -> bool {
        self.resolve_settings_path().exists()
    }

    /// Check whether a Roblox client process is currently running.
    pub fn is_roblox_running(&self) -> bool {
        let process_names = ["RobloxPlayerBeta.exe", "Windows10Universal.exe"];

        process_names.iter().any(|process_name| {
            hidden_command("tasklist")
                .args(["/FI", &format!("IMAGENAME eq {}", process_name)])
                .output()
                .map(|output| {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    stdout.contains(process_name)
                })
                .unwrap_or(false)
        })
    }

    /// Force-close running Roblox client processes.
    pub fn close_running_instances(&self) -> Result<()> {
        let process_names = ["RobloxPlayerBeta.exe", "Windows10Universal.exe"];

        for process_name in process_names {
            let output = hidden_command("taskkill")
                .args(["/F", "/T", "/IM", process_name])
                .output();

            match output {
                Ok(result) => {
                    if result.status.success() {
                        info!("Closed Roblox process: {}", process_name);
                    } else {
                        let stderr = String::from_utf8_lossy(&result.stderr).to_lowercase();
                        let stdout = String::from_utf8_lossy(&result.stdout).to_lowercase();
                        let not_running = stderr.contains("not found")
                            || stderr.contains("not running")
                            || stdout.contains("not found")
                            || stdout.contains("not running")
                            || stdout.contains("no running instance");
                        if !not_running {
                            warn!(
                                "Taskkill for {} returned non-zero status: {}",
                                process_name, stderr
                            );
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to execute taskkill for {}: {}", process_name, e);
                }
            }
        }

        Ok(())
    }

    /// Reopen Roblox after applying boosts.
    pub fn reopen_client(&self) -> Result<()> {
        if let Some(version_folder) = Self::find_roblox_version_folder() {
            let exe_path = version_folder.join("RobloxPlayerBeta.exe");
            if exe_path.exists() {
                match std::process::Command::new(&exe_path).spawn() {
                    Ok(_) => {
                        info!("Relaunched Roblox from {:?}", exe_path);
                        return Ok(());
                    }
                    Err(e) => {
                        warn!("Failed to relaunch Roblox executable directly: {}", e);
                    }
                }
            }
        }

        // Fallback: launch via protocol handler.
        let output = hidden_command("cmd")
            .args(["/C", "start", "", "roblox://"])
            .spawn();

        match output {
            Ok(_) => {
                info!("Relaunched Roblox via roblox:// protocol");
                Ok(())
            }
            Err(e) => Err(anyhow::anyhow!("Failed to relaunch Roblox: {}", e)),
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════════
    //  DYNAMIC RENDER OPTIMIZATION
    // ═══════════════════════════════════════════════════════════════════════════════

    /// Find the current Roblox version folder
    /// Returns the path to the latest version-* directory
    fn find_roblox_version_folder() -> Option<PathBuf> {
        let local_app_data = std::env::var("LOCALAPPDATA").ok()?;
        let versions_dir = PathBuf::from(&local_app_data)
            .join("Roblox")
            .join("Versions");

        if !versions_dir.exists() {
            return None;
        }

        // Find the most recently modified version-* folder
        let mut latest_version: Option<(PathBuf, std::time::SystemTime)> = None;

        if let Ok(entries) = fs::read_dir(&versions_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    let name = path.file_name()?.to_string_lossy();
                    if name.starts_with("version-") {
                        // Check if RobloxPlayerBeta.exe exists in this folder
                        if path.join("RobloxPlayerBeta.exe").exists() {
                            if let Ok(metadata) = entry.metadata() {
                                if let Ok(modified) = metadata.modified() {
                                    if latest_version.is_none()
                                        || modified > latest_version.as_ref()?.1
                                    {
                                        latest_version = Some((path, modified));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        latest_version.map(|(path, _)| path)
    }

    /// Get the ClientSettings folder path (creates it if needed)
    fn get_client_settings_path() -> Option<PathBuf> {
        let version_folder = Self::find_roblox_version_folder()?;
        let client_settings = version_folder.join("ClientSettings");

        // Create ClientSettings folder if it doesn't exist
        if !client_settings.exists() {
            if let Err(e) = fs::create_dir_all(&client_settings) {
                error!("Failed to create ClientSettings folder: {}", e);
                return None;
            }
            info!("Created ClientSettings folder at: {:?}", client_settings);
        }

        Some(client_settings)
    }

    /// Apply all FFlag optimizations to ClientAppSettings.json
    /// Handles: dynamic render, shadows, post-processing, texture quality
    fn apply_client_fflags(&self, config: &RobloxSettingsConfig) -> Result<()> {
        let client_settings = Self::get_client_settings_path()
            .ok_or_else(|| anyhow::anyhow!("Could not find Roblox version folder"))?;

        let settings_path = client_settings.join("ClientAppSettings.json");

        // Read existing settings if file exists
        let mut settings: HashMap<String, serde_json::Value> = if settings_path.exists() {
            fs::read_to_string(&settings_path)
                .ok()
                .and_then(|content| serde_json::from_str(&content).ok())
                .unwrap_or_default()
        } else {
            HashMap::new()
        };

        // Dynamic render optimization
        if let Some(render_value) = config.dynamic_render_optimization.render_value() {
            settings.insert(
                "DFIntDebugDynamicRenderKiloPixels".to_string(),
                serde_json::json!(render_value),
            );
        } else {
            settings.remove("DFIntDebugDynamicRenderKiloPixels");
        }

        // Disable shadows via FFlags
        if config.disable_shadows {
            settings.insert(
                "FIntRenderShadowIntensity".to_string(),
                serde_json::json!(0),
            );
            settings.insert(
                "DFFlagDebugPauseVoxelizer".to_string(),
                serde_json::json!("true"),
            );
        } else {
            settings.remove("FIntRenderShadowIntensity");
            settings.remove("DFFlagDebugPauseVoxelizer");
        }

        // Disable post-processing effects via FFlags
        if config.disable_post_processing {
            settings.insert("FFlagDisablePostFx".to_string(), serde_json::json!("true"));
        } else {
            settings.remove("FFlagDisablePostFx");
        }

        // Reduce texture quality via FFlags (skip mip levels = lower quality textures)
        if config.reduce_texture_quality {
            settings.insert(
                "FIntDebugTextureManagerSkipMips".to_string(),
                serde_json::json!(3),
            );
        } else {
            settings.remove("FIntDebugTextureManagerSkipMips");
        }

        // Write or delete the file
        if settings.is_empty() {
            if settings_path.exists() {
                fs::remove_file(&settings_path)?;
            }
        } else {
            let json = serde_json::to_string_pretty(&settings)?;
            fs::write(&settings_path, json)?;
        }

        info!("FFlag optimizations applied to ClientAppSettings.json");
        Ok(())
    }

    /// Remove all SwiftTunnel FFlag settings from ClientAppSettings.json
    fn remove_all_fflags(&self) -> Result<()> {
        let client_settings = match Self::get_client_settings_path() {
            Some(path) => path,
            None => {
                info!("No Roblox version folder found, skipping FFlag cleanup");
                return Ok(());
            }
        };

        let settings_path = client_settings.join("ClientAppSettings.json");

        if settings_path.exists() {
            let content = fs::read_to_string(&settings_path)?;
            let mut settings: HashMap<String, serde_json::Value> =
                serde_json::from_str(&content).unwrap_or_default();

            // Remove all our FFlags
            let our_keys = [
                "DFIntDebugDynamicRenderKiloPixels",
                "FIntRenderShadowIntensity",
                "DFFlagDebugPauseVoxelizer",
                "FFlagDisablePostFx",
                "FIntDebugTextureManagerSkipMips",
            ];
            for key in our_keys {
                settings.remove(key);
            }

            if settings.is_empty() {
                fs::remove_file(&settings_path)?;
            } else {
                let json = serde_json::to_string_pretty(&settings)?;
                fs::write(&settings_path, json)?;
            }
            info!("FFlag optimizations removed from ClientAppSettings.json");
        }

        Ok(())
    }

    /// Apply dynamic render optimization
    pub fn apply_dynamic_render_optimization(
        &self,
        mode: &crate::structs::DynamicRenderMode,
    ) -> Result<()> {
        // If mode is Off, remove the setting
        let render_value = match mode.render_value() {
            Some(v) => v,
            None => return self.remove_dynamic_render_optimization(),
        };

        let client_settings = Self::get_client_settings_path()
            .ok_or_else(|| anyhow::anyhow!("Could not find Roblox version folder"))?;

        let settings_path = client_settings.join("ClientAppSettings.json");

        // Build settings map
        let mut settings: HashMap<String, serde_json::Value> = HashMap::new();

        // Read existing settings if file exists
        if settings_path.exists() {
            if let Ok(content) = fs::read_to_string(&settings_path) {
                if let Ok(existing) =
                    serde_json::from_str::<HashMap<String, serde_json::Value>>(&content)
                {
                    settings = existing;
                }
            }
        }

        // Dynamic render optimization - reduces render load for better performance
        // Low=3, Medium=2, High=1 (lower value = more aggressive optimization)
        settings.insert(
            "DFIntDebugDynamicRenderKiloPixels".to_string(),
            serde_json::json!(render_value),
        );

        // Write settings to file
        let json = serde_json::to_string_pretty(&settings)?;
        fs::write(&settings_path, json)?;

        info!("Dynamic render optimization enabled ({:?})", mode);

        Ok(())
    }

    /// Remove dynamic render optimization settings
    fn remove_dynamic_render_optimization(&self) -> Result<()> {
        let client_settings = match Self::get_client_settings_path() {
            Some(path) => path,
            None => {
                info!("No Roblox version folder found, skipping cleanup");
                return Ok(());
            }
        };

        let settings_path = client_settings.join("ClientAppSettings.json");

        if settings_path.exists() {
            let content = fs::read_to_string(&settings_path)?;
            let mut settings: HashMap<String, serde_json::Value> =
                serde_json::from_str(&content).unwrap_or_default();

            // Remove our setting
            settings.remove("DFIntDebugDynamicRenderKiloPixels");

            if settings.is_empty() {
                fs::remove_file(&settings_path)?;
                info!("Dynamic render optimization disabled");
            } else {
                let json = serde_json::to_string_pretty(&settings)?;
                fs::write(&settings_path, json)?;
                info!("Dynamic render optimization disabled");
            }
        }

        Ok(())
    }
}

impl Default for RobloxOptimizer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Helper: create a RobloxOptimizer pointing at a specific path
    fn optimizer_with_path(settings_path: PathBuf) -> RobloxOptimizer {
        RobloxOptimizer {
            settings_path,
            backup_path: PathBuf::from("test_backup.xml"),
        }
    }

    // ── extract_int_value ───────────────────────────────────────────

    #[test]
    fn extract_int_value_parses_int_tag() {
        let xml = r#"<roblox><int name="FramerateCap">144</int></roblox>"#;
        assert_eq!(
            RobloxOptimizer::extract_int_value(xml, "FramerateCap"),
            Some(144)
        );
    }

    #[test]
    fn extract_int_value_returns_none_for_missing_field() {
        let xml = r#"<roblox><int name="FramerateCap">60</int></roblox>"#;
        assert_eq!(RobloxOptimizer::extract_int_value(xml, "NonExistent"), None);
    }

    #[test]
    fn extract_int_value_parses_token_tag() {
        let xml = r#"<roblox><token name="SavedQualityLevel">7</token></roblox>"#;
        assert_eq!(
            RobloxOptimizer::extract_int_value(xml, "SavedQualityLevel"),
            Some(7)
        );
    }

    #[test]
    fn extract_int_value_returns_none_for_non_numeric() {
        let xml = r#"<roblox><int name="FramerateCap">abc</int></roblox>"#;
        assert_eq!(
            RobloxOptimizer::extract_int_value(xml, "FramerateCap"),
            None
        );
    }

    #[test]
    fn extract_int_value_handles_whitespace() {
        let xml = r#"<roblox><int name="FramerateCap">  240  </int></roblox>"#;
        assert_eq!(
            RobloxOptimizer::extract_int_value(xml, "FramerateCap"),
            Some(240)
        );
    }

    // ── extract_bool_value ──────────────────────────────────────────

    #[test]
    fn extract_bool_value_parses_true() {
        let xml = r#"<roblox><bool name="Fullscreen">true</bool></roblox>"#;
        assert_eq!(
            RobloxOptimizer::extract_bool_value(xml, "Fullscreen"),
            Some(true)
        );
    }

    #[test]
    fn extract_bool_value_parses_false() {
        let xml = r#"<roblox><bool name="Fullscreen">false</bool></roblox>"#;
        assert_eq!(
            RobloxOptimizer::extract_bool_value(xml, "Fullscreen"),
            Some(false)
        );
    }

    #[test]
    fn extract_bool_value_case_insensitive() {
        let xml = r#"<roblox><bool name="Fullscreen">True</bool></roblox>"#;
        assert_eq!(
            RobloxOptimizer::extract_bool_value(xml, "Fullscreen"),
            Some(true)
        );
    }

    #[test]
    fn extract_bool_value_returns_none_for_missing() {
        let xml = r#"<roblox><bool name="Fullscreen">true</bool></roblox>"#;
        assert_eq!(RobloxOptimizer::extract_bool_value(xml, "Missing"), None);
    }

    // ── set_xml_int_value ───────────────────────────────────────────

    #[test]
    fn set_xml_int_value_replaces_existing() {
        let xml = r#"<roblox><int name="FramerateCap">60</int></roblox>"#;
        let opt = optimizer_with_path(PathBuf::from("dummy"));
        let result = opt.set_xml_int_value(xml, "FramerateCap", 999);
        assert_eq!(
            result,
            r#"<roblox><int name="FramerateCap">999</int></roblox>"#
        );
    }

    #[test]
    fn set_xml_int_value_returns_original_if_not_found() {
        let xml = r#"<roblox><int name="FramerateCap">60</int></roblox>"#;
        let opt = optimizer_with_path(PathBuf::from("dummy"));
        let result = opt.set_xml_int_value(xml, "NonExistent", 123);
        assert_eq!(result, xml);
    }

    // ── graphics_quality_to_int ─────────────────────────────────────

    #[test]
    fn graphics_quality_to_int_all_variants() {
        let opt = optimizer_with_path(PathBuf::from("dummy"));
        assert_eq!(opt.graphics_quality_to_int(&GraphicsQuality::Automatic), 0);
        assert_eq!(opt.graphics_quality_to_int(&GraphicsQuality::Manual), 0);
        assert_eq!(opt.graphics_quality_to_int(&GraphicsQuality::Level1), 1);
        assert_eq!(opt.graphics_quality_to_int(&GraphicsQuality::Level2), 2);
        assert_eq!(opt.graphics_quality_to_int(&GraphicsQuality::Level3), 3);
        assert_eq!(opt.graphics_quality_to_int(&GraphicsQuality::Level4), 4);
        assert_eq!(opt.graphics_quality_to_int(&GraphicsQuality::Level5), 5);
        assert_eq!(opt.graphics_quality_to_int(&GraphicsQuality::Level6), 6);
        assert_eq!(opt.graphics_quality_to_int(&GraphicsQuality::Level7), 7);
        assert_eq!(opt.graphics_quality_to_int(&GraphicsQuality::Level8), 8);
        assert_eq!(opt.graphics_quality_to_int(&GraphicsQuality::Level9), 9);
        assert_eq!(opt.graphics_quality_to_int(&GraphicsQuality::Level10), 10);
    }

    // ── find_settings_file ──────────────────────────────────────────

    #[test]
    fn find_settings_file_picks_highest_numbered() {
        let dir = std::env::temp_dir().join("roblox_opt_test_find");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        // Create files 5 and 10
        fs::write(dir.join("GlobalBasicSettings_5.xml"), "a").unwrap();
        fs::write(dir.join("GlobalBasicSettings_10.xml"), "b").unwrap();

        let result = RobloxOptimizer::find_settings_file(&dir);
        assert_eq!(result, dir.join("GlobalBasicSettings_10.xml"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn find_settings_file_falls_back_to_default() {
        let dir = std::env::temp_dir().join("roblox_opt_test_fallback");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        // No settings files exist
        let result = RobloxOptimizer::find_settings_file(&dir);
        assert_eq!(result, dir.join("GlobalBasicSettings_13.xml"));

        let _ = fs::remove_dir_all(&dir);
    }

    // ── read_current_settings ───────────────────────────────────────

    #[test]
    fn read_current_settings_parses_xml() {
        let dir = std::env::temp_dir().join("roblox_opt_test_read");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let xml = r#"<roblox>
            <int name="FramerateCap">240</int>
            <int name="GraphicsQualityLevel">8</int>
            <bool name="Fullscreen">true</bool>
        </roblox>"#;

        let path = dir.join("settings.xml");
        fs::write(&path, xml).unwrap();

        let opt = optimizer_with_path(path);
        let settings = opt.read_current_settings().unwrap();

        assert_eq!(settings.fps_cap, 240);
        assert_eq!(settings.graphics_quality, 8);
        assert!(settings.fullscreen);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_current_settings_uses_defaults_for_missing() {
        let dir = std::env::temp_dir().join("roblox_opt_test_defaults");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let xml = r#"<roblox></roblox>"#;
        let path = dir.join("settings.xml");
        fs::write(&path, xml).unwrap();

        let opt = optimizer_with_path(path);
        let settings = opt.read_current_settings().unwrap();

        assert_eq!(settings.fps_cap, 60);
        assert_eq!(settings.graphics_quality, 5);
        assert!(!settings.fullscreen);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_current_settings_errors_if_file_missing() {
        let opt = optimizer_with_path(PathBuf::from("nonexistent_file.xml"));
        assert!(opt.read_current_settings().is_err());
    }
}
