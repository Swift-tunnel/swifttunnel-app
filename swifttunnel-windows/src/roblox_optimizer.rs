use crate::structs::*;
use log::{info, warn, error};
use std::path::PathBuf;
use std::fs;
use std::collections::HashMap;

#[cfg(windows)]
use std::os::windows::fs::MetadataExt;
#[cfg(windows)]
use windows::Win32::Storage::FileSystem::{SetFileAttributesW, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_READONLY};

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

    /// Get the path to the settings file
    pub fn get_settings_path(&self) -> &PathBuf {
        &self.settings_path
    }

    /// Read current Roblox settings from the XML file
    pub fn read_current_settings(&self) -> Result<CurrentRobloxSettings> {
        if !self.settings_path.exists() {
            return Err(anyhow::anyhow!("Roblox settings file not found"));
        }

        let content = fs::read_to_string(&self.settings_path)?;

        // Parse FPS cap
        let fps_cap = Self::extract_int_value(&content, "FramerateCap").unwrap_or(60);

        // Parse graphics quality level
        let graphics_quality = Self::extract_int_value(&content, "GraphicsQualityLevel").unwrap_or(5);

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
                let value_str = &content[value_start..value_start + end].trim().to_lowercase();
                return Some(value_str == "true");
            }
        }
        None
    }

    /// Remove read-only attribute from a file (Windows only)
    #[cfg(windows)]
    fn remove_readonly(&self) -> Result<()> {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;

        let path_wide: Vec<u16> = OsStr::new(&self.settings_path)
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
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;

        let path_wide: Vec<u16> = OsStr::new(&self.settings_path)
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
        if let Ok(metadata) = fs::metadata(&self.settings_path) {
            // FILE_ATTRIBUTE_READONLY = 0x1
            (metadata.file_attributes() & 0x1) != 0
        } else {
            false
        }
    }

    #[cfg(not(windows))]
    fn remove_readonly(&self) -> Result<()> {
        // On non-Windows, use permissions
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&self.settings_path)?.permissions();
        perms.set_mode(0o644); // rw-r--r--
        fs::set_permissions(&self.settings_path, perms)?;
        Ok(())
    }

    #[cfg(not(windows))]
    fn set_readonly(&self) -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&self.settings_path)?.permissions();
        perms.set_mode(0o444); // r--r--r--
        fs::set_permissions(&self.settings_path, perms)?;
        Ok(())
    }

    #[cfg(not(windows))]
    fn is_readonly(&self) -> bool {
        if let Ok(metadata) = fs::metadata(&self.settings_path) {
            metadata.permissions().readonly()
        } else {
            false
        }
    }

    /// Apply Roblox-specific optimizations
    pub fn apply_optimizations(&self, config: &RobloxSettingsConfig) -> Result<()> {
        info!("Applying Roblox optimizations via GlobalBasicSettings");

        if !self.settings_path.exists() {
            return Err(anyhow::anyhow!("Roblox settings file not found. Please ensure Roblox is installed and has been run at least once."));
        }

        // Remove read-only if it was set (so we can write)
        if self.is_readonly() {
            info!("Settings file is read-only, removing attribute to apply changes...");
            if let Err(e) = self.remove_readonly() {
                error!("Failed to remove read-only attribute: {}", e);
                return Err(anyhow::anyhow!("Cannot modify settings: file is read-only and we couldn't remove the attribute. Error: {}", e));
            }
        }

        // Backup current settings first
        self.backup_settings()?;

        // Read current content
        let mut content = fs::read_to_string(&self.settings_path)?;

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

        // Apply reduced motion if reducing quality
        if config.reduce_texture_quality {
            content = self.set_xml_bool_value(&content, "ReducedMotion", true);
        }

        // Write updated content back
        fs::write(&self.settings_path, &content)?;

        // Note: We no longer set the file to read-only. Setting it read-only
        // caused Roblox to fail with "Failed to apply critical settings" because
        // Roblox needs to write to this file during its startup sequence.
        // The FPS settings may be reset by Roblox, but the background monitor
        // will re-detect and re-apply them when needed.

        // Apply dynamic render optimization
        if let Err(e) = self.apply_dynamic_render_optimization(&config.dynamic_render_optimization) {
            warn!("Could not apply dynamic render optimization: {}", e);
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
        if self.settings_path.exists() {
            info!("Creating backup of Roblox settings");
            fs::copy(&self.settings_path, &self.backup_path)?;
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

        // Remove read-only if set (so we can restore)
        if self.is_readonly() {
            let _ = self.remove_readonly();
        }

        fs::copy(&self.backup_path, &self.settings_path)?;

        // Also remove dynamic render optimization when restoring
        if let Err(e) = self.remove_dynamic_render_optimization() {
            warn!("Could not remove dynamic render optimization during restore: {}", e);
        }

        // Don't set read-only after restore - user is disabling optimizations
        info!("Settings restored successfully");
        Ok(())
    }

    /// Check if Roblox is installed (settings file exists)
    pub fn is_roblox_installed(&self) -> bool {
        self.settings_path.exists()
    }

    // ═══════════════════════════════════════════════════════════════════════════════
    //  DYNAMIC RENDER OPTIMIZATION
    // ═══════════════════════════════════════════════════════════════════════════════

    /// Find the current Roblox version folder
    /// Returns the path to the latest version-* directory
    fn find_roblox_version_folder() -> Option<PathBuf> {
        let local_app_data = std::env::var("LOCALAPPDATA").ok()?;
        let versions_dir = PathBuf::from(&local_app_data).join("Roblox").join("Versions");

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
                                    if latest_version.is_none() || modified > latest_version.as_ref()?.1 {
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

    /// Apply dynamic render optimization
    pub fn apply_dynamic_render_optimization(&self, mode: &crate::structs::DynamicRenderMode) -> Result<()> {
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
                if let Ok(existing) = serde_json::from_str::<HashMap<String, serde_json::Value>>(&content) {
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
