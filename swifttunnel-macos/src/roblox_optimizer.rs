use crate::structs::*;
use log::{info, warn};
use std::path::PathBuf;
use std::fs;
use std::collections::HashMap;
use std::process::Command;

/// Current Roblox settings read from ClientAppSettings.json
#[derive(Debug, Clone)]
pub struct CurrentRobloxSettings {
    pub fps_cap: u32,
    pub graphics_quality: i32,
    pub fullscreen: bool,
}

pub struct RobloxOptimizer {
    /// Path to Roblox's ClientSettings directory inside the app bundle
    client_settings_dir: Option<PathBuf>,
    /// Path to ClientAppSettings.json
    settings_path: Option<PathBuf>,
    /// Backup of original settings
    backup_path: PathBuf,
}

impl RobloxOptimizer {
    pub fn new() -> Self {
        let client_settings_dir = Self::find_client_settings_dir();
        let settings_path = client_settings_dir.as_ref().map(|d| d.join("ClientAppSettings.json"));

        let backup_path = dirs::data_dir()
            .map(|d| d.join("SwiftTunnel").join("roblox_settings_backup.json"))
            .unwrap_or_else(|| PathBuf::from("/tmp/roblox_settings_backup.json"));

        Self {
            client_settings_dir,
            settings_path,
            backup_path,
        }
    }

    /// Find the ClientSettings directory inside Roblox.app
    ///
    /// On macOS, Roblox stores FFlag settings in:
    /// /Applications/Roblox.app/Contents/MacOS/ClientSettings/ClientAppSettings.json
    fn find_client_settings_dir() -> Option<PathBuf> {
        // Standard installation path
        let app_path = PathBuf::from("/Applications/Roblox.app/Contents/MacOS/ClientSettings");
        if app_path.parent().map(|p| p.exists()).unwrap_or(false) {
            // Parent (MacOS dir) exists, so Roblox is installed
            return Some(app_path);
        }

        // Check user Applications folder
        if let Some(home) = dirs::home_dir() {
            let user_app_path = home.join("Applications/Roblox.app/Contents/MacOS/ClientSettings");
            if user_app_path.parent().map(|p| p.exists()).unwrap_or(false) {
                return Some(user_app_path);
            }
        }

        info!("Roblox.app not found in standard locations");
        None
    }

    /// Get the path to the settings file
    pub fn get_settings_path(&self) -> Option<&PathBuf> {
        self.settings_path.as_ref()
    }

    /// Read current Roblox settings from ClientAppSettings.json
    pub fn read_current_settings(&self) -> Result<CurrentRobloxSettings> {
        let path = self.settings_path.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Roblox settings path not found"))?;

        if !path.exists() {
            // No settings file means defaults are in use
            return Ok(CurrentRobloxSettings {
                fps_cap: 60,
                graphics_quality: 5,
                fullscreen: false,
            });
        }

        let content = fs::read_to_string(path)?;
        let settings: HashMap<String, serde_json::Value> = serde_json::from_str(&content)
            .unwrap_or_default();

        let fps_cap = settings.get("DFIntTaskSchedulerTargetFps")
            .and_then(|v| v.as_u64())
            .unwrap_or(60) as u32;

        let graphics_quality = settings.get("FIntRomarkStartWithGraphicQualityLevel")
            .and_then(|v| v.as_i64())
            .unwrap_or(5) as i32;

        Ok(CurrentRobloxSettings {
            fps_cap,
            graphics_quality,
            fullscreen: false,
        })
    }

    /// Apply Roblox-specific optimizations via ClientAppSettings.json FFlags
    pub fn apply_optimizations(&self, config: &RobloxSettingsConfig) -> Result<()> {
        info!("Applying Roblox optimizations via ClientAppSettings.json");

        let client_settings_dir = self.client_settings_dir.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Roblox is not installed. Please install Roblox from roblox.com first."))?;

        // Create ClientSettings directory if it doesn't exist
        if !client_settings_dir.exists() {
            fs::create_dir_all(client_settings_dir)?;
            info!("Created ClientSettings directory at: {:?}", client_settings_dir);
        }

        let settings_path = client_settings_dir.join("ClientAppSettings.json");

        // Backup current settings first
        self.backup_settings(&settings_path)?;

        // Read existing settings if file exists
        let mut settings: HashMap<String, serde_json::Value> = if settings_path.exists() {
            let content = fs::read_to_string(&settings_path)?;
            serde_json::from_str(&content).unwrap_or_default()
        } else {
            HashMap::new()
        };

        // Apply FPS unlock
        if config.unlock_fps {
            settings.insert(
                "DFIntTaskSchedulerTargetFps".to_string(),
                serde_json::Value::Number(serde_json::Number::from(config.target_fps)),
            );
            // Disable Vulkan preference on macOS (use Metal)
            settings.insert(
                "FFlagDebugGraphicsPreferVulkan".to_string(),
                serde_json::Value::Bool(false),
            );
            info!("Set FPS target to: {}", config.target_fps);
        }

        // Apply graphics quality
        let quality_value = config.graphics_quality.to_level();
        if quality_value > 0 {
            settings.insert(
                "FIntRomarkStartWithGraphicQualityLevel".to_string(),
                serde_json::Value::Number(serde_json::Number::from(quality_value)),
            );
            info!("Set graphics quality to level: {}", quality_value);
        }

        // Reduce texture quality if requested
        if config.reduce_texture_quality {
            settings.insert(
                "FIntDebugTextureManagerSkipMips".to_string(),
                serde_json::Value::Number(serde_json::Number::from(2)),
            );
        }

        // Apply dynamic render optimization
        if let Some(render_value) = config.dynamic_render_optimization.render_value() {
            settings.insert(
                "DFIntDebugDynamicRenderKiloPixels".to_string(),
                serde_json::Value::String(render_value.to_string()),
            );
            info!("Dynamic render optimization enabled ({:?})", config.dynamic_render_optimization);
        }

        // Write settings to file
        let json = serde_json::to_string_pretty(&settings)?;
        fs::write(&settings_path, json)?;

        // Make settings file immutable to prevent Roblox from overwriting our FPS settings
        if config.unlock_fps {
            self.set_immutable(&settings_path, true);
        }

        info!("Roblox optimizations applied successfully");
        Ok(())
    }

    /// Backup current settings
    fn backup_settings(&self, settings_path: &PathBuf) -> Result<()> {
        if settings_path.exists() {
            info!("Creating backup of Roblox settings");
            if let Some(parent) = self.backup_path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            fs::copy(settings_path, &self.backup_path)?;
            info!("Backup created at: {:?}", self.backup_path);
        }
        Ok(())
    }

    /// Restore original settings from backup
    pub fn restore_settings(&self) -> Result<()> {
        info!("Restoring original Roblox settings from backup");

        let settings_path = match self.settings_path.as_ref() {
            Some(p) => p,
            None => {
                warn!("No settings path available");
                return Ok(());
            }
        };

        // Remove immutable flag first so we can write
        self.set_immutable(settings_path, false);

        if self.backup_path.exists() {
            fs::copy(&self.backup_path, settings_path)?;
            info!("Settings restored from backup");
        } else {
            // No backup - remove our settings file so Roblox uses defaults
            if settings_path.exists() {
                let _ = fs::remove_file(settings_path);
                info!("Removed custom settings, Roblox will use defaults");
            }
        }

        Ok(())
    }

    /// Set or clear the macOS immutable (uchg) flag on a file
    ///
    /// This prevents Roblox from overwriting our FPS settings.
    /// Uses `chflags` command.
    fn set_immutable(&self, path: &PathBuf, immutable: bool) {
        let flag = if immutable { "uchg" } else { "nouchg" };
        match Command::new("chflags").args([flag, &path.to_string_lossy()]).output() {
            Ok(result) => {
                if result.status.success() {
                    info!("Set {} flag on settings file", flag);
                } else {
                    warn!("Failed to set {} flag (may need elevated privileges)", flag);
                }
            }
            Err(e) => {
                warn!("Failed to run chflags: {}", e);
            }
        }
    }

    /// Check if Roblox is installed
    pub fn is_roblox_installed(&self) -> bool {
        self.client_settings_dir.is_some()
    }

    /// Apply dynamic render optimization independently
    pub fn apply_dynamic_render_optimization(&self, mode: &DynamicRenderMode) -> Result<()> {
        let render_value = match mode.render_value() {
            Some(v) => v,
            None => return self.remove_dynamic_render_optimization(),
        };

        let client_settings_dir = self.client_settings_dir.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Could not find Roblox installation"))?;

        if !client_settings_dir.exists() {
            fs::create_dir_all(client_settings_dir)?;
        }

        let settings_path = client_settings_dir.join("ClientAppSettings.json");

        // Read existing settings
        let mut settings: HashMap<String, serde_json::Value> = if settings_path.exists() {
            self.set_immutable(&settings_path, false);
            let content = fs::read_to_string(&settings_path)?;
            serde_json::from_str(&content).unwrap_or_default()
        } else {
            HashMap::new()
        };

        settings.insert(
            "DFIntDebugDynamicRenderKiloPixels".to_string(),
            serde_json::Value::String(render_value.to_string()),
        );

        let json = serde_json::to_string_pretty(&settings)?;
        fs::write(&settings_path, json)?;

        info!("Dynamic render optimization enabled ({:?})", mode);
        Ok(())
    }

    /// Remove dynamic render optimization settings
    fn remove_dynamic_render_optimization(&self) -> Result<()> {
        let client_settings_dir = match self.client_settings_dir.as_ref() {
            Some(path) => path,
            None => {
                info!("No Roblox installation found, skipping cleanup");
                return Ok(());
            }
        };

        let settings_path = client_settings_dir.join("ClientAppSettings.json");

        if settings_path.exists() {
            self.set_immutable(&settings_path, false);
            let content = fs::read_to_string(&settings_path)?;
            let mut settings: HashMap<String, serde_json::Value> =
                serde_json::from_str(&content).unwrap_or_default();

            settings.remove("DFIntDebugDynamicRenderKiloPixels");

            if settings.is_empty() {
                fs::remove_file(&settings_path)?;
            } else {
                let json = serde_json::to_string_pretty(&settings)?;
                fs::write(&settings_path, json)?;
            }

            info!("Dynamic render optimization disabled");
        }

        Ok(())
    }
}

impl Default for RobloxOptimizer {
    fn default() -> Self {
        Self::new()
    }
}
