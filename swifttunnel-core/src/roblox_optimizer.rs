use crate::hidden_command;
use crate::structs::*;
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

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
    pub window_size: Option<(u32, u32)>,
}

pub struct RobloxOptimizer {
    settings_path: PathBuf,
    backup_path: PathBuf,
}

#[derive(Debug, PartialEq, Eq)]
enum FFlagApplyOutcome {
    Applied,
    SkippedMissingRobloxVersion,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct GpuPreferenceSnapshot {
    #[serde(default)]
    values: HashMap<String, Option<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum GpuPreferenceRestoreAction {
    Restore(String),
    Delete,
    LeaveUntouched,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct NvidiaProfileSnapshot {
    #[serde(default)]
    applied: bool,
    #[serde(default)]
    roblox_profile_xml: Option<String>,
}

const GPU_PREFERENCE_SNAPSHOT_FILE: &str = "gpu_preference_snapshots.json";

fn gpu_preference_snapshot_path() -> Option<PathBuf> {
    dirs::config_dir().map(|p| p.join("SwiftTunnel").join(GPU_PREFERENCE_SNAPSHOT_FILE))
}

impl RobloxOptimizer {
    const MIN_WINDOW_WIDTH: u32 = 800;
    const MAX_WINDOW_WIDTH: u32 = 3840;
    const MIN_WINDOW_HEIGHT: u32 = 600;
    const MAX_WINDOW_HEIGHT: u32 = 2160;

    pub fn new() -> Self {
        // Find the GlobalBasicSettings XML file
        let local_app_data = std::env::var("LOCALAPPDATA").unwrap_or_default();
        let roblox_dir = PathBuf::from(&local_app_data).join("Roblox");

        // Find the GlobalBasicSettings file (could be numbered)
        let settings_path = Self::find_settings_file(&roblox_dir);

        Self {
            settings_path,
            backup_path: dirs::data_local_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join("SwiftTunnel")
                .join("roblox_settings_backup.xml"),
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

    /// Proactively repair Roblox GlobalBasicSettings file permissions.
    ///
    /// Older versions of SwiftTunnel (and some user tweaks) could leave the
    /// GlobalBasicSettings XML file marked read-only. Roblox needs to write to
    /// this file during startup; if it's read-only, Roblox may show
    /// "Failed to download or apply critical settings".
    pub fn repair_global_basic_settings_permissions(&self) -> Result<()> {
        let settings_path = self.resolve_settings_path();
        if !settings_path.exists() {
            return Ok(());
        }

        if Self::is_readonly_path(&settings_path) {
            info!(
                "Roblox GlobalBasicSettings is read-only. Removing attribute to prevent startup errors..."
            );
            Self::remove_readonly_path(&settings_path)?;
        }

        Ok(())
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
        let window_size = Self::extract_vector2_value(&content, "StartScreenSize")
            .and_then(|(x, y)| Self::sanitize_window_dimensions_from_xml(x, y));

        Ok(CurrentRobloxSettings {
            fps_cap: fps_cap as u32,
            graphics_quality,
            fullscreen,
            window_size,
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

    fn extract_vector2_value(content: &str, name: &str) -> Option<(i32, i32)> {
        let pattern = format!("<Vector2 name=\"{}\">", name);
        let start = content.find(&pattern)?;
        let vector_start = start + pattern.len();
        let vector_end = content[vector_start..].find("</Vector2>")?;
        let vector_body = &content[vector_start..vector_start + vector_end];

        let x = Self::extract_vector_axis(vector_body, "X")?;
        let y = Self::extract_vector_axis(vector_body, "Y")?;
        Some((x, y))
    }

    fn extract_vector_axis(vector_body: &str, axis: &str) -> Option<i32> {
        let open = format!("<{}>", axis);
        let close = format!("</{}>", axis);
        let start = vector_body.find(&open)?;
        let value_start = start + open.len();
        let end = vector_body[value_start..].find(&close)?;
        let value = &vector_body[value_start..value_start + end];
        value.trim().parse().ok()
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

    /// Apply Roblox-specific optimizations.
    /// Returns a list of non-fatal warnings (e.g. FFlag failures) on success.
    /// Only returns `Err` when the XML settings step fails hard.
    pub fn apply_optimizations(&self, config: &RobloxSettingsConfig) -> Result<Vec<String>> {
        info!("Applying Roblox optimizations via GlobalBasicSettings");
        let settings_path = self.resolve_settings_path();
        let mut warnings: Vec<String> = Vec::new();

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

        self.apply_xml_settings(&settings_path, config)?;

        // Apply FFlag optimizations (ultraboost) — always attempted regardless
        // of whether the XML settings step succeeded. FFlags live in a separate
        // file (ClientAppSettings.json) inside the Roblox version folder and are
        // independent of GlobalBasicSettings.
        if let Err(e) = self.apply_client_fflags(config) {
            let msg = format!("Could not apply FFlag optimizations: {}", e);
            warn!("{}", msg);
            warnings.push(msg);
        }

        // Per-app GPU preference: on hybrid laptops (Intel iGPU + dGPU)
        // Roblox often defaults to the integrated GPU. Setting "High
        // performance" via HKCU\...\UserGpuPreferences routes it to the
        // discrete GPU, which can be 3-10× the framerate. Reversed when
        // Ultraboost is disabled.
        if let Err(e) = Self::sync_gpu_preference(config.ultraboost) {
            let msg = format!("Could not sync Roblox GPU preference: {}", e);
            warn!("{}", msg);
            warnings.push(msg);
        }

        if let Err(e) = Self::sync_nvidia_profile(config.ultraboost) {
            let msg = format!("Could not sync NVIDIA Roblox potato profile: {}", e);
            warn!("{}", msg);
            warnings.push(msg);
        }

        info!("Roblox optimizations applied successfully");
        Ok(warnings)
    }

    /// `HKCU\SOFTWARE\Microsoft\DirectX\UserGpuPreferences` — Windows uses
    /// this key to route per-app GPU selection. The value name is the
    /// executable's absolute path; the data is `GpuPreference=N;` where
    /// `2` = High performance and `1` = Power saving.
    const USER_GPU_PREFERENCES_KEY: &'static str =
        r"HKCU\SOFTWARE\Microsoft\DirectX\UserGpuPreferences";
    const ROBLOX_GPU_EXECUTABLES: &'static [&'static str] =
        &["RobloxPlayerBeta.exe", "RobloxStudioBeta.exe"];
    const GPU_PREFERENCE_HIGH_PERFORMANCE: &'static str = "GpuPreference=2;";

    /// Mirror the Ultraboost toggle into Windows' per-app GPU preference.
    ///
    /// When `enable == true`, every `RobloxPlayerBeta.exe` /
    /// `RobloxStudioBeta.exe` discovered under
    /// `%LOCALAPPDATA%\Roblox\Versions\version-*` is registered as
    /// `GpuPreference=2;` (High performance), after snapshotting any existing
    /// user value. When `enable == false`, only values tracked in the snapshot
    /// are restored or deleted; unknown values are left untouched because they
    /// may be user-owned.
    fn sync_gpu_preference(enable: bool) -> Result<()> {
        let mut targets: Vec<String> = Self::collect_roblox_gpu_executables()
            .into_iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();

        // On the disable path, include tracked entries for older Roblox
        // version folders that may have since been deleted by Roblox
        // auto-update. Untracked stale rows are observed for diagnostics but
        // not deleted: without a snapshot they are indistinguishable from a
        // user-owned Windows graphics preference.
        if !enable {
            let snapshot = Self::load_gpu_preference_snapshot();
            for tracked in snapshot.values.keys() {
                if !targets.contains(tracked) {
                    targets.push(tracked.clone());
                }
            }
            for stale in Self::collect_stale_roblox_gpu_preference_names() {
                if !targets.contains(&stale) {
                    targets.push(stale);
                }
            }
        }

        if targets.is_empty() {
            // Nothing to do — Roblox isn't installed (or hasn't been launched
            // yet) AND no stale entries exist. Not an error: avoid noisy
            // popups if the user enables Ultraboost before installing Roblox.
            return Ok(());
        }

        let mut failures: Vec<String> = Vec::new();

        if enable {
            let mut snapshot = Self::load_gpu_preference_snapshot();
            for path_str in &targets {
                if !snapshot.values.contains_key(path_str) {
                    let original =
                        Self::query_registry_string_value(Self::USER_GPU_PREFERENCES_KEY, path_str)
                            .map_err(|e| {
                                anyhow::anyhow!(
                                    "Could not snapshot existing GPU preference for {}: {}",
                                    path_str,
                                    e
                                )
                            })?;
                    snapshot.values.insert(path_str.clone(), original);
                }
            }
            Self::persist_gpu_preference_snapshot(&snapshot)?;

            for path_str in targets {
                if let Err(e) = Self::set_registry_string_value(
                    Self::USER_GPU_PREFERENCES_KEY,
                    &path_str,
                    Self::GPU_PREFERENCE_HIGH_PERFORMANCE,
                ) {
                    warn!("GPU preference apply for {} failed: {}", path_str, e);
                    failures.push(format!("{}: {}", path_str, e));
                }
            }

            if failures.is_empty() {
                return Ok(());
            }

            return Err(anyhow::anyhow!(
                "GPU preference apply failed for {} executable(s): {}",
                failures.len(),
                failures.join("; ")
            ));
        }

        let mut snapshot = Self::load_gpu_preference_snapshot();
        for path_str in targets {
            match Self::gpu_preference_restore_action(snapshot.values.get(&path_str)) {
                GpuPreferenceRestoreAction::Restore(original) => {
                    if let Err(e) = Self::set_registry_string_value(
                        Self::USER_GPU_PREFERENCES_KEY,
                        &path_str,
                        &original,
                    ) {
                        warn!("GPU preference restore for {} failed: {}", path_str, e);
                        failures.push(format!("{}: {}", path_str, e));
                    } else {
                        snapshot.values.remove(&path_str);
                    }
                }
                GpuPreferenceRestoreAction::Delete => {
                    if let Err(e) =
                        Self::delete_registry_value(Self::USER_GPU_PREFERENCES_KEY, &path_str)
                    {
                        warn!("GPU preference clear for {} failed: {}", path_str, e);
                        failures.push(format!("{}: {}", path_str, e));
                    } else {
                        snapshot.values.remove(&path_str);
                    }
                }
                GpuPreferenceRestoreAction::LeaveUntouched => {
                    info!(
                        "Leaving untracked Roblox GPU preference untouched: {}",
                        path_str
                    );
                }
            }
        }

        if let Err(e) = Self::persist_gpu_preference_snapshot(&snapshot) {
            failures.push(format!("snapshot persistence: {}", e));
        }

        if failures.is_empty() {
            return Ok(());
        }

        Err(anyhow::anyhow!(
            "GPU preference restore failed for {} executable(s): {}",
            failures.len(),
            failures.join("; ")
        ))
    }

    fn load_gpu_preference_snapshot() -> GpuPreferenceSnapshot {
        let Some(path) = gpu_preference_snapshot_path() else {
            return GpuPreferenceSnapshot::default();
        };
        let content = match fs::read_to_string(&path) {
            Ok(content) => content,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return GpuPreferenceSnapshot::default();
            }
            Err(e) => {
                warn!("Failed to read Roblox GPU preference snapshot: {}", e);
                return GpuPreferenceSnapshot::default();
            }
        };

        match serde_json::from_str(&content) {
            Ok(snapshot) => snapshot,
            Err(e) => {
                warn!("Failed to parse Roblox GPU preference snapshot: {}", e);
                GpuPreferenceSnapshot::default()
            }
        }
    }

    fn persist_gpu_preference_snapshot(snapshot: &GpuPreferenceSnapshot) -> Result<()> {
        let Some(path) = gpu_preference_snapshot_path() else {
            return if snapshot.values.is_empty() {
                Ok(())
            } else {
                Err(anyhow::anyhow!(
                    "could not resolve config directory for GPU preference snapshot"
                ))
            };
        };

        if snapshot.values.is_empty() {
            match fs::remove_file(&path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(anyhow::anyhow!(
                        "failed to remove GPU preference snapshot {}: {}",
                        path.display(),
                        e
                    ));
                }
            }
            return Ok(());
        }

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(snapshot)?;
        fs::write(&path, json)?;
        Ok(())
    }

    fn gpu_preference_restore_action(
        snapshot: Option<&Option<String>>,
    ) -> GpuPreferenceRestoreAction {
        match snapshot {
            Some(Some(original)) => GpuPreferenceRestoreAction::Restore(original.clone()),
            Some(None) => GpuPreferenceRestoreAction::Delete,
            None => GpuPreferenceRestoreAction::LeaveUntouched,
        }
    }

    /// Enumerate `HKCU\SOFTWARE\Microsoft\DirectX\UserGpuPreferences` value
    /// names that look like a Roblox version-folder executable. Used by the
    /// disable path to clean up entries written for version-* folders that
    /// Roblox auto-updated away — `reg query` returns the value name (the
    /// full exe path) regardless of whether the file still exists on disk.
    fn collect_stale_roblox_gpu_preference_names() -> Vec<String> {
        let output = match hidden_command("reg")
            .args(["query", Self::USER_GPU_PREFERENCES_KEY])
            .output()
        {
            Ok(out) if out.status.success() => out,
            // No key at all means nothing to clean up.
            _ => return Vec::new(),
        };

        let stdout = String::from_utf8_lossy(&output.stdout);
        Self::parse_gpu_preference_names(&stdout)
    }

    /// Pure parser pulled out so tests can validate without running `reg`.
    /// Picks rows that name an executable under a Roblox version folder.
    fn parse_gpu_preference_names(reg_query_output: &str) -> Vec<String> {
        let mut names = Vec::new();
        for line in reg_query_output.lines() {
            // `reg query` rows look like:
            //   "    C:\…\version-abcdef\RobloxPlayerBeta.exe    REG_SZ    GpuPreference=2;"
            // The value name is everything between leading whitespace and
            // the type column (`REG_SZ` etc.).
            let Some((name_part, _rest)) = line.split_once("    REG_SZ") else {
                continue;
            };
            let name = name_part.trim();
            if name.is_empty() {
                continue;
            }
            let lowered = name.to_ascii_lowercase();
            // Only pick up entries that look like our prior writes: under a
            // Roblox version folder AND one of our known executable stems.
            if !lowered.contains(r"\roblox\versions\version-") {
                continue;
            }
            let is_known_exe = Self::ROBLOX_GPU_EXECUTABLES
                .iter()
                .any(|exe| lowered.ends_with(&exe.to_ascii_lowercase()));
            if !is_known_exe {
                continue;
            }
            names.push(name.to_string());
        }
        names
    }

    fn collect_roblox_gpu_executables() -> Vec<PathBuf> {
        let version_folders = Self::find_roblox_version_folders();
        let mut out = Vec::new();
        for folder in version_folders {
            for exe in Self::ROBLOX_GPU_EXECUTABLES {
                let candidate = folder.join(exe);
                if candidate.exists() {
                    out.push(candidate);
                }
            }
        }
        out
    }

    // NVIDIA Profile Inspector integration used by Ultraboost. This is
    // deliberately gated to machines that actually report an NVIDIA GPU.
    const NPI_EXE_NAME: &'static str = "nvidiaProfileInspector.exe";
    const NPI_RELEASE_TAG: &'static str = "v3.0.1.12";
    const NPI_RELEASE_ZIP_URL: &'static str = "https://github.com/Orbmu2k/nvidiaProfileInspector/releases/download/v3.0.1.12/nvidiaProfileInspector.zip";
    const NPI_RELEASE_ZIP_SHA256: &'static str =
        "494065af4ac3e9ce672c95e51e6b8a5301c208b6fed777ee6bbfe755081ba308";
    const NPI_EXE_SHA256: &'static str =
        "61452518fdd2464313e08589dd6b6e9d00d3fd36c1622e1105884ab1ad7334d4";
    const NPI_REFERENCE_XML_SHA256: &'static str =
        "fb19d0ed9a8f1b95caa3675a94f80e2e14ae891c8fe83f164e0bb62513c2bb3f";
    const NPI_CONFIG_SHA256: &'static str =
        "051099983b896673909e01a1f631b6652abb88da95c9f06f3efef4be033091fa";
    const NPI_PDB_SHA256: &'static str =
        "68ab6fe22594a906e40bb414a76a30106fa1c8d95f778c910f07e194623e7070";
    const NPI_PROFILE_NAME: &'static str = "Roblox";
    const NPI_ROBLOX_EXE: &'static str = "RobloxPlayerBeta.exe";
    const NPI_IMPORT_TIMEOUT_SECS: u64 = 15;
    const NPI_EXPORT_TIMEOUT_SECS: u64 = 20;
    const NVIDIA_PROFILE_SNAPSHOT_FILE: &'static str = "nvidia_profile_snapshot.json";

    fn sync_nvidia_profile(enable: bool) -> Result<()> {
        Self::sync_nvidia_profile_with_policy(enable, true)
    }

    fn sync_nvidia_profile_startup(enable: bool) -> Result<()> {
        Self::sync_nvidia_profile_with_policy(enable, false)
    }

    fn sync_nvidia_profile_with_policy(enable: bool, allow_download: bool) -> Result<()> {
        if !Self::has_nvidia_gpu() {
            info!("Skipping NVIDIA Roblox profile: no NVIDIA GPU detected");
            return Ok(());
        }

        if enable && !crate::is_administrator() {
            return Err(anyhow::anyhow!(
                "NVIDIA Profile Inspector requires SwiftTunnel to run as administrator"
            ));
        }

        if enable {
            Self::apply_nvidia_profile(allow_download)
        } else {
            Self::reset_nvidia_profile(allow_download)
        }
    }

    fn apply_nvidia_profile(allow_download: bool) -> Result<()> {
        let inspector = Self::resolve_nvidia_profile_inspector(allow_download)?
            .ok_or_else(|| anyhow::anyhow!("NVIDIA Profile Inspector helper is not installed"))?;
        let existing_snapshot = Self::read_nvidia_profile_snapshot()?;
        let had_existing_marker = existing_snapshot.applied;
        let original_profile_xml = if had_existing_marker {
            existing_snapshot.roblox_profile_xml
        } else {
            Self::capture_nvidia_profile_snapshot(&inspector)
                .map_err(|e| {
                    anyhow::anyhow!(
                        "Could not snapshot existing NVIDIA Roblox profile before Ultraboost apply: {}",
                        e
                    )
                })?
                .roblox_profile_xml
        };

        let snapshot = NvidiaProfileSnapshot {
            applied: true,
            roblox_profile_xml: original_profile_xml,
        };
        Self::write_nvidia_profile_snapshot(&snapshot)?;

        let profile_path = Self::write_nvidia_potato_profile(true)?;
        if let Err(e) = Self::run_nvidia_profile_import(&inspector, &profile_path, "apply") {
            if !had_existing_marker {
                let _ = Self::clear_nvidia_profile_snapshot();
            }
            return Err(e);
        }
        info!(
            "NVIDIA Roblox potato profile applied via {}",
            inspector.display()
        );
        Ok(())
    }

    fn reset_nvidia_profile(allow_download: bool) -> Result<()> {
        let snapshot = match Self::read_nvidia_profile_snapshot() {
            Ok(snapshot) => snapshot,
            Err(e) => {
                warn!(
                    "NVIDIA profile snapshot is unreadable; falling back to deterministic reset: {}",
                    e
                );
                NvidiaProfileSnapshot {
                    applied: true,
                    roblox_profile_xml: None,
                }
            }
        };
        if !snapshot.applied {
            info!("Skipping NVIDIA Roblox profile reset: no SwiftTunnel-applied profile marker");
            return Ok(());
        }

        let inspector = Self::resolve_nvidia_profile_inspector(allow_download)?.ok_or_else(|| {
            anyhow::anyhow!(
                "NVIDIA Profile Inspector helper is unavailable; NVIDIA Roblox profile reset remains pending"
            )
        })?;

        if let Some(profile_xml) = snapshot.roblox_profile_xml.as_deref() {
            let restore_path = Self::write_nvidia_profile_restore(profile_xml)?;
            Self::run_nvidia_profile_import(&inspector, &restore_path, "restore snapshot")?;
        } else {
            let reset_path = Self::write_nvidia_potato_profile(false)?;
            Self::run_nvidia_profile_import(&inspector, &reset_path, "reset")?;
        }

        Self::clear_nvidia_profile_snapshot()?;
        info!(
            "NVIDIA Roblox potato profile reset via {}",
            inspector.display()
        );
        Ok(())
    }

    fn run_nvidia_profile_import(
        inspector: &Path,
        profile_path: &Path,
        action: &str,
    ) -> Result<()> {
        let mut command = std::process::Command::new(inspector);
        command.arg("-silentImport").arg(profile_path);
        let output = Self::run_command_with_timeout(
            command,
            Self::NPI_IMPORT_TIMEOUT_SECS,
            "NVIDIA Profile Inspector import",
        )?;

        if output.status.success() {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            Err(anyhow::anyhow!(
                "NVIDIA Profile Inspector {} exited with {}: {}{}{}",
                action,
                output.status,
                stderr.trim(),
                if stderr.trim().is_empty() || stdout.trim().is_empty() {
                    ""
                } else {
                    " / "
                },
                stdout.trim()
            ))
        }
    }

    fn has_nvidia_gpu() -> bool {
        let Some(output) = Self::run_video_controller_query() else {
            return false;
        };
        Self::parse_has_nvidia_gpu(&output)
    }

    fn run_video_controller_query() -> Option<String> {
        let mut command = hidden_command("powershell");
        command.args([
            "-Command",
            "Get-CimInstance Win32_VideoController | Select-Object -ExpandProperty Name",
        ]);
        let output = Self::run_command_with_timeout(command, 5, "PowerShell GPU query").ok()?;
        if output.status.success() {
            Some(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            None
        }
    }

    fn parse_has_nvidia_gpu(output: &str) -> bool {
        output
            .lines()
            .any(|line| line.to_ascii_lowercase().contains("nvidia"))
    }

    fn resolve_nvidia_profile_inspector(_allow_download: bool) -> Result<Option<PathBuf>> {
        Self::staged_nvidia_profile_inspector_path()
    }

    fn staged_nvidia_profile_inspector_path() -> Result<Option<PathBuf>> {
        let exe_dir = std::env::current_exe()
            .ok()
            .and_then(|path| path.parent().map(|parent| parent.to_path_buf()));
        let Some(exe_dir) = exe_dir else {
            return Ok(None);
        };

        for path in [
            exe_dir
                .join("tools")
                .join("nvidiaProfileInspector")
                .join(Self::NPI_EXE_NAME),
            exe_dir
                .join("resources")
                .join("tools")
                .join("nvidiaProfileInspector")
                .join(Self::NPI_EXE_NAME),
            exe_dir
                .join("nvidiaProfileInspector")
                .join(Self::NPI_EXE_NAME),
        ] {
            if !path.is_file() {
                continue;
            }
            match Self::verify_nvidia_profile_inspector_bundle(&path) {
                Ok(()) => return Ok(Some(path)),
                Err(e) => warn!(
                    "Ignoring staged NVIDIA Profile Inspector helper at {}: {}",
                    path.display(),
                    e
                ),
            }
        }

        Ok(None)
    }

    fn verify_nvidia_profile_inspector_bundle(exe_path: &Path) -> Result<()> {
        Self::verify_file_sha256(
            exe_path,
            Self::NPI_EXE_SHA256,
            "NVIDIA Profile Inspector executable",
        )?;
        let dir = exe_path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("NVIDIA Profile Inspector executable has no parent"))?;
        Self::verify_file_sha256(
            &dir.join("Reference.xml"),
            Self::NPI_REFERENCE_XML_SHA256,
            "NVIDIA Profile Inspector Reference.xml",
        )?;
        Self::verify_file_sha256(
            &dir.join("nvidiaProfileInspector.exe.config"),
            Self::NPI_CONFIG_SHA256,
            "NVIDIA Profile Inspector config",
        )?;
        Self::verify_file_sha256(
            &dir.join("nvidiaProfileInspector.pdb"),
            Self::NPI_PDB_SHA256,
            "NVIDIA Profile Inspector PDB",
        )?;
        Self::reject_unexpected_nvidia_profile_inspector_files(dir)?;
        Ok(())
    }

    fn reject_unexpected_nvidia_profile_inspector_files(dir: &Path) -> Result<()> {
        const ALLOWED: &[&str] = &[
            "README.md",
            "Reference.xml",
            "nvidiaProfileInspector.exe",
            "nvidiaProfileInspector.exe.config",
            "nvidiaProfileInspector.pdb",
        ];

        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                return Err(anyhow::anyhow!(
                    "NVIDIA Profile Inspector directory contains a non-UTF-8 entry: {}",
                    path.display()
                ));
            };
            if !ALLOWED
                .iter()
                .any(|allowed| name.eq_ignore_ascii_case(allowed))
            {
                return Err(anyhow::anyhow!(
                    "NVIDIA Profile Inspector directory contains unexpected file {}; refusing elevated helper execution",
                    path.display()
                ));
            }
        }
        Ok(())
    }

    fn verify_file_sha256(path: &Path, expected: &str, label: &str) -> Result<()> {
        let actual = Self::sha256_file(path)?;
        if actual.eq_ignore_ascii_case(expected) {
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "{} SHA-256 mismatch for {}: expected {}, got {}",
                label,
                path.display(),
                expected,
                actual
            ))
        }
    }

    fn sha256_file(path: &Path) -> Result<String> {
        let mut file = fs::File::open(path)?;
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 8192];

        loop {
            let read = file.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }

        Ok(format!("{:x}", hasher.finalize()))
    }

    fn capture_nvidia_profile_snapshot(inspector: &Path) -> Result<NvidiaProfileSnapshot> {
        let Some(inspector_dir) = inspector.parent() else {
            return Ok(NvidiaProfileSnapshot::default());
        };

        let before = std::time::SystemTime::now();
        let mut command = std::process::Command::new(inspector);
        command.arg("-exportCustomized").current_dir(inspector_dir);
        let output = Self::run_command_with_timeout(
            command,
            Self::NPI_EXPORT_TIMEOUT_SECS,
            "NVIDIA Profile Inspector export",
        )?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!(
                "profile export failed with {}: {}",
                output.status,
                stderr.trim()
            ));
        }

        let Some(export_path) = Self::latest_npi_export(inspector_dir, before)? else {
            return Err(anyhow::anyhow!(
                "NVIDIA Profile Inspector export produced no CustomProfiles_*.nip file"
            ));
        };
        let content = Self::read_text_file_lossy(&export_path)?;
        let roblox_profile_xml = Self::extract_nvidia_profile_xml(&content, Self::NPI_PROFILE_NAME);
        let _ = fs::remove_file(export_path);
        Ok(NvidiaProfileSnapshot {
            applied: false,
            roblox_profile_xml,
        })
    }

    fn latest_npi_export(dir: &Path, since: std::time::SystemTime) -> Result<Option<PathBuf>> {
        let mut newest: Option<(std::time::SystemTime, PathBuf)> = None;
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if !name.starts_with("CustomProfiles_") || !name.ends_with(".nip") {
                continue;
            }
            let modified = entry.metadata()?.modified()?;
            if modified < since {
                continue;
            }
            if newest
                .as_ref()
                .map(|(best, _)| modified > *best)
                .unwrap_or(true)
            {
                newest = Some((modified, path));
            }
        }
        Ok(newest.map(|(_, path)| path))
    }

    fn extract_nvidia_profile_xml(content: &str, profile_name: &str) -> Option<String> {
        let mut search_from = 0;
        while let Some(relative_start) = content[search_from..].find("<Profile>") {
            let start = search_from + relative_start;
            let Some(relative_end) = content[start..].find("</Profile>") else {
                break;
            };
            let end = start + relative_end + "</Profile>".len();
            let profile = &content[start..end];
            if profile.contains(&format!("<ProfileName>{}</ProfileName>", profile_name)) {
                return Some(profile.to_string());
            }
            search_from = end;
        }
        None
    }

    fn nvidia_profile_snapshot_path() -> Result<PathBuf> {
        dirs::data_local_dir()
            .map(|path| {
                path.join("SwiftTunnel")
                    .join(Self::NVIDIA_PROFILE_SNAPSHOT_FILE)
            })
            .ok_or_else(|| anyhow::anyhow!("could not resolve local app data directory"))
    }

    fn read_nvidia_profile_snapshot() -> Result<NvidiaProfileSnapshot> {
        let path = Self::nvidia_profile_snapshot_path()?;
        if !path.exists() {
            return Ok(NvidiaProfileSnapshot::default());
        }
        let content = fs::read_to_string(path)?;
        serde_json::from_str(&content)
            .map_err(|e| anyhow::anyhow!("Failed to parse NVIDIA profile snapshot: {}", e))
    }

    fn write_nvidia_profile_snapshot(snapshot: &NvidiaProfileSnapshot) -> Result<()> {
        let path = Self::nvidia_profile_snapshot_path()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, serde_json::to_string_pretty(snapshot)?)?;
        Ok(())
    }

    fn clear_nvidia_profile_snapshot() -> Result<()> {
        let path = Self::nvidia_profile_snapshot_path()?;
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    fn write_nvidia_profile_restore(profile_xml: &str) -> Result<PathBuf> {
        let dir = Self::nvidia_profile_dir()?;
        fs::create_dir_all(&dir)?;
        let path = dir.join("roblox-potato-mode-restore.nip");
        let xml = format!(
            "<?xml version=\"1.0\" encoding=\"utf-16\"?>\r\n<ArrayOfProfile>\r\n{}\r\n</ArrayOfProfile>\r\n",
            profile_xml
        );
        Self::write_utf16le(&path, &xml)?;
        Ok(path)
    }

    fn nvidia_profile_dir() -> Result<PathBuf> {
        dirs::data_local_dir()
            .map(|path| path.join("SwiftTunnel").join("nvidia-profiles"))
            .ok_or_else(|| anyhow::anyhow!("could not resolve local app data directory"))
    }

    fn write_nvidia_potato_profile(enable: bool) -> Result<PathBuf> {
        let dir = Self::nvidia_profile_dir()?;
        fs::create_dir_all(&dir)?;
        let path = dir.join(if enable {
            "roblox-potato-mode.nip"
        } else {
            "roblox-potato-mode-reset.nip"
        });
        let xml = Self::nvidia_potato_profile_xml(enable);
        Self::write_utf16le(&path, &xml)?;
        Ok(path)
    }

    fn nvidia_potato_profile_xml(enable: bool) -> String {
        let settings = if enable {
            vec![
                ("Texture Filtering - LOD Bias (DX)", 7_573_135, 120),
                (
                    "Texture Filtering - LOD Bias Auto-Adjust (for SGSSAA)",
                    6_524_559,
                    0,
                ),
                ("Anisotropic Filtering - Mode", 282_245_910, 1),
                ("Anisotropic Filtering - Setting", 270_426_537, 0),
                ("Anisotropic Filter - Optimization", 8_703_344, 1),
                ("Anisotropic Filter - Sample Optimization", 15_151_633, 1),
                ("Texture Filtering - Negative LOD bias", 1_686_376, 0),
                ("Texture Filtering - Quality", 13_510_289, 20),
                ("Texture Filtering - Trilinear Optimization", 3_066_610, 1),
            ]
        } else {
            vec![
                ("Texture Filtering - LOD Bias (DX)", 7_573_135, 0),
                (
                    "Texture Filtering - LOD Bias Auto-Adjust (for SGSSAA)",
                    6_524_559,
                    1,
                ),
                ("Anisotropic Filtering - Mode", 282_245_910, 0),
                ("Anisotropic Filtering - Setting", 270_426_537, 1),
                ("Anisotropic Filter - Optimization", 8_703_344, 0),
                ("Anisotropic Filter - Sample Optimization", 15_151_633, 0),
                ("Texture Filtering - Negative LOD bias", 1_686_376, 0),
                ("Texture Filtering - Quality", 13_510_289, 0),
                ("Texture Filtering - Trilinear Optimization", 3_066_610, 0),
            ]
        };

        let setting_xml = settings
            .into_iter()
            .map(|(name, id, value)| {
                format!(
                    "      <ProfileSetting>\r\n        <SettingNameInfo>{name}</SettingNameInfo>\r\n        <SettingID>{id}</SettingID>\r\n        <SettingValue>{value}</SettingValue>\r\n        <ValueType>Dword</ValueType>\r\n      </ProfileSetting>"
                )
            })
            .collect::<Vec<_>>()
            .join("\r\n");

        format!(
            "<?xml version=\"1.0\" encoding=\"utf-16\"?>\r\n<ArrayOfProfile>\r\n  <Profile>\r\n    <ProfileName>{profile}</ProfileName>\r\n    <Executeables>\r\n      <string>{exe}</string>\r\n    </Executeables>\r\n    <Settings>\r\n{settings}\r\n    </Settings>\r\n  </Profile>\r\n</ArrayOfProfile>\r\n",
            profile = Self::NPI_PROFILE_NAME,
            exe = Self::NPI_ROBLOX_EXE,
            settings = setting_xml
        )
    }

    fn write_utf16le(path: &Path, content: &str) -> Result<()> {
        let mut bytes = Vec::with_capacity(2 + content.len() * 2);
        bytes.extend_from_slice(&[0xFF, 0xFE]);
        for unit in content.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        fs::write(path, bytes)?;
        Ok(())
    }

    fn read_text_file_lossy(path: &Path) -> Result<String> {
        let bytes = fs::read(path)?;
        if bytes.starts_with(&[0xFF, 0xFE]) {
            let units = bytes[2..]
                .chunks_exact(2)
                .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                .collect::<Vec<_>>();
            Ok(String::from_utf16_lossy(&units))
        } else if bytes.starts_with(&[0xFE, 0xFF]) {
            let units = bytes[2..]
                .chunks_exact(2)
                .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
                .collect::<Vec<_>>();
            Ok(String::from_utf16_lossy(&units))
        } else {
            Ok(String::from_utf8_lossy(&bytes).to_string())
        }
    }

    fn run_command_with_timeout(
        mut command: std::process::Command,
        timeout_secs: u64,
        label: &str,
    ) -> Result<std::process::Output> {
        use std::process::Stdio;
        use std::time::{Duration, Instant};

        command.stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = command.spawn()?;
        let start = Instant::now();
        let timeout = Duration::from_secs(timeout_secs);

        loop {
            if child.try_wait()?.is_some() {
                return Ok(child.wait_with_output()?);
            }
            if start.elapsed() >= timeout {
                let _ = child.kill();
                let _ = child.wait();
                return Err(anyhow::anyhow!(
                    "{} timed out after {}s",
                    label,
                    timeout_secs
                ));
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn escape_powershell_single_quoted(value: &str) -> String {
        value.replace('\'', "''")
    }

    fn query_registry_string_value(key_path: &str, value_name: &str) -> Result<Option<String>> {
        let output = hidden_command("reg")
            .args(["query", key_path, "/v", value_name])
            .output()?;

        if !output.status.success() {
            return Ok(None);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        Self::parse_registry_string_value(&stdout, value_name)
            .map(Some)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "reg query succeeded for {}\\{} but no REG_SZ row was parsed",
                    key_path,
                    value_name
                )
            })
    }

    fn parse_registry_string_value(reg_query_output: &str, value_name: &str) -> Option<String> {
        for line in reg_query_output.lines() {
            let Some((name_part, data)) = line.split_once("    REG_SZ") else {
                continue;
            };
            if name_part.trim().eq_ignore_ascii_case(value_name) {
                return Some(data.trim().to_string());
            }
        }
        None
    }

    fn set_registry_string_value(key_path: &str, value_name: &str, data: &str) -> Result<()> {
        let output = hidden_command("reg")
            .args([
                "add", key_path, "/v", value_name, "/t", "REG_SZ", "/d", data, "/f",
            ])
            .output()?;
        if output.status.success() {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(anyhow::anyhow!("reg add failed: {}", stderr.trim()))
        }
    }

    fn delete_registry_value(key_path: &str, value_name: &str) -> Result<()> {
        let output = hidden_command("reg")
            .args(["delete", key_path, "/v", value_name, "/f"])
            .output()?;

        if output.status.success() {
            return Ok(());
        }

        // `reg delete` returns a non-zero exit code with a localised error
        // string for both "value missing" and real failures (permission
        // denied, key locked, etc.). Substring matching English phrases
        // breaks on non-English Windows. Probe the registry instead: if the
        // value is genuinely absent the desired post-state already holds.
        //
        // Propagate a probe-spawn failure with `?` rather than `unwrap_or`
        // — silently treating "we couldn't even run `reg query`" as
        // success would let an admin-required delete report cleared while
        // the GPU preference is still live (Greptile-flagged regression).
        let probe = hidden_command("reg")
            .args(["query", key_path, "/v", value_name])
            .output()?;

        if !probe.status.success() {
            // `reg query` failed with a clean non-zero exit — the value
            // is gone, which is the post-state we wanted.
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(anyhow::anyhow!("reg delete failed: {}", stderr.trim()))
    }

    /// Apply XML-level settings (FPS cap, graphics quality, window size).
    /// Separated from apply_optimizations so FFlags can run independently.
    fn apply_xml_settings(
        &self,
        settings_path: &PathBuf,
        config: &RobloxSettingsConfig,
    ) -> Result<()> {
        // Backup current settings first
        self.backup_settings_for(settings_path)?;

        // Read current content
        let mut content = fs::read_to_string(settings_path)?;

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

        // Apply windowed resolution and fullscreen defaults.
        let (window_width, window_height) =
            Self::sanitize_window_dimensions(config.window_width, config.window_height);
        content = self.set_xml_vector2_value(
            &content,
            "StartScreenSize",
            window_width as i32,
            window_height as i32,
        );
        content = self.set_xml_bool_value(&content, "Fullscreen", config.window_fullscreen);
        info!(
            "Set Roblox launch window to {}x{} (fullscreen: {})",
            window_width, window_height, config.window_fullscreen
        );

        // Write updated content back
        fs::write(settings_path, &content)?;

        // Note: We no longer set the file to read-only. Setting it read-only
        // caused Roblox to fail with "Failed to apply critical settings" because
        // Roblox needs to write to this file during its startup sequence.
        // The FPS settings may be reset by Roblox, but the background monitor
        // will re-detect and re-apply them when needed.

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

        let entry = format!("<bool name=\"{}\">{}</bool>", name, value_str);
        Self::append_setting_block(content, &entry)
    }

    fn set_xml_vector2_value(&self, content: &str, name: &str, x: i32, y: i32) -> String {
        let pattern = format!("<Vector2 name=\"{}\">", name);
        let entry = format!(
            "<Vector2 name=\"{}\"><X>{}</X><Y>{}</Y></Vector2>",
            name, x, y
        );

        if let Some(start) = content.find(&pattern) {
            let Some(end_offset) = content[start..].find("</Vector2>") else {
                return content.to_string();
            };
            let end = start + end_offset + "</Vector2>".len();
            return format!("{}{}{}", &content[..start], entry, &content[end..]);
        }

        Self::append_setting_block(content, &entry)
    }

    fn append_setting_block(content: &str, entry: &str) -> String {
        if let Some(close_idx) = content.rfind("</roblox>") {
            let mut output = String::new();
            output.push_str(&content[..close_idx]);
            if !output.ends_with('\n') {
                output.push('\n');
            }
            output.push_str("  ");
            output.push_str(entry);
            output.push('\n');
            output.push_str(&content[close_idx..]);
            output
        } else {
            format!("{}\n{}\n", content, entry)
        }
    }

    fn sanitize_window_dimensions(width: u32, height: u32) -> (u32, u32) {
        let mut sanitized_width = width.clamp(Self::MIN_WINDOW_WIDTH, Self::MAX_WINDOW_WIDTH);
        let mut sanitized_height = height.clamp(Self::MIN_WINDOW_HEIGHT, Self::MAX_WINDOW_HEIGHT);

        if sanitized_width % 2 != 0 {
            sanitized_width = if sanitized_width == Self::MAX_WINDOW_WIDTH {
                sanitized_width - 1
            } else {
                sanitized_width + 1
            };
        }

        if sanitized_height % 2 != 0 {
            sanitized_height = if sanitized_height == Self::MAX_WINDOW_HEIGHT {
                sanitized_height - 1
            } else {
                sanitized_height + 1
            };
        }

        (sanitized_width, sanitized_height)
    }

    fn sanitize_window_dimensions_from_xml(width: i32, height: i32) -> Option<(u32, u32)> {
        if width <= 0 || height <= 0 {
            return None;
        }
        Some(Self::sanitize_window_dimensions(
            width as u32,
            height as u32,
        ))
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

        if let Err(e) = Self::sync_nvidia_profile(false) {
            warn!(
                "Could not reset NVIDIA Roblox potato profile during restore: {}",
                e
            );
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
    //  ULTRABOOST FFLAGS
    // ═══════════════════════════════════════════════════════════════════════════════

    /// Allowlisted performance FFlags applied by Ultraboost.
    ///
    /// Every entry was verified against Roblox's Sept-2025 client FFlag
    /// allowlist; non-allowlisted flags are silently ignored by the engine
    /// and are intentionally not written here. Additions over the prior
    /// version:
    ///   * `DFFlagDebugPauseVoxelizer=True` — pauses the voxel-lighting
    ///     voxelizer thread, cutting CPU work in scenes with Voxel
    ///     dynamic lighting (most legacy games).
    ///   * Four CSG LOD switching distances pinned at `0` — forces the
    ///     lowest-poly LOD bucket at the shortest possible distance.
    ///   * `FFlagDebugGraphicsPreferVulkan=False` /
    ///     `FFlagDebugGraphicsPreferOpenGL=False` — defensive negations so
    ///     a bootstrapper preset cannot silently undo our D3D11 selection
    ///     (Vulkan on Roblox/Windows is unofficial and crash-prone).
    ///
    /// `DFIntDebugFRMQualityLevelOverride` is `1` (lowest) instead of the
    /// prior `4`; Roblox's FRM quality scales 1-21 and community
    /// performance presets use the minimum for maximum FPS.
    ///
    /// `FIntDebugForceMSAASamples` is `1` instead of `0` because Roblox's
    /// client allowlist accepts 1x/2x/4x MSAA samples. A value of `0` can be
    /// ignored, leaving anti-aliasing at the user's previous/default quality.
    const ULTRABOOST_FFLAGS: &[(&str, &str)] = &[
        ("FFlagHandleAltEnterFullscreenManually", "False"),
        ("FFlagDebugGraphicsPreferD3D11", "True"),
        ("FFlagDebugGraphicsPreferVulkan", "False"),
        ("FFlagDebugGraphicsPreferOpenGL", "False"),
        ("FIntDebugForceMSAASamples", "1"),
        ("DFFlagTextureQualityOverrideEnabled", "True"),
        ("DFIntTextureQualityOverride", "0"),
        ("DFIntDebugFRMQualityLevelOverride", "1"),
        ("FFlagDebugSkyGray", "True"),
        ("FIntFRMMinGrassDistance", "0"),
        ("FIntFRMMaxGrassDistance", "0"),
        ("FIntGrassMovementReducedMotionFactor", "0"),
        ("DFFlagDebugPauseVoxelizer", "True"),
        ("DFIntCSGLevelOfDetailSwitchingDistance", "0"),
        ("DFIntCSGLevelOfDetailSwitchingDistanceL12", "0"),
        ("DFIntCSGLevelOfDetailSwitchingDistanceL23", "0"),
        ("DFIntCSGLevelOfDetailSwitchingDistanceL34", "0"),
    ];

    /// Roblox's local client configuration FFlag allowlist accepted by Custom
    /// FFlag Import. This intentionally stays broader than Ultraboost:
    /// Ultraboost writes only SwiftTunnel's performance preset, while custom
    /// import may accept any Roblox-allowlisted key.
    const CUSTOM_FFLAG_ALLOWLIST: &[(&str, &str)] = &[
        ("DFIntCSGLevelOfDetailSwitchingDistance", "0"),
        ("DFIntCSGLevelOfDetailSwitchingDistanceL12", "0"),
        ("DFIntCSGLevelOfDetailSwitchingDistanceL23", "0"),
        ("DFIntCSGLevelOfDetailSwitchingDistanceL34", "0"),
        ("FFlagHandleAltEnterFullscreenManually", "False"),
        ("DFFlagTextureQualityOverrideEnabled", "True"),
        ("DFIntTextureQualityOverride", "0"),
        ("FIntDebugForceMSAASamples", "1"),
        ("DFFlagDisableDPIScale", "False"),
        ("FFlagDebugGraphicsPreferD3D11", "True"),
        ("FFlagDebugSkyGray", "True"),
        ("DFFlagDebugPauseVoxelizer", "True"),
        ("DFIntDebugFRMQualityLevelOverride", "1"),
        ("FIntFRMMaxGrassDistance", "0"),
        ("FIntFRMMinGrassDistance", "0"),
        ("FFlagDebugGraphicsPreferVulkan", "False"),
        ("FFlagDebugGraphicsPreferOpenGL", "False"),
        ("FIntGrassMovementReducedMotionFactor", "0"),
    ];

    /// Retired FFlag. Previously written for FPS unlock, but the framerate cap is
    /// now driven solely by `FramerateCap` in GlobalBasicSettings. Still removed
    /// from existing ClientAppSettings so prior versions' entries are cleaned up.
    const FPS_UNLOCK_FFLAG: &str = "DFIntTaskSchedulerTargetFps";

    /// Old blocked FFlags that must be cleaned up from previous versions.
    ///
    /// `DFFlagDebugPauseVoxelizer` was previously listed here because earlier
    /// builds wrote it as a disabled override. It is now actively part of
    /// `ULTRABOOST_FFLAGS` (it's allowlisted and yields a real CPU lift on
    /// voxel-lighting scenes), so removing it from the cleanup list prevents
    /// us from immediately stripping our own write.
    const LEGACY_BLOCKED_FFLAGS: &[&str] = &[
        "DFIntDebugDynamicRenderKiloPixels",
        "FIntRenderShadowIntensity",
        "FFlagDisablePostFx",
        "FIntDebugTextureManagerSkipMips",
    ];

    /// Former SwiftTunnel UltraBoost entries that should be removed from
    /// existing ClientAppSettings. `DFFlagDisableDPIScale` is a valid Roblox
    /// client flag, but it favors sharper high-DPI rendering over maximum FPS
    /// so it is no longer written by Ultraboost.
    const REMOVED_ULTRABOOST_FFLAGS: &[&str] = &["DFFlagDisableDPIScale"];

    fn parse_custom_fflags(config: &RobloxSettingsConfig) -> Result<HashMap<String, String>> {
        if !config.custom_fflags_enabled {
            return Ok(HashMap::new());
        }
        if config.ultraboost {
            return Err(anyhow::anyhow!(
                "Choose either Ultraboost or Custom FFlag Import, not both."
            ));
        }

        let raw = config.custom_fflags_json.trim();
        if raw.is_empty() {
            return Err(anyhow::anyhow!(
                "Paste a JSON object before applying custom FFlags."
            ));
        }
        if raw.len() > 8192 {
            return Err(anyhow::anyhow!(
                "Custom FFlag JSON is too large. Keep it under 8 KB."
            ));
        }

        let value: serde_json::Value = serde_json::from_str(raw)
            .map_err(|e| anyhow::anyhow!("Custom FFlags must be valid JSON: {}", e))?;
        let Some(object) = value.as_object() else {
            return Err(anyhow::anyhow!(
                "Custom FFlags must be a JSON object like {{ \"FFlagName\": true }}."
            ));
        };
        if object.is_empty() {
            return Err(anyhow::anyhow!(
                "Custom FFlags must include at least one allowlisted key."
            ));
        }

        let mut output = HashMap::new();
        for (key, value) in object {
            let Some((_, expected)) = Self::CUSTOM_FFLAG_ALLOWLIST
                .iter()
                .find(|(allowed_key, _)| *allowed_key == key)
            else {
                return Err(anyhow::anyhow!(
                    "Custom FFlag '{}' is not in Roblox's local client FFlag allowlist.",
                    key
                ));
            };

            let normalized = Self::normalize_custom_fflag_value(key, expected, value)?;
            output.insert(key.clone(), normalized);
        }

        Ok(output)
    }

    fn normalize_custom_fflag_value(
        key: &str,
        expected: &str,
        value: &serde_json::Value,
    ) -> Result<String> {
        let expects_bool = expected.eq_ignore_ascii_case("true")
            || expected.eq_ignore_ascii_case("false")
            || key.starts_with("FFlag")
            || key.starts_with("DFFlag");

        if expects_bool {
            if let Some(v) = value.as_bool() {
                return Ok(if v { "True" } else { "False" }.to_string());
            }
            if let Some(v) = value.as_str() {
                return match v.trim().to_ascii_lowercase().as_str() {
                    "true" => Ok("True".to_string()),
                    "false" => Ok("False".to_string()),
                    _ => Err(anyhow::anyhow!(
                        "Custom FFlag '{}' must be true or false.",
                        key
                    )),
                };
            }
            return Err(anyhow::anyhow!(
                "Custom FFlag '{}' must be true or false.",
                key
            ));
        }

        let integer = if let Some(v) = value.as_i64() {
            Some(v)
        } else if let Some(v) = value.as_u64() {
            i64::try_from(v).ok()
        } else if let Some(v) = value.as_str() {
            v.trim().parse::<i64>().ok()
        } else {
            None
        };

        let Some(integer) = integer else {
            return Err(anyhow::anyhow!(
                "Custom FFlag '{}' must be an integer.",
                key
            ));
        };
        if !(-1_000_000..=1_000_000).contains(&integer) {
            return Err(anyhow::anyhow!(
                "Custom FFlag '{}' is outside the allowed integer range.",
                key
            ));
        }

        Ok(integer.to_string())
    }

    /// Known Bloxstrap-family persistent ClientSettings locations under LOCALAPPDATA.
    ///
    /// The normal Roblox version folder is still handled separately. These paths
    /// are for bootstrappers that copy persistent user modifications into the
    /// active Roblox version folder when they launch Roblox.
    const BOOTSTRAPPER_CLIENT_SETTINGS_LOCATIONS: &[(&str, &[&str])] = &[
        ("Bloxstrap", &["Modifications", "ClientSettings"]),
        ("Bloxstrap-QA", &["Modifications", "ClientSettings"]),
        ("Fishstrap", &["Modifications", "ClientSettings"]),
        ("Fishstrap-QA", &["Modifications", "ClientSettings"]),
        ("Bubblestrap", &["Modifications", "ClientSettings"]),
        ("Froststrap", &["ClientSettings"]),
        ("Froststrap-QA", &["ClientSettings"]),
        ("Voidstrap", &["VoidstrapMods", "ClientSettings"]),
        ("Voidstrap-QA", &["VoidstrapMods", "ClientSettings"]),
    ];

    /// Find the current Roblox version folder under LOCALAPPDATA.
    /// Returns the path to the latest version-* directory with RobloxPlayerBeta.exe.
    fn find_roblox_version_folder() -> Option<PathBuf> {
        let local_app_data = std::env::var("LOCALAPPDATA").ok()?;
        Self::find_roblox_version_folder_in(&PathBuf::from(local_app_data))
    }

    fn find_roblox_version_folder_in(local_app_data: &PathBuf) -> Option<PathBuf> {
        Self::find_roblox_version_folders_in(local_app_data)
            .into_iter()
            .next()
    }

    fn find_roblox_version_folders() -> Vec<PathBuf> {
        let Some(local_app_data) = std::env::var("LOCALAPPDATA").ok() else {
            return Vec::new();
        };
        Self::find_roblox_version_folders_in(&PathBuf::from(local_app_data))
    }

    fn find_roblox_version_folders_in(local_app_data: &PathBuf) -> Vec<PathBuf> {
        let versions_dir = local_app_data.join("Roblox").join("Versions");

        if !versions_dir.exists() {
            return Vec::new();
        }

        let mut versions: Vec<(PathBuf, std::time::SystemTime)> = Vec::new();

        if let Ok(entries) = fs::read_dir(&versions_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    let Some(name) = path.file_name().map(|value| value.to_string_lossy()) else {
                        continue;
                    };
                    if name.starts_with("version-") {
                        if path.join("RobloxPlayerBeta.exe").exists() {
                            if let Ok(metadata) = entry.metadata() {
                                let modified = metadata
                                    .modified()
                                    .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
                                versions.push((path, modified));
                            }
                        }
                    }
                }
            }
        }

        versions.sort_by(|(_, left), (_, right)| right.cmp(left));
        versions.into_iter().map(|(path, _)| path).collect()
    }

    /// Get the ClientSettings folder path (creates it if needed).
    fn get_client_settings_path() -> Result<Option<PathBuf>> {
        let version_folder = match Self::find_roblox_version_folder() {
            Some(path) => path,
            None => return Ok(None),
        };
        Self::get_client_settings_path_for_version(&version_folder)
    }

    fn get_client_settings_paths(create_missing: bool) -> Result<Vec<PathBuf>> {
        let Some(local_app_data) = std::env::var("LOCALAPPDATA").ok().map(PathBuf::from) else {
            return Ok(Vec::new());
        };
        Self::get_client_settings_paths_for_local_app_data(&local_app_data, create_missing)
    }

    #[cfg(test)]
    fn get_client_settings_path_for_local_app_data(
        local_app_data: &PathBuf,
    ) -> Result<Option<PathBuf>> {
        let version_folder = match Self::find_roblox_version_folder_in(local_app_data) {
            Some(path) => path,
            None => return Ok(None),
        };
        Self::get_client_settings_path_for_version(&version_folder)
    }

    fn get_client_settings_path_for_version(version_folder: &PathBuf) -> Result<Option<PathBuf>> {
        Self::get_client_settings_path_for_version_checked(version_folder, true)
    }

    fn get_client_settings_paths_for_versions(
        version_folders: &[PathBuf],
        create_missing: bool,
    ) -> Result<Vec<PathBuf>> {
        let mut paths = Vec::new();
        let mut failures = Vec::new();
        for version_folder in version_folders {
            match Self::get_client_settings_path_for_version_checked(version_folder, create_missing)
            {
                Ok(Some(path)) => paths.push(path),
                Ok(None) => {}
                Err(e) => {
                    failures.push(format!("{}: {}", version_folder.display(), e));
                    warn!(
                        "Skipping Roblox version folder {} while collecting ClientSettings: {}",
                        version_folder.display(),
                        e
                    );
                }
            }
        }
        if paths.is_empty() && !failures.is_empty() {
            return Err(anyhow::anyhow!(
                "Failed to collect ClientSettings from {} Roblox version folder(s): {}",
                failures.len(),
                failures.join("; ")
            ));
        }
        Ok(paths)
    }

    fn get_client_settings_paths_for_local_app_data(
        local_app_data: &PathBuf,
        create_missing: bool,
    ) -> Result<Vec<PathBuf>> {
        let version_folders = Self::find_roblox_version_folders_in(local_app_data);
        let mut paths = match Self::get_client_settings_paths_for_versions(
            &version_folders,
            create_missing,
        ) {
            Ok(version_paths) => version_paths,
            Err(e) => {
                warn!(
                    "Skipping Roblox version folder ClientSettings paths after collection failure: {}",
                    e
                );
                Vec::new()
            }
        };
        paths.extend(
            Self::get_bootstrapper_client_settings_paths_for_local_app_data(
                local_app_data,
                create_missing,
            ),
        );
        Ok(Self::dedupe_paths(paths))
    }

    fn get_client_settings_path_for_version_checked(
        version_folder: &PathBuf,
        create_missing: bool,
    ) -> Result<Option<PathBuf>> {
        let client_settings = version_folder.join("ClientSettings");

        if !client_settings.exists() {
            if !create_missing {
                return Ok(None);
            }
            fs::create_dir_all(&client_settings)?;
            info!("Created ClientSettings folder at: {:?}", client_settings);
        } else if !client_settings.is_dir() {
            return Err(anyhow::anyhow!(
                "ClientSettings path exists but is not a folder: {}",
                client_settings.display()
            ));
        }

        Ok(Some(client_settings))
    }

    fn get_bootstrapper_client_settings_paths_for_local_app_data(
        local_app_data: &PathBuf,
        create_missing: bool,
    ) -> Vec<PathBuf> {
        let mut paths = Vec::new();
        let mut failures = Vec::new();

        for (project_name, relative_segments) in Self::BOOTSTRAPPER_CLIENT_SETTINGS_LOCATIONS {
            let base = local_app_data.join(project_name);
            if !base.exists() {
                continue;
            }

            if !base.is_dir() {
                warn!(
                    "Skipping {} bootstrapper path because it is not a folder",
                    base.display()
                );
                continue;
            }

            let client_settings = relative_segments
                .iter()
                .fold(base, |path, segment| path.join(segment));

            match Self::get_bootstrapper_client_settings_path_checked(
                project_name,
                &client_settings,
                create_missing,
            ) {
                Ok(Some(path)) => paths.push(path),
                Ok(None) => {}
                Err(e) => {
                    failures.push(format!("{}: {}", client_settings.display(), e));
                    warn!(
                        "Skipping {} bootstrapper ClientSettings path {}: {}",
                        project_name,
                        client_settings.display(),
                        e
                    );
                }
            }
        }

        if !failures.is_empty() {
            warn!(
                "Failed to collect ClientSettings from {} supported bootstrapper path(s): {}",
                failures.len(),
                failures.join("; ")
            );
        }

        paths
    }

    fn get_bootstrapper_client_settings_path_checked(
        project_name: &str,
        client_settings: &PathBuf,
        create_missing: bool,
    ) -> Result<Option<PathBuf>> {
        if !client_settings.exists() {
            if !create_missing {
                return Ok(None);
            }
            fs::create_dir_all(client_settings)?;
            info!(
                "Created {} ClientSettings folder at: {:?}",
                project_name, client_settings
            );
        } else if !client_settings.is_dir() {
            return Err(anyhow::anyhow!(
                "{} ClientSettings path exists but is not a folder",
                project_name
            ));
        }

        Ok(Some(client_settings.clone()))
    }

    fn dedupe_paths(paths: Vec<PathBuf>) -> Vec<PathBuf> {
        let mut seen = std::collections::HashSet::new();
        let mut deduped = Vec::new();
        for path in paths {
            if seen.insert(path.clone()) {
                deduped.push(path);
            }
        }
        deduped
    }

    /// Apply FFlag optimizations to ClientAppSettings.json
    /// When ultraboost or custom FFlags are enabled, writes curated allowlisted performance FFlags.
    /// FPS unlock is handled separately via GlobalBasicSettings `FramerateCap`.
    /// Always cleans up old blocked or retired FFlags from previous versions.
    fn apply_client_fflags(&self, config: &RobloxSettingsConfig) -> Result<FFlagApplyOutcome> {
        let custom_fflags_requested = !Self::parse_custom_fflags(config)?.is_empty();
        let should_write_fflags = config.ultraboost || custom_fflags_requested;
        let client_settings_paths = Self::get_client_settings_paths(should_write_fflags)?;
        if client_settings_paths.is_empty() {
            if should_write_fflags {
                return Err(anyhow::anyhow!(
                    "No Roblox or supported bootstrapper ClientSettings path was found. Launch Roblox or an installed supported bootstrapper once, then apply Ultraboost again."
                ));
            }
            {
                info!(
                    "No Roblox or supported bootstrapper ClientSettings path found, skipping FFlag cleanup"
                );
                return Ok(FFlagApplyOutcome::SkippedMissingRobloxVersion);
            }
        }

        self.apply_client_fflags_in_paths(config, client_settings_paths)
    }

    #[cfg(test)]
    fn apply_client_fflags_for_local_app_data(
        &self,
        config: &RobloxSettingsConfig,
        local_app_data: &PathBuf,
    ) -> Result<FFlagApplyOutcome> {
        let custom_fflags_requested = !Self::parse_custom_fflags(config)?.is_empty();
        let should_write_fflags = config.ultraboost || custom_fflags_requested;
        let client_settings_paths = Self::get_client_settings_paths_for_local_app_data(
            local_app_data,
            should_write_fflags,
        )?;
        if client_settings_paths.is_empty() {
            if should_write_fflags {
                return Err(anyhow::anyhow!(
                    "No Roblox or supported bootstrapper ClientSettings path was found. Launch Roblox or an installed supported bootstrapper once, then apply Ultraboost again."
                ));
            }
            {
                info!(
                    "No Roblox or supported bootstrapper ClientSettings path found, skipping FFlag cleanup"
                );
                return Ok(FFlagApplyOutcome::SkippedMissingRobloxVersion);
            }
        }

        self.apply_client_fflags_in_paths(config, client_settings_paths)
    }

    fn apply_client_fflags_in_paths(
        &self,
        config: &RobloxSettingsConfig,
        client_settings_paths: Vec<PathBuf>,
    ) -> Result<FFlagApplyOutcome> {
        let mut applied_any = false;
        let mut active_failure = None;
        let mut secondary_failures = Vec::new();

        for (index, client_settings) in client_settings_paths.iter().enumerate() {
            match self.apply_client_fflags_in_path(config, client_settings) {
                Ok(_) => {
                    applied_any = true;
                }
                Err(e) => {
                    let failure = format!("{}: {}", client_settings.display(), e);
                    warn!(
                        "Failed to apply FFlags to ClientSettings path {}: {}",
                        client_settings.display(),
                        e
                    );
                    if index == 0 {
                        active_failure = Some(failure);
                    } else {
                        secondary_failures.push(failure);
                    }
                }
            }
        }

        if let Some(failure) = active_failure {
            return Err(anyhow::anyhow!(
                "Failed to apply FFlags to the primary ClientSettings path: {}",
                failure
            ));
        }

        if !applied_any {
            return Err(anyhow::anyhow!(
                "Failed to apply FFlags to {} ClientSettings path(s): {}",
                secondary_failures.len(),
                secondary_failures.join("; ")
            ));
        }

        if !secondary_failures.is_empty() {
            warn!(
                "Applied FFlags to the primary ClientSettings path, but failed to update {} secondary ClientSettings path(s): {}",
                secondary_failures.len(),
                secondary_failures.join("; ")
            );
        }

        Ok(FFlagApplyOutcome::Applied)
    }

    fn apply_client_fflags_in_path(
        &self,
        config: &RobloxSettingsConfig,
        client_settings: &PathBuf,
    ) -> Result<FFlagApplyOutcome> {
        if !client_settings.is_dir() {
            return Err(anyhow::anyhow!(
                "ClientSettings path exists but is not a folder: {}",
                client_settings.display()
            ));
        }

        let settings_path = client_settings.join("ClientAppSettings.json");

        let mut settings = Self::read_client_app_settings(&settings_path)?;

        // Always clean up old blocked or retired FFlags from previous versions
        for key in Self::LEGACY_BLOCKED_FFLAGS {
            settings.remove(*key);
        }
        for key in Self::REMOVED_ULTRABOOST_FFLAGS {
            settings.remove(*key);
        }

        if config.ultraboost {
            // Insert all ultraboost FFlags
            for (key, value) in Self::ULTRABOOST_FFLAGS {
                settings.insert(key.to_string(), serde_json::json!(value));
            }
            info!("Ultraboost FFlags applied");
        } else {
            // Remove all ultraboost FFlags
            for (key, _) in Self::ULTRABOOST_FFLAGS {
                settings.remove(*key);
            }
        }

        let custom_fflags = Self::parse_custom_fflags(config)?;
        if !custom_fflags.is_empty() {
            for (key, value) in custom_fflags {
                settings.insert(key, serde_json::json!(value));
            }
            info!("Custom allowlisted FFlags applied");
        }

        // FPS unlock is driven by GlobalBasicSettings `FramerateCap`; the old
        // scheduler FFlag is retired and always stripped from existing files.
        settings.remove(Self::FPS_UNLOCK_FFLAG);

        // Write or delete the file
        if settings.is_empty() {
            if settings_path.exists() {
                fs::remove_file(&settings_path)?;
                Self::remove_empty_bootstrapper_client_settings_dir(client_settings)?;
            }
        } else {
            let json = serde_json::to_string_pretty(&settings)?;
            fs::write(&settings_path, json)?;
        }

        info!("FFlag optimizations applied to ClientAppSettings.json");
        Ok(FFlagApplyOutcome::Applied)
    }

    fn read_client_app_settings(
        settings_path: &PathBuf,
    ) -> Result<HashMap<String, serde_json::Value>> {
        if !settings_path.exists() {
            return Ok(HashMap::new());
        }

        let content = fs::read_to_string(settings_path)?;
        serde_json::from_str(&content).map_err(|e| {
            anyhow::anyhow!(
                "Failed to parse ClientAppSettings.json at {}: {}",
                settings_path.display(),
                e
            )
        })
    }

    /// Remove all SwiftTunnel FFlag settings from ClientAppSettings.json
    fn remove_all_fflags(&self) -> Result<()> {
        let client_settings_paths = Self::get_client_settings_paths(false)?;
        self.remove_all_fflags_in_paths(client_settings_paths)
    }

    fn remove_all_fflags_in_paths(&self, client_settings_paths: Vec<PathBuf>) -> Result<()> {
        if client_settings_paths.is_empty() {
            info!(
                "No Roblox or supported bootstrapper ClientSettings path found, skipping FFlag cleanup"
            );
            return Ok(());
        }

        let mut failures = Vec::new();

        for client_settings in client_settings_paths {
            let settings_path = client_settings.join("ClientAppSettings.json");

            if !settings_path.exists() {
                continue;
            }

            let result = (|| -> Result<()> {
                let mut settings = Self::read_client_app_settings(&settings_path)?;

                // Remove all ultraboost FFlags
                for (key, _) in Self::ULTRABOOST_FFLAGS {
                    settings.remove(*key);
                }

                settings.remove(Self::FPS_UNLOCK_FFLAG);

                // Remove old blocked FFlags (legacy cleanup)
                for key in Self::LEGACY_BLOCKED_FFLAGS {
                    settings.remove(*key);
                }
                for key in Self::REMOVED_ULTRABOOST_FFLAGS {
                    settings.remove(*key);
                }

                if settings.is_empty() {
                    fs::remove_file(&settings_path)?;
                    Self::remove_empty_bootstrapper_client_settings_dir(&client_settings)?;
                } else {
                    let json = serde_json::to_string_pretty(&settings)?;
                    fs::write(&settings_path, json)?;
                }
                Ok(())
            })();

            match result {
                Ok(()) => {
                    info!("FFlag optimizations removed from ClientAppSettings.json");
                }
                Err(e) => {
                    warn!(
                        "Failed to remove FFlags from {}: {}",
                        settings_path.display(),
                        e
                    );
                    failures.push(format!("{}: {}", settings_path.display(), e));
                }
            }
        }

        if failures.is_empty() {
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "Failed to remove FFlags from {} ClientSettings path(s): {}",
                failures.len(),
                failures.join("; ")
            ))
        }
    }

    fn remove_empty_bootstrapper_client_settings_dir(client_settings: &Path) -> Result<()> {
        if !Self::is_supported_bootstrapper_client_settings_path(client_settings) {
            return Ok(());
        }

        match fs::remove_dir(client_settings) {
            Ok(()) => {
                info!(
                    "Removed empty bootstrapper ClientSettings folder at: {:?}",
                    client_settings
                );
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::DirectoryNotEmpty => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    fn is_supported_bootstrapper_client_settings_path(client_settings: &Path) -> bool {
        Self::BOOTSTRAPPER_CLIENT_SETTINGS_LOCATIONS.iter().any(
            |(project_name, relative_segments)| {
                let mut suffix = PathBuf::from(project_name);
                for segment in *relative_segments {
                    suffix.push(segment);
                }
                client_settings.ends_with(suffix)
            },
        )
    }

    #[cfg(test)]
    fn remove_all_fflags_for_local_app_data(&self, local_app_data: &PathBuf) -> Result<()> {
        let client_settings_paths =
            Self::get_client_settings_paths_for_local_app_data(local_app_data, false)?;
        self.remove_all_fflags_in_paths(client_settings_paths)
    }

    /// Reapply saved Ultraboost client-side state after Roblox creates a new version folder.
    pub fn reapply_saved_client_fflags(&self, config: &RobloxSettingsConfig) -> Result<()> {
        self.apply_client_fflags(config)?;
        if let Err(e) = Self::sync_nvidia_profile_startup(config.ultraboost) {
            warn!(
                "Could not sync NVIDIA Roblox potato profile on startup reapply: {}",
                e
            );
        }
        Ok(())
    }
}

impl Default for RobloxOptimizer {
    fn default() -> Self {
        Self::new()
    }
}

impl RobloxOptimizer {
    /// Remove all SwiftTunnel FFlag entries for uninstall.
    ///
    /// Constructs a temporary instance and delegates to the private
    /// `remove_all_fflags` method. Individual errors are logged but
    /// never propagate so the rest of uninstall can proceed.
    pub fn cleanup_for_uninstall() {
        info!("Roblox optimizer: cleaning up FFlags for uninstall");
        let optimizer = Self::new();
        if let Err(e) = optimizer.remove_all_fflags() {
            warn!("Failed to remove Roblox FFlags during uninstall: {e}");
        }
        // Also drop the per-app dGPU preference entries we may have written.
        // Best-effort; missing values are not an error.
        if let Err(e) = Self::sync_gpu_preference(false) {
            warn!("Failed to clear Roblox GPU preference during uninstall: {e}");
        }
        if let Err(e) = Self::sync_nvidia_profile(false) {
            warn!("Failed to clear NVIDIA Roblox profile during uninstall: {e}");
        }
        info!("Roblox optimizer: uninstall cleanup completed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Helper: create a RobloxOptimizer pointing at a specific path
    fn optimizer_with_path(settings_path: PathBuf) -> RobloxOptimizer {
        let backup_path = settings_path.with_extension("backup.xml");
        RobloxOptimizer {
            settings_path,
            backup_path,
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

    // ── extract_vector2_value ───────────────────────────────────────

    #[test]
    fn extract_vector2_value_parses_window_size() {
        let xml = r#"<roblox>
            <Vector2 name="StartScreenSize">
                <X>1920</X>
                <Y>1080</Y>
            </Vector2>
        </roblox>"#;
        assert_eq!(
            RobloxOptimizer::extract_vector2_value(xml, "StartScreenSize"),
            Some((1920, 1080))
        );
    }

    #[test]
    fn extract_vector2_value_returns_none_for_malformed_vector() {
        let xml = r#"<roblox><Vector2 name="StartScreenSize"><X>1920</X></Vector2></roblox>"#;
        assert_eq!(
            RobloxOptimizer::extract_vector2_value(xml, "StartScreenSize"),
            None
        );
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

    #[test]
    fn set_xml_vector2_value_upserts_start_screen_size() {
        let xml = r#"<roblox><int name="FramerateCap">60</int></roblox>"#;
        let opt = optimizer_with_path(PathBuf::from("dummy"));
        let result = opt.set_xml_vector2_value(xml, "StartScreenSize", 1280, 720);
        assert!(
            result.contains(r#"<Vector2 name="StartScreenSize"><X>1280</X><Y>720</Y></Vector2>"#)
        );
    }

    #[test]
    fn set_xml_bool_value_upserts_when_missing() {
        let xml = r#"<roblox><int name="FramerateCap">60</int></roblox>"#;
        let opt = optimizer_with_path(PathBuf::from("dummy"));
        let result = opt.set_xml_bool_value(xml, "Fullscreen", true);
        assert!(result.contains(r#"<bool name="Fullscreen">true</bool>"#));
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

    // ── sanitize_window_dimensions ──────────────────────────────────

    #[test]
    fn sanitize_window_dimensions_clamps_and_even_rounds() {
        assert_eq!(
            RobloxOptimizer::sanitize_window_dimensions(799, 2159),
            (800, 2160)
        );
        assert_eq!(
            RobloxOptimizer::sanitize_window_dimensions(3841, 601),
            (3840, 602)
        );
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
            <Vector2 name="StartScreenSize">
                <X>1919</X>
                <Y>1081</Y>
            </Vector2>
        </roblox>"#;

        let path = dir.join("settings.xml");
        fs::write(&path, xml).unwrap();

        let opt = optimizer_with_path(path);
        let settings = opt.read_current_settings().unwrap();

        assert_eq!(settings.fps_cap, 240);
        assert_eq!(settings.graphics_quality, 8);
        assert!(settings.fullscreen);
        assert_eq!(settings.window_size, Some((1920, 1082)));

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
        assert_eq!(settings.window_size, None);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_current_settings_errors_if_path_is_not_file() {
        let dir = std::env::temp_dir().join("roblox_opt_test_unreadable_settings_path");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let missing_settings_path = dir.join("missing-settings.xml");
        fs::create_dir_all(&missing_settings_path).unwrap();

        let opt = optimizer_with_path(missing_settings_path);
        assert!(opt.read_current_settings().is_err());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn apply_optimizations_inserts_and_sanitizes_window_settings() {
        let dir = std::env::temp_dir().join("roblox_opt_test_apply_window");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let path = dir.join("settings.xml");
        let xml = r#"<roblox>
            <int name="FramerateCap">60</int>
            <int name="GraphicsQualityLevel">5</int>
            <token name="SavedQualityLevel">5</token>
        </roblox>"#;
        fs::write(&path, xml).unwrap();

        let opt = optimizer_with_path(path.clone());
        let config = RobloxSettingsConfig {
            graphics_quality: GraphicsQuality::Level3,
            unlock_fps: true,
            target_fps: 240,
            window_width: 799,
            window_height: 601,
            window_fullscreen: true,
            ultraboost: false,
            ..Default::default()
        };

        opt.apply_optimizations(&config).unwrap();

        let updated = fs::read_to_string(&path).unwrap();
        assert!(updated.contains(r#"<int name="FramerateCap">240</int>"#));
        assert!(updated.contains(r#"<int name="GraphicsQualityLevel">3</int>"#));
        assert!(updated.contains(r#"<token name="SavedQualityLevel">3</token>"#));
        assert!(
            updated.contains(r#"<Vector2 name="StartScreenSize"><X>800</X><Y>602</Y></Vector2>"#)
        );
        assert!(updated.contains(r#"<bool name="Fullscreen">true</bool>"#));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn fflag_cleanup_skips_missing_roblox_version_when_ultraboost_off() {
        let dir = std::env::temp_dir().join("roblox_opt_test_fflag_missing_skip");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let opt = optimizer_with_path(dir.join("settings.xml"));
        let config = RobloxSettingsConfig {
            ultraboost: false,
            ..Default::default()
        };

        let outcome = opt.apply_client_fflags_for_local_app_data(&config, &dir);

        assert_eq!(
            outcome.unwrap(),
            FFlagApplyOutcome::SkippedMissingRobloxVersion
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn fflag_apply_reports_missing_version_when_ultraboost_requested() {
        let dir = std::env::temp_dir().join("roblox_opt_test_fflag_missing_requested");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let opt = optimizer_with_path(dir.join("settings.xml"));
        let config = RobloxSettingsConfig {
            ultraboost: true,
            ..Default::default()
        };

        let result = opt.apply_client_fflags_for_local_app_data(&config, &dir);

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("supported bootstrapper ClientSettings path")
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn custom_fflags_apply_allowlisted_json() {
        let dir = std::env::temp_dir().join("roblox_opt_test_custom_fflag_apply");
        let _ = fs::remove_dir_all(&dir);
        let client_settings = dir
            .join("Bloxstrap")
            .join("Modifications")
            .join("ClientSettings");
        fs::create_dir_all(&client_settings).unwrap();

        let opt = optimizer_with_path(dir.join("settings.xml"));
        let config = RobloxSettingsConfig {
            custom_fflags_enabled: true,
            custom_fflags_json: r#"{
                "FFlagDebugSkyGray": true,
                "DFIntTextureQualityOverride": 0
            }"#
            .to_string(),
            ..Default::default()
        };

        opt.apply_client_fflags_for_local_app_data(&config, &dir)
            .unwrap();

        let content = fs::read_to_string(client_settings.join("ClientAppSettings.json")).unwrap();
        let settings: HashMap<String, serde_json::Value> = serde_json::from_str(&content).unwrap();
        assert_eq!(
            settings.get("FFlagDebugSkyGray"),
            Some(&serde_json::json!("True"))
        );
        assert_eq!(
            settings.get("DFIntTextureQualityOverride"),
            Some(&serde_json::json!("0"))
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn custom_fflags_reject_unknown_keys() {
        let config = RobloxSettingsConfig {
            custom_fflags_enabled: true,
            custom_fflags_json: r#"{ "FFlagTotallyUnsafe": true }"#.to_string(),
            ..Default::default()
        };

        let err = RobloxOptimizer::parse_custom_fflags(&config).unwrap_err();

        assert!(
            err.to_string()
                .contains("not in Roblox's local client FFlag allowlist")
        );
    }

    #[test]
    fn custom_fflags_accept_official_allowlisted_dpi_scale_flag() {
        let config = RobloxSettingsConfig {
            custom_fflags_enabled: true,
            custom_fflags_json: r#"{ "DFFlagDisableDPIScale": true }"#.to_string(),
            ..Default::default()
        };

        let parsed = RobloxOptimizer::parse_custom_fflags(&config).unwrap();

        assert_eq!(
            parsed.get("DFFlagDisableDPIScale"),
            Some(&"True".to_string())
        );
    }

    #[test]
    fn custom_fflags_reject_empty_json_when_enabled() {
        let config = RobloxSettingsConfig {
            custom_fflags_enabled: true,
            custom_fflags_json: String::new(),
            ..Default::default()
        };

        let err = RobloxOptimizer::parse_custom_fflags(&config).unwrap_err();

        assert!(err.to_string().contains("Paste a JSON object"));
    }

    #[test]
    fn custom_fflags_reject_ultraboost_overlap() {
        let config = RobloxSettingsConfig {
            ultraboost: true,
            custom_fflags_enabled: true,
            custom_fflags_json: r#"{ "FFlagDebugSkyGray": true }"#.to_string(),
            ..Default::default()
        };

        let err = RobloxOptimizer::parse_custom_fflags(&config).unwrap_err();

        assert!(
            err.to_string()
                .contains("either Ultraboost or Custom FFlag")
        );
    }

    #[test]
    fn fflag_apply_skips_missing_path_when_only_fps_unlock_requested() {
        // FPS unlock no longer writes any FFlag (it uses GlobalBasicSettings
        // `FramerateCap`), so requesting it with no Roblox version present is a
        // graceful cleanup skip, not a hard error.
        let dir = std::env::temp_dir().join("roblox_opt_test_fflag_missing_fps");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let opt = optimizer_with_path(dir.join("settings.xml"));
        let config = RobloxSettingsConfig {
            unlock_fps: true,
            target_fps: 165,
            ..Default::default()
        };

        let outcome = opt.apply_client_fflags_for_local_app_data(&config, &dir);

        assert_eq!(
            outcome.unwrap(),
            FFlagApplyOutcome::SkippedMissingRobloxVersion
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn fflag_apply_strips_retired_fps_flag_but_keeps_user_flags() {
        // Positive + negative: applying Ultraboost must remove a pre-existing
        // retired FPS scheduler flag, while leaving unrelated user flags intact.
        let dir = std::env::temp_dir().join("roblox_opt_test_fflag_retired_fps");
        let _ = fs::remove_dir_all(&dir);
        let client_settings = dir
            .join("Bloxstrap")
            .join("Modifications")
            .join("ClientSettings");
        fs::create_dir_all(&client_settings).unwrap();
        fs::write(
            client_settings.join("ClientAppSettings.json"),
            r#"{
  "DFIntTaskSchedulerTargetFps": 240,
  "FStringUserOwnedFlag": "keep-me"
}"#,
        )
        .unwrap();

        let opt = optimizer_with_path(dir.join("settings.xml"));
        let config = RobloxSettingsConfig {
            ultraboost: true,
            unlock_fps: true,
            target_fps: 240,
            ..Default::default()
        };

        opt.apply_client_fflags_for_local_app_data(&config, &dir)
            .unwrap();

        let content = fs::read_to_string(client_settings.join("ClientAppSettings.json")).unwrap();
        let settings: HashMap<String, serde_json::Value> = serde_json::from_str(&content).unwrap();
        assert!(
            !settings.contains_key(RobloxOptimizer::FPS_UNLOCK_FFLAG),
            "retired FPS scheduler flag must be stripped on apply"
        );
        assert_eq!(
            settings.get("FStringUserOwnedFlag"),
            Some(&serde_json::json!("keep-me")),
            "unrelated user flags must be preserved"
        );
        assert_eq!(
            settings.get("FFlagDebugGraphicsPreferD3D11"),
            Some(&serde_json::json!("True"))
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn fflag_apply_updates_bloxstrap_persistent_client_settings() {
        let dir = std::env::temp_dir().join("roblox_opt_test_fflag_bloxstrap");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("Bloxstrap")).unwrap();

        let opt = optimizer_with_path(dir.join("settings.xml"));
        let config = RobloxSettingsConfig {
            ultraboost: true,
            unlock_fps: true,
            target_fps: 165,
            ..Default::default()
        };

        let outcome = opt.apply_client_fflags_for_local_app_data(&config, &dir);

        assert_eq!(outcome.unwrap(), FFlagApplyOutcome::Applied);
        let settings_path = dir
            .join("Bloxstrap")
            .join("Modifications")
            .join("ClientSettings")
            .join("ClientAppSettings.json");
        let content = fs::read_to_string(settings_path).unwrap();
        let settings: HashMap<String, serde_json::Value> = serde_json::from_str(&content).unwrap();
        assert_eq!(
            settings.get("FFlagDebugGraphicsPreferD3D11"),
            Some(&serde_json::json!("True"))
        );
        assert!(
            !settings.contains_key(RobloxOptimizer::FPS_UNLOCK_FFLAG),
            "retired FPS scheduler flag must not be written"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn fflag_apply_removes_empty_bootstrapper_client_settings_folder_when_disabled() {
        let dir = std::env::temp_dir().join("roblox_opt_test_fflag_disable_empty_bootstrapper");
        let _ = fs::remove_dir_all(&dir);
        let client_settings = dir
            .join("Bloxstrap")
            .join("Modifications")
            .join("ClientSettings");
        fs::create_dir_all(&client_settings).unwrap();
        fs::write(
            client_settings.join("ClientAppSettings.json"),
            r#"{
  "FFlagDebugGraphicsPreferD3D11": "True",
  "DFIntTaskSchedulerTargetFps": 165
}"#,
        )
        .unwrap();

        let opt = optimizer_with_path(dir.join("settings.xml"));
        let config = RobloxSettingsConfig {
            ultraboost: false,
            unlock_fps: false,
            ..Default::default()
        };

        opt.apply_client_fflags_for_local_app_data(&config, &dir)
            .unwrap();

        assert!(!client_settings.exists());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn fflag_apply_updates_known_non_bloxstrap_layouts() {
        let dir = std::env::temp_dir().join("roblox_opt_test_fflag_strap_layouts");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("Froststrap")).unwrap();
        fs::create_dir_all(dir.join("Voidstrap")).unwrap();

        let opt = optimizer_with_path(dir.join("settings.xml"));
        let config = RobloxSettingsConfig {
            ultraboost: true,
            ..Default::default()
        };

        opt.apply_client_fflags_for_local_app_data(&config, &dir)
            .unwrap();

        let froststrap_settings = dir
            .join("Froststrap")
            .join("ClientSettings")
            .join("ClientAppSettings.json");
        let voidstrap_settings = dir
            .join("Voidstrap")
            .join("VoidstrapMods")
            .join("ClientSettings")
            .join("ClientAppSettings.json");

        assert!(
            fs::read_to_string(froststrap_settings)
                .unwrap()
                .contains("FFlagDebugGraphicsPreferD3D11")
        );
        assert!(
            fs::read_to_string(voidstrap_settings)
                .unwrap()
                .contains("FFlagDebugGraphicsPreferD3D11")
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn fflag_apply_does_not_create_unknown_bootstrapper_paths() {
        let dir = std::env::temp_dir().join("roblox_opt_test_fflag_unknown_strap");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("MaybeStrap").join("Modifications")).unwrap();

        let opt = optimizer_with_path(dir.join("settings.xml"));
        let config = RobloxSettingsConfig {
            ultraboost: true,
            ..Default::default()
        };

        let result = opt.apply_client_fflags_for_local_app_data(&config, &dir);

        assert!(result.is_err());
        assert!(
            !dir.join("MaybeStrap")
                .join("Modifications")
                .join("ClientSettings")
                .exists(),
            "unsupported bootstrapper-looking folders must not be created"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn fflag_apply_keeps_roblox_version_when_bootstrapper_path_is_malformed() {
        let dir = std::env::temp_dir().join("roblox_opt_test_fflag_bad_strap_good_roblox");
        let _ = fs::remove_dir_all(&dir);
        let version_dir = dir.join("Roblox").join("Versions").join("version-good");
        fs::create_dir_all(&version_dir).unwrap();
        fs::write(version_dir.join("RobloxPlayerBeta.exe"), "").unwrap();
        fs::create_dir_all(dir.join("Bloxstrap").join("Modifications")).unwrap();
        fs::write(
            dir.join("Bloxstrap")
                .join("Modifications")
                .join("ClientSettings"),
            "not a directory",
        )
        .unwrap();

        let opt = optimizer_with_path(dir.join("settings.xml"));
        let config = RobloxSettingsConfig {
            ultraboost: true,
            ..Default::default()
        };

        let outcome = opt.apply_client_fflags_for_local_app_data(&config, &dir);

        assert_eq!(outcome.unwrap(), FFlagApplyOutcome::Applied);
        let content = fs::read_to_string(
            version_dir
                .join("ClientSettings")
                .join("ClientAppSettings.json"),
        )
        .unwrap();
        assert!(content.contains("FFlagDebugGraphicsPreferD3D11"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn fflag_apply_reports_missing_when_only_roblox_path_is_malformed() {
        let dir = std::env::temp_dir().join("roblox_opt_test_fflag_clientsettings_file");
        let _ = fs::remove_dir_all(&dir);
        let version_dir = dir.join("Roblox").join("Versions").join("version-bad");
        fs::create_dir_all(&version_dir).unwrap();
        fs::write(version_dir.join("RobloxPlayerBeta.exe"), "").unwrap();
        fs::write(version_dir.join("ClientSettings"), "not a directory").unwrap();

        let opt = optimizer_with_path(dir.join("settings.xml"));
        let config = RobloxSettingsConfig {
            ultraboost: true,
            ..Default::default()
        };

        let result = opt.apply_client_fflags_for_local_app_data(&config, &dir);

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("supported bootstrapper ClientSettings path")
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn fflag_apply_keeps_bootstrapper_path_when_roblox_version_is_malformed() {
        let dir = std::env::temp_dir().join("roblox_opt_test_fflag_bad_roblox_good_strap");
        let _ = fs::remove_dir_all(&dir);
        let version_dir = dir.join("Roblox").join("Versions").join("version-bad");
        fs::create_dir_all(&version_dir).unwrap();
        fs::write(version_dir.join("RobloxPlayerBeta.exe"), "").unwrap();
        fs::write(version_dir.join("ClientSettings"), "not a directory").unwrap();
        fs::create_dir_all(dir.join("Bloxstrap")).unwrap();

        let opt = optimizer_with_path(dir.join("settings.xml"));
        let config = RobloxSettingsConfig {
            ultraboost: true,
            ..Default::default()
        };

        let outcome = opt.apply_client_fflags_for_local_app_data(&config, &dir);

        assert_eq!(outcome.unwrap(), FFlagApplyOutcome::Applied);
        let content = fs::read_to_string(
            dir.join("Bloxstrap")
                .join("Modifications")
                .join("ClientSettings")
                .join("ClientAppSettings.json"),
        )
        .unwrap();
        assert!(content.contains("FFlagDebugGraphicsPreferD3D11"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn fflag_apply_preserves_malformed_client_app_settings() {
        let dir = std::env::temp_dir().join("roblox_opt_test_fflag_malformed_json_apply");
        let _ = fs::remove_dir_all(&dir);
        let client_settings = dir
            .join("Bloxstrap")
            .join("Modifications")
            .join("ClientSettings");
        fs::create_dir_all(&client_settings).unwrap();
        let settings_path = client_settings.join("ClientAppSettings.json");
        fs::write(&settings_path, "{ this is not valid json").unwrap();

        let opt = optimizer_with_path(dir.join("settings.xml"));
        let config = RobloxSettingsConfig {
            ultraboost: true,
            ..Default::default()
        };

        let result = opt.apply_client_fflags_for_local_app_data(&config, &dir);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Failed to parse"));
        assert_eq!(
            fs::read_to_string(settings_path).unwrap(),
            "{ this is not valid json"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn fflag_apply_updates_all_valid_version_folders() {
        let dir = std::env::temp_dir().join("roblox_opt_test_fflag_all_versions");
        let _ = fs::remove_dir_all(&dir);
        let versions_dir = dir.join("Roblox").join("Versions");
        let old_version = versions_dir.join("version-old");
        let new_version = versions_dir.join("version-new");
        fs::create_dir_all(&old_version).unwrap();
        fs::create_dir_all(&new_version).unwrap();
        fs::write(old_version.join("RobloxPlayerBeta.exe"), "").unwrap();
        fs::write(new_version.join("RobloxPlayerBeta.exe"), "").unwrap();

        let opt = optimizer_with_path(dir.join("settings.xml"));
        let config = RobloxSettingsConfig {
            ultraboost: true,
            ..Default::default()
        };

        let outcome = opt.apply_client_fflags_for_local_app_data(&config, &dir);

        assert_eq!(outcome.unwrap(), FFlagApplyOutcome::Applied);
        for version in [&old_version, &new_version] {
            let settings_path = version
                .join("ClientSettings")
                .join("ClientAppSettings.json");
            let content = fs::read_to_string(settings_path).unwrap();
            assert!(content.contains("FFlagDebugGraphicsPreferD3D11"));
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn fflag_apply_removes_retired_ultraboost_flags_when_enabled() {
        let dir = std::env::temp_dir().join("roblox_opt_test_fflag_retired_ultraboost");
        let _ = fs::remove_dir_all(&dir);
        let version = dir.join("Roblox").join("Versions").join("version-active");
        let client_settings = version.join("ClientSettings");
        fs::create_dir_all(&client_settings).unwrap();
        fs::write(version.join("RobloxPlayerBeta.exe"), "").unwrap();
        fs::write(
            client_settings.join("ClientAppSettings.json"),
            r#"{
  "DFFlagDisableDPIScale": "True",
  "FStringUserOwnedFlag": "keep-me"
}"#,
        )
        .unwrap();

        let opt = optimizer_with_path(dir.join("settings.xml"));
        let config = RobloxSettingsConfig {
            ultraboost: true,
            ..Default::default()
        };

        opt.apply_client_fflags_for_local_app_data(&config, &dir)
            .unwrap();

        let content = fs::read_to_string(client_settings.join("ClientAppSettings.json")).unwrap();
        let settings: HashMap<String, serde_json::Value> = serde_json::from_str(&content).unwrap();
        assert_eq!(
            settings.get("FFlagDebugGraphicsPreferD3D11"),
            Some(&serde_json::json!("True"))
        );
        assert!(!settings.contains_key("DFFlagDisableDPIScale"));
        assert_eq!(
            settings.get("FStringUserOwnedFlag"),
            Some(&serde_json::json!("keep-me"))
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn fflag_apply_upgrades_existing_ultraboost_texture_preset() {
        let dir = std::env::temp_dir().join("roblox_opt_test_fflag_upgrade_potato_preset");
        let _ = fs::remove_dir_all(&dir);
        let version = dir.join("Roblox").join("Versions").join("version-active");
        let client_settings = version.join("ClientSettings");
        fs::create_dir_all(&client_settings).unwrap();
        fs::write(version.join("RobloxPlayerBeta.exe"), "").unwrap();
        fs::write(
            client_settings.join("ClientAppSettings.json"),
            r#"{
  "FFlagDebugGraphicsPreferD3D11": "True",
  "FIntDebugForceMSAASamples": "0",
  "FStringUserOwnedFlag": "keep-me"
}"#,
        )
        .unwrap();

        let opt = optimizer_with_path(dir.join("settings.xml"));
        let config = RobloxSettingsConfig {
            ultraboost: true,
            ..Default::default()
        };

        opt.apply_client_fflags_for_local_app_data(&config, &dir)
            .unwrap();

        let content = fs::read_to_string(client_settings.join("ClientAppSettings.json")).unwrap();
        let settings: HashMap<String, serde_json::Value> = serde_json::from_str(&content).unwrap();
        assert_eq!(
            settings.get("DFFlagTextureQualityOverrideEnabled"),
            Some(&serde_json::json!("True")),
            "startup reapply must add the low-texture override for existing Ultraboost users"
        );
        assert_eq!(
            settings.get("DFIntTextureQualityOverride"),
            Some(&serde_json::json!("0")),
            "startup reapply must pin Roblox to its lowest texture-quality preset"
        );
        assert_eq!(
            settings.get("FIntDebugForceMSAASamples"),
            Some(&serde_json::json!("1")),
            "older Ultraboost installs using the ignored 0x MSAA value must migrate to 1x"
        );
        assert_eq!(
            settings.get("FStringUserOwnedFlag"),
            Some(&serde_json::json!("keep-me")),
            "user-owned flags must survive the Ultraboost preset upgrade"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn fflag_apply_ignores_version_like_folder_without_player_exe() {
        let dir = std::env::temp_dir().join("roblox_opt_test_fflag_ignore_nearmiss");
        let _ = fs::remove_dir_all(&dir);
        let versions_dir = dir.join("Roblox").join("Versions");
        let valid_version = versions_dir.join("version-valid");
        let near_miss = versions_dir.join("version-without-player");
        fs::create_dir_all(&valid_version).unwrap();
        fs::create_dir_all(&near_miss).unwrap();
        fs::write(valid_version.join("RobloxPlayerBeta.exe"), "").unwrap();

        let opt = optimizer_with_path(dir.join("settings.xml"));
        let config = RobloxSettingsConfig {
            ultraboost: true,
            ..Default::default()
        };

        opt.apply_client_fflags_for_local_app_data(&config, &dir)
            .unwrap();

        assert!(
            valid_version
                .join("ClientSettings")
                .join("ClientAppSettings.json")
                .exists()
        );
        assert!(
            !near_miss.join("ClientSettings").exists(),
            "version-like folders without RobloxPlayerBeta.exe must not be repaired"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn fflag_apply_skips_broken_legacy_version_folder() {
        let dir = std::env::temp_dir().join("roblox_opt_test_fflag_skip_broken_legacy");
        let _ = fs::remove_dir_all(&dir);
        let versions_dir = dir.join("Roblox").join("Versions");
        let broken_version = versions_dir.join("version-broken");
        let good_version = versions_dir.join("version-good");

        for version in [&broken_version, &good_version] {
            fs::create_dir_all(version).unwrap();
            fs::write(version.join("RobloxPlayerBeta.exe"), "").unwrap();
        }
        fs::write(broken_version.join("ClientSettings"), "not a directory").unwrap();

        let opt = optimizer_with_path(dir.join("settings.xml"));
        let config = RobloxSettingsConfig {
            ultraboost: true,
            ..Default::default()
        };

        let outcome = opt.apply_client_fflags_for_local_app_data(&config, &dir);

        assert_eq!(outcome.unwrap(), FFlagApplyOutcome::Applied);
        let good_settings_path = good_version
            .join("ClientSettings")
            .join("ClientAppSettings.json");
        let content = fs::read_to_string(good_settings_path).unwrap();
        assert!(content.contains("FFlagDebugGraphicsPreferD3D11"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn fflag_apply_reports_success_when_only_older_version_write_fails() {
        let dir = std::env::temp_dir().join("roblox_opt_test_fflag_apply_secondary_error");
        let _ = fs::remove_dir_all(&dir);
        let active_settings = dir.join("active").join("ClientSettings");
        let old_settings = dir.join("old").join("ClientSettings");
        fs::create_dir_all(&active_settings).unwrap();
        fs::create_dir_all(old_settings.join("ClientAppSettings.json")).unwrap();

        let opt = optimizer_with_path(dir.join("settings.xml"));
        let config = RobloxSettingsConfig {
            ultraboost: true,
            ..Default::default()
        };

        let outcome =
            opt.apply_client_fflags_in_paths(&config, vec![active_settings.clone(), old_settings]);

        assert_eq!(outcome.unwrap(), FFlagApplyOutcome::Applied);
        let content = fs::read_to_string(active_settings.join("ClientAppSettings.json")).unwrap();
        assert!(content.contains("FFlagDebugGraphicsPreferD3D11"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn fflag_apply_does_not_mask_active_version_write_failure() {
        let dir = std::env::temp_dir().join("roblox_opt_test_fflag_apply_primary_error");
        let _ = fs::remove_dir_all(&dir);
        let active_settings = dir.join("active").join("ClientSettings");
        let old_settings = dir.join("old").join("ClientSettings");
        fs::create_dir_all(active_settings.join("ClientAppSettings.json")).unwrap();
        fs::create_dir_all(&old_settings).unwrap();

        let opt = optimizer_with_path(dir.join("settings.xml"));
        let config = RobloxSettingsConfig {
            ultraboost: true,
            ..Default::default()
        };

        let result = opt.apply_client_fflags_in_paths(&config, vec![active_settings, old_settings]);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("primary"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn remove_all_fflags_cleans_every_version_and_preserves_user_flags() {
        let dir = std::env::temp_dir().join("roblox_opt_test_fflag_remove_all_versions");
        let _ = fs::remove_dir_all(&dir);
        let versions_dir = dir.join("Roblox").join("Versions");
        let first_version = versions_dir.join("version-first");
        let second_version = versions_dir.join("version-second");

        for version in [&first_version, &second_version] {
            let client_settings = version.join("ClientSettings");
            fs::create_dir_all(&client_settings).unwrap();
            fs::write(version.join("RobloxPlayerBeta.exe"), "").unwrap();
            fs::write(
                client_settings.join("ClientAppSettings.json"),
                r#"{
  "FFlagDebugGraphicsPreferD3D11": "True",
  "FStringUserOwnedFlag": "keep-me"
}"#,
            )
            .unwrap();
        }

        let opt = optimizer_with_path(dir.join("settings.xml"));
        opt.remove_all_fflags_for_local_app_data(&dir).unwrap();

        for version in [&first_version, &second_version] {
            let settings_path = version
                .join("ClientSettings")
                .join("ClientAppSettings.json");
            let content = fs::read_to_string(settings_path).unwrap();
            assert!(!content.contains("FFlagDebugGraphicsPreferD3D11"));
            assert!(content.contains("FStringUserOwnedFlag"));
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn remove_all_fflags_continues_after_folder_error() {
        let dir = std::env::temp_dir().join("roblox_opt_test_fflag_remove_partial_error");
        let _ = fs::remove_dir_all(&dir);
        let versions_dir = dir.join("Roblox").join("Versions");
        let broken_version = versions_dir.join("version-broken");
        let good_version = versions_dir.join("version-good");

        for version in [&broken_version, &good_version] {
            fs::create_dir_all(version.join("ClientSettings")).unwrap();
            fs::write(version.join("RobloxPlayerBeta.exe"), "").unwrap();
        }

        fs::create_dir_all(
            broken_version
                .join("ClientSettings")
                .join("ClientAppSettings.json"),
        )
        .unwrap();
        fs::write(
            good_version
                .join("ClientSettings")
                .join("ClientAppSettings.json"),
            r#"{
  "FFlagDebugGraphicsPreferD3D11": "True",
  "FStringUserOwnedFlag": "keep-me"
}"#,
        )
        .unwrap();

        let opt = optimizer_with_path(dir.join("settings.xml"));
        let result = opt.remove_all_fflags_in_paths(vec![
            broken_version.join("ClientSettings"),
            good_version.join("ClientSettings"),
        ]);

        assert!(result.is_err());
        let good_settings_path = good_version
            .join("ClientSettings")
            .join("ClientAppSettings.json");
        let content = fs::read_to_string(good_settings_path).unwrap();
        assert!(!content.contains("FFlagDebugGraphicsPreferD3D11"));
        assert!(content.contains("FStringUserOwnedFlag"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn remove_all_fflags_cleans_bootstrapper_settings_and_preserves_user_flags() {
        let dir = std::env::temp_dir().join("roblox_opt_test_fflag_remove_bootstrapper");
        let _ = fs::remove_dir_all(&dir);
        let client_settings = dir
            .join("Fishstrap")
            .join("Modifications")
            .join("ClientSettings");
        fs::create_dir_all(&client_settings).unwrap();
        fs::write(
            client_settings.join("ClientAppSettings.json"),
            r#"{
  "FFlagDebugGraphicsPreferD3D11": "True",
  "DFIntTaskSchedulerTargetFps": 240,
  "FStringUserOwnedFlag": "keep-me"
}"#,
        )
        .unwrap();

        let opt = optimizer_with_path(dir.join("settings.xml"));
        opt.remove_all_fflags_for_local_app_data(&dir).unwrap();

        let content = fs::read_to_string(client_settings.join("ClientAppSettings.json")).unwrap();
        assert!(!content.contains("FFlagDebugGraphicsPreferD3D11"));
        assert!(!content.contains(RobloxOptimizer::FPS_UNLOCK_FFLAG));
        assert!(content.contains("FStringUserOwnedFlag"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn remove_all_fflags_removes_empty_bootstrapper_client_settings_folder() {
        let dir = std::env::temp_dir().join("roblox_opt_test_fflag_remove_empty_bootstrapper");
        let _ = fs::remove_dir_all(&dir);
        let client_settings = dir
            .join("Bloxstrap")
            .join("Modifications")
            .join("ClientSettings");
        fs::create_dir_all(&client_settings).unwrap();
        fs::write(
            client_settings.join("ClientAppSettings.json"),
            r#"{
  "FFlagDebugGraphicsPreferD3D11": "True",
  "DFIntTaskSchedulerTargetFps": 240
}"#,
        )
        .unwrap();

        let opt = optimizer_with_path(dir.join("settings.xml"));
        opt.remove_all_fflags_for_local_app_data(&dir).unwrap();

        assert!(!client_settings.exists());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn remove_all_fflags_keeps_unknown_empty_client_settings_folder() {
        let dir = std::env::temp_dir().join("roblox_opt_test_fflag_keep_unknown_empty_folder");
        let _ = fs::remove_dir_all(&dir);
        let client_settings = dir.join("Unknownstrap").join("ClientSettings");
        fs::create_dir_all(&client_settings).unwrap();
        fs::write(
            client_settings.join("ClientAppSettings.json"),
            r#"{
  "FFlagDebugGraphicsPreferD3D11": "True",
  "DFIntTaskSchedulerTargetFps": 240
}"#,
        )
        .unwrap();

        let opt = optimizer_with_path(dir.join("settings.xml"));
        opt.remove_all_fflags_in_paths(vec![client_settings.clone()])
            .unwrap();

        assert!(client_settings.exists());
        assert!(!client_settings.join("ClientAppSettings.json").exists());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn remove_all_fflags_preserves_malformed_client_app_settings() {
        let dir = std::env::temp_dir().join("roblox_opt_test_fflag_malformed_json_remove");
        let _ = fs::remove_dir_all(&dir);
        let client_settings = dir
            .join("Bloxstrap")
            .join("Modifications")
            .join("ClientSettings");
        fs::create_dir_all(&client_settings).unwrap();
        let settings_path = client_settings.join("ClientAppSettings.json");
        fs::write(&settings_path, "{ this is not valid json").unwrap();

        let opt = optimizer_with_path(dir.join("settings.xml"));
        let result = opt.remove_all_fflags_for_local_app_data(&dir);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Failed to parse"));
        assert_eq!(
            fs::read_to_string(settings_path).unwrap(),
            "{ this is not valid json"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn repair_global_basic_settings_permissions_removes_readonly() {
        let dir = std::env::temp_dir().join("roblox_opt_test_repair_perms");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let path = dir.join("settings.xml");
        fs::write(&path, "<roblox></roblox>").unwrap();

        // Use the cross-platform set_readonly_path helper
        RobloxOptimizer::set_readonly_path(&path).unwrap();
        assert!(RobloxOptimizer::is_readonly_path(&path));

        let opt = optimizer_with_path(path.clone());
        opt.repair_global_basic_settings_permissions().unwrap();

        assert!(!RobloxOptimizer::is_readonly_path(&path));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn repair_global_basic_settings_permissions_noop_when_missing() {
        let dir = std::env::temp_dir().join("roblox_opt_test_repair_noop");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let path = dir.join("settings.xml");
        // File doesn't exist — should return Ok(()) without error
        let opt = optimizer_with_path(path);
        opt.repair_global_basic_settings_permissions().unwrap();

        let _ = fs::remove_dir_all(&dir);
    }

    // ── ultraboost FFlag constants ────────────────────────────────────

    #[test]
    fn ultraboost_fflags_count() {
        // 10 originals + Vulkan/OpenGL defensive negations + 5 new allowlisted
        // perf flags (DFFlagDebugPauseVoxelizer + 4 CSG LOD distance entries).
        assert_eq!(
            RobloxOptimizer::ULTRABOOST_FFLAGS.len(),
            17,
            "Expected 17 ultraboost FFlags"
        );
    }

    #[test]
    fn legacy_blocked_fflags_count() {
        // DFFlagDebugPauseVoxelizer moved out of LEGACY_BLOCKED_FFLAGS because
        // it is now an active Ultraboost flag (allowlisted and useful).
        assert_eq!(
            RobloxOptimizer::LEGACY_BLOCKED_FFLAGS.len(),
            4,
            "Expected 4 legacy blocked FFlags"
        );
    }

    #[test]
    fn removed_ultraboost_fflags_count() {
        assert_eq!(
            RobloxOptimizer::REMOVED_ULTRABOOST_FFLAGS.len(),
            1,
            "Expected 1 retired ultraboost FFlag"
        );
    }

    /// Regression test for the GPU-preference cleanup gap Greptile flagged:
    /// `sync_gpu_preference(false)` must also pick up entries written for
    /// Roblox version folders that have been auto-updated away. Parses a
    /// fake `reg query` table including unrelated apps + a stale entry.
    #[test]
    fn parse_gpu_preference_names_picks_only_roblox_version_entries() {
        let sample = r#"
HKEY_CURRENT_USER\SOFTWARE\Microsoft\DirectX\UserGpuPreferences
    DirectXUserGlobalSettings    REG_SZ    VRROptimizeEnable=0;
    C:\Program Files\Discord\Discord.exe    REG_SZ    GpuPreference=2;
    C:\Users\evelyn\AppData\Local\Roblox\Versions\version-aaa111\RobloxPlayerBeta.exe    REG_SZ    GpuPreference=2;
    C:\Users\evelyn\AppData\Local\Roblox\Versions\version-bbb222\RobloxStudioBeta.exe    REG_SZ    GpuPreference=2;
    C:\Users\evelyn\AppData\Local\Roblox\Versions\version-ccc333\Other.exe    REG_SZ    GpuPreference=2;
"#;
        let names = RobloxOptimizer::parse_gpu_preference_names(sample);
        assert_eq!(
            names,
            vec![
                "C:\\Users\\evelyn\\AppData\\Local\\Roblox\\Versions\\version-aaa111\\RobloxPlayerBeta.exe".to_string(),
                "C:\\Users\\evelyn\\AppData\\Local\\Roblox\\Versions\\version-bbb222\\RobloxStudioBeta.exe".to_string(),
            ],
            "Must keep Roblox version entries and exclude Discord, the global setting, and non-known exes"
        );
    }

    #[test]
    fn parse_gpu_preference_names_returns_empty_for_no_matches() {
        let sample = r#"
HKEY_CURRENT_USER\SOFTWARE\Microsoft\DirectX\UserGpuPreferences
    DirectXUserGlobalSettings    REG_SZ    VRROptimizeEnable=0;
    C:\Program Files\Steam\Steam.exe    REG_SZ    GpuPreference=2;
"#;
        assert!(RobloxOptimizer::parse_gpu_preference_names(sample).is_empty());
    }

    #[test]
    fn gpu_preference_restore_action_restores_snapshot_values() {
        let original = Some("GpuPreference=1;".to_string());
        assert_eq!(
            RobloxOptimizer::gpu_preference_restore_action(Some(&original)),
            GpuPreferenceRestoreAction::Restore("GpuPreference=1;".to_string())
        );
    }

    #[test]
    fn gpu_preference_restore_action_deletes_only_snapshot_absent_values() {
        let originally_absent = None;
        assert_eq!(
            RobloxOptimizer::gpu_preference_restore_action(Some(&originally_absent)),
            GpuPreferenceRestoreAction::Delete
        );
        assert_eq!(
            RobloxOptimizer::gpu_preference_restore_action(None),
            GpuPreferenceRestoreAction::LeaveUntouched
        );
    }

    #[test]
    fn gpu_preference_snapshot_preserves_absent_original_values() {
        let mut snapshot = GpuPreferenceSnapshot::default();
        snapshot.values.insert(
            r"C:\Users\evelyn\AppData\Local\Roblox\Versions\version-aaa111\RobloxPlayerBeta.exe"
                .to_string(),
            None,
        );
        snapshot.values.insert(
            r"C:\Users\evelyn\AppData\Local\Roblox\Versions\version-bbb222\RobloxStudioBeta.exe"
                .to_string(),
            Some("GpuPreference=1;".to_string()),
        );

        let json = serde_json::to_string(&snapshot).unwrap();
        let roundtrip: GpuPreferenceSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip, snapshot);
    }

    #[test]
    fn parse_registry_string_value_extracts_path_named_value_data() {
        let sample = r#"
HKEY_CURRENT_USER\SOFTWARE\Microsoft\DirectX\UserGpuPreferences
    C:\Users\evelyn\AppData\Local\Roblox\Versions\version-aaa111\RobloxPlayerBeta.exe    REG_SZ    GpuPreference=1;
"#;

        assert_eq!(
            RobloxOptimizer::parse_registry_string_value(
                sample,
                r"C:\Users\evelyn\AppData\Local\Roblox\Versions\version-aaa111\RobloxPlayerBeta.exe",
            ),
            Some("GpuPreference=1;".to_string())
        );
    }

    #[test]
    fn ultraboost_and_legacy_fflags_are_disjoint() {
        let ultraboost_keys: Vec<&str> = RobloxOptimizer::ULTRABOOST_FFLAGS
            .iter()
            .map(|(k, _)| *k)
            .collect();
        for legacy_key in RobloxOptimizer::LEGACY_BLOCKED_FFLAGS
            .iter()
            .chain(RobloxOptimizer::REMOVED_ULTRABOOST_FFLAGS.iter())
        {
            assert!(
                !ultraboost_keys.contains(legacy_key),
                "Cleaned-up key '{}' should not appear in ultraboost FFlags",
                legacy_key
            );
        }
    }

    #[test]
    fn ultraboost_fflags_have_no_duplicate_keys() {
        let keys: Vec<&str> = RobloxOptimizer::ULTRABOOST_FFLAGS
            .iter()
            .map(|(k, _)| *k)
            .collect();
        let mut unique = keys.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(
            keys.len(),
            unique.len(),
            "Ultraboost FFlags contain duplicate keys"
        );
    }

    #[test]
    fn parse_has_nvidia_gpu_detects_nvidia_names() {
        let sample = "Intel(R) UHD Graphics\r\nNVIDIA GeForce RTX 4060 Laptop GPU\r\n";
        assert!(RobloxOptimizer::parse_has_nvidia_gpu(sample));
    }

    #[test]
    fn parse_has_nvidia_gpu_ignores_non_nvidia_names() {
        let sample = "AMD Radeon RX 7800 XT\r\nIntel(R) Arc(TM) Graphics\r\n";
        assert!(!RobloxOptimizer::parse_has_nvidia_gpu(sample));
    }

    #[test]
    fn nvidia_potato_profile_xml_enables_roblox_lod_bias() {
        let xml = RobloxOptimizer::nvidia_potato_profile_xml(true);

        assert!(xml.contains("<ProfileName>Roblox</ProfileName>"));
        assert!(xml.contains("<string>RobloxPlayerBeta.exe</string>"));
        assert!(
            xml.contains("<SettingNameInfo>Texture Filtering - LOD Bias (DX)</SettingNameInfo>")
        );
        assert!(xml.contains(
            "<SettingID>7573135</SettingID>\r\n        <SettingValue>120</SettingValue>"
        ));
        assert!(xml.contains(
            "<SettingID>13510289</SettingID>\r\n        <SettingValue>20</SettingValue>"
        ));
    }

    #[test]
    fn nvidia_potato_profile_xml_resets_lod_bias() {
        let xml = RobloxOptimizer::nvidia_potato_profile_xml(false);

        assert!(xml.contains("<ProfileName>Roblox</ProfileName>"));
        assert!(xml.contains("<string>RobloxPlayerBeta.exe</string>"));
        assert!(
            xml.contains(
                "<SettingID>7573135</SettingID>\r\n        <SettingValue>0</SettingValue>"
            )
        );
        assert!(
            xml.contains(
                "<SettingID>13510289</SettingID>\r\n        <SettingValue>0</SettingValue>"
            )
        );
    }

    #[test]
    fn escape_powershell_single_quoted_doubles_quotes() {
        assert_eq!(
            RobloxOptimizer::escape_powershell_single_quoted("C:\\Users\\O'Brien\\file.zip"),
            "C:\\Users\\O''Brien\\file.zip"
        );
    }

    #[test]
    fn npi_release_url_is_pinned() {
        assert!(RobloxOptimizer::NPI_RELEASE_ZIP_URL.contains(RobloxOptimizer::NPI_RELEASE_TAG));
        assert!(!RobloxOptimizer::NPI_RELEASE_ZIP_URL.contains("/latest/"));
    }

    #[test]
    fn extract_nvidia_profile_xml_selects_only_roblox_profile() {
        let exported = r#"<?xml version="1.0" encoding="utf-16"?>
<ArrayOfProfile>
  <Profile>
    <ProfileName>Other Game</ProfileName>
    <Settings></Settings>
  </Profile>
  <Profile>
    <ProfileName>Roblox</ProfileName>
    <Executeables><string>RobloxPlayerBeta.exe</string></Executeables>
    <Settings><ProfileSetting><SettingID>7573135</SettingID></ProfileSetting></Settings>
  </Profile>
</ArrayOfProfile>"#;

        let profile = RobloxOptimizer::extract_nvidia_profile_xml(exported, "Roblox").unwrap();
        assert!(profile.contains("<ProfileName>Roblox</ProfileName>"));
        assert!(profile.contains("<SettingID>7573135</SettingID>"));
        assert!(!profile.contains("Other Game"));
    }

    #[test]
    fn nvidia_profile_snapshot_roundtrips_optional_roblox_profile() {
        let snapshot = NvidiaProfileSnapshot {
            applied: true,
            roblox_profile_xml: Some(
                "<Profile><ProfileName>Roblox</ProfileName></Profile>".to_string(),
            ),
        };

        let json = serde_json::to_string(&snapshot).unwrap();
        let roundtrip: NvidiaProfileSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip, snapshot);
    }

    #[test]
    fn sha256_file_returns_lowercase_hex() {
        let dir = std::env::temp_dir().join("roblox_opt_test_sha256_file");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("payload.bin");
        fs::write(&path, b"abc").unwrap();

        assert_eq!(
            RobloxOptimizer::sha256_file(&path).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );

        let _ = fs::remove_dir_all(&dir);
    }
}
