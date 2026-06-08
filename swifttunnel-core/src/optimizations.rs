//! Reversible system optimizations for the desktop Optimization tab.
//!
//! Each tweak is a list of small, individually-reversible actions (registry
//! writes, power-plan settings, a service pause, or scheduled-task toggles).
//! `apply` captures the prior state into a snapshot persisted on disk, then
//! makes the change; `revert` restores from that snapshot. Snapshot presence is
//! the source of truth for "is this tweak active", so state survives restarts.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

const SNAPSHOT_FILE: &str = "optimization_snapshots.json";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Hive {
    Hkcu,
    Hklm,
}

/// A single reversible change. A tweak is an ordered list of these.
enum Action {
    RegDword {
        hive: Hive,
        path: &'static str,
        name: &'static str,
        value: u32,
    },
    RegString {
        hive: Hive,
        path: &'static str,
        name: &'static str,
        value: &'static str,
    },
    /// Active power scheme AC value (via powercfg aliases, e.g. SUB_PROCESSOR).
    PowerAc {
        subgroup: &'static str,
        setting: &'static str,
        value: u32,
    },
    /// Stop the service and set it to Disabled.
    ServiceDisable {
        name: &'static str,
    },
    /// Disable a scheduled task.
    TaskDisable {
        path: &'static str,
    },
}

struct Tweak {
    id: &'static str,
    requires_admin: bool,
    requires_reboot: bool,
    actions: &'static [Action],
}

/// The catalog. Ids MUST match the frontend optimization catalog 1:1.
const TWEAKS: &[Tweak] = &[
    Tweak {
        id: "mouse_acceleration_disable",
        requires_admin: false,
        requires_reboot: false,
        actions: &[
            Action::RegString {
                hive: Hive::Hkcu,
                path: r"Control Panel\Mouse",
                name: "MouseSpeed",
                value: "0",
            },
            Action::RegString {
                hive: Hive::Hkcu,
                path: r"Control Panel\Mouse",
                name: "MouseThreshold1",
                value: "0",
            },
            Action::RegString {
                hive: Hive::Hkcu,
                path: r"Control Panel\Mouse",
                name: "MouseThreshold2",
                value: "0",
            },
        ],
    },
    Tweak {
        id: "visual_effects_performance",
        requires_admin: false,
        requires_reboot: false,
        actions: &[Action::RegDword {
            hive: Hive::Hkcu,
            path: r"Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects",
            name: "VisualFXSetting",
            value: 2,
        }],
    },
    Tweak {
        id: "transparency_disable",
        requires_admin: false,
        requires_reboot: false,
        actions: &[Action::RegDword {
            hive: Hive::Hkcu,
            path: r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize",
            name: "EnableTransparency",
            value: 0,
        }],
    },
    Tweak {
        id: "background_apps_disable",
        requires_admin: false,
        requires_reboot: false,
        actions: &[
            Action::RegDword {
                hive: Hive::Hkcu,
                path: r"Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications",
                name: "GlobalUserDisabled",
                value: 1,
            },
            Action::RegDword {
                hive: Hive::Hkcu,
                path: r"Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications",
                name: "BackgroundAppGlobalToggle",
                value: 0,
            },
        ],
    },
    Tweak {
        id: "game_bar_dvr_disable",
        requires_admin: false,
        requires_reboot: false,
        actions: &[
            Action::RegDword {
                hive: Hive::Hkcu,
                path: r"Software\Microsoft\Windows\CurrentVersion\GameDVR",
                name: "AppCaptureEnabled",
                value: 0,
            },
            Action::RegDword {
                hive: Hive::Hkcu,
                path: r"Software\Microsoft\Windows\CurrentVersion\GameDVR",
                name: "AudioCaptureEnabled",
                value: 0,
            },
            Action::RegDword {
                hive: Hive::Hkcu,
                path: r"Software\Microsoft\GameBar",
                name: "ShowStartupPanel",
                value: 0,
            },
            Action::RegDword {
                hive: Hive::Hkcu,
                path: r"System\GameConfigStore",
                name: "GameDVR_Enabled",
                value: 0,
            },
        ],
    },
    Tweak {
        id: "power_throttling_disable",
        requires_admin: true,
        requires_reboot: false,
        actions: &[Action::RegDword {
            hive: Hive::Hklm,
            path: r"SYSTEM\CurrentControlSet\Control\Power\PowerThrottling",
            name: "PowerThrottlingOff",
            value: 1,
        }],
    },
    Tweak {
        id: "core_parking_disable",
        requires_admin: true,
        requires_reboot: false,
        actions: &[Action::PowerAc {
            subgroup: "SUB_PROCESSOR",
            setting: "CPMINCORES",
            value: 100,
        }],
    },
    Tweak {
        id: "sysmain_pause",
        requires_admin: true,
        requires_reboot: false,
        actions: &[Action::ServiceDisable { name: "SysMain" }],
    },
    Tweak {
        id: "hags_enable",
        requires_admin: true,
        requires_reboot: true,
        actions: &[Action::RegDword {
            hive: Hive::Hklm,
            path: r"SYSTEM\CurrentControlSet\Control\GraphicsDrivers",
            name: "HwSchMode",
            value: 2,
        }],
    },
    Tweak {
        // The CEIP scheduled tasks are protected and refuse `schtasks /Change`
        // even when elevated ("Access is denied"). Use the admin-writable
        // telemetry policy instead, which actually reduces data collection.
        id: "telemetry_tasks_disable",
        requires_admin: true,
        requires_reboot: false,
        actions: &[Action::RegDword {
            hive: Hive::Hklm,
            path: r"SOFTWARE\Policies\Microsoft\Windows\DataCollection",
            name: "AllowTelemetry",
            value: 0,
        }],
    },
];

fn find_tweak(id: &str) -> Option<&'static Tweak> {
    TWEAKS.iter().find(|t| t.id == id)
}

// ── Snapshot model ──────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind")]
enum ActionSnapshot {
    RegDword { value: Option<u32> },
    RegString { value: Option<String> },
    Power { value: Option<u32> },
    Service { start_type: Option<u32> },
    Task { was_enabled: bool },
}

type Snapshots = BTreeMap<String, Vec<ActionSnapshot>>;

fn snapshot_path() -> Option<PathBuf> {
    dirs::config_dir().map(|p| p.join("SwiftTunnel").join(SNAPSHOT_FILE))
}

fn load_all() -> Snapshots {
    let Some(path) = snapshot_path() else {
        return Snapshots::new();
    };
    match std::fs::read_to_string(&path) {
        Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
        Err(_) => Snapshots::new(),
    }
}

fn save_all(map: &Snapshots) -> Result<(), String> {
    let path = snapshot_path().ok_or("No config dir for optimization snapshots")?;
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let json =
        serde_json::to_string_pretty(map).map_err(|e| format!("serialize snapshots: {e}"))?;
    std::fs::write(&path, json).map_err(|e| format!("write snapshots: {e}"))
}

// ── Public API ──────────────────────────────────────────────────────────────

/// Ids of every tweak that currently has a snapshot (i.e. is applied).
pub fn active_ids() -> Vec<String> {
    load_all().keys().cloned().collect()
}

/// Apply a tweak. Returns whether a restart is required to finish.
/// No-op (returns Ok) if the tweak is already applied.
pub fn apply(id: &str) -> Result<bool, String> {
    let tweak = find_tweak(id).ok_or_else(|| format!("Unknown optimization: {id}"))?;

    let mut snapshots = load_all();
    if snapshots.contains_key(id) {
        return Ok(tweak.requires_reboot); // already applied
    }

    if tweak.requires_admin && !crate::utils::is_administrator() {
        return Err(
            "Administrator required. Restart SwiftTunnel as administrator to apply this optimization."
                .to_string(),
        );
    }

    // Capture the prior state of every action BEFORE changing anything.
    let mut captured: Vec<ActionSnapshot> = Vec::with_capacity(tweak.actions.len());
    for action in tweak.actions {
        captured.push(capture_action(action)?);
    }

    // Apply each action; on the first failure, roll back what we already did.
    for (index, action) in tweak.actions.iter().enumerate() {
        if let Err(e) = apply_action(action) {
            for (done_action, snap) in tweak.actions[..index].iter().zip(captured.iter()) {
                let _ = restore_action(done_action, snap);
            }
            return Err(format!("Failed to apply {id}: {e}"));
        }
    }

    snapshots.insert(id.to_string(), captured);
    save_all(&snapshots)?;
    Ok(tweak.requires_reboot)
}

/// Revert a tweak from its snapshot. Returns whether a restart is required.
/// No-op (returns Ok) if the tweak is not currently applied.
pub fn revert(id: &str) -> Result<bool, String> {
    let tweak = find_tweak(id).ok_or_else(|| format!("Unknown optimization: {id}"))?;

    let mut snapshots = load_all();
    let Some(captured) = snapshots.get(id).cloned() else {
        return Ok(tweak.requires_reboot); // already inactive
    };

    if tweak.requires_admin && !crate::utils::is_administrator() {
        return Err(
            "Administrator required. Restart SwiftTunnel as administrator to revert this optimization."
                .to_string(),
        );
    }

    let mut first_error: Option<String> = None;
    for (action, snap) in tweak.actions.iter().zip(captured.iter()) {
        if let Err(e) = restore_action(action, snap) {
            if first_error.is_none() {
                first_error = Some(e);
            }
        }
    }

    // Drop the snapshot regardless: restore is best-effort and we should not
    // leave the tweak stuck "on" if most actions reverted.
    snapshots.remove(id);
    save_all(&snapshots)?;

    match first_error {
        Some(e) => Err(format!("Reverted {id} with errors: {e}")),
        None => Ok(tweak.requires_reboot),
    }
}

// ── Action execution (Windows) ──────────────────────────────────────────────

#[cfg(windows)]
fn capture_action(action: &Action) -> Result<ActionSnapshot, String> {
    Ok(match action {
        Action::RegDword {
            hive, path, name, ..
        } => ActionSnapshot::RegDword {
            value: read_reg_dword(*hive, path, name),
        },
        Action::RegString {
            hive, path, name, ..
        } => ActionSnapshot::RegString {
            value: read_reg_string(*hive, path, name),
        },
        Action::PowerAc {
            subgroup, setting, ..
        } => ActionSnapshot::Power {
            value: read_power_ac(subgroup, setting),
        },
        Action::ServiceDisable { name } => ActionSnapshot::Service {
            start_type: read_service_start_type(name),
        },
        Action::TaskDisable { path } => ActionSnapshot::Task {
            was_enabled: read_task_enabled(path).unwrap_or(false),
        },
    })
}

#[cfg(windows)]
fn apply_action(action: &Action) -> Result<(), String> {
    match action {
        Action::RegDword {
            hive,
            path,
            name,
            value,
        } => write_reg_dword(*hive, path, name, *value),
        Action::RegString {
            hive,
            path,
            name,
            value,
        } => write_reg_string(*hive, path, name, value),
        Action::PowerAc {
            subgroup,
            setting,
            value,
        } => set_power_ac(subgroup, setting, *value),
        Action::ServiceDisable { name } => {
            // Stop is best-effort (service may already be stopped).
            let _ = run("sc", &["stop", name]);
            run("sc", &["config", name, "start=", "disabled"]).map(|_| ())
        }
        Action::TaskDisable { path } => {
            run("schtasks", &["/Change", "/TN", path, "/DISABLE"]).map(|_| ())
        }
    }
}

#[cfg(windows)]
fn restore_action(action: &Action, snap: &ActionSnapshot) -> Result<(), String> {
    match (action, snap) {
        (Action::RegDword { hive, path, name, .. }, ActionSnapshot::RegDword { value }) => {
            match value {
                Some(v) => write_reg_dword(*hive, path, name, *v),
                None => delete_reg_value(*hive, path, name),
            }
        }
        (Action::RegString { hive, path, name, .. }, ActionSnapshot::RegString { value }) => {
            match value {
                Some(v) => write_reg_string(*hive, path, name, v),
                None => delete_reg_value(*hive, path, name),
            }
        }
        (Action::PowerAc { subgroup, setting, .. }, ActionSnapshot::Power { value }) => {
            match value {
                Some(v) => set_power_ac(subgroup, setting, *v),
                None => Ok(()),
            }
        }
        (Action::ServiceDisable { name }, ActionSnapshot::Service { start_type }) => {
            let keyword = match start_type {
                Some(2) => "auto",
                Some(3) => "demand",
                Some(4) => "disabled",
                _ => "demand",
            };
            run("sc", &["config", name, "start=", keyword])?;
            // If it was previously enabled, start it again (best-effort).
            if matches!(start_type, Some(2) | Some(3)) {
                let _ = run("sc", &["start", name]);
            }
            Ok(())
        }
        (Action::TaskDisable { path }, ActionSnapshot::Task { was_enabled }) => {
            if *was_enabled {
                run("schtasks", &["/Change", "/TN", path, "/ENABLE"]).map(|_| ())
            } else {
                Ok(())
            }
        }
        _ => Err("snapshot/action mismatch".to_string()),
    }
}

// ── Registry helpers (Windows) ──────────────────────────────────────────────

#[cfg(windows)]
fn reg_root(hive: Hive) -> winreg::RegKey {
    use winreg::RegKey;
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
    RegKey::predef(match hive {
        Hive::Hkcu => HKEY_CURRENT_USER,
        Hive::Hklm => HKEY_LOCAL_MACHINE,
    })
}

#[cfg(windows)]
fn read_reg_dword(hive: Hive, path: &str, name: &str) -> Option<u32> {
    let key = reg_root(hive).open_subkey(path).ok()?;
    key.get_value::<u32, _>(name).ok()
}

#[cfg(windows)]
fn read_reg_string(hive: Hive, path: &str, name: &str) -> Option<String> {
    let key = reg_root(hive).open_subkey(path).ok()?;
    key.get_value::<String, _>(name).ok()
}

#[cfg(windows)]
fn write_reg_dword(hive: Hive, path: &str, name: &str, value: u32) -> Result<(), String> {
    let (key, _) = reg_root(hive)
        .create_subkey(path)
        .map_err(|e| format!("open {path}: {e}"))?;
    key.set_value(name, &value)
        .map_err(|e| format!("set {name}: {e}"))
}

#[cfg(windows)]
fn write_reg_string(hive: Hive, path: &str, name: &str, value: &str) -> Result<(), String> {
    let (key, _) = reg_root(hive)
        .create_subkey(path)
        .map_err(|e| format!("open {path}: {e}"))?;
    key.set_value(name, &value.to_string())
        .map_err(|e| format!("set {name}: {e}"))
}

#[cfg(windows)]
fn delete_reg_value(hive: Hive, path: &str, name: &str) -> Result<(), String> {
    let key = match reg_root(hive).open_subkey_with_flags(path, winreg::enums::KEY_ALL_ACCESS) {
        Ok(k) => k,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(format!("open {path}: {e}")),
    };
    match key.delete_value(name) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("delete {name}: {e}")),
    }
}

#[cfg(windows)]
fn read_service_start_type(name: &str) -> Option<u32> {
    read_reg_dword(
        Hive::Hklm,
        &format!(r"SYSTEM\CurrentControlSet\Services\{name}"),
        "Start",
    )
}

// ── powercfg helpers (Windows) ──────────────────────────────────────────────

#[cfg(windows)]
fn read_power_ac(subgroup: &str, setting: &str) -> Option<u32> {
    let out = crate::hidden_command("powercfg")
        .args(["/query", "SCHEME_CURRENT", subgroup, setting])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("Current AC Power Setting Index:") {
            let token = rest.trim();
            let parsed = if let Some(hex) = token.strip_prefix("0x") {
                u32::from_str_radix(hex, 16).ok()
            } else {
                token.parse::<u32>().ok()
            };
            return parsed;
        }
    }
    None
}

#[cfg(windows)]
fn set_power_ac(subgroup: &str, setting: &str, value: u32) -> Result<(), String> {
    run(
        "powercfg",
        &[
            "/setacvalueindex",
            "SCHEME_CURRENT",
            subgroup,
            setting,
            &value.to_string(),
        ],
    )?;
    run("powercfg", &["/setactive", "SCHEME_CURRENT"]).map(|_| ())
}

// ── scheduled tasks (Windows) ───────────────────────────────────────────────

#[cfg(windows)]
fn read_task_enabled(path: &str) -> Option<bool> {
    let out = crate::hidden_command("schtasks")
        .args(["/Query", "/TN", path, "/FO", "LIST"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None; // task does not exist
    }
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        if let Some(rest) = line.trim().strip_prefix("Status:") {
            let status = rest.trim().to_ascii_lowercase();
            return Some(status != "disabled");
        }
    }
    None
}

// ── command runner (Windows) ────────────────────────────────────────────────

#[cfg(windows)]
fn run(program: &str, args: &[&str]) -> Result<String, String> {
    let out = crate::hidden_command(program)
        .args(args)
        .output()
        .map_err(|e| format!("run {program}: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
        let detail = if !stderr.is_empty() { stderr } else { stdout };
        Err(format!("{program} failed: {detail}"))
    }
}

// ── Non-Windows stubs ───────────────────────────────────────────────────────

#[cfg(not(windows))]
fn capture_action(_action: &Action) -> Result<ActionSnapshot, String> {
    Err("Optimizations are only supported on Windows".to_string())
}

#[cfg(not(windows))]
fn apply_action(_action: &Action) -> Result<(), String> {
    Err("Optimizations are only supported on Windows".to_string())
}

#[cfg(not(windows))]
fn restore_action(_action: &Action, _snap: &ActionSnapshot) -> Result<(), String> {
    Err("Optimizations are only supported on Windows".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_ids_are_unique() {
        let mut ids: Vec<&str> = TWEAKS.iter().map(|t| t.id).collect();
        ids.sort_unstable();
        let len = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), len, "duplicate tweak id in catalog");
    }

    #[test]
    fn catalog_matches_frontend_ids() {
        // Keep this list in lockstep with src/components/optimization/optimizationCatalog.ts
        let expected = [
            "mouse_acceleration_disable",
            "visual_effects_performance",
            "transparency_disable",
            "background_apps_disable",
            "game_bar_dvr_disable",
            "power_throttling_disable",
            "core_parking_disable",
            "sysmain_pause",
            "hags_enable",
            "telemetry_tasks_disable",
        ];
        for id in expected {
            assert!(find_tweak(id).is_some(), "missing tweak: {id}");
        }
        assert_eq!(TWEAKS.len(), expected.len());
    }

    #[test]
    fn unknown_tweak_errors() {
        assert!(apply("does_not_exist").is_err());
        assert!(revert("does_not_exist").is_err());
    }
}
