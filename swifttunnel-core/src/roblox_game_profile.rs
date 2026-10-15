//! Temporary FPS/graphics overrides with conditional restoration and a crash journal.
use crate::{
    roblox_library::{GamePreferences, RobloxClient},
    roblox_optimizer::RobloxOptimizer,
};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
enum Property {
    Fps,
    Quality,
    SavedQuality,
}
impl Property {
    fn name(self) -> &'static str {
        match self {
            Self::Fps => "FramerateCap",
            Self::Quality => "GraphicsQualityLevel",
            Self::SavedQuality => "SavedQualityLevel",
        }
    }
    fn tag(self) -> &'static str {
        if self == Self::SavedQuality {
            "token"
        } else {
            "int"
        }
    }
}
#[derive(Serialize, Deserialize)]
struct Override {
    property: Property,
    before: Option<i32>,
    applied: i32,
}
#[derive(Serialize, Deserialize)]
struct Journal {
    client: RobloxClient,
    fields: Vec<Override>,
    #[serde(default)]
    flags: Vec<FlagOverride>,
    #[serde(default)]
    created_at: u64,
}

#[derive(Serialize, Deserialize)]
struct FlagOverride {
    path: PathBuf,
    before: serde_json::Value,
    applied: Option<serde_json::Value>,
    #[serde(default)]
    applied_hash: String,
}
const QUALITY_FLAG: &str = "DFIntDebugFRMQualityLevelOverride";
const RESTORE_ERROR: &str =
    "Couldn't restore your Roblox FPS and graphics settings. Contact support and include your log.";
fn flag_plan(level: Option<i32>) -> Result<Vec<FlagOverride>, String> {
    let Some(level) = level else {
        return Ok(Vec::new());
    };
    let files = RobloxOptimizer::existing_client_flag_files().map_err(|e| e.to_string())?;
    let mut output = Vec::new();
    for path in files.into_iter().take(64) {
        let raw = read(&path)?;
        let value: serde_json::Value = serde_json::from_str(raw.trim_start_matches('\u{feff}'))
            .map_err(|_| {
                "Clean invalid launcher flag files before using a game graphics profile."
                    .to_string()
            })?;
        if let Some(before) = value.get(QUALITY_FLAG) {
            let valid = before.as_i64().is_some_and(|v| (-1..=10).contains(&v))
                || before
                    .as_str()
                    .is_some_and(|v| v.parse::<i32>().is_ok_and(|v| (-1..=10).contains(&v)));
            if !valid {
                continue;
            }
            let applied = (level > 0).then(|| {
                if before.is_string() {
                    serde_json::Value::String(level.to_string())
                } else {
                    serde_json::Value::from(level)
                }
            });
            if applied.as_ref() != Some(before) {
                let mut next = value.clone();
                if let Some(object) = next.as_object_mut() {
                    match &applied {
                        Some(value) => {
                            object.insert(QUALITY_FLAG.into(), value.clone());
                        }
                        None => {
                            object.remove(QUALITY_FLAG);
                        }
                    }
                }
                output.push(FlagOverride {
                    path,
                    before: before.clone(),
                    applied,
                    applied_hash: checksum(
                        &serde_json::to_vec_pretty(&next).map_err(|e| e.to_string())?,
                    ),
                });
            }
        }
    }
    Ok(output)
}
fn apply_flag(flag: &FlagOverride, restore: bool) -> Result<(), String> {
    if restore && !flag.path.exists() {
        return Ok(());
    }
    let allowed = RobloxOptimizer::existing_client_flag_files().map_err(|e| e.to_string())?;
    if !allowed.contains(&flag.path) {
        log::warn!(
            "Game profile recovery flag path no longer matches an installed flag file: {}",
            flag.path.display()
        );
        return Err("Couldn't restore your Roblox graphics settings because a FastFlags file moved. Contact support and include your log.".into());
    }
    let metadata = fs::symlink_metadata(&flag.path).map_err(|e| e.to_string())?;
    if metadata.file_type().is_symlink() {
        return Err("Couldn't update Roblox's FastFlags because the file links to another location. Contact support and include your log.".into());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err("Couldn't update Roblox's FastFlags because the file links to another location. Contact support and include your log.".into());
        }
    }
    let raw = read(&flag.path)?;
    let mut value: serde_json::Value =
        serde_json::from_str(raw.trim_start_matches('\u{feff}')).map_err(|e| e.to_string())?;
    let object = value
        .as_object_mut()
        .ok_or("Launcher flags are not a JSON object.")?;
    if restore {
        if object.get(QUALITY_FLAG) != flag.applied.as_ref() {
            return Ok(());
        }
        object.insert(QUALITY_FLAG.into(), flag.before.clone());
    } else {
        if object.get(QUALITY_FLAG) != Some(&flag.before) {
            return Err("Launcher flags changed while preparing the game. Try Play again.".into());
        }
        match &flag.applied {
            Some(applied) => {
                object.insert(QUALITY_FLAG.into(), applied.clone());
            }
            None => {
                object.remove(QUALITY_FLAG);
            }
        }
    }
    write(
        &flag.path,
        &serde_json::to_vec_pretty(&value).map_err(|e| e.to_string())?,
    )
}

fn journal_path() -> Result<PathBuf, String> {
    dirs::config_dir()
        .map(|p| p.join("SwiftTunnel").join("game-profile.json"))
        .ok_or("Windows could not find your settings folder.".into())
}
pub fn pending() -> bool {
    journal_path().is_ok_and(|p| p.exists())
}
fn read(path: &Path) -> Result<String, String> {
    let recovery = path
        .file_name()
        .is_some_and(|name| name == "game-profile.json");
    let mut bytes = Vec::new();
    fs::File::open(path)
        .and_then(|file| file.take(256 * 1024 + 1).read_to_end(&mut bytes))
        .map_err(|error| {
            log::warn!(
                "Could not read game settings file {}: {error}",
                path.display()
            );
            if recovery {
                RESTORE_ERROR.to_string()
            } else {
                "Could not read Roblox preferences. Open Roblox once, close it and try again."
                    .to_string()
            }
        })?;
    if bytes.len() > 256 * 1024 {
        log::warn!("Game settings file exceeds 256 KB: {}", path.display());
        return Err(if recovery {
            RESTORE_ERROR.into()
        } else {
            "Couldn't read your Roblox settings. Contact support and include your log.".into()
        });
    }
    String::from_utf8(bytes).map_err(|error| {
        log::warn!(
            "Game settings file is not UTF-8, {}: {error}",
            path.display()
        );
        if recovery {
            RESTORE_ERROR.into()
        } else {
            "Couldn't read your Roblox settings. Contact support and include your log.".into()
        }
    })
}
fn write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    for ancestor in path.parent().into_iter().flat_map(Path::ancestors) {
        let meta = fs::symlink_metadata(ancestor).map_err(|e| e.to_string())?;
        if meta.file_type().is_symlink() {
            return Err("Couldn't save your Roblox settings because the folder links to another location. Contact support and include your log.".into());
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if meta.file_attributes() & 0x400 != 0 {
                return Err("Couldn't save your Roblox settings because the folder links to another location. Contact support and include your log.".into());
            }
        }
    }
    let temporary = path.with_extension(format!("{}.game-profile.tmp", std::process::id()));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|e| format!("Could not save game preferences: {e}"))?;
    let result = (|| -> std::io::Result<()> {
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.map_err(|e| format!("Could not save game preferences: {e}"))
}
fn pattern(property: Property) -> regex_lite::Regex {
    regex_lite::Regex::new(&format!(
        r#"<{}\s+name="{}">\s*(-?\d+)\s*</{}>"#,
        property.tag(),
        property.name(),
        property.tag()
    ))
    .unwrap()
}
fn value(xml: &str, property: Property) -> Option<i32> {
    pattern(property)
        .captures(xml)?
        .get(1)?
        .as_str()
        .parse()
        .ok()
}
fn set(xml: &str, property: Property, number: Option<i32>) -> String {
    let pattern = pattern(property);
    let replacement = number
        .map(|n| {
            format!(
                r#"<{} name="{}">{n}</{}>"#,
                property.tag(),
                property.name(),
                property.tag()
            )
        })
        .unwrap_or_default();
    if pattern.is_match(xml) {
        pattern.replace(xml, replacement.as_str()).to_string()
    } else if number.is_some() {
        xml.replacen("</Properties>", &format!("{replacement}\n</Properties>"), 1)
    } else {
        xml.into()
    }
}
fn stopped() -> bool {
    #[cfg(windows)]
    {
        // An unreadable process snapshot is not proof that changing the
        // player's files is safe. Keep the journal for a later retry.
        crate::process_snapshot::any_named(crate::process_names::ROBLOX_PLAYER_PROCESS_NAMES)
            .is_ok_and(|running| !running)
    }
    #[cfg(not(windows))]
    {
        let mut system = sysinfo::System::new();
        system.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
        !system.processes().values().any(|p| {
            crate::process_names::is_roblox_player_process_name(&p.name().to_string_lossy())
        })
    }
}
pub fn player_stopped() -> bool {
    stopped()
}

pub fn apply(client: RobloxClient, preferences: &GamePreferences) -> Result<bool, String> {
    apply_inner(client, preferences, false)
}
pub fn apply_native(client: RobloxClient, preferences: &GamePreferences) -> Result<bool, String> {
    apply_inner(client, preferences, true)
}
fn apply_inner(
    client: RobloxClient,
    preferences: &GamePreferences,
    native: bool,
) -> Result<bool, String> {
    if !prepare_profile(preferences, stopped, restore)? {
        return Ok(false);
    }
    let path = RobloxOptimizer::game_preferences_path(client)?;
    let mut xml = read(&path)?;
    if !xml.contains("</Properties>") {
        return Err("Roblox's preferences file could not be updated safely.".into());
    }
    let mut fields = Vec::new();
    let choices = [
        (Property::Fps, preferences.fps_cap.map(|fps| fps as i32)),
        (
            Property::Quality,
            preferences.graphics_quality.as_ref().map(|g| g.to_level()),
        ),
        (
            Property::SavedQuality,
            preferences.graphics_quality.as_ref().map(|g| g.to_level()),
        ),
    ];
    for (property, applied) in choices {
        if let Some(applied) = applied {
            let before = value(&xml, property);
            if before != Some(applied) {
                fields.push(Override {
                    property,
                    before,
                    applied,
                });
                xml = set(&xml, property, Some(applied));
            }
        }
    }
    let flags = if native {
        Vec::new()
    } else {
        flag_plan(preferences.graphics_quality.as_ref().map(|g| g.to_level()))?
    };
    if fields.is_empty() && flags.is_empty() {
        return Ok(false);
    }
    let journal = Journal {
        client,
        fields,
        flags,
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0),
    };
    // Never change the player's file if the originals would be rejected by
    // our own recovery reader later.
    validate_journal(&journal).map_err(|_| {
        "Roblox's saved FPS or graphics settings aren't supported. Change them in Roblox, then try Play again.".to_string()
    })?;
    write(
        &journal_path()?,
        &serde_json::to_vec(&journal).map_err(|e| e.to_string())?,
    )?;
    write(&path, xml.as_bytes())?;
    for flag in &journal.flags {
        apply_flag(flag, false)?;
    }
    Ok(true)
}

fn prepare_profile(
    preferences: &GamePreferences,
    stopped: impl FnOnce() -> bool,
    restore: impl FnOnce() -> Result<bool, String>,
) -> Result<bool, String> {
    preferences.validate()?;
    let overrides = preferences.fps_cap.is_some() || preferences.graphics_quality.is_some();
    if overrides && !stopped() {
        return Err("Close Roblox before applying a game's FPS or graphics profile.".into());
    }
    // Even an unconfigured game must not inherit the previous game's
    // temporary settings while background recovery is still waiting.
    restore()?;
    Ok(overrides)
}

/// Each restore is independent: a damaged profile must not prevent recovery
/// of an otherwise valid FastFlags backup, or vice versa.
pub fn restore_launch_settings() -> Result<bool, String> {
    restore_settings_with(restore, crate::roblox_launch_flags::restore)
}

fn restore_settings_with(
    profile: impl FnOnce() -> Result<bool, String>,
    flags: impl FnOnce() -> Result<bool, String>,
) -> Result<bool, String> {
    let profile = profile();
    let flags = flags();
    match (profile, flags) {
        (Ok(profile), Ok(flags)) => Ok(profile || flags),
        (Err(profile), Err(flags)) => {
            log::warn!("Both launch settings restores failed: profile={profile}; flags={flags}");
            Err("Couldn't restore your Roblox settings or FastFlags. Contact support and include your log.".into())
        }
        (Err(error), _) | (_, Err(error)) => Err(error),
    }
}
fn restore_xml(mut xml: String, fields: &[Override]) -> String {
    for field in fields {
        // Keep settings the player changed during the game. Restore only a
        // field that still contains this feature's temporary value.
        if value(&xml, field.property) == Some(field.applied) {
            xml = set(&xml, field.property, field.before);
        }
    }
    xml
}
pub fn restore() -> Result<bool, String> {
    let journal_path = journal_path()?;
    if !journal_path.exists() || !stopped() {
        return Ok(false);
    }
    let bytes = read(&journal_path)?;
    let journal: Journal = serde_json::from_str(&bytes).map_err(|error| {
        log::warn!(
            "Game profile recovery record could not be decoded; retained for inspection: {error}"
        );
        RESTORE_ERROR.to_string()
    })?;
    validate_journal(&journal)?;
    let path = RobloxOptimizer::game_preferences_path(journal.client)?;
    let xml = read(&path)?;
    let restored = restore_xml(xml.clone(), &journal.fields);
    if restored != xml {
        write(&path, restored.as_bytes())?;
    }
    for flag in &journal.flags {
        apply_flag(flag, true)?;
    }
    // A strap may copy its modifications into a new Roblox version during
    // launch. Restore a copy only when it was created during this profile and
    // its entire contents still match our temporary file exactly.
    for path in RobloxOptimizer::existing_client_flag_files().map_err(|e| e.to_string())? {
        if journal.flags.iter().any(|f| f.path == path) {
            continue;
        }
        let created = fs::metadata(&path)
            .and_then(|m| m.created())
            .ok()
            .and_then(|at| at.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_millis() as u64);
        if created.is_none_or(|at| at < journal.created_at) {
            continue;
        }
        let bytes = read(&path)?.into_bytes();
        let actual_hash = checksum(&bytes);
        if let Some(template) = journal
            .flags
            .iter()
            .find(|f| !f.applied_hash.is_empty() && actual_hash == f.applied_hash)
        {
            let copy = FlagOverride {
                path,
                before: template.before.clone(),
                applied: template.applied.clone(),
                applied_hash: template.applied_hash.clone(),
            };
            apply_flag(&copy, true)?;
        }
    }
    fs::remove_file(journal_path).map_err(|e| {
        log::warn!("Game profile restored but recovery record could not be removed: {e}");
        "Your Roblox settings were restored, but cleanup failed. Restart SwiftTunnel. If it happens again, contact support.".to_string()
    })?;
    Ok(true)
}

fn validate_journal(journal: &Journal) -> Result<(), String> {
    if journal.fields.len() > 3
        || journal.flags.len() > 64
        || journal.flags.iter().any(|f| {
            !f.path.is_absolute()
                || f.path
                    .file_name()
                    .is_none_or(|name| name != "ClientAppSettings.json")
                || f.before.to_string().len() > 32
                || !valid_flag_value(&f.before)
                || f.applied.as_ref().is_some_and(|v| !valid_flag_value(v))
                || f.applied.as_ref().is_some_and(|v| v.to_string().len() > 32)
                || !f.applied_hash.is_empty()
                    && (f.applied_hash.len() != 64
                        || !f.applied_hash.bytes().all(|b| b.is_ascii_hexdigit()))
        })
        || journal.fields.iter().enumerate().any(|(i, f)| {
            journal.fields[..i].iter().any(|g| g.property == f.property)
                || !valid_property_value(f.property, f.applied)
                || f.before
                    .is_some_and(|n| !valid_property_value(f.property, n))
        })
    {
        log::warn!("Game profile recovery record failed field, flag or path validation");
        return Err(RESTORE_ERROR.into());
    }
    Ok(())
}

fn checksum(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}

fn valid_property_value(property: Property, value: i32) -> bool {
    match property {
        Property::Fps => (0..=99999).contains(&value),
        // GraphicsQualityLevel stores the engine's QualityLevel (0..=21),
        // not the menu's SavedQualitySetting (0..=10). Keep legacy -1
        // originals restorable as before.
        Property::Quality => (-1..=21).contains(&value),
        Property::SavedQuality => (-1..=10).contains(&value),
    }
}

fn valid_flag_value(value: &serde_json::Value) -> bool {
    value.as_i64().is_some_and(|v| (-1..=10).contains(&v))
        || value
            .as_str()
            .is_some_and(|v| v.parse::<i32>().is_ok_and(|v| (-1..=10).contains(&v)))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn game_without_overrides_restores_the_previous_profile_before_returning() {
        let restored = std::cell::Cell::new(false);
        let overrides = prepare_profile(
            &GamePreferences::default(),
            || true,
            || {
                restored.set(true);
                Ok(true)
            },
        )
        .unwrap();
        assert!(!overrides);
        assert!(restored.get());
        assert_eq!(
            prepare_profile(
                &GamePreferences::default(),
                || true,
                || Err("restore failed".into())
            )
            .unwrap_err(),
            "restore failed"
        );
    }

    #[test]
    fn game_with_overrides_cannot_restore_or_apply_while_player_is_running() {
        let preferences = GamePreferences {
            fps_cap: Some(240),
            ..Default::default()
        };
        assert!(
            prepare_profile(
                &preferences,
                || false,
                || panic!("must not change a running player's settings")
            )
            .is_err()
        );
        assert!(prepare_profile(&preferences, || true, || Ok(false)).unwrap());
    }

    #[test]
    fn independent_recovery_attempts_both_backups_for_every_result_combination() {
        let outcomes = [Ok(false), Ok(true), Err("fixture failure".to_string())];
        for profile in &outcomes {
            for flags in &outcomes {
                let calls = std::cell::Cell::new(0);
                let result = restore_settings_with(
                    || {
                        assert_eq!(calls.get(), 0);
                        calls.set(1);
                        profile.clone()
                    },
                    || {
                        assert_eq!(calls.get(), 1);
                        calls.set(2);
                        flags.clone()
                    },
                );
                assert_eq!(calls.get(), 2);
                match (profile, flags) {
                    (Ok(profile), Ok(flags)) => assert_eq!(result.unwrap(), *profile || *flags),
                    _ => assert!(result.is_err()),
                }
            }
        }
    }
    #[test]
    fn recovery_accepts_the_real_engine_quality_range_and_restores_previous_values() {
        // The actual record that produced the user's false "invalid values" error.
        let mut journal: Journal = serde_json::from_str(r#"{"client":"standard","fields":[{"property":"Fps","before":1000,"applied":99999},{"property":"Quality","before":11,"applied":5}],"flags":[],"created_at":1791912167898}"#).unwrap();
        validate_journal(&journal).unwrap();
        let xml = r#"<Properties><int name="FramerateCap">99999</int><int name="GraphicsQualityLevel">5</int><token name="SavedQualityLevel">5</token></Properties>"#;
        let restored = restore_xml(xml.into(), &journal.fields);
        assert_eq!(value(&restored, Property::Fps), Some(1000));
        assert_eq!(value(&restored, Property::Quality), Some(11));
        assert_eq!(value(&restored, Property::SavedQuality), Some(5));
        for original in 11..=21 {
            journal.fields[1].before = Some(original);
            validate_journal(&journal).unwrap();
        }
        journal.fields[1].before = Some(22);
        assert!(validate_journal(&journal).is_err());
        journal.fields[1].before = Some(-2);
        assert!(validate_journal(&journal).is_err());
    }

    #[test]
    fn recovery_still_rejects_invalid_saved_quality_and_duplicate_properties() {
        let mut journal = Journal {
            client: RobloxClient::Standard,
            fields: vec![Override {
                property: Property::SavedQuality,
                before: Some(11),
                applied: 5,
            }],
            flags: Vec::new(),
            created_at: 0,
        };
        assert!(validate_journal(&journal).is_err());
        journal.fields[0].before = Some(10);
        validate_journal(&journal).unwrap();
        journal.fields.push(Override {
            property: Property::SavedQuality,
            before: Some(3),
            applied: 5,
        });
        assert!(validate_journal(&journal).is_err());
    }
    #[test]
    fn restoration_preserves_user_changes_and_other_properties() {
        let xml = r#"<Properties><int name="FramerateCap">240</int><int name="GraphicsQualityLevel">7</int><float name="Volume">0.5</float></Properties>"#;
        let fields = vec![
            Override {
                property: Property::Fps,
                before: Some(144),
                applied: 240,
            },
            Override {
                property: Property::Quality,
                before: Some(3),
                applied: 5,
            },
        ];
        let restored = restore_xml(xml.into(), &fields);
        assert_eq!(value(&restored, Property::Fps), Some(144));
        assert_eq!(value(&restored, Property::Quality), Some(7));
        assert!(restored.contains("Volume"));
    }
    #[test]
    fn restoration_removes_only_a_property_that_the_profile_created() {
        let xml = r#"<Properties><int name="FramerateCap">240</int></Properties>"#;
        let restored = restore_xml(
            xml.into(),
            &[Override {
                property: Property::Fps,
                before: None,
                applied: 240,
            }],
        );
        assert!(!restored.contains("FramerateCap"));
        assert!(restored.contains("</Properties>"));
    }
}
