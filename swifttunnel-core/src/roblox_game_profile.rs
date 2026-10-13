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
        return Err("A profile's launcher flag file is no longer at its original location. Its recovery journal was kept.".into());
    }
    let metadata = fs::symlink_metadata(&flag.path).map_err(|e| e.to_string())?;
    if metadata.file_type().is_symlink() {
        return Err("A redirected flag file was left untouched.".into());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err("A redirected flag file was left untouched.".into());
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
    let mut bytes = Vec::new();
    fs::File::open(path)
        .and_then(|file| file.take(256 * 1024 + 1).read_to_end(&mut bytes))
        .map_err(|_| {
            "Could not read Roblox preferences. Open Roblox once, close it and try again."
                .to_string()
        })?;
    if bytes.len() > 256 * 1024 {
        return Err("Roblox's preferences file is unexpectedly large.".into());
    }
    String::from_utf8(bytes).map_err(|_| "Roblox's preferences file is not valid UTF-8.".into())
}
fn write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    for ancestor in path.parent().into_iter().flat_map(Path::ancestors) {
        let meta = fs::symlink_metadata(ancestor).map_err(|e| e.to_string())?;
        if meta.file_type().is_symlink() {
            return Err("A redirected preferences folder was left untouched.".into());
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if meta.file_attributes() & 0x400 != 0 {
                return Err("A redirected preferences folder was left untouched.".into());
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
    let mut system = sysinfo::System::new();
    system.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
    !system
        .processes()
        .values()
        .any(|p| crate::process_names::is_roblox_player_process_name(&p.name().to_string_lossy()))
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
    preferences.validate()?;
    if preferences.fps_cap.is_none() && preferences.graphics_quality.is_none() {
        return Ok(false);
    }
    if !stopped() {
        return Err("Close Roblox before applying a game's FPS or graphics profile.".into());
    }
    restore()?;
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
    let journal: Journal = serde_json::from_str(&bytes).map_err(|_| "The saved game profile could not be restored safely. The original journal has been kept.".to_string())?;
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
        return Err(
            "The saved game profile contains invalid values. The journal has been kept.".into(),
        );
    }
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
        format!("Preferences restored, but their recovery journal could not be cleared: {e}")
    })?;
    Ok(true)
}

fn checksum(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}

fn valid_property_value(property: Property, value: i32) -> bool {
    match property {
        Property::Fps => (0..=99999).contains(&value),
        _ => (-1..=10).contains(&value),
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
