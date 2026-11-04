//! Edit one entry of a `Key=Value;Key=Value;` registry string.
//!
//! Windows keeps several unrelated graphics settings in one string,
//! `HKCU\Software\Microsoft\DirectX\UserGpuPreferences\DirectXUserGlobalSettings`:
//! "Optimizations for windowed games" (`SwapEffectUpgradeEnable`), variable
//! refresh rate for windowed games (`VRROptimizeEnable`), Auto HDR
//! (`AutoHDREnable`) and more. A tweak that owns one of them must change only
//! that entry. Writing the whole string switched the others off.

/// `current` with `key` set to `value`, keeping every other entry in order.
pub fn set_entry(current: Option<&str>, key: &str, value: &str) -> String {
    let mut entries = parse(current);
    match entries
        .iter_mut()
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
    {
        Some(entry) => entry.1 = value.to_string(),
        None => entries.push((key.to_string(), value.to_string())),
    }
    format(&entries)
}

/// Undo [`set_entry`] for `key` against the value captured before it ran.
///
/// Starts from `current`, so settings the player changed in the meantime are
/// kept. `key` goes back to its original value, or is removed if it had none.
/// Original entries that are now missing are added back: an earlier build
/// replaced the whole string, and reverting is how those machines get their
/// other settings back. Returns `None` when the value should be deleted
/// because it did not exist before and nothing is left.
pub fn restore_entry(current: Option<&str>, original: Option<&str>, key: &str) -> Option<String> {
    let original_entries = parse(original);
    let mut entries = parse(current);
    entries.retain(|(k, _)| !k.eq_ignore_ascii_case(key));
    for (k, v) in &original_entries {
        if !entries
            .iter()
            .any(|(existing, _)| existing.eq_ignore_ascii_case(k))
        {
            entries.push((k.clone(), v.clone()));
        }
    }
    if entries.is_empty() && original.is_none() {
        return None;
    }
    Some(format(&entries))
}

fn parse(value: Option<&str>) -> Vec<(String, String)> {
    value
        .unwrap_or_default()
        .split(';')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(|entry| match entry.split_once('=') {
            Some((k, v)) => (k.trim().to_string(), v.trim().to_string()),
            None => (entry.to_string(), String::new()),
        })
        .collect()
}

fn format(entries: &[(String, String)]) -> String {
    entries.iter().map(|(k, v)| format!("{k}={v};")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "SwapEffectUpgradeEnable";

    #[test]
    fn setting_one_entry_keeps_the_players_other_graphics_settings() {
        assert_eq!(
            set_entry(Some("VRROptimizeEnable=1;AutoHDREnable=1;"), KEY, "1"),
            "VRROptimizeEnable=1;AutoHDREnable=1;SwapEffectUpgradeEnable=1;"
        );
        assert_eq!(
            set_entry(
                Some("SwapEffectUpgradeEnable=0;VRROptimizeEnable=1;"),
                KEY,
                "1"
            ),
            "SwapEffectUpgradeEnable=1;VRROptimizeEnable=1;"
        );
        assert_eq!(set_entry(None, KEY, "1"), "SwapEffectUpgradeEnable=1;");
        assert_eq!(set_entry(Some(""), KEY, "1"), "SwapEffectUpgradeEnable=1;");
    }

    #[test]
    fn restoring_puts_back_only_our_entry() {
        // Absent before: removed, the rest kept, including a later change.
        assert_eq!(
            restore_entry(
                Some("VRROptimizeEnable=0;SwapEffectUpgradeEnable=1;"),
                Some("VRROptimizeEnable=1;"),
                KEY
            )
            .as_deref(),
            Some("VRROptimizeEnable=0;")
        );
        // Present before: original value back.
        assert_eq!(
            restore_entry(
                Some("SwapEffectUpgradeEnable=1;"),
                Some("SwapEffectUpgradeEnable=0;"),
                KEY
            )
            .as_deref(),
            Some("SwapEffectUpgradeEnable=0;")
        );
        // No value before and nothing else now: delete it.
        assert_eq!(
            restore_entry(Some("SwapEffectUpgradeEnable=1;"), None, KEY),
            None
        );
    }

    #[test]
    fn restoring_after_an_older_build_wiped_the_string_brings_the_rest_back() {
        assert_eq!(
            restore_entry(
                Some("SwapEffectUpgradeEnable=1;"),
                Some("VRROptimizeEnable=1;AutoHDREnable=1;"),
                KEY
            )
            .as_deref(),
            Some("VRROptimizeEnable=1;AutoHDREnable=1;")
        );
    }

    #[test]
    fn keys_match_without_case_and_odd_spacing_is_tolerated() {
        assert_eq!(
            set_entry(Some(" swapeffectupgradeenable = 0 ; Other=2"), KEY, "1"),
            "swapeffectupgradeenable=1;Other=2;"
        );
    }
}
