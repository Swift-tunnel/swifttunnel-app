pub const ROBLOX_PROCESS_NAMES: &[&str] = &[
    "robloxplayerbeta.exe",
    "robloxplayer.exe",
    "robloxapp.exe",
    "windows10universal.exe",
    "robloxplayerlauncher.exe",
    "robloxstudiobeta.exe",
    "robloxstudio.exe",
    "robloxstudiolauncherbeta.exe",
    "robloxstudiolauncher.exe",
];

fn basename(name: &str) -> &str {
    name.rsplit(['\\', '/']).next().unwrap_or(name)
}

fn process_stem(name: &str) -> &str {
    basename(name).trim_end_matches(".exe")
}

fn is_roblox_process_name_lowercase(process_name_lower: &str) -> bool {
    let stem = process_stem(process_name_lower);
    ROBLOX_PROCESS_NAMES
        .iter()
        .map(|candidate| process_stem(candidate))
        .any(|candidate_stem| candidate_stem == stem)
}

pub fn process_name_matches_alias(process_name: &str, alias: &str) -> bool {
    let process_name = basename(process_name).to_ascii_lowercase();
    let alias = basename(alias).to_ascii_lowercase();
    process_stem(&process_name) == process_stem(&alias)
}

pub fn process_name_matches_tunnel_app(process_name_lower: &str, tunnel_app_lower: &str) -> bool {
    let name_stem = process_stem(process_name_lower);
    let app_stem = process_stem(tunnel_app_lower);
    name_stem == app_stem
        || name_stem.contains(app_stem)
        || app_stem.contains(name_stem)
        || (is_roblox_process_name_lowercase(process_name_lower)
            && is_roblox_process_name_lowercase(tunnel_app_lower))
}

pub fn process_name_matches_any_tunnel_app<'a>(
    process_name_lower: &str,
    tunnel_apps_lower: impl IntoIterator<Item = &'a String>,
) -> bool {
    tunnel_apps_lower
        .into_iter()
        .any(|app| process_name_matches_tunnel_app(process_name_lower, app))
}

pub fn is_roblox_process_name(process_name: &str) -> bool {
    ROBLOX_PROCESS_NAMES
        .iter()
        .any(|candidate| process_name_matches_alias(process_name, candidate))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_roblox_process_name_matches_known_variants() {
        for name in [
            "RobloxPlayerBeta.exe",
            "robloxplayer.exe",
            "C:\\Program Files\\Roblox\\RobloxApp.exe",
            "Windows10Universal.exe",
            "robloxstudiolauncherbeta.exe",
        ] {
            assert!(is_roblox_process_name(name), "expected {name} to match");
        }

        assert!(!is_roblox_process_name("chrome.exe"));
        assert!(!is_roblox_process_name("robloxhelper.exe"));
    }

    #[test]
    fn test_process_name_matches_tunnel_app_supports_generic_aliases() {
        assert!(process_name_matches_tunnel_app(
            "robloxapp.exe",
            "robloxplayerbeta.exe"
        ));
        assert!(process_name_matches_tunnel_app(
            "robloxplayerbeta.exe",
            "roblox"
        ));
        assert!(!process_name_matches_tunnel_app("chrome.exe", "roblox"));
    }
}
