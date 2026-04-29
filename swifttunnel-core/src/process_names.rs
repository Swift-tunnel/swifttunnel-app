pub const ROBLOX_PROCESS_NAMES: &[&str] = &[
    "robloxplayerbeta.exe",
    "robloxplayer.exe",
    "robloxapp.exe",
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

fn is_roblox_tunnel_alias_lowercase(alias_lower: &str) -> bool {
    process_stem(alias_lower) == "roblox" || is_roblox_process_name_lowercase(alias_lower)
}

fn is_generic_store_host_lowercase(name_lower: &str) -> bool {
    process_stem(name_lower) == "windows10universal"
}

pub fn process_name_matches_alias(process_name: &str, alias: &str) -> bool {
    let process_name = basename(process_name).to_ascii_lowercase();
    let alias = basename(alias).to_ascii_lowercase();
    process_stem(&process_name) == process_stem(&alias)
}

pub fn process_name_matches_tunnel_app(process_name_lower: &str, tunnel_app_lower: &str) -> bool {
    if is_generic_store_host_lowercase(process_name_lower)
        || is_generic_store_host_lowercase(tunnel_app_lower)
    {
        return false;
    }

    let name_stem = process_stem(process_name_lower);
    let app_stem = process_stem(tunnel_app_lower);
    name_stem == app_stem
        || (is_roblox_process_name_lowercase(process_name_lower)
            && is_roblox_tunnel_alias_lowercase(tunnel_app_lower))
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
            "robloxstudiolauncherbeta.exe",
        ] {
            assert!(is_roblox_process_name(name), "expected {name} to match");
        }

        // Windows10Universal.exe is the generic UWP app host: Photos, Calculator, every
        // Microsoft Store app runs under that name. It is not tunnel-eligible.
        assert!(!is_roblox_process_name("Windows10Universal.exe"));
        assert!(!is_roblox_process_name("chrome.exe"));
        assert!(!is_roblox_process_name("robloxhelper.exe"));
    }

    #[test]
    fn test_is_roblox_process_name_rejects_store_package_path() {
        assert!(!is_roblox_process_name(
            r"C:\Program Files\WindowsApps\ROBLOXCORPORATION.ROBLOX_2.617.655.0_x64__55nm5eh3cm0pr\Windows10Universal.exe"
        ));
        assert!(!is_roblox_process_name(
            r"\Device\HarddiskVolume3\Program Files\WindowsApps\ROBLOXCORPORATION.ROBLOX_2.617.655.0_x64__55nm5eh3cm0pr\Windows10Universal.exe"
        ));
        assert!(!is_roblox_process_name(
            r"C:\Program Files\WindowsApps\Microsoft.MicrosoftSolitaireCollection_4.20.0.0_x64__8wekyb3d8bbwe\Windows10Universal.exe"
        ));
        assert!(!process_name_matches_tunnel_app(
            r"c:\program files\windowsapps\microsoft.mahjong_1.0.0.0_x64__8wekyb3d8bbwe\windows10universal.exe",
            "robloxplayerbeta.exe"
        ));
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
        assert!(!process_name_matches_tunnel_app(
            "robloxhelper.exe",
            "roblox"
        ));
    }

    #[test]
    fn test_process_name_matches_tunnel_app_rejects_substring_lookalikes() {
        assert!(!process_name_matches_tunnel_app(
            "player.exe",
            "robloxplayerbeta.exe"
        ));
        assert!(!process_name_matches_tunnel_app(
            "window.exe",
            "windows10universal.exe"
        ));
        assert!(!process_name_matches_tunnel_app(
            "robloxstudiohelper.exe",
            "robloxstudio.exe"
        ));
    }

    #[test]
    fn test_process_name_matches_tunnel_app_rejects_store_package_identity() {
        assert!(!process_name_matches_tunnel_app(
            r"c:\program files\windowsapps\robloxcorporation.roblox_2.617.655.0_x64__55nm5eh3cm0pr\windows10universal.exe",
            "robloxplayerbeta.exe"
        ));
        assert!(!process_name_matches_tunnel_app(
            "windows10universal.exe",
            "robloxplayerbeta.exe"
        ));
        assert!(!process_name_matches_tunnel_app(
            "windows10universal.exe",
            "windows10universal.exe"
        ));
    }
}
