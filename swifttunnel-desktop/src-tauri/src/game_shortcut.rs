use std::path::PathBuf;
static PENDING: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);
static INITIAL_TAKEN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
pub fn queue(place: String) {
    if let Ok(mut pending) = PENDING.lock() {
        *pending = Some(place);
    }
}
pub fn take_request() -> Option<String> {
    use std::sync::atomic::Ordering;
    if let Some(place) = PENDING.lock().ok().and_then(|mut p| p.take()) {
        INITIAL_TAKEN.store(true, Ordering::Release);
        return Some(place);
    }
    if INITIAL_TAKEN.swap(true, Ordering::AcqRel) {
        None
    } else {
        startup_target(&std::env::args().collect::<Vec<_>>())
    }
}
use windows::{
    Win32::{
        System::Com::{
            CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx,
            CoUninitialize, IPersistFile,
        },
        UI::Shell::{IShellLinkW, ShellLink},
    },
    core::{Interface, PCWSTR},
};
pub fn startup_target(args: &[String]) -> Option<String> {
    args.windows(2)
        .find(|pair| {
            pair[0] == "--open-game" && swifttunnel_core::roblox_library::valid_place_id(&pair[1])
        })
        .map(|p| p[1].clone())
}
pub fn create(place: &str, name: &str) -> Result<String, String> {
    if !swifttunnel_core::roblox_library::valid_place_id(place) {
        return Err("Choose a valid game.".into());
    }
    let base =
        std::env::var_os("USERPROFILE").ok_or("Windows could not find your Downloads folder.")?;
    let directory = PathBuf::from(base).join("Downloads/SwiftTunnel shortcuts");
    swifttunnel_core::roblox_native_launch::safe_path(&directory)?;
    std::fs::create_dir_all(&directory).map_err(|e| e.to_string())?;
    let label: String = name
        .chars()
        .filter(|c| !c.is_control() && !"<>:\"/\\|?*".contains(*c))
        .take(60)
        .collect();
    let path = directory.join(format!(
        "SwiftTunnel {} - {place}.lnk",
        label.trim_matches([' ', '.'])
    ));
    if path.exists() {
        return Ok(path.to_string_lossy().into_owned());
    }
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let wide = |s: &str| s.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
    let exe_text = wide(&exe.to_string_lossy());
    let arguments = wide(&format!("--open-game {place}"));
    let destination = wide(&path.to_string_lossy());
    unsafe {
        CoInitializeEx(None, COINIT_APARTMENTTHREADED)
            .ok()
            .map_err(|e| e.to_string())?;
        struct Apartment;
        impl Drop for Apartment {
            fn drop(&mut self) {
                unsafe {
                    CoUninitialize();
                }
            }
        }
        let _apartment = Apartment;
        let link: IShellLinkW =
            CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER).map_err(|e| e.to_string())?;
        link.SetPath(PCWSTR(exe_text.as_ptr()))
            .map_err(|e| e.to_string())?;
        link.SetArguments(PCWSTR(arguments.as_ptr()))
            .map_err(|e| e.to_string())?;
        link.SetIconLocation(PCWSTR(exe_text.as_ptr()), 0)
            .map_err(|e| e.to_string())?;
        let persist: IPersistFile = link.cast().map_err(|e| e.to_string())?;
        persist
            .Save(PCWSTR(destination.as_ptr()), true)
            .map_err(|e| e.to_string())?;
    }
    Ok(path.to_string_lossy().into_owned())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shortcut_cannot_pass_auth_tokens_or_commands() {
        assert_eq!(
            startup_target(&["app".into(), "--open-game".into(), "1818".into()]),
            Some("1818".into())
        );
        assert_eq!(
            startup_target(&["--open-game".into(), "1&ticket=secret".into()]),
            None
        );
    }
}
