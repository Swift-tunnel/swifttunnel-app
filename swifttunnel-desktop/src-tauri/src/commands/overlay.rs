use crate::state::AppState;
use tauri::State;

/// One OS hotkey registration, independent of WebView focus or polling.
#[tauri::command]
pub async fn ensure_overlay_shortcut(app: tauri::AppHandle) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || shortcut(app))
        .await
        .map_err(|e| e.to_string())?
}

#[cfg(windows)]
fn shortcut(app: tauri::AppHandle) -> Result<(), String> {
    use std::sync::{OnceLock, mpsc};
    use tauri::Emitter;
    use windows::Win32::UI::{
        Input::KeyboardAndMouse::{
            MOD_CONTROL, MOD_NOREPEAT, MOD_SHIFT, RegisterHotKey, UnregisterHotKey,
        },
        WindowsAndMessaging::{GetMessageW, MSG, WM_HOTKEY},
    };
    static READY: OnceLock<Result<(), String>> = OnceLock::new();
    READY
        .get_or_init(|| {
            let (send, receive) = mpsc::sync_channel(1);
            std::thread::Builder::new()
                .name("overlay-shortcut".into())
                .spawn(move || unsafe {
                    let registered = RegisterHotKey(
                        None,
                        1,
                        MOD_CONTROL | MOD_SHIFT | MOD_NOREPEAT,
                        u32::from(b'O'),
                    )
                    .map_err(|_| {
                        "Ctrl+Shift+O is unavailable. Another app may be using it.".to_string()
                    });
                    let _ = send.send(registered.clone());
                    if registered.is_err() {
                        return;
                    }
                    let mut message = MSG::default();
                    while GetMessageW(&mut message, None, 0, 0).0 > 0 {
                        if message.message == WM_HOTKEY && message.wParam.0 == 1 {
                            let _ = app.emit_to("main", "overlay-toggle-request", ());
                        }
                    }
                    let _ = UnregisterHotKey(None, 1);
                })
                .map_err(|e| e.to_string())?;
            receive
                .recv()
                .map_err(|_| "The overlay shortcut could not start.".to_string())?
        })
        .clone()
}
#[cfg(not(windows))]
fn shortcut(_: tauri::AppHandle) -> Result<(), String> {
    Err("Overlay shortcuts are available on Windows.".into())
}

#[tauri::command]
pub async fn overlay_game_monitor(
    state: State<'_, AppState>,
) -> Result<Option<swifttunnel_core::roblox_window::GameMonitor>, String> {
    let monitor = state.performance_monitor.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let pid = monitor.lock().poll_roblox_pid();
        pid.and_then(swifttunnel_core::roblox_window::monitor_for_player)
    })
    .await
    .map_err(|e| e.to_string())
}
