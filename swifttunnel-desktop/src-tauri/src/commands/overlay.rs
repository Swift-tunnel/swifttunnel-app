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
    use std::sync::{Arc, Weak, mpsc};
    use tauri::Emitter;
    use windows::Win32::UI::{
        Input::KeyboardAndMouse::{
            MOD_CONTROL, MOD_NOREPEAT, MOD_SHIFT, RegisterHotKey, UnregisterHotKey,
        },
        WindowsAndMessaging::{GetMessageW, MSG, WM_HOTKEY},
    };
    static READY: parking_lot::Mutex<Weak<()>> = parking_lot::Mutex::new(Weak::new());
    ensure_registration(&READY, || {
        let (send, receive) = mpsc::sync_channel(1);
        let registration = Arc::new(());
        let worker_registration = registration.clone();
        std::thread::Builder::new()
            .name("overlay-shortcut".into())
            .spawn(move || unsafe {
                let _registration = worker_registration;
                let registered = RegisterHotKey(
                    None,
                    1,
                    MOD_CONTROL | MOD_SHIFT | MOD_NOREPEAT,
                    u32::from(b'O'),
                )
                .map_err(|_| {
                    "Ctrl+Shift+O is unavailable. Another app may be using it.".to_string()
                });
                if send.send(registered.clone()).is_err() {
                    if registered.is_ok() {
                        let _ = UnregisterHotKey(None, 1);
                    }
                    return;
                }
                if registered.is_err() {
                    return;
                }
                let mut message = MSG::default();
                loop {
                    let received = GetMessageW(&mut message, None, 0, 0).0;
                    if received <= 0 {
                        if received < 0 {
                            log::warn!(
                                "Overlay shortcut listener stopped: {}",
                                windows::core::Error::from_thread()
                            );
                        }
                        break;
                    }
                    if message.message == WM_HOTKEY && message.wParam.0 == 1 {
                        let _ = app.emit_to("main", "overlay-toggle-request", ());
                    }
                }
                let _ = UnregisterHotKey(None, 1);
            })
            .map_err(|e| e.to_string())?;
        receive
            .recv()
            .map_err(|_| "The overlay shortcut could not start.".to_string())??;
        Ok(registration)
    })
}

#[cfg(windows)]
fn ensure_registration(
    ready: &parking_lot::Mutex<std::sync::Weak<()>>,
    start: impl FnOnce() -> Result<std::sync::Arc<()>, String>,
) -> Result<(), String> {
    let mut ready = ready.lock();
    if ready.upgrade().is_some() {
        return Ok(());
    }
    // Cache only a live worker. A registration conflict, failed startup or
    // exited message loop must remain retryable when the overlay is toggled.
    let registration = start()?;
    *ready = std::sync::Arc::downgrade(&registration);
    Ok(())
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use std::sync::{Arc, Weak};

    #[test]
    fn shortcut_failure_and_worker_exit_are_retryable_without_duplicate_live_workers() {
        let ready = parking_lot::Mutex::new(Weak::new());
        assert_eq!(
            ensure_registration(&ready, || Err("already used".into())),
            Err("already used".into())
        );
        let worker = Arc::new(());
        ensure_registration(&ready, || Ok(worker.clone())).unwrap();
        ensure_registration(&ready, || {
            panic!("the existing worker still owns this hotkey")
        })
        .unwrap();
        drop(worker);
        let replacement = Arc::new(());
        ensure_registration(&ready, || Ok(replacement.clone())).unwrap();
        assert!(std::sync::Weak::ptr_eq(
            &ready.lock(),
            &Arc::downgrade(&replacement)
        ));
    }
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
