use tauri::{
    AppHandle, Emitter, Listener, Manager,
    menu::{Menu, MenuItem, Submenu},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
};

use crate::window_restore::restore_main_window;

pub fn setup_tray(app: &AppHandle) -> Result<(), Box<dyn std::error::Error>> {
    // The first menu is available immediately, without loading a library or
    // waiting for a disk-backed state lock on the UI thread.
    let menu = game_menu(app, &Default::default(), false)?;

    let icon = app.default_window_icon().cloned().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "default window icon must be set before tray setup",
        )
    })?;

    let _tray = TrayIconBuilder::with_id("main-tray")
        .icon(icon)
        .menu(&menu)
        .tooltip("SwiftTunnel")
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "show" => {
                if let Some(window) = app.get_webview_window("main") {
                    restore_main_window(&window);
                }
            }
            "quit" => {
                app.exit(0);
            }
            action
                if action.starts_with("play:")
                    || matches!(action, "library" | "favourites" | "rejoin" | "copy") =>
            {
                if let Some(window) = app.get_webview_window("main") {
                    restore_main_window(&window);
                }
                let _ = app.emit("games-open", action);
            }
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                let app = tray.app_handle();
                if let Some(window) = app.get_webview_window("main") {
                    restore_main_window(&window);
                }
            }
        })
        .build(app)?;
    let menu_app = app.clone();
    let (updates, mut requests) = tokio::sync::watch::channel(());
    let _ = updates.send(());
    app.listen(crate::commands::games::LIBRARY_CHANGED, move |_| {
        let _ = updates.send(());
    });
    tauri::async_runtime::spawn(async move {
        while requests.changed().await.is_ok() {
            // Metadata and favourite events often arrive together. Keep one
            // worker and one latest pending update instead of spawning a menu
            // rebuild for each event. Events during a rebuild trigger another.
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
            requests.borrow_and_update();
            let worker_app = menu_app.clone();
            let _ = tauri::async_runtime::spawn_blocking(move || {
                let Some(state) = worker_app.try_state::<crate::state::AppState>() else {
                    return;
                };
                let (library, current) = {
                    let mut games = state.games.lock();
                    (
                        games.library().cloned().unwrap_or_default(),
                        games.current.is_some(),
                    )
                };
                // Release the library lock before Tauri dispatches menu work
                // to the UI thread.
                if let Some(tray) = worker_app.tray_by_id("main-tray")
                    && let Ok(menu) = game_menu(&worker_app, &library, current)
                {
                    let _ = tray.set_menu(Some(menu));
                }
            })
            .await;
        }
    });

    Ok(())
}
fn game_menu(
    app: &AppHandle,
    library: &swifttunnel_core::roblox_library::GameLibrary,
    current: bool,
) -> Result<Menu<tauri::Wry>, Box<dyn std::error::Error>> {
    use swifttunnel_core::roblox_library::RobloxClient;
    let show = MenuItem::with_id(app, "show", "Show SwiftTunnel", true, None::<&str>)?;
    let games = MenuItem::with_id(app, "library", "Games", true, None::<&str>)?;
    let rejoin = MenuItem::with_id(
        app,
        "rejoin",
        "Rejoin last server",
        library
            .entries
            .iter()
            .any(|e| e.job_id.is_some() && e.client == RobloxClient::Standard),
        None::<&str>,
    )?;
    let copy = MenuItem::with_id(app, "copy", "Copy current join link", current, None::<&str>)?;
    let favourites = Submenu::with_items(app, "Favourites", true, &[])?;
    for entry in library
        .entries
        .iter()
        .filter(|e| e.favourite && e.client == RobloxClient::Standard)
        .take(20)
    {
        let label: String = entry.name.chars().take(60).collect();
        favourites.append(&MenuItem::with_id(
            app,
            format!("play:{}", entry.place_id),
            label,
            true,
            None::<&str>,
        )?)?;
    }
    if !library
        .entries
        .iter()
        .any(|e| e.favourite && e.client == RobloxClient::Standard)
    {
        favourites.append(&MenuItem::with_id(
            app,
            "favourites",
            "Save games in your Library",
            true,
            None::<&str>,
        )?)?;
    }
    let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
    Ok(Menu::with_items(
        app,
        &[&show, &games, &rejoin, &copy, &favourites, &quit],
    )?)
}
