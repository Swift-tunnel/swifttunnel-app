use tauri::{
    AppHandle, Emitter, Listener, Manager,
    menu::{Menu, MenuItem, Submenu},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
};

use crate::window_restore::restore_main_window;

pub fn setup_tray(app: &AppHandle) -> Result<(), Box<dyn std::error::Error>> {
    let menu = game_menu(app)?;

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
    app.listen(crate::commands::games::LIBRARY_CHANGED, move |_| {
        let menu_app = menu_app.clone();
        tauri::async_runtime::spawn(async move {
            if let Some(tray) = menu_app.tray_by_id("main-tray")
                && let Ok(menu) = game_menu(&menu_app)
            {
                let _ = tray.set_menu(Some(menu));
            }
        });
    });

    Ok(())
}
fn game_menu(app: &AppHandle) -> Result<Menu<tauri::Wry>, Box<dyn std::error::Error>> {
    use swifttunnel_core::roblox_library::{GameLibrary, RobloxClient, library_path};
    let library = library_path()
        .ok()
        .and_then(|p| GameLibrary::load(&p).ok())
        .unwrap_or_default();
    let current = app
        .try_state::<crate::state::AppState>()
        .is_some_and(|state| state.games.lock().current.is_some());
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
