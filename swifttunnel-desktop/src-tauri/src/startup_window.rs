use tauri::{Manager, WebviewWindowBuilder};

use crate::startup_failure::{self, Stage};

pub(crate) fn create(app: &tauri::App) {
    let config = app
        .config()
        .app
        .windows
        .iter()
        .find(|window| window.label == "main")
        .unwrap_or_else(|| startup_failure::abort(Stage::Window, "missing main window config"));
    let builder = || {
        WebviewWindowBuilder::from_config(app, config)
            .unwrap_or_else(|error| startup_failure::abort(Stage::Window, error))
    };
    if let Err(error) = builder().build() {
        #[cfg(windows)]
        if is_profile_access_error(&error) {
            log::warn!("Could not open the original WebView2 profile: {error}");
            let primary = app
                .path()
                .app_local_data_dir()
                .unwrap_or_else(|error| startup_failure::abort(Stage::WindowData, error));
            let recovery = prepare_recovery_profile(&primary)
                .unwrap_or_else(|error| startup_failure::abort(Stage::WindowData, error));
            builder()
                .data_directory(recovery.clone())
                .build()
                .unwrap_or_else(|error| startup_failure::abort(Stage::WindowData, error));
            app.manage(RecoveryWebviewProfile(recovery));
            log::info!("Opened the desktop window using the recovery WebView2 profile");
            return;
        }
        startup_failure::abort(Stage::Window, error);
    }
}

#[cfg(windows)]
pub(crate) struct RecoveryWebviewProfile(pub(crate) std::path::PathBuf);

#[cfg(windows)]
fn is_profile_access_error(error: &tauri::Error) -> bool {
    use std::io::ErrorKind;
    use windows::Win32::Foundation::{
        ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, ERROR_DIRECTORY, ERROR_FILE_EXISTS,
    };

    match error {
        // Tauri creates the configured directory before starting WebView2.
        tauri::Error::Io(error) => matches!(
            error.kind(),
            ErrorKind::PermissionDenied | ErrorKind::AlreadyExists | ErrorKind::NotADirectory
        ),
        tauri::Error::Runtime(tauri_runtime::Error::CreateWebview(error)) => {
            let Some(wry::Error::WebView2Error(webview2_com::Error::WindowsError(error))) =
                error.downcast_ref::<wry::Error>()
            else {
                return false;
            };
            [
                ERROR_ACCESS_DENIED,
                ERROR_FILE_EXISTS,
                ERROR_ALREADY_EXISTS,
                ERROR_DIRECTORY,
            ]
            .iter()
            .any(|code| error.code() == code.to_hresult())
        }
        _ => false,
    }
}

#[cfg(windows)]
fn prepare_recovery_profile(primary: &std::path::Path) -> std::io::Result<std::path::PathBuf> {
    use std::{fs, io, os::windows::fs::MetadataExt};
    use windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    let mut name = primary
        .file_name()
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "invalid WebView2 profile path")
        })?
        .to_os_string();
    name.push("-webview-recovery");
    let recovery = primary.with_file_name(name);
    match fs::create_dir(&recovery) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }

    // Keep the original profile intact. A recovery folder left by a previous
    // launch can be reused, but never follow a redirected profile directory.
    for (path, may_be_missing) in [(&recovery, false), (&recovery.join("EBWebView"), true)] {
        match fs::symlink_metadata(path) {
            Ok(metadata)
                if metadata.is_dir()
                    && metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 == 0 => {}
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid WebView2 recovery directory",
                ));
            }
            Err(error) if may_be_missing && error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(recovery)
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use windows::Win32::Foundation::{
        ERROR_ACCESS_DENIED, ERROR_FILE_EXISTS, ERROR_FILE_NOT_FOUND,
    };

    #[test]
    fn only_profile_access_failures_retry_with_another_directory() {
        for (code, expected) in [
            (ERROR_ACCESS_DENIED, true),
            (ERROR_FILE_EXISTS, true),
            (ERROR_FILE_NOT_FOUND, false),
        ] {
            let webview_error = wry::Error::WebView2Error(code.to_hresult().into());
            let error =
                tauri::Error::Runtime(tauri_runtime::Error::CreateWebview(Box::new(webview_error)));
            assert_eq!(is_profile_access_error(&error), expected);
        }
        assert!(!is_profile_access_error(&tauri::Error::Runtime(
            tauri_runtime::Error::CreateWindow
        )));
    }

    #[test]
    fn recovery_preserves_an_obstructed_original_profile() {
        use std::{fs, time::SystemTime};

        let nonce = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let fixture = std::env::temp_dir().join(format!("swifttunnel-webview-test-{nonce}"));
        let original = fixture.join("desktop");
        fs::create_dir(&fixture).unwrap();
        fs::create_dir(&original).unwrap();
        let obstruction = original.join("EBWebView");
        fs::write(&obstruction, b"existing data").unwrap();

        let recovery = prepare_recovery_profile(&original).unwrap();
        assert_eq!(recovery, fixture.join("desktop-webview-recovery"));
        assert!(recovery.is_dir());
        assert_eq!(prepare_recovery_profile(&original).unwrap(), recovery);
        assert_eq!(fs::read(&obstruction).unwrap(), b"existing data");

        let bad_recovery = recovery.join("EBWebView");
        fs::write(&bad_recovery, b"existing recovery data").unwrap();
        assert!(prepare_recovery_profile(&original).is_err());
        assert_eq!(fs::read(&bad_recovery).unwrap(), b"existing recovery data");

        fs::remove_file(bad_recovery).unwrap();
        fs::remove_file(obstruction).unwrap();
        fs::remove_dir(recovery).unwrap();
        fs::remove_dir(original).unwrap();
        fs::remove_dir(fixture).unwrap();
    }
}
