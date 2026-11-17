//! Remove a standard installed copy whose Windows Installer record is gone.

use crate::utils::known_folder_path as known_folder;
use std::fs::{File, OpenOptions};
use std::io::{self, ErrorKind};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_READONLY,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_DISPOSITION_INFO, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, FileDispositionInfo, GetFileInformationByHandle, MOVEFILE_DELAY_UNTIL_REBOOT,
    MOVEFILE_WRITE_THROUGH, MoveFileExW, SetFileInformationByHandle,
};
use windows::Win32::UI::Shell::{
    FOLDERID_CommonPrograms, FOLDERID_ProgramFiles, FOLDERID_PublicDesktop,
};
use windows::Win32::UI::WindowsAndMessaging::{MB_ICONINFORMATION, MB_OK, MessageBoxW};
use windows::core::{PCWSTR, w};

const DELETE_ACCESS: u32 = 0x0001_0000;
const USE_SETUP: &str = "Run SwiftTunnel Setup to repair the installation, then uninstall from Windows Settings > Apps.";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Client {
    Desktop,
    Lite,
}

impl Client {
    fn name(self) -> &'static str {
        match self {
            Self::Desktop => crate::installed_clients::FULL_APP,
            Self::Lite => crate::installed_clients::LITE,
        }
    }

    fn executable_name(self) -> &'static str {
        match self {
            Self::Desktop => "swifttunnel-desktop.exe",
            Self::Lite => "swifttunnel-lite.exe",
        }
    }
}

fn installed_executable(program_files: &Path, client: Client) -> PathBuf {
    program_files
        .join(client.name())
        .join(client.executable_name())
}

pub(crate) fn default_executable(client: Client) -> io::Result<PathBuf> {
    Ok(installed_executable(
        &known_folder(&FOLDERID_ProgramFiles)?,
        client,
    ))
}

pub fn lite_is_bundled(executable: &Path) -> bool {
    let is_named = |path: &Path, name| {
        path.file_name()
            .is_some_and(|part| crate::utils::same_path_part(part, std::ffi::OsStr::new(name)))
    };
    executable.parent().is_some_and(|dir| {
        is_named(dir, "lite") && dir.parent().is_some_and(|up| is_named(up, "resources"))
    })
}

pub fn is_standard_install(client: Client, executable: &Path) -> Result<bool, String> {
    if cfg!(debug_assertions) {
        return Ok(false);
    }
    let expected = default_executable(client).map_err(|error| error.to_string())?;
    Ok(crate::utils::paths_match(executable, &expected))
}

fn registered_product(client: Client, root: &Path) -> Result<Option<String>, String> {
    match client {
        Client::Desktop => crate::msi_uninstall::desktop_product_code(root),
        Client::Lite => crate::msi_uninstall::lite_product_code(root),
    }
}

fn require_missing_registration(client: Client, root: &Path) -> Result<(), String> {
    if registered_product(client, root)?.is_some()
        || crate::installed_clients::product_is_registered(client.name())?
    {
        return Err("Windows still has an uninstall record. Use Windows Settings > Apps.".into());
    }
    Ok(())
}

fn broken_record(
    client: Client,
    root: &Path,
    code: &str,
) -> Result<Option<swifttunnel_msi_repair::Orphan>, String> {
    let Some(record) = swifttunnel_msi_repair::machine_registration(code)
        .map_err(|error| format!("Could not read the Windows uninstall record: {error}"))?
    else {
        return Ok(None);
    };
    if !record
        .display_name
        .trim()
        .eq_ignore_ascii_case(client.name())
        || !swifttunnel_msi_repair::machine_sources_are_missing(code, &record.local_package)
        || !swifttunnel_msi_repair::machine_install_location(code)
            .is_some_and(|location| crate::utils::paths_match(Path::new(&location), root))
        || !crate::msi_uninstall::is_only_related_product(client == Client::Lite, code)?
        || crate::installed_clients::product_is_registered_except_machine_msi(
            client.name(),
            Some(code),
        )?
    {
        return Ok(None);
    }
    Ok(Some(record))
}

/// Whether Windows lists this client but can no longer uninstall it.
pub fn registration_is_broken(
    client: Client,
    executable: &Path,
    code: &str,
) -> Result<bool, String> {
    let Some(root) = executable.parent() else {
        return Ok(false);
    };
    Ok(is_standard_install(client, executable)? && broken_record(client, root, code)?.is_some())
}

/// Folders the packages create, deepest first, without the install folder.
fn packaged_directories(client: Client, root: &Path) -> Vec<PathBuf> {
    let driver_root = if client == Client::Desktop {
        root.join("resources/drivers")
    } else {
        root.join("drivers")
    };
    let package = driver_root.join("winpkfilter");
    let mut directories = Vec::new();
    for arch in ["x64", "arm64"] {
        directories.push(package.join(arch).join("win10"));
        directories.push(package.join(arch));
    }
    directories.push(package);
    directories.push(driver_root);
    if client == Client::Desktop {
        directories.push(root.join("resources/lite"));
        directories.push(root.join("resources"));
    }
    directories
}

/// Remove folders the deleted files left empty. Never recursive: a folder that
/// still holds anything, listed or not, stays exactly as it is.
fn remove_empty_directories(directories: &[PathBuf]) {
    for directory in directories {
        match open_owned(directory, true).and_then(remove_opened) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => log::info!(
                "Left a folder in place after uninstall ({}): {error}",
                directory.display()
            ),
        }
    }
}

// Match the released MSI File tables. Do not walk or remove whole resource
// trees: older and newer layouts can coexist with files we do not recognize.
const DESKTOP_FILES: &[&str] = &[
    "swifttunnel_msi_actions.dll",
    "Uninstall SwiftTunnel.lnk",
    "resources/swifty.png",
    "resources/lite/.gitignore",
    "resources/lite/swifttunnel-lite.exe",
    "resources/drivers/mullvad-split-tunnel.sys",
    "resources/drivers/winfw.dll",
    "resources/drivers/WinpkFilter-arm64.msi",
    "resources/drivers/WinpkFilter-x64.msi",
    "resources/drivers/wintun.dll",
];
const DRIVER_FILES: &[&str] = &["ndisrd.cat", "ndisrd.sys", "ndisrd_lwf.inf"];

fn packaged_paths(client: Client, root: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let driver_root = if client == Client::Desktop {
        paths.extend(DESKTOP_FILES.iter().map(|name| root.join(name)));
        root.join("resources/drivers")
    } else {
        root.join("drivers")
    };
    for arch in ["x64", "arm64"] {
        let package = driver_root.join("winpkfilter").join(arch).join("win10");
        paths.extend(DRIVER_FILES.iter().map(|name| package.join(name)));
    }
    paths
}

fn shortcut_paths(client: Client) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    // Both packages are per-machine. Leave shortcuts made by individual users
    // alone, including those in redirected desktop or Start menu folders.
    if let Ok(programs) = known_folder(&FOLDERID_CommonPrograms) {
        let folder = programs.join(client.name());
        paths.push(folder.join(format!("{}.lnk", client.name())));
        paths.push(folder.join(format!("Uninstall {}.lnk", client.name())));
        if client == Client::Desktop {
            paths.push(folder.join("SwiftTunnel Lite.lnk"));
        }
    }
    if client == Client::Desktop
        && let Ok(desktop) = known_folder(&FOLDERID_PublicDesktop)
    {
        paths.push(desktop.join("SwiftTunnel.lnk"));
    }
    paths
}

fn file_info(file: &File) -> io::Result<BY_HANDLE_FILE_INFORMATION> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    unsafe { GetFileInformationByHandle(HANDLE(file.as_raw_handle()), &mut info) }
        .map_err(io::Error::from)?;
    Ok(info)
}

fn safe_object(info: &BY_HANDLE_FILE_INFORMATION, directory: bool) -> bool {
    info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 == 0
        && (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0) == directory
        && (directory
            || (info.nNumberOfLinks == 1 && info.dwFileAttributes & FILE_ATTRIBUTE_READONLY.0 == 0))
}

fn open_checked(path: &Path, directory: bool, removable: bool) -> io::Result<File> {
    let access = FILE_READ_ATTRIBUTES.0 | if removable { DELETE_ACCESS } else { 0 };
    let share = FILE_SHARE_READ
        | FILE_SHARE_WRITE
        | if removable {
            FILE_SHARE_DELETE
        } else {
            Default::default()
        };
    let flags = FILE_FLAG_OPEN_REPARSE_POINT
        | if directory {
            FILE_FLAG_BACKUP_SEMANTICS
        } else {
            Default::default()
        };
    let file = OpenOptions::new()
        .access_mode(access)
        .share_mode(share.0)
        .custom_flags(flags.0)
        .open(path)?;
    if !safe_object(&file_info(&file)?, directory) {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "Unexpected file or redirected folder",
        ));
    }
    Ok(file)
}

/// Pin the path components while opening the leaf. The open leaf can then be
/// deleted by handle without following a replaced path.
fn pin_directories(directory: &Path) -> io::Result<Vec<File>> {
    let mut ancestors: Vec<_> = directory
        .ancestors()
        .filter(|path| path.is_absolute())
        .collect();
    ancestors.reverse();
    ancestors
        .into_iter()
        .map(|path| open_checked(path, true, false))
        .collect()
}

fn open_owned(path: &Path, directory: bool) -> io::Result<File> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("Missing parent folder"))?;
    let _directories = pin_directories(parent)?;
    open_checked(path, directory, true)
}

fn remove_opened(file: File) -> io::Result<()> {
    let info = FILE_DISPOSITION_INFO { DeleteFile: true };
    unsafe {
        SetFileInformationByHandle(
            HANDLE(file.as_raw_handle()),
            FileDispositionInfo,
            std::ptr::from_ref(&info).cast(),
            std::mem::size_of_val(&info) as u32,
        )
    }
    .map_err(io::Error::from)
}

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

fn rename_new(from: &Path, to: &Path) -> io::Result<()> {
    let from = wide(from);
    let to = wide(to);
    unsafe {
        MoveFileExW(
            PCWSTR(from.as_ptr()),
            PCWSTR(to.as_ptr()),
            MOVEFILE_WRITE_THROUGH,
        )
    }
    .map_err(io::Error::from)
}

fn queue_delete(path: &Path) -> io::Result<()> {
    let path = wide(path);
    unsafe {
        MoveFileExW(
            PCWSTR(path.as_ptr()),
            PCWSTR::null(),
            MOVEFILE_DELAY_UNTIL_REBOOT,
        )
    }
    .map_err(io::Error::from)
}

fn same_file(first: &File, second: &File) -> io::Result<bool> {
    let identity = |info: BY_HANDLE_FILE_INFORMATION| {
        (
            info.dwVolumeSerialNumber,
            info.nFileIndexHigh,
            info.nFileIndexLow,
        )
    };
    Ok(identity(file_info(first)?) == identity(file_info(second)?))
}

fn retire_executable(
    executable: &Path,
    expected: &File,
    queue: impl FnOnce(&Path) -> io::Result<()>,
) -> io::Result<PathBuf> {
    if !same_file(expected, &open_checked(executable, false, true)?)? {
        return Err(io::Error::other(
            "The installation changed during uninstall",
        ));
    }
    // The running image cannot be deleted yet. Queue only a unique retired
    // name, so a reinstall before restart cannot lose its new executable.
    let retired = executable.with_file_name(format!(
        ".swifttunnel-remove-{:032x}.pending",
        rand::random::<u128>()
    ));
    rename_new(executable, &retired)?;
    let result = (|| {
        if !same_file(expected, &open_checked(&retired, false, true)?)? {
            return Err(io::Error::other("The executable changed during uninstall"));
        }
        queue(&retired)
    })();
    if result.is_err()
        && let Err(restore) = rename_new(&retired, executable)
    {
        log::warn!("Could not restore the original executable name: {restore}");
    }
    result.map(|()| retired)
}

pub struct Plan {
    client: Client,
    executable: PathBuf,
    image: File,
    files: Vec<(PathBuf, File)>,
    skipped_shortcut: bool,
    /// Windows records to clear first, because nothing can uninstall through
    /// them. Cleared in `finish`, after system cleanup has succeeded.
    broken: Option<swifttunnel_msi_repair::Orphan>,
    _root: Vec<File>,
}

/// Preflight only. Refuse development, portable, redirected, and ambiguous
/// installs before running system cleanup.
pub fn plan_for_running_client(client: Client) -> Result<Plan, String> {
    let executable = std::env::current_exe().map_err(|error| error.to_string())?;
    if !is_standard_install(client, &executable)? || !crate::is_administrator() {
        return Err(format!(
            "Could not verify a standard installed copy. {USE_SETUP}"
        ));
    }
    let root = executable
        .parent()
        .ok_or("Could not locate the installation folder.")?;
    let broken = match registered_product(client, root)? {
        Some(code) => Some(
            broken_record(client, root, &code)?
                .ok_or("Windows still has an uninstall record. Use Windows Settings > Apps.")?,
        ),
        None => {
            require_missing_registration(client, root)?;
            None
        }
    };
    let root_handles = pin_directories(root).map_err(|error| {
        format!("Could not safely open the installation folder: {error}. {USE_SETUP}")
    })?;
    let image = open_checked(&executable, false, true).map_err(|error| {
        format!("Could not safely open the installed executable: {error}. {USE_SETUP}")
    })?;
    let mut files = Vec::new();
    for path in packaged_paths(client, root) {
        match open_owned(&path, false) {
            Ok(file) => files.push((path, file)),
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "Could not safely open an installed file: {error}. {USE_SETUP}"
                ));
            }
        }
    }
    let mut skipped_shortcut = false;
    for path in shortcut_paths(client) {
        match open_owned(&path, false) {
            Ok(file) => files.push((path, file)),
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => {
                skipped_shortcut = true;
                log::warn!("Could not safely open a SwiftTunnel shortcut: {error}");
            }
        }
    }
    Ok(Plan {
        client,
        executable,
        image,
        files,
        skipped_shortcut,
        broken,
        _root: root_handles,
    })
}

pub fn finish(plan: Plan) -> Result<(), String> {
    let root = plan
        .executable
        .parent()
        .ok_or("Could not locate the installation folder.")?
        .to_path_buf();
    if plan.broken.is_none() {
        require_missing_registration(plan.client, &root)?;
    }
    let retired = retire_executable(&plan.executable, &plan.image, |retired| {
        // If scheduling fails, retain the Windows record. If registry cleanup
        // fails, retire_executable restores the original name and the queued
        // path no longer refers to this executable.
        queue_delete(retired)?;
        if let Some(record) = &plan.broken {
            let current = broken_record(plan.client, &root, &record.product_code)
                .map_err(io::Error::other)?;
            let Some(current) =
                current.filter(|current| current.local_package == record.local_package)
            else {
                return Err(io::Error::other(
                    "The Windows uninstall record changed. Try uninstalling again.",
                ));
            };
            swifttunnel_msi_repair::clear_registration(&current).map_err(io::Error::other)?;
        }
        require_missing_registration(plan.client, &root).map_err(io::Error::other)
    })
    .map_err(|error| format!("Could not remove the installed executable: {error}. {USE_SETUP}"))?;
    let mut incomplete = plan.skipped_shortcut;
    for (path, file) in plan.files {
        if let Err(error) = remove_opened(file) {
            incomplete = true;
            log::warn!(
                "Could not remove installed file {}: {error}",
                path.display()
            );
        }
    }
    // An install folder full of empty folders reads as a failed uninstall.
    let mut emptied = packaged_directories(plan.client, &root);
    if let Ok(programs) = known_folder(&FOLDERID_CommonPrograms) {
        emptied.push(programs.join(plan.client.name()));
    }
    remove_empty_directories(&emptied);
    // The install folder still holds the retired executable, so it goes at
    // restart, after that file, and only if nothing else is left in it. A
    // reinstall before then leaves it populated and Windows keeps it.
    if let Ok(mut entries) = std::fs::read_dir(&root)
        && matches!(entries.next(), Some(Ok(entry)) if entry.path() == retired)
        && entries.next().is_none()
        && let Err(error) = queue_delete(&root)
    {
        log::info!("Could not queue the install folder for removal: {error}");
    }
    log::info!(
        "Unregistered {:?} uninstall queued its retired executable for removal at restart",
        plan.client
    );
    let message = if incomplete {
        w!(
            "Restart Windows to finish uninstalling. Some files could not be removed. Contact support if you need help removing them."
        )
    } else {
        w!("Restart Windows to finish uninstalling SwiftTunnel. Your settings and logs were kept.")
    };
    unsafe {
        MessageBoxW(
            None,
            message,
            w!("SwiftTunnel uninstall"),
            MB_OK | MB_ICONINFORMATION,
        )
    };
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("swift-uninstall-{:032x}", rand::random::<u128>()));
        std::fs::create_dir(&root).unwrap();
        root
    }

    #[test]
    fn package_names_leave_unlisted_files_and_the_other_client_alone() {
        let program_files = Path::new(r"E:\Program Files");
        let desktop = installed_executable(program_files, Client::Desktop);
        let lite = installed_executable(program_files, Client::Lite);
        assert!(!lite_is_bundled(&lite));
        let paths = packaged_paths(Client::Desktop, desktop.parent().unwrap());
        let bundled = desktop
            .parent()
            .unwrap()
            .join("resources/lite/swifttunnel-lite.exe");
        assert!(lite_is_bundled(&bundled));
        assert!(
            paths
                .iter()
                .any(|path| crate::utils::paths_match(path, &bundled))
        );
        assert!(
            paths
                .iter()
                .all(|path| !path.starts_with(lite.parent().unwrap()))
        );
        assert!(!paths.iter().any(|path| path.ends_with("personal.txt")));
    }

    #[test]
    fn only_folders_left_empty_are_removed() {
        for client in [Client::Desktop, Client::Lite] {
            let root = fixture();
            let directories = packaged_directories(client, &root);
            // Every packaged file sits in the root or a listed folder, so no
            // file removal can strand a folder this does not know about.
            for file in packaged_paths(client, &root) {
                let parent = file.parent().unwrap();
                assert!(parent == root || directories.iter().any(|dir| dir == parent));
                std::fs::create_dir_all(parent).unwrap();
                std::fs::write(&file, b"packaged").unwrap();
            }
            assert!(!directories.contains(&root));
            let kept = directories[0].join("personal.txt");
            std::fs::write(&kept, b"mine").unwrap();
            for file in packaged_paths(client, &root) {
                let _ = std::fs::remove_file(file);
            }
            remove_empty_directories(&directories);
            // The folder with an unlisted file survives, with its parents.
            assert_eq!(std::fs::read(&kept).unwrap(), b"mine");
            let remaining: Vec<_> = directories.iter().filter(|dir| dir.exists()).collect();
            assert!(remaining.iter().all(|dir| kept.starts_with(dir)));
            assert!(remaining.len() >= 3);
            std::fs::remove_file(&kept).unwrap();
            remove_empty_directories(&directories);
            assert!(directories.iter().all(|dir| !dir.exists()));
            assert!(root.exists());
            std::fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn retirement_queues_only_the_old_name_and_rolls_back_if_scheduling_fails() {
        let root = fixture();
        let executable = root.join("swifttunnel-desktop.exe");
        std::fs::write(&executable, b"old").unwrap();
        let image = open_owned(&executable, false).unwrap();
        assert!(
            retire_executable(&executable, &image, |_| Err(io::Error::other("fixture"))).is_err()
        );
        assert_eq!(std::fs::read(&executable).unwrap(), b"old");
        let mut retired = None;
        retire_executable(&executable, &image, |path| {
            retired = Some(path.to_owned());
            Ok(())
        })
        .unwrap();
        let retired = retired.unwrap();
        assert_ne!(retired, executable);
        assert!(!executable.exists());
        std::fs::write(&executable, b"new").unwrap();
        drop(image);
        remove_opened(open_owned(&retired, false).unwrap()).unwrap();
        assert!(!retired.exists());
        assert_eq!(std::fs::read(&executable).unwrap(), b"new");
        std::fs::remove_file(&executable).unwrap();
        std::fs::remove_dir(&root).unwrap();
    }

    #[test]
    fn file_checks_reject_redirects_and_hard_links() {
        let info = |attrs, links| BY_HANDLE_FILE_INFORMATION {
            dwFileAttributes: attrs,
            nNumberOfLinks: links,
            ..Default::default()
        };
        assert!(safe_object(&info(0, 1), false));
        assert!(!safe_object(&info(0, 2), false));
        assert!(!safe_object(
            &info(FILE_ATTRIBUTE_REPARSE_POINT.0, 1),
            false
        ));
        assert!(!safe_object(
            &info(
                FILE_ATTRIBUTE_DIRECTORY.0 | FILE_ATTRIBUTE_REPARSE_POINT.0,
                1
            ),
            true
        ));
    }

    #[test]
    fn retirement_can_rename_a_loaded_windows_executable() {
        use std::os::windows::process::CommandExt;
        use std::process::{Command, Stdio};
        use windows::Win32::System::Threading::CREATE_NO_WINDOW;

        let root = fixture();
        let executable = root.join("swifttunnel-desktop.exe");
        let ping = crate::utils::trusted_windows_root()
            .unwrap()
            .join("System32/ping.exe");
        std::fs::copy(ping, &executable).unwrap();
        let mut process = Command::new(&executable)
            .args(["-n", "10", "127.0.0.1"])
            .creation_flags(CREATE_NO_WINDOW.0)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let result = (|| {
            let _root = pin_directories(&root)?;
            let image = open_owned(&executable, false)?;
            let mut retired = None;
            retire_executable(&executable, &image, |path| {
                retired = Some(path.to_owned());
                Ok(())
            })?;
            assert!(process.try_wait()?.is_none());
            Ok::<_, io::Error>(retired.unwrap())
        })();
        let _ = process.kill();
        process.wait().unwrap();
        let path = result.as_ref().unwrap_or(&executable);
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(&root).unwrap();
        assert!(result.is_ok(), "{result:?}");
    }
}
