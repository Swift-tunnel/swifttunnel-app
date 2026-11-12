//! Read Windows Installer's recorded sources without contacting remote hosts.

use std::fs::OpenOptions;
use std::io::ErrorKind;
use std::os::windows::{
    ffi::OsStrExt,
    fs::{MetadataExt, OpenOptionsExt},
};
use std::path::{Component, Path, PathBuf, Prefix};
use windows::core::{w, PCWSTR, PWSTR};
use windows::Win32::Foundation::{ERROR_NO_MORE_ITEMS, ERROR_SUCCESS};
use windows::Win32::Storage::FileSystem::{
    GetDriveTypeW, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_SHARE_READ,
};
use windows::Win32::System::ApplicationInstallationAndServicing::{
    MsiGetProductInfoExW, MsiSourceListEnumMediaDisksW, MsiSourceListEnumSourcesW,
    MsiSourceListGetInfoW, MSIINSTALLCONTEXT_MACHINE, MSISOURCETYPE_NETWORK, MSISOURCETYPE_URL,
};

fn msi_string(mut read: impl FnMut(PWSTR, &mut u32) -> u32) -> Option<String> {
    let mut buffer = vec![0u16; 32_768];
    let mut length = buffer.len() as u32;
    let status = read(PWSTR(buffer.as_mut_ptr()), &mut length);
    (status == ERROR_SUCCESS.0)
        .then(|| String::from_utf16(buffer.get(..length as usize)?).ok())
        .flatten()
}

fn definitely_missing(path: &Path) -> bool {
    // GetDriveTypeW returns DRIVE_FIXED for a local fixed disk.
    const DRIVE_FIXED: u32 = 3;
    let mut parts = path.components();
    let Some(Component::Prefix(prefix)) = parts.next() else {
        return false;
    };
    if !matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
        || parts.next() != Some(Component::RootDir)
        || !parts.clone().all(|part| {
            matches!(part, Component::Normal(name)
            if !name.to_string_lossy().contains(':'))
        })
    {
        return false;
    }
    let mut current = PathBuf::from(prefix.as_os_str()).join(r"\");
    let root: Vec<_> = current.as_os_str().encode_wide().chain(Some(0)).collect();
    if unsafe { GetDriveTypeW(PCWSTR(root.as_ptr())) } != DRIVE_FIXED {
        return false;
    }
    // The deferred MSI action runs as SYSTEM. Keep checked directories open
    // without write or delete sharing while descending to the source.
    let mut directories = Vec::new();
    for part in std::iter::once(None).chain(parts.map(Some)) {
        if let Some(part) = part {
            current.push(part);
        }
        let file = match OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES.0)
            .share_mode(FILE_SHARE_READ.0)
            .custom_flags((FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT).0)
            .open(&current)
        {
            Ok(file) => file,
            Err(error) => return part.is_some() && error.kind() == ErrorKind::NotFound,
        };
        let Ok(metadata) = file.metadata() else {
            return false;
        };
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 || !metadata.is_dir() {
            // An existing file or a redirected path is insufficient proof.
            return false;
        }
        directories.push(file);
    }
    false
}

fn machine_product_info(code: PCWSTR, property: PCWSTR) -> Option<String> {
    msi_string(|value, len| unsafe {
        MsiGetProductInfoExW(
            code,
            PCWSTR::null(),
            MSIINSTALLCONTEXT_MACHINE,
            property,
            Some(value),
            Some(len),
        )
    })
}

pub fn machine_install_location(product_code: &str) -> Option<String> {
    let code: Vec<_> = product_code.encode_utf16().chain(Some(0)).collect();
    machine_product_info(PCWSTR(code.as_ptr()), w!("InstallLocation"))
}

/// Confirm the cache and every recorded source for this machine product are
/// missing. Remote, redirected, removable and unreadable sources are unknown.
pub fn machine_sources_are_missing(product_code: &str, cached: &str) -> bool {
    if !definitely_missing(Path::new(cached)) {
        return false;
    }
    let code: Vec<_> = product_code.encode_utf16().chain(Some(0)).collect();
    let code = PCWSTR(code.as_ptr());
    let machine = MSIINSTALLCONTEXT_MACHINE;
    if !machine_product_info(code, w!("LocalPackage"))
        .is_some_and(|path| Path::new(&path) == Path::new(cached))
    {
        return false;
    }
    let source_info = |property| {
        msi_string(|value, len| unsafe {
            MsiSourceListGetInfoW(
                code,
                PCWSTR::null(),
                machine,
                0,
                property,
                Some(value),
                Some(len),
            )
        })
    };
    let Some(package) = source_info(w!("PackageName")) else {
        return false;
    };
    let package = Path::new(&package);
    if !matches!(package.components().next(), Some(Component::Normal(name)) if name == package.as_os_str() && !name.to_string_lossy().contains(':'))
    {
        return false;
    }
    let source_missing = |directory: &str| {
        let directory = Path::new(directory);
        directory.is_absolute() && definitely_missing(&directory.join(package))
    };
    match (
        source_info(w!("LastUsedType")),
        source_info(w!("LastUsedSource")),
    ) {
        (Some(kind), Some(source)) if kind.is_empty() && source.is_empty() => {}
        (Some(kind), Some(source)) if kind == "n" && source_missing(&source) => {}
        _ => return false,
    }
    if !source_info(w!("MediaPackagePath")).is_some_and(|path| path.is_empty()) {
        return false;
    }
    // A real media source is ambiguous. The embedded packages also register
    // an empty disk row, which identifies no usable source.
    for index in 0..64 {
        let mut label = [0u16; 260];
        let mut prompt = [0u16; 260];
        let (mut label_len, mut prompt_len) = (label.len() as u32, prompt.len() as u32);
        let status = unsafe {
            MsiSourceListEnumMediaDisksW(
                code,
                PCWSTR::null(),
                machine,
                0,
                index,
                None,
                Some(PWSTR(label.as_mut_ptr())),
                Some(&mut label_len),
                Some(PWSTR(prompt.as_mut_ptr())),
                Some(&mut prompt_len),
            )
        };
        if status == ERROR_NO_MORE_ITEMS.0 {
            break;
        }
        if status != ERROR_SUCCESS.0 || label_len != 0 || prompt_len != 0 || index == 63 {
            return false;
        }
    }
    let url_status = unsafe {
        MsiSourceListEnumSourcesW(
            code,
            PCWSTR::null(),
            machine,
            MSISOURCETYPE_URL.0 as u32,
            0,
            None,
            None,
        )
    };
    if url_status != ERROR_NO_MORE_ITEMS.0 {
        return false;
    }
    let mut buffer = vec![0u16; 32_768];
    for index in 0..64 {
        let mut length = buffer.len() as u32;
        let status = unsafe {
            MsiSourceListEnumSourcesW(
                code,
                PCWSTR::null(),
                machine,
                MSISOURCETYPE_NETWORK.0 as u32,
                index,
                Some(PWSTR(buffer.as_mut_ptr())),
                Some(&mut length),
            )
        };
        if status == ERROR_NO_MORE_ITEMS.0 {
            return true;
        }
        if status != ERROR_SUCCESS.0
            || !buffer
                .get(..length as usize)
                .and_then(|value| String::from_utf16(value).ok())
                .is_some_and(|source| source_missing(&source))
        {
            return false;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_installer_source_must_be_provably_missing_on_a_fixed_disk() {
        let directory = std::env::temp_dir().join(format!(
            "swift-uninstall-source-{:032x}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&directory).unwrap();
        let package = directory.join("preserved.msi");
        assert!(definitely_missing(&package));
        std::fs::write(&package, b"preserved installer").unwrap();
        assert!(!definitely_missing(&package));
        assert!(!definitely_missing(Path::new(
            r"\\invalid\share\missing.msi"
        )));
        assert!(!definitely_missing(Path::new("missing.msi")));
        assert!(!definitely_missing(
            &directory.join(r"missing\..\preserved.msi")
        ));
        std::fs::remove_file(&package).unwrap();
        std::fs::remove_dir(&directory).unwrap();
    }
}
