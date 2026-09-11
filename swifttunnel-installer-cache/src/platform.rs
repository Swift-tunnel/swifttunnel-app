use super::{package_name, CacheNote};
use std::os::windows::{
    ffi::{OsStrExt, OsStringExt},
    fs::OpenOptionsExt,
    io::{AsRawHandle, FromRawHandle},
};
use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    path::{Component, Path, PathBuf, Prefix},
    sync::Arc,
};
use windows::{
    core::{BOOL, PCWSTR},
    Win32::{
        Foundation::{LocalFree, GENERIC_READ, GENERIC_WRITE, HANDLE, HLOCAL},
        Security::{
            Authorization::{
                ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
                SE_FILE_OBJECT,
            },
            EqualSid, GetSecurityDescriptorControl, GetSecurityDescriptorDacl,
            GetSecurityDescriptorOwner, ACL, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
            PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
        },
        Storage::FileSystem::*,
        System::Com::CoTaskMemFree,
        UI::Shell::{FOLDERID_ProgramData, SHGetKnownFolderPath, KF_FLAG_DEFAULT},
    },
};

// Explicit owner and protected DACL at creation, never inherited from ProgramData.
// Users can read a registered source, but only SYSTEM/Administrators can change it.
const DIR_SD: &str = "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)";
const FILE_SD: &str = "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)";
const CACHE_DIR: &str = "SwiftTunnelInstallerCache";

/// Resolve the OS installer without consulting PATH or inherited environment.
pub fn windows_installer_path() -> io::Result<PathBuf> {
    let mut buf = vec![0u16; 32768];
    let len =
        unsafe { windows::Win32::System::SystemInformation::GetSystemDirectoryW(Some(&mut buf)) }
            as usize;
    if len == 0 || len >= buf.len() {
        return Err(io::Error::last_os_error());
    }
    Ok(PathBuf::from(std::ffi::OsString::from_wide(&buf[..len])).join("msiexec.exe"))
}

fn denied(reason: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, reason)
}
fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}
fn win_error(e: windows::core::Error) -> io::Error {
    e.into()
}

struct Descriptor(PSECURITY_DESCRIPTOR);
impl Descriptor {
    fn parse(sddl: &str) -> io::Result<Self> {
        let text: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
        let mut sd = PSECURITY_DESCRIPTOR::default();
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(text.as_ptr()),
                1,
                &mut sd,
                None,
            )
        }
        .map_err(win_error)?;
        Ok(Self(sd))
    }
    fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.0 .0,
            bInheritHandle: false.into(),
        }
    }
}
impl Drop for Descriptor {
    fn drop(&mut self) {
        unsafe {
            let _ = LocalFree(Some(HLOCAL(self.0 .0)));
        }
    }
}

fn check_security(file: &File, expected_sddl: &str) -> io::Result<()> {
    let expected = Descriptor::parse(expected_sddl)?;
    let mut sd = PSECURITY_DESCRIPTOR::default();
    unsafe {
        GetSecurityInfo(
            HANDLE(file.as_raw_handle()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            Some(&mut sd),
        )
        .ok()
        .map_err(win_error)?;
    }
    let actual = Descriptor(sd);
    unsafe {
        let mut owner = PSID::default();
        let mut expected_owner = PSID::default();
        let mut defaulted = BOOL::default();
        GetSecurityDescriptorOwner(actual.0, &mut owner, &mut defaulted).map_err(win_error)?;
        GetSecurityDescriptorOwner(expected.0, &mut expected_owner, &mut defaulted)
            .map_err(win_error)?;
        if EqualSid(owner, expected_owner).is_err() {
            return Err(denied("Installer cache is not administrator-owned"));
        }
        let mut control = 0;
        let mut revision = 0;
        GetSecurityDescriptorControl(actual.0, &mut control, &mut revision).map_err(win_error)?;
        if control & 0x1000 == 0 {
            return Err(denied("Installer cache DACL is not protected"));
        }
        let mut present = BOOL::default();
        let mut acl: *mut ACL = std::ptr::null_mut();
        let mut expected_acl: *mut ACL = std::ptr::null_mut();
        GetSecurityDescriptorDacl(actual.0, &mut present, &mut acl, &mut defaulted)
            .map_err(win_error)?;
        if !present.as_bool() || acl.is_null() {
            return Err(denied("Installer cache has no restrictive DACL"));
        }
        GetSecurityDescriptorDacl(expected.0, &mut present, &mut expected_acl, &mut defaulted)
            .map_err(win_error)?;
        // Exact ACL comparison deliberately refuses custom descriptors. Never
        // change an existing object's ACL to try to revoke already open handles.
        let a = std::slice::from_raw_parts(acl.cast::<u8>(), (*acl).AclSize as usize);
        let b =
            std::slice::from_raw_parts(expected_acl.cast::<u8>(), (*expected_acl).AclSize as usize);
        if a != b {
            return Err(denied(
                "Installer cache permissions do not match the protected policy",
            ));
        }
    }
    Ok(())
}

fn check_object(file: &File, directory: bool) -> io::Result<()> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    unsafe { GetFileInformationByHandle(HANDLE(file.as_raw_handle()), &mut info) }
        .map_err(win_error)?;
    if !safe_object(info.dwFileAttributes, info.nNumberOfLinks, directory) {
        return Err(denied(
            "Installer cache contains a reparse point, hard link, or wrong object type",
        ));
    }
    Ok(())
}
fn safe_object(attributes: u32, links: u32, directory: bool) -> bool {
    attributes & FILE_ATTRIBUTE_REPARSE_POINT.0 == 0
        && (attributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0) == directory
        && (directory || links == 1)
}
fn open_directory(path: &Path, protected: bool) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .access_mode(0x0002_0080)
        .share_mode(if protected {
            FILE_SHARE_READ.0
        } else {
            FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0
        })
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0 | FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(path)?;
    check_object(&file, true)?;
    if protected {
        check_security(&file, DIR_SD)?;
    }
    Ok(file)
}
fn open_package(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ.0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(path)?;
    check_object(&file, false)?;
    check_security(&file, FILE_SD)?;
    Ok(file)
}

struct CacheInner {
    path: PathBuf,
    _directories: Vec<File>,
}
#[derive(Clone)]
pub struct InstallerCache {
    inner: Arc<CacheInner>,
}

/// Holds the read handle that excludes write/delete opens. Keep this value
/// alive through msiexec consumption. Permanent cache ACLs protect the path
/// even if Windows Installer closes the application during an upgrade.
pub struct ProtectedInstaller {
    path: PathBuf,
    _file: File,
    _cache: Arc<CacheInner>,
}
impl ProtectedInstaller {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl InstallerCache {
    pub fn open() -> io::Result<Self> {
        let raw = unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramData, KF_FLAG_DEFAULT, None) }
            .map_err(win_error)?;
        let path = unsafe { PathBuf::from(std::ffi::OsString::from_wide(raw.as_wide())) };
        unsafe {
            CoTaskMemFree(Some(raw.0.cast()));
        }
        Self::open_under(&path, CACHE_DIR)
    }
    fn open_under(base: &Path, name: &str) -> io::Result<Self> {
        if !base.has_root()
            || !matches!(base.components().next(), Some(Component::Prefix(p)) if matches!(p.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)))
            || base
                .components()
                .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
        {
            return Err(denied(
                "Installer cache needs a local absolute known-folder path",
            ));
        }
        // Keep all ancestors open without delete sharing so pathname resolution
        // cannot be redirected while the protected cache and MSI are in use.
        let mut directories = Vec::new();
        for path in base.ancestors().collect::<Vec<_>>().into_iter().rev() {
            directories.push(open_directory(path, false)?);
        }
        let path = base.join(name);
        let sd = Descriptor::parse(DIR_SD)?;
        let text = wide(&path);
        if let Err(e) = unsafe { CreateDirectoryW(PCWSTR(text.as_ptr()), Some(&sd.attributes())) } {
            if e.code() != windows::Win32::Foundation::ERROR_ALREADY_EXISTS.to_hresult() {
                return Err(win_error(e));
            }
        }
        directories.push(open_directory(&path, true)?);
        Ok(Self {
            inner: Arc::new(CacheInner {
                path,
                _directories: directories,
            }),
        })
    }

    /// No overwrite or pruning: a registered source is immutable by content hash.
    pub fn stage(&self, suggested: &str, bytes: &[u8]) -> io::Result<ProtectedInstaller> {
        let path = self.inner.path.join(package_name(suggested, bytes)?);
        match open_package(&path) {
            Ok(mut file) => {
                verify_contents(&mut file, bytes)?;
                return Ok(ProtectedInstaller {
                    path,
                    _file: file,
                    _cache: self.inner.clone(),
                });
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        if let Err(error) = self.publish(&path, bytes, false) {
            // Another installer may have published this immutable content while
            // we staged it. Accept only a locked, protected, exact match.
            let mut file = open_package(&path).map_err(|_| error)?;
            verify_contents(&mut file, bytes)?;
            return Ok(ProtectedInstaller {
                path,
                _file: file,
                _cache: self.inner.clone(),
            });
        }
        let mut file = open_package(&path)?;
        verify_contents(&mut file, bytes)?;
        Ok(ProtectedInstaller {
            path,
            _file: file,
            _cache: self.inner.clone(),
        })
    }

    fn publish(&self, destination: &Path, bytes: &[u8], replace: bool) -> io::Result<()> {
        let staged = self
            .inner
            .path
            .join(format!(".stage-{:032x}.tmp", rand::random::<u128>()));
        let sd = Descriptor::parse(FILE_SD)?;
        let text = wide(&staged);
        let handle = unsafe {
            CreateFileW(
                PCWSTR(text.as_ptr()),
                GENERIC_READ.0 | GENERIC_WRITE.0,
                FILE_SHARE_READ,
                Some(&sd.attributes()),
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
        }
        .map_err(win_error)?;
        let mut file = unsafe { File::from_raw_handle(handle.0) };
        let result = (|| {
            file.write_all(bytes)?;
            file.sync_all()?;
            drop(file);
            let from = wide(&staged);
            let to = wide(destination);
            let flags = if replace {
                MOVEFILE_WRITE_THROUGH | MOVEFILE_REPLACE_EXISTING
            } else {
                MOVEFILE_WRITE_THROUGH
            };
            match unsafe { MoveFileExW(PCWSTR(from.as_ptr()), PCWSTR(to.as_ptr()), flags) } {
                Ok(()) => Ok(()),
                Err(e)
                    if !replace
                        && (e.code()
                            == windows::Win32::Foundation::ERROR_ALREADY_EXISTS.to_hresult()
                            || e.code()
                                == windows::Win32::Foundation::ERROR_FILE_EXISTS.to_hresult()) =>
                {
                    Ok(())
                }
                Err(e) => Err(win_error(e)),
            }
        })();
        // Only our freshly created temporary name, never an existing package.
        let _ = std::fs::remove_file(&staged);
        result
    }

    pub fn write_note(&self, note: CacheNote, bytes: &[u8]) -> io::Result<()> {
        if bytes.len() > 16 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Cache note too large",
            ));
        }
        self.publish(&self.inner.path.join(note.name()), bytes, true)
    }
    pub fn read_note(&self, note: CacheNote) -> io::Result<String> {
        let file = open_package(&self.inner.path.join(note.name()))?;
        if file.metadata()?.len() > 16 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Cache note too large",
            ));
        }
        let mut content = String::new();
        file.take(16 * 1024).read_to_string(&mut content)?;
        Ok(content)
    }
}

fn verify_contents(file: &mut File, bytes: &[u8]) -> io::Result<()> {
    if file.metadata()?.len() != bytes.len() as u64 {
        return Err(denied("Cached installer contents differ"));
    }
    let mut buf = [0u8; 64 * 1024];
    for chunk in bytes.chunks(buf.len()) {
        file.read_exact(&mut buf[..chunk.len()])?;
        if &buf[..chunk.len()] != chunk {
            return Err(denied("Cached installer contents differ"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn security_descriptors_parse_with_protected_dacls() {
        for text in [DIR_SD, FILE_SD] {
            let sd = Descriptor::parse(text).unwrap();
            let mut control = 0;
            let mut revision = 0;
            unsafe { GetSecurityDescriptorControl(sd.0, &mut control, &mut revision) }.unwrap();
            assert_ne!(control & 0x1000, 0);
        }
    }
    #[test]
    fn refuses_reparse_points_hard_links_and_wrong_types() {
        assert!(safe_object(FILE_ATTRIBUTE_NORMAL.0, 1, false));
        assert!(!safe_object(FILE_ATTRIBUTE_NORMAL.0, 2, false));
        assert!(!safe_object(FILE_ATTRIBUTE_REPARSE_POINT.0, 1, false));
        assert!(!safe_object(FILE_ATTRIBUTE_DIRECTORY.0, 1, false));
        assert!(!safe_object(
            FILE_ATTRIBUTE_DIRECTORY.0 | FILE_ATTRIBUTE_REPARSE_POINT.0,
            1,
            true
        ));
    }
    #[test]
    fn held_read_handle_rejects_changes_and_content_mismatch() {
        let path =
            std::env::temp_dir().join(format!("swift-cache-test-{:032x}", rand::random::<u128>()));
        std::fs::write(&path, b"original").unwrap();
        let mut file = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ.0)
            .open(&path)
            .unwrap();
        assert!(std::fs::write(&path, b"modified").is_err());
        assert!(std::fs::remove_file(&path).is_err());
        assert!(verify_contents(&mut file, b"impostor").is_err());
        drop(file);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn comparison_checks_the_entire_package() {
        use std::io::{Seek, SeekFrom};
        let path =
            std::env::temp_dir().join(format!("swift-cache-bytes-{:032x}", rand::random::<u128>()));
        let bytes = vec![7u8; 128 * 1024 + 13];
        std::fs::write(&path, &bytes).unwrap();
        let mut file = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ.0)
            .open(&path)
            .unwrap();
        verify_contents(&mut file, &bytes).unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        let mut mismatch = bytes.clone();
        *mismatch.last_mut().unwrap() ^= 1;
        assert!(verify_contents(&mut file, &mismatch).is_err());
        file.seek(SeekFrom::Start(0)).unwrap();
        assert!(verify_contents(&mut file, &bytes[..bytes.len() - 1]).is_err());
        drop(file);
        std::fs::remove_file(&path).unwrap();
    }
    #[test]
    #[ignore = "requires an elevated disposable Windows machine; creates an isolated protected test directory"]
    fn protected_cache_round_trip() {
        let base = std::env::temp_dir();
        let name = format!("swift-protected-test-{:032x}", rand::random::<u128>());
        let cache = InstallerCache::open_under(&base, &name).unwrap();
        let first = cache.stage("test.msi", b"first package").unwrap();
        let again = cache.stage("test.msi", b"first package").unwrap();
        assert_eq!(first.path(), again.path());
        assert!(OpenOptions::new().write(true).open(first.path()).is_err());
        let second = cache.stage("test.msi", b"other package").unwrap();
        assert_ne!(first.path(), second.path());
        cache.write_note(CacheNote::LiteAttempt, b"3.1.6").unwrap();
        assert_eq!(cache.read_note(CacheNote::LiteAttempt).unwrap(), "3.1.6");
        let dir = cache.inner.path.clone();
        drop((first, again, second, cache));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
