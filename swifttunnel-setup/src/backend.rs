use crate::model::{
    action_allowed, registration_matches, registration_version, result_message, Action, Command,
    Installed, Package, DESKTOP_FAMILY, LITE_FAMILY,
};
use std::path::Path;
use std::sync::mpsc::{Receiver, Sender};
use swifttunnel_installer_cache::{InstallerCache, ProtectedInstaller};

pub enum Event {
    Ready(Package, Vec<Installed>),
    Progress(String),
    Finished(Action, i32, Vec<Installed>),
    Failed(String),
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

#[link(name = "msi")]
extern "system" {
    fn MsiOpenDatabaseW(path: *const u16, persist: *const u16, handle: *mut u32) -> u32;
    fn MsiDatabaseOpenViewW(database: u32, query: *const u16, view: *mut u32) -> u32;
    fn MsiViewExecute(view: u32, record: u32) -> u32;
    fn MsiViewFetch(view: u32, record: *mut u32) -> u32;
    fn MsiRecordGetStringW(record: u32, field: u32, value: *mut u16, size: *mut u32) -> u32;
    fn MsiCloseHandle(handle: u32) -> u32;
    fn MsiEnumRelatedProductsW(
        upgrade: *const u16,
        reserved: u32,
        index: u32,
        code: *mut u16,
    ) -> u32;
    fn MsiGetProductInfoW(
        code: *const u16,
        property: *const u16,
        value: *mut u16,
        size: *mut u32,
    ) -> u32;
    fn MsiQueryProductStateW(code: *const u16) -> i32;
}

struct MsiHandle(u32);
impl Drop for MsiHandle {
    fn drop(&mut self) {
        unsafe {
            MsiCloseHandle(self.0);
        }
    }
}
fn check(code: u32, operation: &str) -> Result<(), String> {
    if code == 0 {
        Ok(())
    } else {
        Err(format!("Windows Installer could not {operation} (error {code}). Download Setup again or contact support."))
    }
}

fn guid(value: &str) -> bool {
    value.len() == 38
        && value.bytes().enumerate().all(|(i, c)| match i {
            0 => c == b'{',
            37 => c == b'}',
            9 | 14 | 19 | 24 => c == b'-',
            _ => c.is_ascii_hexdigit(),
        })
}

fn read_package(path: &Path, expected_name: &str) -> Result<Package, String> {
    use std::os::windows::ffi::OsStrExt;
    let path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut database = 0;
    check(
        unsafe { MsiOpenDatabaseW(path.as_ptr(), std::ptr::null(), &mut database) },
        "read the bundled package",
    )?;
    let database = MsiHandle(database);
    let property = |name: &str| -> Result<String, String> {
        let query = wide(&format!(
            "SELECT `Value` FROM `Property` WHERE `Property`='{name}'"
        ));
        let mut view = 0;
        check(
            unsafe { MsiDatabaseOpenViewW(database.0, query.as_ptr(), &mut view) },
            "read package metadata",
        )?;
        let view = MsiHandle(view);
        check(
            unsafe { MsiViewExecute(view.0, 0) },
            "query package metadata",
        )?;
        let mut record = 0;
        check(
            unsafe { MsiViewFetch(view.0, &mut record) },
            "find package metadata",
        )?;
        let record = MsiHandle(record);
        let mut value = vec![0u16; 1024];
        let mut size = value.len() as u32;
        check(
            unsafe { MsiRecordGetStringW(record.0, 1, value.as_mut_ptr(), &mut size) },
            "read a package property",
        )?;
        String::from_utf16(&value[..size as usize]).map_err(|_| "Invalid package text".into())
    };
    let package = Package {
        name: property("ProductName")?,
        version: property("ProductVersion")?,
        product_code: property("ProductCode")?,
        upgrade_code: property("UpgradeCode")?,
    };
    let family = if expected_name == "SwiftTunnelLite-Installer.msi" {
        LITE_FAMILY
    } else if expected_name == "SwiftTunnel-Installer.msi" {
        DESKTOP_FAMILY
    } else {
        return Err("Unknown setup product. Download Setup again.".into());
    };
    if !guid(&package.product_code) || !package.upgrade_code.eq_ignore_ascii_case(family) {
        return Err(
            "The bundled package does not match this SwiftTunnel product. Download Setup again."
                .into(),
        );
    }
    Ok(package)
}

fn installed_products(package: &Package) -> Result<Vec<Installed>, String> {
    let mut products = Vec::new();
    for index in 0..32 {
        let mut code = [0u16; 39];
        let status = unsafe {
            MsiEnumRelatedProductsW(
                wide(&package.upgrade_code).as_ptr(),
                0,
                index,
                code.as_mut_ptr(),
            )
        };
        if status == 259 {
            return Ok(products);
        }
        check(status, "identify installed copies")?;
        let product_code = String::from_utf16_lossy(&code[..38]);
        if !guid(&product_code) {
            return Err("Invalid Windows Installer registration. Contact support.".into());
        }
        let Some(info) = registration_version(
            |property| {
                let mut value = [0u16; 256];
                let mut length = value.len() as u32;
                let status = unsafe {
                    MsiGetProductInfoW(
                        code.as_ptr(),
                        wide(property).as_ptr(),
                        value.as_mut_ptr(),
                        &mut length,
                    )
                };
                if status != 0 {
                    return Err(status);
                }
                value
                    .get(..length as usize)
                    .and_then(|value| String::from_utf16(value).ok())
                    .ok_or(13) // ERROR_INVALID_DATA
            },
            || unsafe { MsiQueryProductStateW(code.as_ptr()) },
        )?
        else {
            continue;
        };
        products.push(Installed {
            product_code,
            version: info.version,
            advertised: info.advertised,
        });
    }
    Err("Too many SwiftTunnel installation records. Open Windows Settings > Apps to select the installation.".into())
}

fn execute(
    package: &Package,
    source: &ProtectedInstaller,
    action: Action,
) -> Result<(i32, Vec<Installed>), String> {
    use std::os::windows::process::CommandExt;
    // Re-read immediately before acting. Never trust the UI's earlier snapshot.
    let installed = installed_products(package)?;
    if !action_allowed(package, &installed, action) {
        return Err("The installation changed or this package cannot perform that action. Close Setup and open the current installer.".into());
    }
    let target_code = if action == Action::Uninstall {
        &installed[0].product_code
    } else {
        &package.product_code
    };
    let mut command = std::process::Command::new(
        swifttunnel_installer_cache::windows_installer_path().map_err(|e| e.to_string())?,
    );
    if action == Action::Uninstall {
        command.arg("/x").arg(target_code);
    } else {
        command.arg("/i").arg(source.path());
        match action {
            Action::Repair => {
                command.args(["REINSTALL=ALL", "REINSTALLMODE=vomus"]);
            }
            Action::Reinstall => {
                command.args(["REINSTALL=ALL", "REINSTALLMODE=vamus"]);
            }
            _ => {}
        }
    }
    // The launcher displays completion and reboot requirements itself. It never
    // claims success merely because msiexec started, and keeps the source locked.
    let code = command
        .args(["/qn", "/norestart", "REBOOT=ReallySuppress"])
        .creation_flags(0x0800_0000)
        .status()
        .map_err(|e| format!("Could not start Windows Installer: {e}"))?
        .code()
        .unwrap_or(-1);
    let after = registrations_after_action(action, target_code, code, &installed, || {
        installed_products(package)
    })?;
    Ok((code, after))
}

fn registrations_after_action(
    action: Action,
    target_code: &str,
    code: i32,
    before: &[Installed],
    read: impl FnOnce() -> Result<Vec<Installed>, String>,
) -> Result<Vec<Installed>, String> {
    if code == 1618 {
        // The operation did not start. Querying again while another installer
        // owns Windows Installer can obscure the original, actionable result.
        return Ok(before.to_vec());
    }
    let succeeded = matches!(code, 0 | 3010 | 1641);
    let after = match read() {
        Ok(after) => after,
        Err(_) if !succeeded => {
            // Preserve the original error. The next action always rechecks
            // registration before it invokes Windows Installer.
            return Ok(before.to_vec());
        }
        Err(error) => {
            return Err(format!(
                "Installer returned {code}, but verification failed: {error}"
            ));
        }
    };
    if succeeded && !registration_matches(action, target_code, &after) {
        return Err("Windows Installer finished, but the expected registration could not be confirmed. Restart Windows and contact support if it persists.".into());
    }
    Ok(after)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn busy_windows_installer_keeps_its_result_without_another_registry_query() {
        let before = [Installed {
            product_code: "old-product".into(),
            version: "3.9.6".into(),
            advertised: false,
        }];
        let after =
            registrations_after_action(Action::Install, "new-product", 1618, &before, || {
                panic!("another installer already owns the transaction")
            })
            .unwrap();
        assert_eq!(after[0].product_code, before[0].product_code);
        assert!(result_message(Action::Install, 1618).1.contains("Wait"));
    }

    #[test]
    fn registry_read_failure_only_blocks_successful_operations() {
        let unreadable = || Err("registration unavailable".to_string());
        assert!(
            registrations_after_action(Action::Repair, "product", 1603, &[], unreadable).is_ok()
        );
        assert!(
            registrations_after_action(Action::Repair, "product", 3010, &[], unreadable).is_err()
        );
    }
}

pub fn worker(commands: Receiver<Command>, events: Sender<Event>) {
    let prepare = || -> Result<_, String> {
        if crate::MSI_BYTES.is_empty() {
            return Err(
                "This development build has no MSI. Use the release Setup download.".into(),
            );
        }
        let source = InstallerCache::open()
            .and_then(|cache| cache.stage(crate::MSI_NAME, crate::MSI_BYTES))
            .map_err(|e| e.to_string())?;
        let package = read_package(source.path(), crate::MSI_NAME)?;
        let installed = installed_products(&package)?;
        Ok((source, package, installed))
    };
    let (source, package, installed) = match prepare() {
        Ok(value) => value,
        Err(error) => {
            crate::log_failure(&error);
            let _ = events.send(Event::Failed(error));
            return;
        }
    };
    if events
        .send(Event::Ready(package.clone(), installed))
        .is_err()
    {
        return;
    }
    let mut lite: Option<(ProtectedInstaller, Package)> = None;
    let mut selected_lite = false;
    while let Ok(command) = commands.recv() {
        let result = match command {
            Command::DownloadLite => (|| -> Result<Event, String> {
                if lite.is_none() {
                    let (download, version) = crate::lite_download::download(|status| {
                        let _ = events.send(Event::Progress(status));
                    })?;
                    let package = read_package(download.path(), "SwiftTunnelLite-Installer.msi")?;
                    if package.version != version {
                        return Err("Lite's package version does not match its verified release. Nothing was installed.".into());
                    }
                    lite = Some((download, package));
                }
                let (_, package) = lite.as_ref().unwrap();
                let installed = installed_products(package)?;
                selected_lite = true;
                Ok(Event::Ready(package.clone(), installed))
            })(),
            Command::UseBundled => installed_products(&package).map(|installed| {
                selected_lite = false;
                Event::Ready(package.clone(), installed)
            }),
            Command::Execute(action) => {
                let (selected_source, selected_package) = if selected_lite {
                    let (source, package) =
                        lite.as_ref().expect("selected only after verification");
                    (source, package)
                } else {
                    (&source, &package)
                };
                execute(selected_package, selected_source, action).map(|(code, installed)| {
                    let (ok, message) = result_message(action, code);
                    if !ok {
                        crate::log_failure(&message);
                    }
                    Event::Finished(action, code, installed)
                })
            }
        };
        let event = result.unwrap_or_else(|error| {
            crate::log_failure(&error);
            Event::Failed(error)
        });
        if events.send(event).is_err() {
            break;
        }
    }
}
