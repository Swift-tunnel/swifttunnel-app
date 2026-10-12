//! Small, documented NVIDIA DRS surface scoped to RobloxPlayerBeta.exe.
//! ABI and IDs: NVIDIA/nvapi nvapi.h, nvapi_interface.h, NvApiDriverSettings.h.
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriverSetting {
    pub id: u32,
    pub current: Option<u32>,
    pub override_value: Option<u32>,
}
#[derive(Clone, Serialize)]
pub struct DriverProfile {
    pub available: bool,
    pub writable: bool,
    pub reason: Option<String>,
    pub settings: Vec<DriverSetting>,
}
#[derive(Clone, Deserialize)]
pub struct DriverChange {
    pub id: u32,
    pub value: Option<u32>,
}
pub const POWER: u32 = 0x1057eb71;
pub const VSYNC: u32 = 0x00a879cf;
pub const FPS: u32 = 0x10835002;
pub const QUEUE: u32 = 0x007ba09e;
const IDS: [u32; 4] = [POWER, VSYNC, FPS, QUEUE];
fn validate(changes: &[DriverChange], expected: &[DriverSetting]) -> Result<(), String> {
    if changes.is_empty()
        || changes.len() > 4
        || expected.len() != 4
        || IDS
            .iter()
            .any(|id| expected.iter().filter(|s| s.id == *id).count() != 1)
    {
        return Err("Refresh the NVIDIA profile before applying changes.".into());
    }
    for (i, c) in changes.iter().enumerate() {
        if changes[..i].iter().any(|p| p.id == c.id) || !IDS.contains(&c.id) {
            return Err("Choose one of the supported Roblox driver settings.".into());
        }
        if let Some(v) = c.value {
            let valid = match c.id {
                POWER => matches!(v, 0 | 1 | 2 | 5),
                VSYNC => matches!(v, 0x60925292 | 0x08416747 | 0x47814940),
                FPS => v <= 1023,
                QUEUE => v <= 4,
                _ => false,
            };
            if !valid {
                return Err("That driver value is outside the supported range.".into());
            }
        }
    }
    Ok(())
}
pub fn inspect() -> DriverProfile {
    match platform::read() {
        Ok(profile) => profile,
        Err(reason) => DriverProfile {
            available: false,
            writable: false,
            reason: Some(reason),
            settings: vec![],
        },
    }
}
pub fn apply(
    changes: Vec<DriverChange>,
    expected: Vec<DriverSetting>,
) -> Result<DriverProfile, String> {
    validate(&changes, &expected)?;
    platform::apply(&changes, &expected)
}

#[cfg(windows)]
mod platform {
    use super::*;
    use std::ffi::c_void;
    type Handle = *mut c_void;
    type Query = unsafe extern "C" fn(u32) -> Handle;
    type NoArgs = unsafe extern "C" fn() -> i32;
    type Create = unsafe extern "C" fn(*mut Handle) -> i32;
    type SessionCall = unsafe extern "C" fn(Handle) -> i32;
    type FindApp = unsafe extern "C" fn(Handle, *const u16, *mut Handle, *mut u32) -> i32;
    type Get = unsafe extern "C" fn(Handle, Handle, u32, *mut u32) -> i32;
    type BufferCall = unsafe extern "C" fn(Handle, Handle, *mut u32) -> i32;
    type CreateProfile = unsafe extern "C" fn(Handle, *mut u32, *mut Handle) -> i32;
    type Delete = unsafe extern "C" fn(Handle, Handle, u32) -> i32;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn LoadLibraryExW(name: *const u16, file: Handle, flags: u32) -> Handle;
        fn GetProcAddress(module: isize, name: *const u8) -> *const c_void;
        fn FreeLibrary(module: Handle) -> i32;
    }
    static GATE: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    struct Session {
        library: Handle,
        query: Query,
        session: Handle,
        initialized: bool,
    }
    impl Session {
        fn open() -> Result<Self, String> {
            let name: Vec<u16> = "nvapi64.dll\0".encode_utf16().collect();
            // System32 only. Never search the current directory or accept a
            // downloaded DLL. No new driver/runtime dependency is bundled.
            let library = unsafe { LoadLibraryExW(name.as_ptr(), std::ptr::null_mut(), 0x800) };
            if library.is_null() {
                return Err("A compatible NVIDIA driver was not found. These controls are unavailable on AMD, Intel and unsupported Windows ARM systems.".into());
            }
            let function = unsafe {
                GetProcAddress(library as isize, c"nvapi_QueryInterface".as_ptr().cast())
            };
            if function.is_null() {
                unsafe {
                    FreeLibrary(library);
                }
                return Err("The installed NVIDIA driver does not expose NVAPI.".into());
            }
            let query: Query = unsafe { std::mem::transmute(function) };
            let mut result = Self {
                library,
                query,
                session: std::ptr::null_mut(),
                initialized: false,
            };
            let initialize: NoArgs = result.function(0x0150e828)?;
            status(unsafe { initialize() })?;
            result.initialized = true;
            let create: Create = result.function(0x0694d52e)?;
            status(unsafe { create(&mut result.session) })?;
            let load: SessionCall = result.function(0x375dbd6b)?;
            status(unsafe { load(result.session) })?;
            Ok(result)
        }
        fn function<T: Copy>(&self, id: u32) -> Result<T, String> {
            let pointer = unsafe { (self.query)(id) };
            if pointer.is_null() || std::mem::size_of::<T>() != std::mem::size_of::<Handle>() {
                return Err(
                    "This NVIDIA driver does not support the requested profile operation.".into(),
                );
            }
            // All callers use the documented NVAPI C function signatures.
            Ok(unsafe { std::mem::transmute_copy(&pointer) })
        }
        fn profile(&self) -> Result<Option<Handle>, String> {
            let find: FindApp = self.function(0xeee566b2)?;
            let name: Vec<u16> = "robloxplayerbeta.exe\0".encode_utf16().collect();
            let mut profile = std::ptr::null_mut();
            let mut app = buffer(12296);
            let code = unsafe { find(self.session, name.as_ptr(), &mut profile, app.as_mut_ptr()) };
            if code == -166 {
                return Ok(None);
            }
            status(code)?;
            if profile.is_null() {
                return Err("NVIDIA returned an invalid Roblox profile.".into());
            }
            Ok(Some(profile))
        }
        fn writable(&self, profile: Handle) -> Result<bool, String> {
            let info: BufferCall = self.function(0x61cd6fd6)?;
            let mut data = buffer(4116);
            status(unsafe { info(self.session, profile, data.as_mut_ptr()) })?;
            // A shared vendor profile could affect Studio or another game.
            // Only edit a profile containing this one Roblox executable.
            Ok(data[4108 / 4] == 1)
        }
        fn read(&self, profile: Option<Handle>) -> Result<Vec<DriverSetting>, String> {
            let get: Get = self.function(0x73bf8338)?;
            IDS.into_iter()
                .map(|id| {
                    let Some(profile) = profile else {
                        return Ok(DriverSetting {
                            id,
                            current: None,
                            override_value: None,
                        });
                    };
                    let mut data = buffer(12320);
                    let code = unsafe { get(self.session, profile, id, data.as_mut_ptr()) };
                    if code == -160 {
                        return Ok(DriverSetting {
                            id,
                            current: None,
                            override_value: None,
                        });
                    }
                    status(code)?;
                    if data[4104 / 4] != 0 {
                        return Err("NVIDIA returned an unsupported value type.".into());
                    }
                    let current = data[8220 / 4];
                    let local = data[4108 / 4] == 0 && data[4112 / 4] == 0;
                    Ok(DriverSetting {
                        id,
                        current: Some(current),
                        override_value: local.then_some(current),
                    })
                })
                .collect()
        }
        fn create_profile(&self) -> Result<Handle, String> {
            let create: CreateProfile = self.function(0xcc176068)?;
            let mut data = buffer(4116);
            put_name(&mut data, 4, "SwiftTunnel Roblox Player");
            let mut profile = std::ptr::null_mut();
            status(unsafe { create(self.session, data.as_mut_ptr(), &mut profile) })?;
            let create_app: BufferCall = self.function(0x4347a9de)?;
            let mut app = buffer(12296);
            put_name(&mut app, 8, "robloxplayerbeta.exe");
            put_name(&mut app, 4104, "Roblox Player");
            status(unsafe { create_app(self.session, profile, app.as_mut_ptr()) })?;
            Ok(profile)
        }
    }
    impl Drop for Session {
        fn drop(&mut self) {
            if !self.session.is_null() {
                if let Ok(destroy) = self.function::<SessionCall>(0xdad9cff8) {
                    unsafe {
                        destroy(self.session);
                    }
                }
            }
            if self.initialized {
                if let Ok(unload) = self.function::<NoArgs>(0xd22bdd7e) {
                    unsafe {
                        unload();
                    }
                }
            }
            unsafe {
                FreeLibrary(self.library);
            }
        }
    }
    fn status(code: i32) -> Result<(), String> {
        match code {
            0 => Ok(()),
            -137 => Err("Windows denied this driver profile change. Open SwiftTunnel as administrator, then retry.".into()),
            -6 => Err("No NVIDIA GPU was found.".into()),
            -9 => Err("The NVIDIA driver uses an unsupported profile format. Update its driver or use NVIDIA Control Panel.".into()),
            _ => Err(format!("NVIDIA could not complete the Roblox profile operation (code {code}). No profile save was completed.")),
        }
    }
    fn buffer(bytes: usize) -> Vec<u32> {
        let mut data = vec![0; bytes / 4];
        data[0] = bytes as u32 | (1 << 16);
        data
    }
    fn put_name(data: &mut [u32], offset: usize, value: &str) {
        for (i, ch) in value.encode_utf16().take(2047).enumerate() {
            let index = offset / 4 + i / 2;
            data[index] |= u32::from(ch) << ((i % 2) * 16);
        }
    }
    fn result(session: &Session, profile: Option<Handle>) -> Result<DriverProfile, String> {
        let writable = profile
            .map(|p| session.writable(p))
            .transpose()?
            .unwrap_or(true);
        Ok(DriverProfile { available:true, writable, reason:(!writable).then(||"NVIDIA shares this profile with other executables. SwiftTunnel keeps it read-only so another game or Studio is not changed.".into()), settings: session.read(profile)? })
    }
    pub fn read() -> Result<DriverProfile, String> {
        let _gate = GATE.lock();
        let session = Session::open()?;
        result(&session, session.profile()?)
    }
    pub fn apply(
        changes: &[DriverChange],
        expected: &[DriverSetting],
    ) -> Result<DriverProfile, String> {
        let _gate = GATE.lock();
        let session = Session::open()?;
        let profile = session.profile()?;
        let current = result(&session, profile)?;
        if !current.writable {
            return Err(current.reason.unwrap());
        }
        if current.settings != expected {
            return Err("The NVIDIA profile changed outside SwiftTunnel. Refresh it and review the values before applying.".into());
        }
        if profile.is_none() && changes.iter().all(|c| c.value.is_none()) {
            return Ok(current);
        }
        let profile = match profile {
            Some(p) => p,
            None => session.create_profile()?,
        };
        let set: BufferCall = session.function(0x577dd202)?;
        let delete: Delete = session.function(0xe4a26362)?;
        for change in changes {
            match change.value {
                Some(value) => {
                    let mut data = buffer(12320);
                    data[4100 / 4] = change.id;
                    data[8220 / 4] = value;
                    status(unsafe { set(session.session, profile, data.as_mut_ptr()) })?;
                }
                None => {
                    let code = unsafe { delete(session.session, profile, change.id) };
                    if code != -160 {
                        status(code)?;
                    }
                }
            }
        }
        let save: SessionCall = session.function(0xfcbc7e14)?;
        status(unsafe { save(session.session) })?;
        result(&session,Some(profile)).map_err(|e|format!("The NVIDIA profile was saved, but reading it back failed: {e}. Refresh before trying again."))
    }
}
#[cfg(not(windows))]
mod platform {
    use super::*;
    pub fn read() -> Result<DriverProfile, String> {
        Err("NVIDIA profile editing is available on Windows only.".into())
    }
    pub fn apply(_: &[DriverChange], _: &[DriverSetting]) -> Result<DriverProfile, String> {
        Err("NVIDIA profile editing is available on Windows only.".into())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn expected() -> Vec<DriverSetting> {
        IDS.into_iter()
            .map(|id| DriverSetting {
                id,
                current: None,
                override_value: None,
            })
            .collect()
    }
    #[test]
    fn rejects_foreign_settings_and_invalid_values() {
        assert!(
            validate(
                &[DriverChange {
                    id: 1,
                    value: Some(0)
                }],
                &expected()
            )
            .is_err()
        );
        assert!(
            validate(
                &[DriverChange {
                    id: FPS,
                    value: Some(5000)
                }],
                &expected()
            )
            .is_err()
        );
        assert!(
            validate(
                &[DriverChange {
                    id: POWER,
                    value: Some(3)
                }],
                &expected()
            )
            .is_err()
        );
        assert!(
            validate(
                &[DriverChange {
                    id: VSYNC,
                    value: Some(1)
                }],
                &expected()
            )
            .is_err()
        );
    }
    #[test]
    fn accepts_scoped_reset_and_valid_documented_values() {
        assert!(
            validate(
                &[
                    DriverChange {
                        id: POWER,
                        value: None
                    },
                    DriverChange {
                        id: QUEUE,
                        value: Some(1)
                    }
                ],
                &expected()
            )
            .is_ok()
        );
    }
    #[test]
    fn rejects_duplicate_or_incomplete_snapshot() {
        let mut e = expected();
        e[1].id = POWER;
        assert!(
            validate(
                &[DriverChange {
                    id: POWER,
                    value: None
                }],
                &e
            )
            .is_err()
        );
    }
    #[test]
    #[ignore = "Read-only probe of the local NVIDIA driver, never writes a profile"]
    fn local_driver_read_only_probe() {
        let p = inspect();
        println!("{}", serde_json::to_string(&p).unwrap());
    }
}
