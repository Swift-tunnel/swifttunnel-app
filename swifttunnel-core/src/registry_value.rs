//! Bounded typed registry reads. A damaged value must not control allocation
//! size or make a failed read look like an absent setting.
use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_SUCCESS};
use windows::Win32::System::Registry::{HKEY, REG_VALUE_TYPE, RegQueryValueExW};
use windows::core::PCWSTR;
use winreg::{RegKey, RegValue, enums::RegType, types::FromRegValue};

pub(crate) const MAX_VALUE_BYTES: usize = 64 * 1024;

pub(crate) fn read<T: FromRegValue>(key: &RegKey, name: &str) -> std::io::Result<Option<T>> {
    read_raw(key, name)?
        .as_ref()
        .map(T::from_reg_value)
        .transpose()
}

pub(crate) fn read_raw(key: &RegKey, name: &str) -> std::io::Result<Option<RegValue>> {
    let name: Vec<_> = name.encode_utf16().chain(std::iter::once(0)).collect();
    for _ in 0..4 {
        let mut length = 0;
        let mut kind = REG_VALUE_TYPE::default();
        let status = unsafe {
            RegQueryValueExW(
                HKEY(key.raw_handle() as *mut _),
                PCWSTR(name.as_ptr()),
                None,
                Some(&mut kind),
                None,
                Some(&mut length),
            )
        };
        if status == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        if status != ERROR_SUCCESS {
            return Err(std::io::Error::from_raw_os_error(status.0 as i32));
        }
        if length as usize > MAX_VALUE_BYTES {
            return Err(std::io::Error::other(
                "Registry value exceeds the 64 KiB read limit",
            ));
        }
        let mut bytes = vec![0; length as usize];
        let status = unsafe {
            RegQueryValueExW(
                HKEY(key.raw_handle() as *mut _),
                PCWSTR(name.as_ptr()),
                None,
                Some(&mut kind),
                Some(bytes.as_mut_ptr()),
                Some(&mut length),
            )
        };
        if status == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        if status == ERROR_MORE_DATA {
            continue;
        }
        if status != ERROR_SUCCESS {
            return Err(std::io::Error::from_raw_os_error(status.0 as i32));
        }
        if length as usize > bytes.len() {
            return Err(std::io::Error::other(
                "Registry value grew beyond its read buffer",
            ));
        }
        bytes.truncate(length as usize);
        let vtype = match kind.0 {
            0 => RegType::REG_NONE,
            1 => RegType::REG_SZ,
            2 => RegType::REG_EXPAND_SZ,
            3 => RegType::REG_BINARY,
            4 => RegType::REG_DWORD,
            5 => RegType::REG_DWORD_BIG_ENDIAN,
            6 => RegType::REG_LINK,
            7 => RegType::REG_MULTI_SZ,
            8 => RegType::REG_RESOURCE_LIST,
            9 => RegType::REG_FULL_RESOURCE_DESCRIPTOR,
            10 => RegType::REG_RESOURCE_REQUIREMENTS_LIST,
            11 => RegType::REG_QWORD,
            _ => {
                return Err(std::io::Error::other(
                    "Registry value has an unsupported type",
                ));
            }
        };
        return Ok(Some(RegValue { bytes, vtype }));
    }
    Err(std::io::Error::other(
        "Registry value changed repeatedly during its read",
    ))
}

pub(crate) fn exists(key: &RegKey, name: &str) -> std::io::Result<bool> {
    let name: Vec<_> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let status = unsafe {
        RegQueryValueExW(
            HKEY(key.raw_handle() as *mut _),
            PCWSTR(name.as_ptr()),
            None,
            None,
            None,
            None,
        )
    };
    if status == ERROR_FILE_NOT_FOUND {
        Ok(false)
    } else if status == ERROR_SUCCESS {
        Ok(true)
    } else {
        Err(std::io::Error::from_raw_os_error(status.0 as i32))
    }
}
