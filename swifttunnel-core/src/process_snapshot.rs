//! Small native process snapshots for launch and cleanup checks. No shell,
//! module walks, environment reads or per-process performance sampling.
use windows::Win32::Foundation::{
    CloseHandle, ERROR_INVALID_PARAMETER, ERROR_NO_MORE_FILES, HANDLE, WAIT_OBJECT_0,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{
    GetExitCodeProcess, OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_SYNCHRONIZE, PROCESS_TERMINATE, QueryFullProcessImageNameW, TerminateProcess,
    WaitForSingleObject,
};
use windows::core::PWSTR;

struct OwnedHandle(HANDLE);
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

#[derive(Debug)]
pub(crate) struct ProcessEntry {
    pub pid: u32,
    pub name: String,
}

pub(crate) fn list() -> Result<Vec<ProcessEntry>, String> {
    let snapshot = OwnedHandle(
        unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }
            .map_err(|error| format!("Could not read running processes: {error}"))?,
    );
    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    let mut next = unsafe { Process32FirstW(snapshot.0, &mut entry) };
    let mut entries = Vec::new();
    while next.is_ok() {
        let length = entry
            .szExeFile
            .iter()
            .position(|c| *c == 0)
            .unwrap_or(entry.szExeFile.len());
        entries.push(ProcessEntry {
            pid: entry.th32ProcessID,
            name: String::from_utf16_lossy(&entry.szExeFile[..length]),
        });
        next = unsafe { Process32NextW(snapshot.0, &mut entry) };
    }
    if let Err(error) = next
        && error.code() != ERROR_NO_MORE_FILES.to_hresult()
    {
        return Err(format!(
            "Could not finish reading running processes: {error}"
        ));
    }
    Ok(entries)
}

pub(crate) fn any_named(names: &[&str]) -> Result<bool, String> {
    Ok(list()?.iter().any(|entry| {
        names
            .iter()
            .any(|name| entry.name.eq_ignore_ascii_case(name))
    }))
}

pub(crate) fn image_path(pid: u32) -> Result<Option<String>, String> {
    let handle = match unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) } {
        Ok(handle) => OwnedHandle(handle),
        Err(error) if error.code() == ERROR_INVALID_PARAMETER.to_hresult() => return Ok(None),
        Err(error) => return Err(format!("Could not open process {pid}: {error}")),
    };
    image_for_handle(handle.0).map(Some)
}

fn image_for_handle(handle: HANDLE) -> Result<String, String> {
    let mut buffer = vec![0u16; 32768];
    let mut length = buffer.len() as u32;
    unsafe {
        QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_WIN32,
            PWSTR(buffer.as_mut_ptr()),
            &mut length,
        )
    }
    .map_err(|error| format!("Could not read the process image: {error}"))?;
    if length as usize > buffer.len() {
        return Err("Process image exceeded its buffer".into());
    }
    Ok(String::from_utf16_lossy(&buffer[..length as usize]))
}

fn terminate_entry(entry: &ProcessEntry, deadline: std::time::Instant) -> Result<bool, String> {
    if std::time::Instant::now() >= deadline {
        return Err("Closing Roblox exceeded its deadline".into());
    }
    let handle = match unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE | PROCESS_SYNCHRONIZE,
            false,
            entry.pid,
        )
    } {
        Ok(handle) => OwnedHandle(handle),
        Err(error) if error.code() == ERROR_INVALID_PARAMETER.to_hresult() => return Ok(false),
        Err(error) => return Err(format!("Could not close {}: {error}", entry.name)),
    };
    // A snapshot PID may have been reused. Verify the current image on the
    // same handle we terminate, rather than trusting the earlier name alone.
    let image = image_for_handle(handle.0)?;
    if !image
        .rsplit(['\\', '/'])
        .next()
        .is_some_and(|name| name.eq_ignore_ascii_case(&entry.name))
    {
        return Ok(false);
    }
    if let Err(error) = unsafe { TerminateProcess(handle.0, 1) } {
        let mut exit_code = 259;
        if unsafe { GetExitCodeProcess(handle.0, &mut exit_code) }.is_ok() && exit_code != 259 {
            return Ok(false);
        }
        return Err(format!("Could not close {}: {error}", entry.name));
    }
    let remaining = deadline
        .saturating_duration_since(std::time::Instant::now())
        .as_millis()
        .min(u32::MAX as u128) as u32;
    if unsafe { WaitForSingleObject(handle.0, remaining) } != WAIT_OBJECT_0 {
        return Err(format!("{} did not finish closing in time", entry.name));
    }
    Ok(true)
}

pub(crate) fn terminate_named(names: &[&str]) -> Result<(), String> {
    let mut failures = Vec::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    for entry in list()? {
        if names
            .iter()
            .any(|name| entry.name.eq_ignore_ascii_case(name))
        {
            if let Err(error) = terminate_entry(&entry, deadline) {
                failures.push(error);
            }
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn snapshot_finds_an_owned_child_and_termination_rechecks_its_image() {
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut child = Child(
            crate::hidden_command("powershell")
                .args([
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "Start-Sleep -Seconds 20",
                ])
                .spawn()
                .unwrap(),
        );
        let entry = list()
            .unwrap()
            .into_iter()
            .find(|entry| entry.pid == child.0.id())
            .unwrap();
        assert!(image_path(entry.pid).unwrap().is_some());
        assert!(
            !terminate_entry(
                &ProcessEntry {
                    pid: entry.pid,
                    name: "RobloxPlayerBeta.exe".into()
                },
                std::time::Instant::now() + std::time::Duration::from_secs(5)
            )
            .unwrap()
        );
        assert!(child.0.try_wait().unwrap().is_none());
        // This calls the private single-entry helper, never termination by a
        // common executable name, so only our own helper process is stopped.
        assert!(terminate_entry(&entry, std::time::Instant::now()).is_err());
        assert!(child.0.try_wait().unwrap().is_none());
        assert!(
            terminate_entry(
                &entry,
                std::time::Instant::now() + std::time::Duration::from_secs(5)
            )
            .unwrap()
        );
        child.0.wait().unwrap();
    }
}
