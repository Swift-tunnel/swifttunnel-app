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

fn visit_entries(mut visit: impl FnMut(&PROCESSENTRY32W) -> bool) -> Result<(), String> {
    let snapshot = OwnedHandle(
        unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }
            .map_err(|error| format!("Could not read running processes: {error}"))?,
    );
    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    let mut next = unsafe { Process32FirstW(snapshot.0, &mut entry) };
    while next.is_ok() {
        if !visit(&entry) {
            return Ok(());
        }
        next = unsafe { Process32NextW(snapshot.0, &mut entry) };
    }
    if let Err(error) = next
        && error.code() != ERROR_NO_MORE_FILES.to_hresult()
    {
        return Err(format!(
            "Could not finish reading running processes: {error}"
        ));
    }
    Ok(())
}

fn name_slice(buffer: &[u16]) -> &[u16] {
    &buffer[..buffer.iter().position(|c| *c == 0).unwrap_or(buffer.len())]
}

fn name_matches(buffer: &[u16], names: &[&str]) -> bool {
    let fold = |unit: u16| {
        if (u16::from(b'A')..=u16::from(b'Z')).contains(&unit) {
            unit + u16::from(b'a' - b'A')
        } else {
            unit
        }
    };
    names.iter().any(|name| {
        name_slice(buffer)
            .iter()
            .copied()
            .map(fold)
            .eq(name.encode_utf16().map(fold))
    })
}

pub(crate) fn list_named(names: &[&str]) -> Result<Vec<ProcessEntry>, String> {
    let mut entries = Vec::new();
    if names.is_empty() {
        return Ok(entries);
    }
    visit_entries(|entry| {
        if name_matches(&entry.szExeFile, names) {
            entries.push(ProcessEntry {
                pid: entry.th32ProcessID,
                name: String::from_utf16_lossy(name_slice(&entry.szExeFile)),
            });
        }
        true
    })?;
    Ok(entries)
}

pub(crate) fn contains_pid(pid: u32) -> Result<bool, String> {
    let mut found = false;
    visit_entries(|entry| {
        found = entry.th32ProcessID == pid;
        !found
    })?;
    Ok(found)
}

pub(crate) fn any_named(names: &[&str]) -> Result<bool, String> {
    if names.is_empty() {
        return Ok(false);
    }
    let mut found = false;
    visit_entries(|entry| {
        // Presence checks need neither a Vec of processes nor a String for
        // every unrelated executable. Compare the native entry in place.
        found = name_matches(&entry.szExeFile, names);
        !found
    })?;
    Ok(found)
}

pub(crate) fn image_path(pid: u32) -> Result<Option<String>, String> {
    let handle = match unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) } {
        Ok(handle) => OwnedHandle(handle),
        Err(error) if error.code() == ERROR_INVALID_PARAMETER.to_hresult() => return Ok(None),
        Err(error) => return Err(format!("Could not open process {pid}: {error}")),
    };
    image_for_handle(handle.0).map(Some)
}

pub(crate) fn image_for_handle(handle: HANDLE) -> Result<String, String> {
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

pub(crate) fn creation_time(handle: HANDLE) -> Result<u64, String> {
    use windows::Win32::Foundation::FILETIME;
    use windows::Win32::System::Threading::GetProcessTimes;
    let (mut created, mut exited, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    unsafe { GetProcessTimes(handle, &mut created, &mut exited, &mut kernel, &mut user) }
        .map_err(|error| format!("Could not read the process creation time: {error}"))?;
    Ok((u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime))
}

#[derive(Clone, PartialEq, Eq)]
struct ProcessOwner {
    sid: Vec<u8>,
    session: u32,
}

fn process_owner(process: HANDLE) -> Result<ProcessOwner, String> {
    use windows::Win32::Security::{
        GetLengthSid, GetTokenInformation, IsValidSid, TOKEN_QUERY, TOKEN_USER, TokenSessionId,
        TokenUser,
    };
    use windows::Win32::System::Threading::OpenProcessToken;
    let mut token = HANDLE::default();
    unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) }
        .map_err(|error| format!("Could not check the Windows account owning Roblox: {error}"))?;
    let token = OwnedHandle(token);
    let mut needed = 0;
    let _ = unsafe { GetTokenInformation(token.0, TokenUser, None, 0, &mut needed) };
    if needed < std::mem::size_of::<TOKEN_USER>() as u32 || needed > 64 * 1024 {
        return Err(
            "Windows could not confirm Roblox's account. Close Roblox yourself, then retry.".into(),
        );
    }
    // TOKEN_USER contains a pointer, so keep its native output aligned.
    let mut buffer = vec![0usize; (needed as usize).div_ceil(std::mem::size_of::<usize>())];
    let capacity = needed;
    unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            Some(buffer.as_mut_ptr().cast()),
            capacity,
            &mut needed,
        )
    }
    .map_err(|error| format!("Could not read Roblox's Windows account: {error}"))?;
    let start = buffer.as_ptr() as usize;
    let end = start + capacity as usize;
    let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    let address = user.User.Sid.0 as usize;
    if address < start || address.checked_add(8).is_none_or(|value| value > end) {
        return Err("Windows returned an invalid Roblox account identifier. Close Roblox yourself, then retry.".into());
    }
    if !unsafe { IsValidSid(user.User.Sid) }.as_bool() {
        return Err("Windows returned an invalid Roblox account identifier. Close Roblox yourself, then retry.".into());
    }
    let length = unsafe { GetLengthSid(user.User.Sid) } as usize;
    if address.checked_add(length).is_none_or(|value| value > end) {
        return Err("Windows returned an invalid Roblox account identifier. Close Roblox yourself, then retry.".into());
    }
    let sid = unsafe { std::slice::from_raw_parts(user.User.Sid.0.cast::<u8>(), length) }.to_vec();
    let mut session = 0u32;
    unsafe {
        GetTokenInformation(
            token.0,
            TokenSessionId,
            Some((&mut session as *mut u32).cast()),
            std::mem::size_of::<u32>() as u32,
            &mut needed,
        )
    }
    .map_err(|error| format!("Could not check Roblox's Windows session: {error}"))?;
    Ok(ProcessOwner { sid, session })
}

fn terminate_entry(
    entry: &ProcessEntry,
    deadline: std::time::Instant,
    owner: &ProcessOwner,
) -> Result<bool, String> {
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
    // The app runs elevated. A same-named player in another account/session
    // is not ours to close. Check the token on the exact handle we terminate.
    // TokenSessionId also avoids a PID-based precheck that can require broader
    // process-query rights than the limited handle already used here.
    if process_owner(handle.0)? != *owner {
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
    if names.is_empty() {
        return Ok(());
    }
    let owner = process_owner(unsafe { windows::Win32::System::Threading::GetCurrentProcess() })?;
    let mut failures = Vec::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    for entry in list_named(names)? {
        if let Err(error) = terminate_entry(&entry, deadline, &owner) {
            failures.push(error);
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
    fn presence_lookup_finds_this_process_and_rejects_an_absent_name() {
        let executable = std::env::current_exe().unwrap();
        let name = executable.file_name().unwrap().to_str().unwrap();
        assert!(any_named(&[&name.to_ascii_uppercase()]).unwrap());
        assert!(
            !any_named(&[&format!("not-running-{:032x}.exe", rand::random::<u128>())]).unwrap()
        );
        assert!(!any_named(&[]).unwrap());
    }

    #[test]
    fn filtered_snapshot_keeps_only_requested_images_and_can_check_an_exact_pid() {
        let executable = std::env::current_exe().unwrap();
        let name = executable.file_name().unwrap().to_str().unwrap();
        let entries = list_named(&[&name.to_ascii_uppercase()]).unwrap();
        assert!(entries.iter().any(|entry| entry.pid == std::process::id()));
        assert!(
            entries
                .iter()
                .all(|entry| entry.name.eq_ignore_ascii_case(name))
        );
        assert!(contains_pid(std::process::id()).unwrap());
        assert!(!contains_pid(u32::MAX).unwrap());
        assert!(list_named(&[]).unwrap().is_empty());
        assert!(
            list_named(&[&format!("not-running-{:032x}.exe", rand::random::<u128>())])
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn native_name_comparison_is_exact_and_stops_at_the_nul() {
        let raw: Vec<_> = "RobloxPlayerBeta.ExE\0ignored.exe".encode_utf16().collect();
        assert!(name_matches(&raw, &["robloxplayerbeta.exe"]));
        assert!(!name_matches(
            &raw,
            &["RobloxPlayer", "PlayerBeta.exe", "RobloxPlayerBeta.exe.old"]
        ));
        let unicode: Vec<_> = "app-漢.exe".encode_utf16().collect();
        assert!(name_matches(&unicode, &["APP-漢.EXE"]));
        assert!(!name_matches(&[0xd800, 0], &["RobloxPlayerBeta.exe"]));
    }
    #[test]
    fn snapshot_finds_an_owned_child_and_termination_rechecks_its_image() {
        let owner =
            process_owner(unsafe { windows::Win32::System::Threading::GetCurrentProcess() })
                .unwrap();
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
        let entry = list_named(&["powershell.exe"])
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
                std::time::Instant::now() + std::time::Duration::from_secs(5),
                &owner,
            )
            .unwrap()
        );
        assert!(child.0.try_wait().unwrap().is_none());
        // This calls the private single-entry helper, never termination by a
        // common executable name, so only our own helper process is stopped.
        assert!(terminate_entry(&entry, std::time::Instant::now(), &owner).is_err());
        assert!(child.0.try_wait().unwrap().is_none());
        let mut foreign = owner.clone();
        foreign.session = foreign.session.wrapping_add(1);
        assert!(
            !terminate_entry(
                &entry,
                std::time::Instant::now() + std::time::Duration::from_secs(5),
                &foreign
            )
            .unwrap()
        );
        assert!(child.0.try_wait().unwrap().is_none());
        foreign = owner.clone();
        *foreign.sid.last_mut().unwrap() ^= 1;
        assert!(
            !terminate_entry(
                &entry,
                std::time::Instant::now() + std::time::Duration::from_secs(5),
                &foreign
            )
            .unwrap()
        );
        assert!(child.0.try_wait().unwrap().is_none());
        assert!(
            terminate_entry(
                &entry,
                std::time::Instant::now() + std::time::Duration::from_secs(5),
                &owner,
            )
            .unwrap()
        );
        child.0.wait().unwrap();
    }
}
