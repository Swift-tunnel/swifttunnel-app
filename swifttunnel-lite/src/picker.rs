//! Ask Windows for a file, with the checks that have to happen before its
//! contents are trusted.

use windows::Win32::Foundation::HWND;
use windows::Win32::UI::Controls::Dialogs::{
    GetOpenFileNameW, OFN_FILEMUSTEXIST, OFN_HIDEREADONLY, OFN_NOCHANGEDIR, OFN_PATHMUSTEXIST,
    OPENFILENAMEW,
};

/// Nothing larger is read off disk.
///
/// Core caps the payload itself at 8KB, but that check happens after the file
/// is in memory. Somebody picking a multi-gigabyte file, by accident or not,
/// should not get that far. The gap between the two leaves room for whitespace
/// and formatting in a file that is otherwise within the real limit.
const MAX_BYTES: u64 = 64 * 1024;

/// The only extensions accepted, checked again after the dialog returns.
///
/// The filter is a convenience, not a control: the name box takes anything
/// typed into it, so the answer has to be checked rather than assumed.
const ALLOWED: [&str; 2] = ["json", "txt"];

/// Show an open dialog and return the file's text.
///
/// Returns Err with something worth showing when the pick fails a check, and
/// Ok(None) when the dialog was simply cancelled, which is not an error and
/// should say nothing.
pub fn read_fflag_file(owner: HWND) -> Result<Option<String>, String> {
    let Some(path) = pick(owner) else {
        return Ok(None);
    };

    let extension = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if !ALLOWED.contains(&extension.as_str()) {
        return Err("Pick a .json or .txt file.".to_string());
    }

    let size = std::fs::metadata(&path)
        .map_err(|e| format!("Could not read that file: {e}"))?
        .len();
    if size == 0 {
        return Err("That file is empty.".to_string());
    }
    if size > MAX_BYTES {
        return Err("That file is too big to be a list of FFlags.".to_string());
    }

    let bytes = std::fs::read(&path).map_err(|e| format!("Could not read that file: {e}"))?;
    let text = String::from_utf8(bytes)
        .map_err(|_| "That file is not text. Export the flags as JSON.".to_string())?;

    // Notepad and plenty of exporters write a byte order mark, and a JSON
    // parser treats it as a stray character before the opening brace.
    Ok(Some(text.trim_start_matches('﻿').to_string()))
}

fn pick(owner: HWND) -> Option<std::path::PathBuf> {
    // Two NUL-separated pairs, terminated by an empty one, which is the shape
    // this API has always wanted. Built rather than written as a literal so no
    // escape has to survive being edited.
    let mut filter: Vec<u16> = Vec::new();
    for part in ["FFlag files (*.json, *.txt)", "*.json;*.txt"] {
        filter.extend(part.encode_utf16());
        filter.push(0);
    }
    filter.push(0);

    let title: Vec<u16> = "Choose an FFlag file"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let mut file = vec![0u16; 1024];
    let mut options = OPENFILENAMEW {
        lStructSize: size_of::<OPENFILENAMEW>() as u32,
        hwndOwner: owner,
        lpstrFilter: windows::core::PCWSTR(filter.as_ptr()),
        lpstrFile: windows::core::PWSTR(file.as_mut_ptr()),
        nMaxFile: file.len() as u32,
        lpstrTitle: windows::core::PCWSTR(title.as_ptr()),
        // NOCHANGEDIR because the dialog otherwise moves the whole process's
        // working directory to wherever the file was.
        Flags: OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY | OFN_NOCHANGEDIR,
        ..Default::default()
    };

    // SAFETY: every pointer above outlives the call, and the buffer is sized
    // by nMaxFile so the dialog cannot write past it.
    let picked = unsafe { GetOpenFileNameW(&mut options).as_bool() };
    if !picked {
        return None;
    }

    let end = file.iter().position(|c| *c == 0).unwrap_or(file.len());
    if end == 0 {
        return None;
    }
    Some(std::path::PathBuf::from(String::from_utf16_lossy(
        &file[..end],
    )))
}
