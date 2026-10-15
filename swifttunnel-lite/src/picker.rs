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
const MAX_BYTES: usize = 64 * 1024;

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

    read_fflag_path(&path).map(Some)
}

fn read_fflag_path(path: &std::path::Path) -> Result<String, String> {
    let extension = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if !ALLOWED.contains(&extension.as_str()) {
        return Err("Pick a .json or .txt file.".to_string());
    }

    // Open once and limit the read itself, not just an earlier path metadata
    // check: an exporter can replace/grow a selected file while it is read.
    let text = swifttunnel_core::utils::read_text_file_bounded(path, MAX_BYTES, "FFlag file")
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::InvalidData {
                "Choose a JSON or text file under 64 KB.".to_string()
            } else {
                format!("Could not read that file: {error}")
            }
        })?;
    if text.is_empty() {
        return Err("That file is empty.".to_string());
    }

    // Notepad and plenty of exporters write a byte order mark, and a JSON
    // parser treats it as a stray character before the opening brace.
    Ok(text.trim_start_matches('\u{feff}').to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fixture(std::path::PathBuf);
    impl Fixture {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!(
                "swift-lite-flag-read-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
            ));
            std::fs::create_dir(&dir).unwrap();
            Self(dir)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn selected_flag_files_are_bounded_text_with_an_allowed_extension() {
        let dir = Fixture::new();
        let path = dir.0.join("flags.JSON");
        std::fs::write(&path, "\u{feff}{\"FFlagDebugSkyGray\":true}").unwrap();
        assert_eq!(
            read_fflag_path(&path).unwrap(),
            "{\"FFlagDebugSkyGray\":true}"
        );
        std::fs::write(&path, []).unwrap();
        assert!(read_fflag_path(&path).unwrap_err().contains("empty"));
        std::fs::write(&path, [0xff]).unwrap();
        assert!(read_fflag_path(&path).is_err());
        let other = dir.0.join("flags.exe");
        std::fs::write(&other, b"{}").unwrap();
        assert!(
            read_fflag_path(&other)
                .unwrap_err()
                .contains(".json or .txt")
        );
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(MAX_BYTES as u64 + 1).unwrap();
        drop(file);
        assert!(read_fflag_path(&path).unwrap_err().contains("64 KB"));
    }
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
