//! Replace a local file without truncating its live contents. Each attempt
//! owns its staging file; interrupted saves cannot reserve a filename forever.
use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
};

pub(crate) fn replace(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Invalid save filename"))?;
    replace_with(path, bytes, || {
        let mut temporary = name.to_os_string();
        temporary.push(format!(
            ".{}.{:016x}.tmp",
            std::process::id(),
            rand::random::<u64>()
        ));
        path.with_file_name(temporary)
    })
}

fn replace_with(
    path: &Path,
    bytes: &[u8],
    mut temporary: impl FnMut() -> PathBuf,
) -> io::Result<()> {
    for _ in 0..8 {
        let temporary = temporary();
        let mut file = match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        };
        let result = (|| {
            file.write_all(bytes)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&temporary, path)
        })();
        if result.is_err() {
            // Never remove someone else's staging or recovery data.
            let _ = fs::remove_file(&temporary);
        }
        return result;
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "Could not prepare a unique save file",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("swift-atomic-{:016x}", rand::random::<u64>()));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn retries_collisions_without_overwriting_or_removing_existing_files() {
        let dir = Fixture::new();
        let target = dir.0.join("settings.json");
        let stale = dir.0.join("stale.tmp");
        let fresh = dir.0.join("fresh.tmp");
        fs::write(&target, b"before").unwrap();
        fs::write(&stale, b"interrupted save").unwrap();
        let mut attempts = 0;
        replace_with(&target, b"after", || {
            attempts += 1;
            if attempts == 1 {
                stale.clone()
            } else {
                fresh.clone()
            }
        })
        .unwrap();
        assert_eq!(attempts, 2);
        assert_eq!(fs::read(&target).unwrap(), b"after");
        assert_eq!(fs::read(&stale).unwrap(), b"interrupted save");
        assert!(!fresh.exists());
    }

    #[test]
    fn exhausting_collisions_preserves_the_live_file_and_other_staging_data() {
        let dir = Fixture::new();
        let target = dir.0.join("settings.json");
        let occupied = dir.0.join("occupied.tmp");
        fs::write(&target, b"before").unwrap();
        fs::write(&occupied, b"owned elsewhere").unwrap();
        assert!(replace_with(&target, b"after", || occupied.clone()).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"before");
        assert_eq!(fs::read(&occupied).unwrap(), b"owned elsewhere");
    }

    #[cfg(windows)]
    #[test]
    fn blocked_rename_keeps_live_contents_and_cleans_only_our_staging_file() {
        use std::os::windows::fs::OpenOptionsExt;
        let dir = Fixture::new();
        let target = dir.0.join("settings.json");
        fs::write(&target, b"before").unwrap();
        let held = fs::OpenOptions::new()
            .read(true)
            .share_mode(3)
            .open(&target)
            .unwrap();
        assert!(replace(&target, b"after").is_err());
        assert_eq!(fs::read(&target).unwrap(), b"before");
        assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 1);
        drop(held);
        replace(&target, b"after").unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"after");
    }
}
