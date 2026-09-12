//! A size-bounded file sink for a logger that serializes access to its writer.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

pub struct RollingLog {
    path: PathBuf,
    previous: PathBuf,
    file: Option<File>,
    size: u64,
    max: u64,
}

impl RollingLog {
    pub fn open(path: &Path, previous: &Path, max: u64) -> io::Result<Self> {
        if max == 0 || path == previous {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid log rotation configuration",
            ));
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        let size = file.metadata()?.len();
        let mut writer = Self {
            path: path.into(),
            previous: previous.into(),
            file: Some(file),
            size,
            max,
        };
        if size >= max {
            writer.rotate()?;
        }
        Ok(writer)
    }

    fn rotate(&mut self) -> io::Result<()> {
        // Windows cannot always rename a file while another handle is open.
        // Close our handle before rotation. Do not log recursively from here.
        self.file.take();
        let archive = (|| -> io::Result<()> {
            if self.size > self.max {
                // A legacy unbounded session may already exceed the cap. Keep
                // only its tail, streaming it without loading the file into RAM.
                let mut old = File::open(&self.path)?;
                old.seek(SeekFrom::Start(self.size - self.max))?;
                io::copy(&mut old.take(self.max), &mut File::create(&self.previous)?)?;
            } else {
                match std::fs::remove_file(&self.previous) {
                    Ok(()) => {}
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e),
                }
                std::fs::rename(&self.path, &self.previous)?;
            }
            Ok(())
        })();
        if let Err(error) = archive {
            eprintln!(
                "SwiftTunnel: could not preserve previous log ({error}); truncating current log"
            );
        }
        // If archiving failed, keep the active log bounded even though history
        // cannot be preserved. A failed reopen propagates rather than growing it.
        self.file = Some(
            OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&self.path)?,
        );
        self.size = 0;
        Ok(())
    }
}

impl Write for RollingLog {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let count = bytes.len().min(self.max.min(usize::MAX as u64) as usize);
        if self.size + count as u64 > self.max {
            self.rotate()?;
        }
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| io::Error::other("log file unavailable"))?;
        let written = file.write(&bytes[..count])?;
        self.size += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file
            .as_mut()
            .ok_or_else(|| io::Error::other("log file unavailable"))?
            .flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "swifttunnel-log-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn current(&self) -> PathBuf {
            self.0.join("current.log")
        }
        fn previous(&self) -> PathBuf {
            self.0.join("previous.log")
        }
        fn open(&self) -> RollingLog {
            RollingLog::open(&self.current(), &self.previous(), 16).unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn running_session_rotates_without_a_restart() {
        let dir = Fixture::new();
        let mut log = dir.open();
        log.write_all(b"11111111").unwrap();
        log.write_all(b"22222222").unwrap();
        log.write_all(b"33333333").unwrap();
        assert_eq!(std::fs::read(dir.previous()).unwrap(), b"1111111122222222");
        assert_eq!(std::fs::read(dir.current()).unwrap(), b"33333333");
        log.write_all(b"4444444455555555").unwrap();
        assert_eq!(std::fs::read(dir.previous()).unwrap(), b"33333333");
        assert_eq!(std::fs::read(dir.current()).unwrap(), b"4444444455555555");
    }

    #[test]
    fn a_single_oversized_write_is_bounded_in_both_files() {
        let dir = Fixture::new();
        let mut log = dir.open();
        log.write_all(&[b'x'; 100]).unwrap();
        assert_eq!(std::fs::metadata(dir.current()).unwrap().len(), 4);
        assert_eq!(std::fs::metadata(dir.previous()).unwrap().len(), 16);
    }

    #[test]
    fn startup_preserves_only_the_tail_of_an_oversized_current_file() {
        let dir = Fixture::new();
        std::fs::write(dir.current(), b"old old old old 1234567890abcdef").unwrap();
        let mut log = dir.open();
        log.write_all(b"new").unwrap();
        assert_eq!(std::fs::read(dir.previous()).unwrap(), b"1234567890abcdef");
        assert_eq!(std::fs::read(dir.current()).unwrap(), b"new");
    }

    #[test]
    fn failed_archive_still_bounds_current_log() {
        let dir = Fixture::new();
        std::fs::create_dir(dir.previous()).unwrap();
        let mut log = dir.open();
        log.write_all(&[b'x'; 16]).unwrap();
        log.write_all(b"new").unwrap();
        assert_eq!(std::fs::read(dir.current()).unwrap(), b"new");
    }

    #[test]
    fn reopening_an_existing_log_counts_its_existing_bytes() {
        let dir = Fixture::new();
        std::fs::write(dir.current(), b"12345678").unwrap();
        let mut log = dir.open();
        log.write_all(b"abcdefgh").unwrap();
        log.write_all(b"new").unwrap();
        assert_eq!(std::fs::read(dir.previous()).unwrap(), b"12345678abcdefgh");
    }
}
