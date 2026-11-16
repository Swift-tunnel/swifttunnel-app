//! A size-bounded file sink for a logger that serializes access to its writer.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const REOPEN_RETRY_INTERVAL: Duration = Duration::from_secs(1);

pub struct RollingLog {
    path: PathBuf,
    previous: PathBuf,
    file: Option<File>,
    size: u64,
    max: u64,
    reopen_after: Option<Instant>,
    #[cfg(windows)]
    _writer_lock: File,
}

impl RollingLog {
    pub fn open(path: &Path, previous: &Path, max: u64) -> io::Result<Self> {
        if max == 0 || path == previous {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid log rotation configuration",
            ));
        }
        // Logging starts before the app's single-instance guard. A second
        // process must not rotate files still owned by the running logger.
        // Keep this handle separate from the log, whose handle changes during
        // rotation. A leftover lock file is harmless after its owner exits.
        #[cfg(windows)]
        let writer_lock = {
            use std::os::windows::fs::OpenOptionsExt;
            let mut lock_path = path.as_os_str().to_os_string();
            lock_path.push(".writer-lock");
            OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(false)
                .share_mode(0)
                .open(lock_path)?
        };
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        let size = file.metadata()?.len();
        let mut writer = Self {
            path: path.into(),
            previous: previous.into(),
            file: Some(file),
            size,
            max,
            reopen_after: None,
            #[cfg(windows)]
            _writer_lock: writer_lock,
        };
        if size >= max {
            writer.rotate()?;
        } else if let Err(error) = trim_archive(previous, max) {
            eprintln!("SwiftTunnel: could not trim previous log ({error})");
        }
        Ok(writer)
    }

    fn ensure_active_file(&mut self) -> io::Result<()> {
        if self.file.is_some() {
            return Ok(());
        }
        let now = Instant::now();
        if self.reopen_after.is_some_and(|at| now < at) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "log reopen retry pending",
            ));
        }
        // A busy or unavailable directory must not cause an open attempt for
        // every log line. Never repeat the archive step just to reopen a file.
        self.reopen_after = Some(now + REOPEN_RETRY_INTERVAL);
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        self.size = file.metadata()?.len();
        self.file = Some(file);
        self.reopen_after = None;
        Ok(())
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

// Compact the tail in place using bounded memory, including archives left by
// older versions. Reading always stays ahead of writing, so bytes are not lost.
fn trim_archive(path: &Path, max: u64) -> io::Result<()> {
    let mut file = match OpenOptions::new().read(true).write(true).open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    let size = file.metadata()?.len();
    if size <= max {
        return Ok(());
    }
    let mut offset = 0;
    let mut buffer = [0; 32 * 1024];
    while offset < max {
        let count = (max - offset).min(buffer.len() as u64) as usize;
        file.seek(SeekFrom::Start(size - max + offset))?;
        file.read_exact(&mut buffer[..count])?;
        file.seek(SeekFrom::Start(offset))?;
        file.write_all(&buffer[..count])?;
        offset += count as u64;
    }
    file.set_len(max)
}

impl Write for RollingLog {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        self.ensure_active_file()?;
        let count = bytes.len().min(self.max.min(usize::MAX as u64) as usize);
        if count as u64 > self.max.saturating_sub(self.size) {
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

    #[cfg(windows)]
    #[test]
    fn logging_recovers_after_a_rotation_reopen_was_temporarily_blocked() {
        use std::os::windows::fs::OpenOptionsExt;
        let dir = Fixture::new();
        let mut log = dir.open();
        log.write_all(b"12345678").unwrap();
        // Rotation closes its handle before reopening it. Insert a competing
        // reader at that boundary, with no changes to real file permissions.
        log.file.take();
        let blocker = OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(dir.current())
            .unwrap();
        assert!(log.rotate().is_err());
        assert!(log.file.is_none());
        drop(blocker);
        log.write_all(b"x").unwrap();
        assert_eq!(std::fs::read(dir.current()).unwrap(), b"12345678x");
    }

    #[test]
    fn recovery_after_archiving_does_not_discard_the_preserved_log() {
        let dir = Fixture::new();
        let mut log = dir.open();
        log.write_all(b"12345678").unwrap();
        log.file.take();
        // State after archiving succeeded but creation of the new log failed.
        std::fs::rename(dir.current(), dir.previous()).unwrap();
        log.write_all(b"x").unwrap();
        assert_eq!(std::fs::read(dir.current()).unwrap(), b"x");
        assert_eq!(std::fs::read(dir.previous()).unwrap(), b"12345678");
    }

    #[cfg(windows)]
    #[test]
    fn failed_reopens_back_off_without_postponing_the_next_retry() {
        use std::os::windows::fs::OpenOptionsExt;
        let dir = Fixture::new();
        let mut log = dir.open();
        log.file.take();
        let blocker = OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(dir.current())
            .unwrap();
        assert!(log.write(b"x").is_err());
        let retry = log.reopen_after;
        assert!(retry.is_some());
        assert_eq!(
            log.write(b"x").unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(log.reopen_after, retry);
        drop(blocker);
        assert_eq!(
            log.write(b"x").unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        // Advance only the fixture's retry deadline, never the system clock.
        log.reopen_after = Some(Instant::now() - REOPEN_RETRY_INTERVAL);
        log.write_all(b"x").unwrap();
        assert!(log.reopen_after.is_none());
        assert_eq!(std::fs::read(dir.current()).unwrap(), b"x");
    }

    #[test]
    fn a_recovered_file_is_remeasured_before_enforcing_the_size_limit() {
        let dir = Fixture::new();
        let mut log = dir.open();
        log.file.take();
        std::fs::write(dir.current(), b"legacy oversized 1234567890abcdef").unwrap();
        log.write_all(b"x").unwrap();
        assert_eq!(std::fs::read(dir.previous()).unwrap(), b"1234567890abcdef");
        assert_eq!(std::fs::read(dir.current()).unwrap(), b"x");
    }

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

    #[cfg(windows)]
    #[test]
    fn another_process_logger_cannot_rotate_a_running_writers_files() {
        let dir = Fixture::new();
        let mut first = dir.open();
        first.write_all(b"1234567890abcdef").unwrap();
        let second = RollingLog::open(&dir.current(), &dir.previous(), 16);
        assert!(second.is_err());
        assert_eq!(std::fs::read(dir.current()).unwrap(), b"1234567890abcdef");
        assert!(!dir.previous().exists());
        first.write_all(b"new").unwrap();
        assert_eq!(std::fs::read(dir.previous()).unwrap(), b"1234567890abcdef");
        drop(first);
        // The lock file can remain on disk. Ownership is the open handle, so
        // neither normal exit nor a stale empty file strands future logging.
        let mut reopened = dir.open();
        reopened.write_all(b" run").unwrap();
        assert_eq!(std::fs::read(dir.current()).unwrap(), b"new run");
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

    #[test]
    fn startup_bounds_legacy_archive_even_with_a_small_current_log() {
        let dir = Fixture::new();
        std::fs::write(dir.current(), b"new").unwrap();
        std::fs::write(dir.previous(), b"old old old old 1234567890abcdef").unwrap();
        let _log = dir.open();
        assert_eq!(std::fs::read(dir.current()).unwrap(), b"new");
        assert_eq!(std::fs::read(dir.previous()).unwrap(), b"1234567890abcdef");
    }

    #[test]
    fn archive_compaction_preserves_tail_across_buffer_boundaries() {
        let dir = Fixture::new();
        let bytes: Vec<u8> = (0..100_000).map(|i| (i % 251) as u8).collect();
        std::fs::write(dir.previous(), &bytes).unwrap();
        trim_archive(&dir.previous(), 90_000).unwrap();
        assert_eq!(std::fs::read(dir.previous()).unwrap(), bytes[10_000..]);
    }
}
