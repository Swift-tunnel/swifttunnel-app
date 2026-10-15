//! Recovery tests must never use an active client's on-disk markers.
use std::{fs, path::PathBuf};

struct RecoveryDirectory(PathBuf);
impl RecoveryDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "SwiftTunnel-test-recovery-{:032x}",
            rand::random::<u128>()
        ));
        fs::create_dir(&path).expect("create owned test recovery directory");
        Self(path)
    }
}
impl Drop for RecoveryDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
thread_local! { static RECOVERY: RecoveryDirectory = RecoveryDirectory::new(); }
pub(crate) fn recovery_directory() -> PathBuf {
    RECOVERY.with(|dir| dir.0.clone())
}

#[test]
fn recovery_fixtures_are_private_to_the_test_thread_and_removed_afterward() {
    fn owned() -> PathBuf {
        let path = recovery_directory();
        fs::write(path.join("marker"), b"owned test").unwrap();
        assert_eq!(recovery_directory(), path);
        path
    }
    let first = std::thread::spawn(owned).join().unwrap();
    let second = std::thread::spawn(owned).join().unwrap();
    assert_ne!(first, second);
    assert!(!first.exists());
    assert!(!second.exists());
}
