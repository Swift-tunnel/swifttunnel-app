//! Auth session storage backed by Windows DPAPI.
//!
//! `auth_session.dat` holds the access/refresh tokens. Bytes are
//! `[0x02][CryptProtectData ciphertext]` — the version byte lets us tell
//! new files from legacy XOR/base64 ones, which we silently re-encrypt with
//! DPAPI on first read so existing users stay logged in across the upgrade.
//!
//! Windows Credential Manager is kept as a secondary store. Both stores hold
//! the same DPAPI ciphertext (the keyring copy is base64-encoded so it can be
//! passed through the keyring's string API).

use super::types::{AuthError, AuthSession, OAuthPendingState};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chrono::{DateTime, Utc};
use keyring::Entry;
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

const SERVICE_NAME: &str = "SwiftTunnel";
const SESSION_KEY: &str = "auth_session";
const OAUTH_STATE_FILE: &str = "oauth_pending.json";
const AUTH_SESSION_FILE: &str = "auth_session.dat";
const REFRESH_FAILURES_FILE: &str = "refresh_failures.json";
const LEGACY_REFRESH_FAILURES_FILE: &str = "refresh_failures.txt";

/// Version tag for the new DPAPI-encrypted auth_session.dat. 0x02 sits well
/// outside the printable base64 alphabet that legacy files use, so the loader
/// can dispatch on the first byte without ambiguity.
const DPAPI_VERSION_TAG: u8 = 0x02;

/// XOR key kept ONLY for one-shot migration of v1 auth_session.dat files.
const LEGACY_OBFUSCATION_KEY: &[u8] = b"SwiftTunnel2024AuthStorage";

/// Window during which consecutive refresh failures are aggregated. Failures
/// older than this reset the counter on the next increment so transient
/// errors days apart never strand a user.
const REFRESH_FAILURE_WINDOW: chrono::Duration = chrono::Duration::hours(1);

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RefreshFailureRecord {
    count: u32,
    first_failure_at: DateTime<Utc>,
}

#[cfg(windows)]
mod dpapi {
    use super::AuthError;
    use windows::Win32::Foundation::{HLOCAL, LocalFree};
    use windows::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CryptProtectData, CryptUnprotectData,
    };
    use windows::core::PCWSTR;

    pub fn protect(plaintext: &[u8]) -> Result<Vec<u8>, AuthError> {
        let input = CRYPT_INTEGER_BLOB {
            cbData: plaintext.len() as u32,
            pbData: plaintext.as_ptr() as *mut u8,
        };
        let mut output = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };

        unsafe {
            CryptProtectData(&input, PCWSTR::null(), None, None, None, 0, &mut output)
                .map_err(|e| AuthError::StorageError(format!("CryptProtectData failed: {}", e)))?;

            let bytes = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
            let _ = LocalFree(Some(HLOCAL(output.pbData as *mut _)));
            Ok(bytes)
        }
    }

    pub fn unprotect(ciphertext: &[u8]) -> Result<Vec<u8>, AuthError> {
        let input = CRYPT_INTEGER_BLOB {
            cbData: ciphertext.len() as u32,
            pbData: ciphertext.as_ptr() as *mut u8,
        };
        let mut output = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };

        unsafe {
            CryptUnprotectData(&input, None, None, None, None, 0, &mut output).map_err(|e| {
                AuthError::StorageError(format!("CryptUnprotectData failed: {}", e))
            })?;

            let bytes = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
            let _ = LocalFree(Some(HLOCAL(output.pbData as *mut _)));
            Ok(bytes)
        }
    }
}

// Non-Windows builds are dev/test only — DPAPI doesn't exist there. Pass the
// data through unchanged so the file format stays consistent and the loader
// still works during local cargo test runs on a developer's Mac.
#[cfg(not(windows))]
mod dpapi {
    use super::AuthError;

    pub fn protect(plaintext: &[u8]) -> Result<Vec<u8>, AuthError> {
        Ok(plaintext.to_vec())
    }

    pub fn unprotect(ciphertext: &[u8]) -> Result<Vec<u8>, AuthError> {
        Ok(ciphertext.to_vec())
    }
}

/// Decode a legacy v1 auth_session.dat (XOR + base64 ASCII text).
fn decrypt_legacy_v1(raw: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(raw).ok()?;
    let obfuscated = BASE64.decode(text.trim()).ok()?;
    Some(
        obfuscated
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ LEGACY_OBFUSCATION_KEY[i % LEGACY_OBFUSCATION_KEY.len()])
            .collect(),
    )
}

/// Secure storage for authentication credentials using DPAPI + keyring.
pub struct SecureStorage {
    keyring_entry: Option<Entry>,
    data_dir: PathBuf,
}

impl SecureStorage {
    /// Create a new SecureStorage instance
    pub fn new() -> Result<Self, AuthError> {
        let data_dir = dirs::data_local_dir()
            .map(|d| d.join("SwiftTunnel"))
            .ok_or_else(|| {
                AuthError::StorageError("Could not determine data directory".to_string())
            })?;

        std::fs::create_dir_all(&data_dir).map_err(|e| {
            AuthError::StorageError(format!("Failed to create data directory: {}", e))
        })?;

        info!("SecureStorage initialized:");
        info!("  Data directory: {}", data_dir.display());
        info!(
            "  Auth file: {}",
            data_dir.join(AUTH_SESSION_FILE).display()
        );

        let keyring_entry = match Entry::new(SERVICE_NAME, SESSION_KEY) {
            Ok(entry) => {
                info!("  Keyring: Available (Windows Credential Manager)");
                Some(entry)
            }
            Err(e) => {
                warn!("  Keyring: Not available ({}). Using file storage only.", e);
                None
            }
        };

        Ok(Self {
            keyring_entry,
            data_dir,
        })
    }

    /// Get the auth session file path
    fn session_file_path(&self) -> PathBuf {
        self.data_dir.join(AUTH_SESSION_FILE)
    }

    /// Encode a session as a versioned DPAPI blob ready for disk or keyring.
    fn encode_session(session: &AuthSession) -> Result<Vec<u8>, AuthError> {
        let json = serde_json::to_vec(session)
            .map_err(|e| AuthError::StorageError(format!("Failed to serialize session: {}", e)))?;
        let ciphertext = dpapi::protect(&json)?;
        let mut blob = Vec::with_capacity(ciphertext.len() + 1);
        blob.push(DPAPI_VERSION_TAG);
        blob.extend_from_slice(&ciphertext);
        Ok(blob)
    }

    /// Decode either a new (DPAPI) or legacy (XOR/base64) blob into a session.
    /// Returns Ok(None) on unrecoverable corruption so the caller can delete
    /// the file and force re-login.
    fn decode_blob(raw: &[u8]) -> Option<AuthSession> {
        if raw.is_empty() {
            return None;
        }

        let json = if raw[0] == DPAPI_VERSION_TAG {
            match dpapi::unprotect(&raw[1..]) {
                Ok(bytes) => bytes,
                Err(e) => {
                    error!("DPAPI unprotect failed: {}", e);
                    return None;
                }
            }
        } else {
            match decrypt_legacy_v1(raw) {
                Some(bytes) => bytes,
                None => {
                    error!("Legacy session blob could not be decoded");
                    return None;
                }
            }
        };

        match serde_json::from_slice::<AuthSession>(&json) {
            Ok(session) => Some(session),
            Err(e) => {
                error!("Failed to deserialize session blob: {}", e);
                None
            }
        }
    }

    /// Store session to file (primary storage) using DPAPI.
    fn store_to_file(&self, session: &AuthSession) -> Result<(), AuthError> {
        let path = self.session_file_path();
        let blob = Self::encode_session(session)?;

        std::fs::write(&path, &blob).map_err(|e| {
            error!("Failed to write session file: {}", e);
            AuthError::StorageError(format!("Failed to write session file: {}", e))
        })?;

        info!(
            "Stored session to {} ({} bytes ciphertext)",
            path.display(),
            blob.len()
        );
        Ok(())
    }

    /// Load session from file (primary storage). Migrates legacy v1 files on
    /// first read by silently re-encrypting them with DPAPI.
    fn load_from_file(&self) -> Result<Option<AuthSession>, AuthError> {
        let path = self.session_file_path();
        if !path.exists() {
            info!("Session file does not exist (first run or logged out)");
            return Ok(None);
        }

        let raw = match std::fs::read(&path) {
            Ok(data) => data,
            Err(e) => {
                error!("Failed to read session file: {}", e);
                return Ok(None);
            }
        };

        let was_legacy = raw.first().copied() != Some(DPAPI_VERSION_TAG);

        let session = match Self::decode_blob(&raw) {
            Some(session) => session,
            None => {
                let _ = std::fs::remove_file(&path);
                return Ok(None);
            }
        };

        if was_legacy {
            info!("Migrating legacy auth_session.dat to DPAPI format");
            if let Err(e) = self.store_to_file(&session) {
                warn!("Failed to re-encrypt legacy session file: {}", e);
            }
        }

        info!("Loaded session for user: {}", session.user.email);
        Ok(Some(session))
    }

    /// Clear session from file
    fn clear_from_file(&self) -> Result<(), AuthError> {
        let path = self.session_file_path();
        if path.exists() {
            std::fs::remove_file(&path).map_err(|e| {
                AuthError::StorageError(format!("Failed to delete session file: {}", e))
            })?;
            info!("Cleared session file");
        }
        Ok(())
    }

    /// Store session to keyring (secondary storage). Holds the same DPAPI
    /// blob as the file, base64-encoded so it fits the keyring's string API.
    fn store_to_keyring(&self, session: &AuthSession) -> Result<(), AuthError> {
        let entry = match &self.keyring_entry {
            Some(e) => e,
            None => {
                debug!("Keyring not available, skipping keyring store");
                return Ok(());
            }
        };

        let blob = Self::encode_session(session)?;
        let encoded = BASE64.encode(&blob);

        match entry.set_password(&encoded) {
            Ok(_) => {
                info!("Session also stored in Windows Credential Manager");
                Ok(())
            }
            Err(e) => {
                warn!(
                    "Failed to store in keyring (file storage still works): {}",
                    e
                );
                Ok(()) // Not fatal — file storage is primary
            }
        }
    }

    /// Load session from keyring (fallback). Accepts both DPAPI blobs and
    /// legacy plaintext-JSON entries written by older builds.
    fn load_from_keyring(&self) -> Result<Option<AuthSession>, AuthError> {
        let entry = match &self.keyring_entry {
            Some(e) => e,
            None => return Ok(None),
        };

        let stored = match entry.get_password() {
            Ok(s) => s,
            Err(keyring::Error::NoEntry) => {
                debug!("No session in keyring");
                return Ok(None);
            }
            Err(e) => {
                warn!("Keyring read error: {:?}", e);
                return Ok(None);
            }
        };

        if let Ok(blob) = BASE64.decode(stored.trim()) {
            if let Some(session) = Self::decode_blob(&blob) {
                return Ok(Some(session));
            }
        }

        match serde_json::from_str::<AuthSession>(&stored) {
            Ok(session) => {
                info!("Migrated legacy plaintext keyring session");
                Ok(Some(session))
            }
            Err(e) => {
                warn!("Failed to deserialize keyring session: {}", e);
                Ok(None)
            }
        }
    }

    /// Clear session from keyring
    fn clear_from_keyring(&self) -> Result<(), AuthError> {
        if let Some(entry) = &self.keyring_entry {
            match entry.delete_credential() {
                Ok(_) => info!("Cleared session from keyring"),
                Err(keyring::Error::NoEntry) => debug!("No keyring session to clear"),
                Err(e) => warn!("Failed to clear keyring session: {}", e),
            }
        }
        Ok(())
    }

    /// Store the authentication session (to BOTH file and keyring)
    pub fn store_session(&self, session: &AuthSession) -> Result<(), AuthError> {
        info!("Storing auth session for {}", session.user.email);
        self.store_to_file(session)?;
        let _ = self.store_to_keyring(session);
        Ok(())
    }

    /// Load the authentication session (try file first, then keyring)
    pub fn load_session(&self) -> Result<Option<AuthSession>, AuthError> {
        if let Some(session) = self.load_from_file()? {
            info!("Loaded session from file storage");
            return Ok(Some(session));
        }

        info!("File storage empty, trying keyring fallback...");
        if let Some(session) = self.load_from_keyring()? {
            info!("Loaded session from keyring (migrating to file storage)");
            let _ = self.store_to_file(&session);
            // Re-encrypt the keyring entry too — load_from_keyring may have
            // returned a legacy plaintext-JSON entry, and we want to overwrite
            // it with the DPAPI blob so a future file deletion can't fall back
            // to plaintext again.
            let _ = self.store_to_keyring(&session);
            return Ok(Some(session));
        }

        info!("No stored session found (user needs to log in)");
        Ok(None)
    }

    /// Clear the stored session (logout) - clears from BOTH storages
    pub fn clear_session(&self) -> Result<(), AuthError> {
        info!("Clearing auth session from all storage locations...");

        let file_result = self.clear_from_file();
        let keyring_result = self.clear_from_keyring();

        if let Err(e) = &file_result {
            error!("File clear error: {}", e);
        }
        if let Err(e) = &keyring_result {
            error!("Keyring clear error: {}", e);
        }

        info!("Auth session cleared");
        Ok(())
    }

    /// Cheap check: is there a session *file* on disk? May return `true` for
    /// files that won't actually decrypt — e.g. a file DPAPI-encrypted under a
    /// different Windows user, or a partial write from a crash mid-migration.
    /// Callers MUST follow up with `load_session` before assuming the user is
    /// logged in. We accept the false-positive because keyring reads on Windows
    /// are synchronous RPCs that don't belong on a hot path.
    pub fn has_session(&self) -> bool {
        self.session_file_path().exists()
    }

    /// Get the OAuth state file path
    fn oauth_state_path(&self) -> PathBuf {
        self.data_dir.join(OAUTH_STATE_FILE)
    }

    /// Save OAuth pending state to disk (for deep link callback after app restart)
    pub fn save_oauth_state(&self, state: &OAuthPendingState) -> Result<(), AuthError> {
        let path = self.oauth_state_path();

        let json = serde_json::to_string(state).map_err(|e| {
            AuthError::StorageError(format!("Failed to serialize OAuth state: {}", e))
        })?;

        std::fs::write(&path, json)
            .map_err(|e| AuthError::StorageError(format!("Failed to write OAuth state: {}", e)))?;

        info!("Saved OAuth pending state to: {}", path.display());
        Ok(())
    }

    /// Load OAuth pending state from disk
    pub fn load_oauth_state(&self) -> Result<Option<OAuthPendingState>, AuthError> {
        let path = self.oauth_state_path();

        if !path.exists() {
            debug!("No OAuth pending state file found");
            return Ok(None);
        }

        let json = std::fs::read_to_string(&path)
            .map_err(|e| AuthError::StorageError(format!("Failed to read OAuth state: {}", e)))?;

        let state: OAuthPendingState = serde_json::from_str(&json).map_err(|e| {
            AuthError::StorageError(format!("Failed to deserialize OAuth state: {}", e))
        })?;

        info!("Loaded OAuth pending state from disk");
        Ok(Some(state))
    }

    /// Clear OAuth pending state from disk
    pub fn clear_oauth_state(&self) -> Result<(), AuthError> {
        let path = self.oauth_state_path();

        if path.exists() {
            std::fs::remove_file(&path).map_err(|e| {
                AuthError::StorageError(format!("Failed to remove OAuth state: {}", e))
            })?;
            info!("Cleared OAuth pending state file");
        }

        Ok(())
    }

    fn refresh_failures_path(&self) -> PathBuf {
        self.data_dir.join(REFRESH_FAILURES_FILE)
    }

    fn legacy_refresh_failures_path(&self) -> PathBuf {
        self.data_dir.join(LEGACY_REFRESH_FAILURES_FILE)
    }

    /// Read the persisted refresh-failure record, dropping any record older
    /// than the aggregation window so the counter doesn't accumulate forever.
    fn read_refresh_record(&self) -> Option<RefreshFailureRecord> {
        let _ = std::fs::remove_file(self.legacy_refresh_failures_path());

        let path = self.refresh_failures_path();
        if !path.exists() {
            return None;
        }
        let raw = std::fs::read_to_string(&path).ok()?;
        let record: RefreshFailureRecord = serde_json::from_str(&raw).ok()?;
        if Utc::now() - record.first_failure_at > REFRESH_FAILURE_WINDOW {
            None
        } else {
            Some(record)
        }
    }

    fn write_refresh_record(&self, record: &RefreshFailureRecord) {
        let path = self.refresh_failures_path();
        match serde_json::to_string(record) {
            Ok(json) => {
                if let Err(e) = std::fs::write(&path, json) {
                    warn!("Failed to write refresh failures record: {}", e);
                }
            }
            Err(e) => warn!("Failed to serialize refresh failures record: {}", e),
        }
    }

    /// Increment the refresh failure counter and return the new count.
    /// Failures older than `REFRESH_FAILURE_WINDOW` reset the count to 1.
    pub fn increment_refresh_failures(&self) -> u32 {
        let new_count = match self.read_refresh_record() {
            Some(mut record) => {
                record.count = record.count.saturating_add(1);
                self.write_refresh_record(&record);
                record.count
            }
            None => {
                let record = RefreshFailureRecord {
                    count: 1,
                    first_failure_at: Utc::now(),
                };
                self.write_refresh_record(&record);
                1
            }
        };
        debug!("Incremented refresh failures to {}", new_count);
        new_count
    }

    /// Get the current (in-window) refresh failure count.
    pub fn get_refresh_failures(&self) -> u32 {
        self.read_refresh_record().map(|r| r.count).unwrap_or(0)
    }

    /// Reset the refresh failure counter (called on successful refresh).
    pub fn reset_refresh_failures(&self) {
        let path = self.refresh_failures_path();
        if path.exists() {
            if let Err(e) = std::fs::remove_file(&path) {
                warn!("Failed to remove refresh failures file: {}", e);
            } else {
                debug!("Reset refresh failures counter");
            }
        }
        let _ = std::fs::remove_file(self.legacy_refresh_failures_path());
    }
}

impl Default for SecureStorage {
    fn default() -> Self {
        Self::new().expect("Failed to create SecureStorage")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};

    fn make_session(suffix: &str) -> AuthSession {
        AuthSession {
            access_token: format!("test_access_token_{}", suffix),
            refresh_token: format!("test_refresh_token_{}", suffix),
            expires_at: Utc::now() + Duration::hours(1),
            user: super::super::types::UserInfo {
                id: format!("user_{}", suffix),
                email: format!("{}@example.com", suffix),
                is_tester: false,
            },
        }
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let session = make_session("rt");
        let blob = SecureStorage::encode_session(&session).unwrap();
        assert_eq!(blob[0], DPAPI_VERSION_TAG);
        let decoded = SecureStorage::decode_blob(&blob).unwrap();
        assert_eq!(decoded.access_token, session.access_token);
        assert_eq!(decoded.refresh_token, session.refresh_token);
        assert_eq!(decoded.user.email, session.user.email);
    }

    #[test]
    fn test_legacy_xor_blob_decodes() {
        let session = make_session("legacy");
        let json = serde_json::to_string(&session).unwrap();
        let xored: Vec<u8> = json
            .as_bytes()
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ LEGACY_OBFUSCATION_KEY[i % LEGACY_OBFUSCATION_KEY.len()])
            .collect();
        let legacy_blob = BASE64.encode(&xored).into_bytes();

        // Legacy blob should never start with the new version tag (base64 is
        // ASCII alphanumerics + + / =, all >= 0x2B).
        assert_ne!(legacy_blob[0], DPAPI_VERSION_TAG);

        let decoded = SecureStorage::decode_blob(&legacy_blob).unwrap();
        assert_eq!(decoded.access_token, session.access_token);
        assert_eq!(decoded.user.email, session.user.email);
    }

    #[test]
    fn test_corrupt_blob_returns_none() {
        let garbage = b"not a real session blob".to_vec();
        assert!(SecureStorage::decode_blob(&garbage).is_none());

        let mut versioned_garbage = vec![DPAPI_VERSION_TAG];
        versioned_garbage.extend_from_slice(b"definitely not DPAPI ciphertext");
        // On Windows this fails CryptUnprotectData; on non-Windows the
        // identity unprotect succeeds but JSON parsing fails. Either way
        // returns None.
        assert!(SecureStorage::decode_blob(&versioned_garbage).is_none());
    }

    #[test]
    fn test_storage_roundtrip_via_file() {
        let storage = SecureStorage::new().unwrap();
        let _ = storage.clear_session();

        let session = make_session("file");
        storage.store_session(&session).unwrap();
        let loaded = storage.load_session().unwrap().unwrap();
        assert_eq!(loaded.access_token, session.access_token);
        assert_eq!(loaded.user.email, session.user.email);

        storage.clear_session().unwrap();
        assert!(storage.load_session().unwrap().is_none());
    }

    #[test]
    fn test_legacy_file_migrated_on_load() {
        let storage = SecureStorage::new().unwrap();
        let _ = storage.clear_session();

        let session = make_session("migrate");
        let json = serde_json::to_string(&session).unwrap();
        let xored: Vec<u8> = json
            .as_bytes()
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ LEGACY_OBFUSCATION_KEY[i % LEGACY_OBFUSCATION_KEY.len()])
            .collect();
        let legacy = BASE64.encode(&xored);
        std::fs::write(storage.session_file_path(), legacy).unwrap();

        let loaded = storage.load_session().unwrap().unwrap();
        assert_eq!(loaded.access_token, session.access_token);

        // After migration the file must start with the new version tag.
        let raw = std::fs::read(storage.session_file_path()).unwrap();
        assert_eq!(raw[0], DPAPI_VERSION_TAG);

        storage.clear_session().unwrap();
    }

    #[test]
    fn test_refresh_failures_within_window_increments() {
        let storage = SecureStorage::new().unwrap();
        storage.reset_refresh_failures();

        assert_eq!(storage.increment_refresh_failures(), 1);
        assert_eq!(storage.increment_refresh_failures(), 2);
        assert_eq!(storage.increment_refresh_failures(), 3);
        assert_eq!(storage.get_refresh_failures(), 3);

        storage.reset_refresh_failures();
        assert_eq!(storage.get_refresh_failures(), 0);
    }

    #[test]
    fn test_refresh_failures_time_bucket_resets_after_window() {
        let storage = SecureStorage::new().unwrap();
        storage.reset_refresh_failures();

        // Stamp a record more than 1 hour old; the next increment should
        // observe it as expired and reset the count back to 1.
        let stale = RefreshFailureRecord {
            count: 99,
            first_failure_at: Utc::now() - Duration::hours(2),
        };
        storage.write_refresh_record(&stale);

        // get_refresh_failures observes the stale record as 0
        assert_eq!(storage.get_refresh_failures(), 0);
        // ...and the next increment starts fresh.
        assert_eq!(storage.increment_refresh_failures(), 1);

        storage.reset_refresh_failures();
    }

    #[test]
    fn test_legacy_refresh_failures_txt_is_deleted() {
        let storage = SecureStorage::new().unwrap();
        storage.reset_refresh_failures();

        std::fs::write(storage.legacy_refresh_failures_path(), "42").unwrap();
        assert!(storage.legacy_refresh_failures_path().exists());

        // Touching the new path through any read/increment must purge the legacy file.
        let _ = storage.get_refresh_failures();
        assert!(!storage.legacy_refresh_failures_path().exists());

        storage.reset_refresh_failures();
    }
}
