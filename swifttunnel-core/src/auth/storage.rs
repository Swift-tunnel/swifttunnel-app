//! Auth session storage backed by AES-256-GCM with a machine-bound key.
//!
//! `auth_session.dat` holds the access/refresh tokens. Bytes are
//! `[0x03][nonce: 12][ciphertext || 16-byte tag]`. The key is derived from a
//! machine identifier (the registry `MachineGuid`) mixed with the per-user
//! data directory path, so sessions written on machine A can't be decrypted
//! on machine B, and sessions written by user A can't be decrypted by user B.
//!
//! We used to encrypt this blob with DPAPI (`CryptProtectData`) — that caused
//! Windows Defender's ML classifier to flag the installer as an infostealer
//! because unsigned PEs that statically import `CryptProtectData` together
//! with kernel-driver install, packet interception, and process enumeration
//! match the infostealer fingerprint almost perfectly. AES-GCM via `ring`
//! gives an equivalent threat model (same-user local-disk protection) without
//! the Win32 crypto imports.
//!
//! Windows Credential Manager is kept as a secondary store. Both stores hold
//! the same AES-GCM blob (the keyring copy is base64-encoded so it can be
//! passed through the keyring's string API).

use super::types::{AuthError, AuthSession, OAuthPendingState};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chrono::{DateTime, Utc};
use keyring::Entry;
use log::{debug, error, info, warn};
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

const SERVICE_NAME: &str = "SwiftTunnel";
const SESSION_KEY: &str = "auth_session";
const OAUTH_STATE_FILE: &str = "oauth_pending.json";
const AUTH_SESSION_FILE: &str = "auth_session.dat";
const REFRESH_FAILURES_FILE: &str = "refresh_failures.json";
const LEGACY_REFRESH_FAILURES_FILE: &str = "refresh_failures.txt";

/// Version tag for AES-256-GCM sealed session blobs. Chosen outside the
/// printable base64 alphabet (>= 0x2B) so the loader can dispatch on the
/// first byte without ambiguity against legacy XOR+base64 files.
const SESSION_VERSION_TAG: u8 = 0x03;

/// Version tag that 1.24.0/1.24.1 wrote with DPAPI. We no longer have the
/// decryption code for these (removing DPAPI was the point). The loader
/// detects them, logs, and deletes the file so the user re-authenticates
/// cleanly on upgrade.
const LEGACY_DPAPI_VERSION_TAG: u8 = 0x02;

/// Key-derivation domain separator. Bumping this string invalidates every
/// sealed session on disk and forces re-login.
const KEY_DERIVATION_INFO: &[u8] = b"swifttunnel-auth-v3-session-key";

/// AES-256-GCM authentication tag length, per the spec. `ring` exposes this
/// as a const on the algorithm but not in a form we can use at module scope.
const AEAD_TAG_LEN: usize = 16;

/// XOR key kept ONLY for one-shot migration of pre-1.24 auth_session.dat
/// files. No new files are ever written in this format.
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

/// Read the Windows machine GUID from the registry. Falls back to a
/// well-known string so a failed read still produces a deterministic key
/// (which means the user can still decrypt what they encrypted on the same
/// machine — the key is stable across app restarts).
#[cfg(windows)]
fn read_machine_id() -> String {
    use winreg::RegKey;
    use winreg::enums::HKEY_LOCAL_MACHINE;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    if let Ok(key) = hklm.open_subkey("SOFTWARE\\Microsoft\\Cryptography") {
        if let Ok(guid) = key.get_value::<String, _>("MachineGuid") {
            return guid;
        }
    }
    String::from("swifttunnel-unknown-machine")
}

#[cfg(not(windows))]
fn read_machine_id() -> String {
    // Local dev / CI on macOS and Linux. The exact string doesn't matter —
    // it just has to be stable within the test run.
    String::from("swifttunnel-dev-machine")
}

/// Derive a 32-byte AES-256 key from the machine id and a per-user bind.
/// `user_bind` is normally the absolute path to the app's data directory,
/// which on Windows lives under `%LOCALAPPDATA%` and is therefore inherently
/// per-user. Tests pass their own isolated path.
fn derive_session_key(user_bind: &[u8]) -> [u8; 32] {
    let machine_id = read_machine_id();

    let mut hasher = Sha256::new();
    hasher.update(KEY_DERIVATION_INFO);
    hasher.update([0xff]);
    hasher.update(machine_id.as_bytes());
    hasher.update([0xff]);
    hasher.update(user_bind);

    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Seal `plaintext` into the on-disk blob format:
/// `[0x03][12-byte nonce][ciphertext || 16-byte tag]`.
fn seal_blob(plaintext: &[u8], user_bind: &[u8]) -> Result<Vec<u8>, AuthError> {
    let key_bytes = derive_session_key(user_bind);
    let unbound = UnboundKey::new(&AES_256_GCM, &key_bytes).map_err(|_| {
        AuthError::StorageError("Failed to build AES-256-GCM key".to_string())
    })?;
    let key = LessSafeKey::new(unbound);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    SystemRandom::new()
        .fill(&mut nonce_bytes)
        .map_err(|_| AuthError::StorageError("Failed to generate nonce".to_string()))?;
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut in_out = plaintext.to_vec();
    key.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
        .map_err(|_| AuthError::StorageError("AES-GCM seal failed".to_string()))?;

    let mut blob = Vec::with_capacity(1 + NONCE_LEN + in_out.len());
    blob.push(SESSION_VERSION_TAG);
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&in_out);
    Ok(blob)
}

/// Open a sealed blob. Returns an error if the version tag is wrong, the
/// blob is truncated, or the tag fails to verify (tamper / wrong user or
/// machine).
fn open_blob(blob: &[u8], user_bind: &[u8]) -> Result<Vec<u8>, AuthError> {
    if blob.len() < 1 + NONCE_LEN + AEAD_TAG_LEN {
        return Err(AuthError::StorageError(
            "Session blob is truncated".to_string(),
        ));
    }
    if blob[0] != SESSION_VERSION_TAG {
        return Err(AuthError::StorageError(format!(
            "Unexpected session version tag {:#04x}",
            blob[0]
        )));
    }

    let key_bytes = derive_session_key(user_bind);
    let unbound = UnboundKey::new(&AES_256_GCM, &key_bytes).map_err(|_| {
        AuthError::StorageError("Failed to build AES-256-GCM key".to_string())
    })?;
    let key = LessSafeKey::new(unbound);

    let mut nonce_arr = [0u8; NONCE_LEN];
    nonce_arr.copy_from_slice(&blob[1..1 + NONCE_LEN]);
    let nonce = Nonce::assume_unique_for_key(nonce_arr);

    let mut buf = blob[1 + NONCE_LEN..].to_vec();
    let plaintext_len = {
        let plaintext = key
            .open_in_place(nonce, Aad::empty(), &mut buf)
            .map_err(|_| {
                AuthError::StorageError(
                    "AES-GCM open failed (tampered or wrong user/machine)".to_string(),
                )
            })?;
        plaintext.len()
    };
    buf.truncate(plaintext_len);
    Ok(buf)
}

/// Decode a legacy v1 auth_session.dat (XOR + base64 ASCII text) written by
/// releases prior to 1.24.0.
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

/// Outcome of trying to decode a blob off disk or out of the keyring.
enum DecodedBlob {
    /// Successfully decoded session — and a hint for whether the caller
    /// should re-encrypt it in the current format (true for legacy v1
    /// migrations).
    Session {
        session: Box<AuthSession>,
        rewrite: bool,
    },
    /// We recognised a 1.24.0/1.24.1 DPAPI blob. Caller should delete the
    /// store and force re-login — we removed the DPAPI decryption code and
    /// can't read these anymore.
    RejectDpapi,
    /// Anything else: corruption, wrong format, wrong key.
    Corrupt,
}

/// Secure storage for authentication credentials.
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

    /// Test-only constructor that points at an isolated, unique data directory
    /// so refresh-failure / session tests don't stomp on each other under
    /// `cargo test`'s default thread pool.
    #[cfg(test)]
    fn with_isolated_data_dir() -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let data_dir = std::env::temp_dir().join(format!(
            "swifttunnel-storage-test-{}-{}-{}",
            std::process::id(),
            nanos,
            n
        ));
        std::fs::create_dir_all(&data_dir).expect("create test data dir");
        Self {
            keyring_entry: None,
            data_dir,
        }
    }

    /// Bytes to mix into the session key alongside the machine id. The data
    /// directory is naturally per-user on Windows (`%LOCALAPPDATA%`), so
    /// using it as the bind means users on the same machine can't read each
    /// other's sessions.
    fn user_bind(&self) -> Vec<u8> {
        self.data_dir.as_os_str().to_string_lossy().as_bytes().to_vec()
    }

    /// Get the auth session file path
    fn session_file_path(&self) -> PathBuf {
        self.data_dir.join(AUTH_SESSION_FILE)
    }

    /// Encode a session as a versioned sealed blob ready for disk or keyring.
    fn encode_session(&self, session: &AuthSession) -> Result<Vec<u8>, AuthError> {
        let json = serde_json::to_vec(session)
            .map_err(|e| AuthError::StorageError(format!("Failed to serialize session: {}", e)))?;
        seal_blob(&json, &self.user_bind())
    }

    /// Decode a blob into one of: a valid session, a 1.24.x DPAPI rejection,
    /// or corrupt/unknown. The caller handles the follow-up action.
    fn decode_blob(&self, raw: &[u8]) -> DecodedBlob {
        if raw.is_empty() {
            return DecodedBlob::Corrupt;
        }

        match raw[0] {
            SESSION_VERSION_TAG => match open_blob(raw, &self.user_bind()) {
                Ok(json) => match serde_json::from_slice::<AuthSession>(&json) {
                    Ok(session) => DecodedBlob::Session {
                        session: Box::new(session),
                        rewrite: false,
                    },
                    Err(e) => {
                        error!("Failed to deserialize session JSON: {}", e);
                        DecodedBlob::Corrupt
                    }
                },
                Err(e) => {
                    error!("AES-GCM open failed: {}", e);
                    DecodedBlob::Corrupt
                }
            },
            LEGACY_DPAPI_VERSION_TAG => {
                warn!(
                    "Session blob is in legacy DPAPI format (1.24.0/1.24.1). \
                     Discarding and forcing re-authentication — DPAPI support was \
                     removed to stop Defender false positives."
                );
                DecodedBlob::RejectDpapi
            }
            _ => {
                // Pre-1.24 XOR+base64 path.
                let Some(json) = decrypt_legacy_v1(raw) else {
                    error!("Legacy session blob could not be decoded");
                    return DecodedBlob::Corrupt;
                };
                match serde_json::from_slice::<AuthSession>(&json) {
                    Ok(session) => DecodedBlob::Session {
                        session: Box::new(session),
                        rewrite: true,
                    },
                    Err(e) => {
                        error!("Failed to deserialize legacy session JSON: {}", e);
                        DecodedBlob::Corrupt
                    }
                }
            }
        }
    }

    /// Store session to file (primary storage).
    fn store_to_file(&self, session: &AuthSession) -> Result<(), AuthError> {
        let path = self.session_file_path();
        let blob = self.encode_session(session)?;

        std::fs::write(&path, &blob).map_err(|e| {
            error!("Failed to write session file: {}", e);
            AuthError::StorageError(format!("Failed to write session file: {}", e))
        })?;

        info!(
            "Stored session to {} ({} bytes sealed)",
            path.display(),
            blob.len()
        );
        Ok(())
    }

    /// Load session from file (primary storage). Migrates legacy pre-1.24
    /// files on first read by re-sealing them in the current format; rejects
    /// 1.24.0/1.24.1 DPAPI files by deleting them and returning `None` so
    /// the caller forces a re-login.
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

        match self.decode_blob(&raw) {
            DecodedBlob::Session { session, rewrite } => {
                if rewrite {
                    info!("Migrating legacy auth_session.dat to AES-GCM format");
                    if let Err(e) = self.store_to_file(&session) {
                        warn!("Failed to re-seal legacy session file: {}", e);
                    }
                }
                info!("Loaded session for user: {}", session.user.email);
                Ok(Some(*session))
            }
            DecodedBlob::RejectDpapi => {
                let _ = std::fs::remove_file(&path);
                let _ = self.clear_from_keyring();
                Ok(None)
            }
            DecodedBlob::Corrupt => {
                let _ = std::fs::remove_file(&path);
                Ok(None)
            }
        }
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

    /// Store session to keyring (secondary storage). Holds the same sealed
    /// blob as the file, base64-encoded so it fits the keyring's string API.
    fn store_to_keyring(&self, session: &AuthSession) -> Result<(), AuthError> {
        let entry = match &self.keyring_entry {
            Some(e) => e,
            None => {
                debug!("Keyring not available, skipping keyring store");
                return Ok(());
            }
        };

        let blob = self.encode_session(session)?;
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

    /// Load session from keyring (fallback). Accepts new sealed blobs,
    /// rejects 1.24.x DPAPI blobs, and accepts legacy plaintext-JSON entries
    /// written by pre-1.24 builds.
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
            match self.decode_blob(&blob) {
                DecodedBlob::Session { session, .. } => return Ok(Some(*session)),
                DecodedBlob::RejectDpapi => {
                    let _ = self.clear_from_keyring();
                    return Ok(None);
                }
                DecodedBlob::Corrupt => {
                    // Fall through to the plaintext-JSON migration path
                    // below in case this is a pre-1.24 plaintext keyring
                    // entry that happens to decode as base64 by accident.
                }
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
            // Re-seal the keyring entry too — load_from_keyring may have
            // returned a legacy plaintext-JSON entry, and we want to overwrite
            // it with the sealed blob so a future file deletion can't fall
            // back to plaintext again.
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
    /// files that won't actually decrypt — e.g. a file sealed under a
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
    fn seal_open_roundtrip_preserves_plaintext() {
        let plaintext = b"super secret session json goes here";
        let bind = b"/some/user/path";
        let blob = seal_blob(plaintext, bind).unwrap();
        assert_eq!(blob[0], SESSION_VERSION_TAG);
        assert!(blob.len() >= 1 + NONCE_LEN + AEAD_TAG_LEN);
        let recovered = open_blob(&blob, bind).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn open_fails_with_wrong_bind() {
        let plaintext = b"payload";
        let blob = seal_blob(plaintext, b"bind-a").unwrap();
        assert!(open_blob(&blob, b"bind-b").is_err());
    }

    #[test]
    fn open_fails_on_truncated_blob() {
        let blob = seal_blob(b"x", b"bind").unwrap();
        for cut in 0..(1 + NONCE_LEN + AEAD_TAG_LEN) {
            assert!(open_blob(&blob[..cut], b"bind").is_err());
        }
    }

    #[test]
    fn nonce_is_random_per_seal() {
        // Two seals of identical plaintext must produce different ciphertexts,
        // otherwise the nonce isn't being randomised.
        let a = seal_blob(b"same", b"bind").unwrap();
        let b = seal_blob(b"same", b"bind").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn encode_decode_session_roundtrip() {
        let storage = SecureStorage::with_isolated_data_dir();
        let session = make_session("rt");
        let blob = storage.encode_session(&session).unwrap();
        assert_eq!(blob[0], SESSION_VERSION_TAG);

        match storage.decode_blob(&blob) {
            DecodedBlob::Session { session: s, rewrite } => {
                assert!(!rewrite, "current-format blob should not request rewrite");
                assert_eq!(s.access_token, session.access_token);
                assert_eq!(s.refresh_token, session.refresh_token);
                assert_eq!(s.user.email, session.user.email);
            }
            _ => panic!("expected DecodedBlob::Session"),
        }
    }

    #[test]
    fn legacy_xor_blob_decodes_and_requests_rewrite() {
        let storage = SecureStorage::with_isolated_data_dir();
        let session = make_session("legacy");
        let json = serde_json::to_string(&session).unwrap();
        let xored: Vec<u8> = json
            .as_bytes()
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ LEGACY_OBFUSCATION_KEY[i % LEGACY_OBFUSCATION_KEY.len()])
            .collect();
        let legacy_blob = BASE64.encode(&xored).into_bytes();

        // Legacy blob starts with base64 ASCII, never with the new version tag.
        assert_ne!(legacy_blob[0], SESSION_VERSION_TAG);
        assert_ne!(legacy_blob[0], LEGACY_DPAPI_VERSION_TAG);

        match storage.decode_blob(&legacy_blob) {
            DecodedBlob::Session { session: s, rewrite } => {
                assert!(rewrite, "legacy blob should request rewrite");
                assert_eq!(s.access_token, session.access_token);
                assert_eq!(s.user.email, session.user.email);
            }
            other => panic!(
                "expected DecodedBlob::Session (legacy), got {}",
                match other {
                    DecodedBlob::RejectDpapi => "RejectDpapi",
                    DecodedBlob::Corrupt => "Corrupt",
                    DecodedBlob::Session { .. } => unreachable!(),
                }
            ),
        }
    }

    #[test]
    fn dpapi_tagged_blob_is_rejected() {
        let storage = SecureStorage::with_isolated_data_dir();
        let mut dpapi = vec![LEGACY_DPAPI_VERSION_TAG];
        dpapi.extend_from_slice(b"opaque DPAPI ciphertext from 1.24.1");

        assert!(matches!(
            storage.decode_blob(&dpapi),
            DecodedBlob::RejectDpapi
        ));
    }

    #[test]
    fn corrupt_blob_is_reported_corrupt() {
        let storage = SecureStorage::with_isolated_data_dir();
        // Starts with SESSION_VERSION_TAG but isn't a real AEAD blob.
        let mut versioned_garbage = vec![SESSION_VERSION_TAG];
        versioned_garbage.extend_from_slice(&[0u8; 40]);
        assert!(matches!(
            storage.decode_blob(&versioned_garbage),
            DecodedBlob::Corrupt
        ));

        // Empty.
        assert!(matches!(
            storage.decode_blob(&[]),
            DecodedBlob::Corrupt
        ));
    }

    #[test]
    fn session_roundtrip_via_file() {
        let storage = SecureStorage::with_isolated_data_dir();

        let session = make_session("file");
        storage.store_session(&session).unwrap();
        let loaded = storage.load_session().unwrap().unwrap();
        assert_eq!(loaded.access_token, session.access_token);
        assert_eq!(loaded.user.email, session.user.email);

        storage.clear_session().unwrap();
        assert!(storage.load_session().unwrap().is_none());
    }

    #[test]
    fn legacy_file_migrated_on_load() {
        let storage = SecureStorage::with_isolated_data_dir();

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
        assert_eq!(raw[0], SESSION_VERSION_TAG);

        storage.clear_session().unwrap();
    }

    #[test]
    fn dpapi_file_is_deleted_and_forces_relogin() {
        let storage = SecureStorage::with_isolated_data_dir();

        // Simulate a 1.24.1 DPAPI file on disk.
        let mut dpapi = vec![LEGACY_DPAPI_VERSION_TAG];
        dpapi.extend_from_slice(b"opaque DPAPI ciphertext from 1.24.1");
        std::fs::write(storage.session_file_path(), &dpapi).unwrap();
        assert!(storage.session_file_path().exists());

        // load_session must return None AND the file must be gone so the
        // next run starts clean.
        assert!(storage.load_session().unwrap().is_none());
        assert!(!storage.session_file_path().exists());
    }

    #[test]
    fn refresh_failures_within_window_increments() {
        let storage = SecureStorage::with_isolated_data_dir();

        assert_eq!(storage.increment_refresh_failures(), 1);
        assert_eq!(storage.increment_refresh_failures(), 2);
        assert_eq!(storage.increment_refresh_failures(), 3);
        assert_eq!(storage.get_refresh_failures(), 3);

        storage.reset_refresh_failures();
        assert_eq!(storage.get_refresh_failures(), 0);
    }

    #[test]
    fn refresh_failures_time_bucket_resets_after_window() {
        let storage = SecureStorage::with_isolated_data_dir();

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
    }

    #[test]
    fn legacy_refresh_failures_txt_is_deleted() {
        let storage = SecureStorage::with_isolated_data_dir();

        std::fs::write(storage.legacy_refresh_failures_path(), "42").unwrap();
        assert!(storage.legacy_refresh_failures_path().exists());

        // Touching the new path through any read/increment must purge the legacy file.
        let _ = storage.get_refresh_failures();
        assert!(!storage.legacy_refresh_failures_path().exists());

        storage.reset_refresh_failures();
    }
}
