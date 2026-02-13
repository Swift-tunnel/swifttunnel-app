//! Dual storage: File-based (primary, reliable) + Windows Credential Manager (secondary)
//!
//! This implementation uses BOTH file storage AND keyring to maximize reliability.
//! File storage is the primary method since it's more predictable across Windows versions.
//! Keyring (Windows Credential Manager) is used as an additional layer.

use super::types::{AuthError, AuthSession, OAuthPendingState};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use keyring::Entry;
use log::{debug, error, info, warn};
use std::path::PathBuf;

const SERVICE_NAME: &str = "SwiftTunnel";
const SESSION_KEY: &str = "auth_session";
const OAUTH_STATE_FILE: &str = "oauth_pending.json";
const AUTH_SESSION_FILE: &str = "auth_session.dat";
const REFRESH_FAILURES_FILE: &str = "refresh_failures.txt";

// Simple obfuscation key - not cryptographically secure but prevents casual reading
// In a real production app, you'd use proper encryption with DPAPI or similar
const OBFUSCATION_KEY: &[u8] = b"SwiftTunnel2024AuthStorage";

/// Secure storage for authentication credentials using dual storage strategy
pub struct SecureStorage {
    keyring_entry: Option<Entry>,
    data_dir: PathBuf,
}

impl SecureStorage {
    /// Create a new SecureStorage instance
    pub fn new() -> Result<Self, AuthError> {
        // Get data directory
        let data_dir = dirs::data_local_dir()
            .map(|d| d.join("SwiftTunnel"))
            .ok_or_else(|| {
                AuthError::StorageError("Could not determine data directory".to_string())
            })?;

        // Ensure directory exists
        std::fs::create_dir_all(&data_dir).map_err(|e| {
            AuthError::StorageError(format!("Failed to create data directory: {}", e))
        })?;

        info!("SecureStorage initialized:");
        info!("  Data directory: {}", data_dir.display());
        info!(
            "  Auth file: {}",
            data_dir.join(AUTH_SESSION_FILE).display()
        );

        // Try to create keyring entry, but don't fail if it doesn't work
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

    /// Simple XOR obfuscation (not secure, but prevents casual reading)
    fn obfuscate(data: &[u8]) -> Vec<u8> {
        data.iter()
            .enumerate()
            .map(|(i, &byte)| byte ^ OBFUSCATION_KEY[i % OBFUSCATION_KEY.len()])
            .collect()
    }

    /// Store session to file (primary storage)
    fn store_to_file(&self, session: &AuthSession) -> Result<(), AuthError> {
        let path = self.session_file_path();
        info!("Storing session to file: {}", path.display());

        let json = serde_json::to_string(session)
            .map_err(|e| AuthError::StorageError(format!("Failed to serialize session: {}", e)))?;

        // Obfuscate and base64 encode
        let obfuscated = Self::obfuscate(json.as_bytes());
        let encoded = BASE64.encode(&obfuscated);

        std::fs::write(&path, &encoded).map_err(|e| {
            error!("Failed to write session file: {}", e);
            AuthError::StorageError(format!("Failed to write session file: {}", e))
        })?;

        // Verify by reading back
        match std::fs::read_to_string(&path) {
            Ok(read_back) if read_back == encoded => {
                info!(
                    "Session stored and verified in file ({} bytes)",
                    encoded.len()
                );
            }
            Ok(_) => {
                warn!("Session stored but file verification mismatch");
            }
            Err(e) => {
                warn!("Session stored but file verification read failed: {}", e);
            }
        }

        Ok(())
    }

    /// Load session from file (primary storage)
    fn load_from_file(&self) -> Result<Option<AuthSession>, AuthError> {
        let path = self.session_file_path();
        info!("Attempting to load session from file: {}", path.display());

        if !path.exists() {
            info!("Session file does not exist (first run or logged out)");
            return Ok(None);
        }

        let encoded = match std::fs::read_to_string(&path) {
            Ok(data) => {
                info!("Read session file ({} bytes)", data.len());
                data
            }
            Err(e) => {
                error!("Failed to read session file: {}", e);
                return Ok(None);
            }
        };

        // Decode and de-obfuscate
        let obfuscated = match BASE64.decode(encoded.trim()) {
            Ok(data) => data,
            Err(e) => {
                error!("Failed to decode session file (base64): {}", e);
                // File might be corrupted, delete it
                let _ = std::fs::remove_file(&path);
                return Ok(None);
            }
        };

        let json_bytes = Self::obfuscate(&obfuscated);
        let json = match String::from_utf8(json_bytes) {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to decode session file (utf8): {}", e);
                let _ = std::fs::remove_file(&path);
                return Ok(None);
            }
        };

        match serde_json::from_str::<AuthSession>(&json) {
            Ok(session) => {
                info!("Loaded session from file for user: {}", session.user.email);
                Ok(Some(session))
            }
            Err(e) => {
                error!("Failed to deserialize session from file: {}", e);
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

    /// Store session to keyring (secondary storage)
    fn store_to_keyring(&self, session: &AuthSession) -> Result<(), AuthError> {
        let entry = match &self.keyring_entry {
            Some(e) => e,
            None => {
                debug!("Keyring not available, skipping keyring store");
                return Ok(());
            }
        };

        let json = serde_json::to_string(session)
            .map_err(|e| AuthError::StorageError(format!("Failed to serialize session: {}", e)))?;

        match entry.set_password(&json) {
            Ok(_) => {
                info!("Session also stored in Windows Credential Manager");
                Ok(())
            }
            Err(e) => {
                warn!(
                    "Failed to store in keyring (file storage still works): {}",
                    e
                );
                Ok(()) // Don't fail - file storage is primary
            }
        }
    }

    /// Load session from keyring (fallback)
    fn load_from_keyring(&self) -> Result<Option<AuthSession>, AuthError> {
        let entry = match &self.keyring_entry {
            Some(e) => e,
            None => return Ok(None),
        };

        match entry.get_password() {
            Ok(json) => {
                info!("Found session in keyring ({} bytes)", json.len());
                match serde_json::from_str(&json) {
                    Ok(session) => Ok(Some(session)),
                    Err(e) => {
                        warn!("Failed to deserialize keyring session: {}", e);
                        Ok(None)
                    }
                }
            }
            Err(keyring::Error::NoEntry) => {
                debug!("No session in keyring");
                Ok(None)
            }
            Err(e) => {
                warn!("Keyring read error: {:?}", e);
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
        info!("========================================");
        info!("STORING AUTH SESSION");
        info!("  User: {}", session.user.email);
        info!("  Token length: {} chars", session.access_token.len());
        info!("  Expires: {}", session.expires_at);
        info!("========================================");

        // Primary: File storage (most reliable)
        self.store_to_file(session)?;

        // Secondary: Keyring (bonus security, but not required)
        let _ = self.store_to_keyring(session);

        info!("Session storage complete");
        Ok(())
    }

    /// Load the authentication session (try file first, then keyring)
    pub fn load_session(&self) -> Result<Option<AuthSession>, AuthError> {
        info!("========================================");
        info!("LOADING AUTH SESSION");
        info!("========================================");

        // Primary: Try file storage first (most reliable)
        if let Some(session) = self.load_from_file()? {
            info!("✓ Session loaded from FILE storage");
            info!("  User: {}", session.user.email);
            info!("  Expires: {}", session.expires_at);
            info!("  Is expired: {}", session.is_expired());
            return Ok(Some(session));
        }

        // Fallback: Try keyring
        info!("File storage empty, trying keyring fallback...");
        if let Some(session) = self.load_from_keyring()? {
            info!("✓ Session loaded from KEYRING (migrating to file storage)");
            // Migrate to file storage for next time
            let _ = self.store_to_file(&session);
            return Ok(Some(session));
        }

        info!("✗ No stored session found (user needs to log in)");
        info!("========================================");
        Ok(None)
    }

    /// Clear the stored session (logout) - clears from BOTH storages
    pub fn clear_session(&self) -> Result<(), AuthError> {
        info!("Clearing auth session from all storage locations...");

        // Clear both
        let file_result = self.clear_from_file();
        let keyring_result = self.clear_from_keyring();

        // Report any errors but don't fail
        if let Err(e) = &file_result {
            error!("File clear error: {}", e);
        }
        if let Err(e) = &keyring_result {
            error!("Keyring clear error: {}", e);
        }

        info!("Auth session cleared");
        Ok(())
    }

    /// Check if a session exists (in either storage)
    pub fn has_session(&self) -> bool {
        self.session_file_path().exists()
            || self
                .keyring_entry
                .as_ref()
                .map(|e| e.get_password().is_ok())
                .unwrap_or(false)
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

    /// Get the refresh failures file path
    fn refresh_failures_path(&self) -> PathBuf {
        self.data_dir.join(REFRESH_FAILURES_FILE)
    }

    /// Increment the refresh failure counter and return the new count
    pub fn increment_refresh_failures(&self) -> u32 {
        let path = self.refresh_failures_path();
        let current = self.get_refresh_failures();
        let new_count = current + 1;

        if let Err(e) = std::fs::write(&path, new_count.to_string()) {
            warn!("Failed to write refresh failures count: {}", e);
        } else {
            debug!("Incremented refresh failures to {}", new_count);
        }

        new_count
    }

    /// Get the current refresh failure count
    pub fn get_refresh_failures(&self) -> u32 {
        let path = self.refresh_failures_path();

        if !path.exists() {
            return 0;
        }

        match std::fs::read_to_string(&path) {
            Ok(content) => content.trim().parse().unwrap_or(0),
            Err(_) => 0,
        }
    }

    /// Reset the refresh failure counter (called on successful refresh)
    pub fn reset_refresh_failures(&self) {
        let path = self.refresh_failures_path();

        if path.exists() {
            if let Err(e) = std::fs::remove_file(&path) {
                warn!("Failed to remove refresh failures file: {}", e);
            } else {
                debug!("Reset refresh failures counter");
            }
        }
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
    use chrono::Utc;

    #[test]
    fn test_obfuscation_roundtrip() {
        let original = b"Hello, World! This is a test.";
        let obfuscated = SecureStorage::obfuscate(original);
        let recovered = SecureStorage::obfuscate(&obfuscated);
        assert_eq!(original.as_slice(), recovered.as_slice());
    }

    #[test]
    fn test_storage_roundtrip() {
        let storage = SecureStorage::new().unwrap();

        // Clean up any existing session
        let _ = storage.clear_session();

        // Create test session
        let session = AuthSession {
            access_token: "test_access_token_12345".to_string(),
            refresh_token: "test_refresh_token_67890".to_string(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
            user: super::super::types::UserInfo {
                id: "test_user_id".to_string(),
                email: "test@example.com".to_string(),
                is_tester: false,
            },
        };

        // Store and load
        storage.store_session(&session).unwrap();
        let loaded = storage.load_session().unwrap();
        assert!(loaded.is_some());

        let loaded = loaded.unwrap();
        assert_eq!(loaded.access_token, session.access_token);
        assert_eq!(loaded.refresh_token, session.refresh_token);
        assert_eq!(loaded.user.email, session.user.email);
        assert_eq!(loaded.user.id, session.user.id);

        // Clean up
        storage.clear_session().unwrap();
        assert!(storage.load_session().unwrap().is_none());
    }
}
