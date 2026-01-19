//! Secure storage using Windows Credential Manager (DPAPI) via keyring crate

use super::types::{AuthError, AuthSession, OAuthPendingState};
use keyring::Entry;
use log::{debug, error, info, warn};
use std::path::PathBuf;

const SERVICE_NAME: &str = "SwiftTunnel";
const SESSION_KEY: &str = "auth_session";
const OAUTH_STATE_FILE: &str = "oauth_pending.json";

/// Secure storage for authentication credentials
pub struct SecureStorage {
    entry: Entry,
}

impl SecureStorage {
    /// Create a new SecureStorage instance
    pub fn new() -> Result<Self, AuthError> {
        info!("Creating SecureStorage with service={}, key={}", SERVICE_NAME, SESSION_KEY);
        let entry = Entry::new(SERVICE_NAME, SESSION_KEY)
            .map_err(|e| AuthError::StorageError(format!("Failed to create keyring entry: {}", e)))?;

        Ok(Self { entry })
    }

    /// Store the authentication session
    pub fn store_session(&self, session: &AuthSession) -> Result<(), AuthError> {
        let json = serde_json::to_string(session)
            .map_err(|e| AuthError::StorageError(format!("Failed to serialize session: {}", e)))?;

        info!("Storing session for user: {} (token length: {})", session.user.email, session.access_token.len());

        self.entry
            .set_password(&json)
            .map_err(|e| {
                error!("Failed to store session in Windows Credential Manager: {}", e);
                AuthError::StorageError(format!("Failed to store session: {}", e))
            })?;

        // Verify the session was stored correctly by reading it back
        match self.entry.get_password() {
            Ok(stored_json) => {
                if stored_json == json {
                    info!("Session stored and verified in Windows Credential Manager");
                } else {
                    warn!("Session stored but verification mismatch");
                }
            }
            Err(e) => {
                warn!("Session stored but verification read failed: {}", e);
            }
        }

        Ok(())
    }

    /// Load the authentication session
    pub fn load_session(&self) -> Result<Option<AuthSession>, AuthError> {
        info!("Attempting to load session from Windows Credential Manager...");

        match self.entry.get_password() {
            Ok(json) => {
                info!("Found stored credential, length: {} bytes", json.len());
                let session: AuthSession = serde_json::from_str(&json)
                    .map_err(|e| {
                        error!("Failed to deserialize session JSON: {}", e);
                        AuthError::StorageError(format!("Failed to deserialize session: {}", e))
                    })?;
                info!("Loaded auth session for user: {}, expires: {}", session.user.email, session.expires_at);
                Ok(Some(session))
            }
            Err(keyring::Error::NoEntry) => {
                info!("No auth session found in Windows Credential Manager (this is normal for first run)");
                Ok(None)
            }
            Err(e) => {
                error!("Failed to load session from Windows Credential Manager: {:?}", e);
                // Don't fail completely - return None to allow fresh login
                warn!("Returning None to allow fresh login despite error");
                Ok(None)
            }
        }
    }

    /// Clear the stored session (logout)
    pub fn clear_session(&self) -> Result<(), AuthError> {
        match self.entry.delete_credential() {
            Ok(_) => {
                info!("Cleared auth session from Keychain");
                Ok(())
            }
            Err(keyring::Error::NoEntry) => {
                debug!("No session to clear");
                Ok(())
            }
            Err(e) => {
                error!("Failed to clear session: {}", e);
                Err(AuthError::StorageError(format!("Failed to clear session: {}", e)))
            }
        }
    }

    /// Check if a session exists
    pub fn has_session(&self) -> bool {
        self.entry.get_password().is_ok()
    }

    /// Get the OAuth state file path
    fn oauth_state_path() -> Option<PathBuf> {
        dirs::data_local_dir().map(|d| d.join("SwiftTunnel").join(OAUTH_STATE_FILE))
    }

    /// Save OAuth pending state to disk (for deep link callback after app restart)
    pub fn save_oauth_state(&self, state: &OAuthPendingState) -> Result<(), AuthError> {
        let path = Self::oauth_state_path()
            .ok_or_else(|| AuthError::StorageError("Could not determine data directory".to_string()))?;

        // Ensure directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| AuthError::StorageError(format!("Failed to create directory: {}", e)))?;
        }

        let json = serde_json::to_string(state)
            .map_err(|e| AuthError::StorageError(format!("Failed to serialize OAuth state: {}", e)))?;

        std::fs::write(&path, json)
            .map_err(|e| AuthError::StorageError(format!("Failed to write OAuth state: {}", e)))?;

        info!("Saved OAuth pending state to: {}", path.display());
        Ok(())
    }

    /// Load OAuth pending state from disk
    pub fn load_oauth_state(&self) -> Result<Option<OAuthPendingState>, AuthError> {
        let path = match Self::oauth_state_path() {
            Some(p) => p,
            None => return Ok(None),
        };

        if !path.exists() {
            debug!("No OAuth pending state file found");
            return Ok(None);
        }

        let json = std::fs::read_to_string(&path)
            .map_err(|e| AuthError::StorageError(format!("Failed to read OAuth state: {}", e)))?;

        let state: OAuthPendingState = serde_json::from_str(&json)
            .map_err(|e| AuthError::StorageError(format!("Failed to deserialize OAuth state: {}", e)))?;

        info!("Loaded OAuth pending state from disk");
        Ok(Some(state))
    }

    /// Clear OAuth pending state from disk
    pub fn clear_oauth_state(&self) -> Result<(), AuthError> {
        let path = match Self::oauth_state_path() {
            Some(p) => p,
            None => return Ok(()),
        };

        if path.exists() {
            std::fs::remove_file(&path)
                .map_err(|e| AuthError::StorageError(format!("Failed to remove OAuth state: {}", e)))?;
            info!("Cleared OAuth pending state file");
        }

        Ok(())
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
    fn test_storage_roundtrip() {
        let storage = SecureStorage::new().unwrap();

        // Clean up any existing session
        let _ = storage.clear_session();

        // Create test session
        let session = AuthSession {
            access_token: "test_access".to_string(),
            refresh_token: "test_refresh".to_string(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
            user: super::super::types::UserInfo {
                id: "test_id".to_string(),
                email: "test@example.com".to_string(),
            },
        };

        // Store and load
        storage.store_session(&session).unwrap();
        let loaded = storage.load_session().unwrap();
        assert!(loaded.is_some());

        let loaded = loaded.unwrap();
        assert_eq!(loaded.access_token, session.access_token);
        assert_eq!(loaded.user.email, session.user.email);

        // Clean up
        storage.clear_session().unwrap();
        assert!(storage.load_session().unwrap().is_none());
    }
}
