//! Checksum verifier - SHA256 verification of downloaded files

use log::{error, info};
use sha2::{Digest, Sha256};
use std::path::Path;
use tokio::fs::File;
use tokio::io::AsyncReadExt;

/// Verify SHA256 checksum of a file
/// Returns Ok(true) if checksum matches, Ok(false) if mismatch, Err on I/O error
pub async fn verify_checksum(file_path: &Path, expected_hex: &str) -> Result<bool, String> {
    info!("Verifying checksum of {}", file_path.display());

    let mut file = File::open(file_path)
        .await
        .map_err(|e| format!("Failed to open file for verification: {}", e))?;

    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024]; // 64KB buffer

    loop {
        let bytes_read = file
            .read(&mut buffer)
            .await
            .map_err(|e| format!("Error reading file: {}", e))?;

        if bytes_read == 0 {
            break;
        }

        hasher.update(&buffer[..bytes_read]);
    }

    let result = hasher.finalize();
    let computed_hex = hex::encode(result);

    let expected_lower = expected_hex.to_lowercase();
    let matches = computed_hex == expected_lower;

    if matches {
        info!("Checksum verified: {}", computed_hex);
    } else {
        error!(
            "Checksum mismatch! Expected: {}, Got: {}",
            expected_lower, computed_hex
        );
    }

    Ok(matches)
}

/// Compute SHA256 hash of a file (for debugging/logging)
pub async fn compute_checksum(file_path: &Path) -> Result<String, String> {
    let mut file = File::open(file_path)
        .await
        .map_err(|e| format!("Failed to open file: {}", e))?;

    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024];

    loop {
        let bytes_read = file
            .read(&mut buffer)
            .await
            .map_err(|e| format!("Error reading file: {}", e))?;

        if bytes_read == 0 {
            break;
        }

        hasher.update(&buffer[..bytes_read]);
    }

    let result = hasher.finalize();
    Ok(hex::encode(result))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_checksum_computation() {
        // Create a temp file with known content
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("swifttunnel_checksum_test.txt");

        // Write known content
        tokio::fs::write(&test_file, b"Hello, World!")
            .await
            .unwrap();

        // SHA256("Hello, World!") = dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f
        let expected = "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f";

        let computed = compute_checksum(&test_file).await.unwrap();
        assert_eq!(computed, expected);

        // Verify checksum
        let verified = verify_checksum(&test_file, expected).await.unwrap();
        assert!(verified);

        // Test mismatch
        let mismatched = verify_checksum(&test_file, "0000000000000000000000000000000000000000000000000000000000000000")
            .await
            .unwrap();
        assert!(!mismatched);

        // Cleanup
        let _ = tokio::fs::remove_file(&test_file).await;
    }
}
