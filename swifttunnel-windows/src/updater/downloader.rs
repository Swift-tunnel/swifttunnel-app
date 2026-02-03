//! Update downloader - downloads installer with progress reporting

use futures_util::StreamExt;
use log::{debug, error, info};
use std::path::PathBuf;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;

/// Download progress callback type
pub type ProgressCallback = Box<dyn Fn(u64, u64) + Send + Sync>;

/// Download an update to the updates directory
/// Returns the path to the downloaded file
pub async fn download_update(
    url: &str,
    filename: &str,
    on_progress: Option<ProgressCallback>,
) -> Result<PathBuf, String> {
    // Create updates directory in %LOCALAPPDATA%\SwiftTunnel\updates
    let updates_dir = dirs::data_local_dir()
        .ok_or("Could not find local data directory")?
        .join("SwiftTunnel")
        .join("updates");

    tokio::fs::create_dir_all(&updates_dir)
        .await
        .map_err(|e| format!("Failed to create updates directory: {}", e))?;

    let dest_path = updates_dir.join(filename);

    info!("Downloading update to: {}", dest_path.display());

    // Create HTTP client
    let client = reqwest::Client::builder()
        .user_agent("SwiftTunnel-Updater")
        .timeout(std::time::Duration::from_secs(600)) // 10 minute timeout for large files
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

    // Start download
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("Download request failed: {}", e))?;

    if !response.status().is_success() {
        return Err(format!("Download failed with status: {}", response.status()));
    }

    let total_size = response.content_length().unwrap_or(0);
    info!("Download size: {} bytes", total_size);

    // Create destination file
    let mut file = File::create(&dest_path)
        .await
        .map_err(|e| format!("Failed to create file: {}", e))?;

    // Stream the download with progress
    let mut stream = response.bytes_stream();
    let mut downloaded: u64 = 0;

    while let Some(chunk_result) = stream.next().await {
        let chunk = chunk_result.map_err(|e| format!("Error reading chunk: {}", e))?;

        file.write_all(&chunk)
            .await
            .map_err(|e| format!("Error writing to file: {}", e))?;

        downloaded += chunk.len() as u64;

        // Report progress
        if let Some(ref callback) = on_progress {
            callback(downloaded, total_size);
        }

        debug!("Downloaded {}/{} bytes", downloaded, total_size);
    }

    file.flush()
        .await
        .map_err(|e| format!("Error flushing file: {}", e))?;

    info!("Download complete: {} bytes", downloaded);

    // Verify file size if we know the expected size
    if total_size > 0 && downloaded != total_size {
        error!(
            "Downloaded size mismatch: expected {}, got {}",
            total_size, downloaded
        );
        // Clean up partial file
        let _ = tokio::fs::remove_file(&dest_path).await;
        return Err(format!(
            "Download incomplete: expected {} bytes, got {}",
            total_size, downloaded
        ));
    }

    Ok(dest_path)
}

/// Download checksum file and return its contents
pub async fn download_checksum(url: &str) -> Result<String, String> {
    let client = reqwest::Client::builder()
        .user_agent("SwiftTunnel-Updater")
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("Checksum download failed: {}", e))?;

    if !response.status().is_success() {
        return Err(format!(
            "Checksum download failed with status: {}",
            response.status()
        ));
    }

    let text = response
        .text()
        .await
        .map_err(|e| format!("Failed to read checksum: {}", e))?;

    // Checksum file format is typically: "<sha256_hex>  <filename>" or just "<sha256_hex>"
    let checksum = text
        .split_whitespace()
        .next()
        .ok_or("Empty checksum file")?
        .to_lowercase();

    // Validate it looks like a SHA256 hash (64 hex characters)
    if checksum.len() != 64 || !checksum.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("Invalid checksum format: {}", checksum));
    }

    Ok(checksum)
}

/// Maximum age for update files before cleanup (24 hours)
const MAX_UPDATE_FILE_AGE_SECS: u64 = 24 * 60 * 60;

/// Maximum number of installer files to keep
const MAX_INSTALLER_FILES: usize = 2;

/// Clean up old update files
///
/// Removes installer files (EXE and MSI) that are:
/// 1. Older than 24 hours
/// 2. Beyond the 2 most recent files
pub async fn cleanup_updates() -> Result<(), String> {
    let updates_dir = dirs::data_local_dir()
        .ok_or("Could not find local data directory")?
        .join("SwiftTunnel")
        .join("updates");

    if !updates_dir.exists() {
        return Ok(());
    }

    let mut entries = tokio::fs::read_dir(&updates_dir)
        .await
        .map_err(|e| format!("Failed to read updates directory: {}", e))?;

    // Collect all installer files (EXE and MSI) with their metadata
    let mut installer_files: Vec<(std::path::PathBuf, std::time::SystemTime)> = Vec::new();

    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|e| format!("Error reading directory entry: {}", e))?
    {
        let path = entry.path();
        let is_installer = path
            .extension()
            .map(|e| e == "exe" || e == "msi")
            .unwrap_or(false);

        if is_installer {
            if let Ok(metadata) = entry.metadata().await {
                if let Ok(modified) = metadata.modified() {
                    installer_files.push((path, modified));
                }
            }
        }
    }

    // Sort by modification time (newest first)
    installer_files.sort_by(|a, b| b.1.cmp(&a.1));

    let now = std::time::SystemTime::now();

    for (i, (path, modified)) in installer_files.iter().enumerate() {
        let should_delete = if i >= MAX_INSTALLER_FILES {
            // Delete files beyond the limit
            true
        } else if let Ok(age) = now.duration_since(*modified) {
            // Delete files older than 24 hours
            age.as_secs() > MAX_UPDATE_FILE_AGE_SECS
        } else {
            false
        };

        if should_delete {
            info!("Cleaning up old update file: {}", path.display());
            if let Err(e) = tokio::fs::remove_file(&path).await {
                debug!("Failed to delete {}: {}", path.display(), e);
            }

            // Also delete associated checksum file
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            let checksum_path = path.with_extension(format!("{}.sha256", ext));
            if checksum_path.exists() {
                let _ = tokio::fs::remove_file(&checksum_path).await;
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_updates_dir_path() {
        let dir = dirs::data_local_dir()
            .map(|d| d.join("SwiftTunnel").join("updates"));
        assert!(dir.is_some());
    }
}
