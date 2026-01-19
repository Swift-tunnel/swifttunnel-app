//! Update downloader - downloads MSI with progress reporting

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

/// Clean up old update files
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

    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|e| format!("Error reading directory entry: {}", e))?
    {
        let path = entry.path();
        if path.extension().map(|e| e == "msi").unwrap_or(false) {
            info!("Cleaning up old update file: {}", path.display());
            let _ = tokio::fs::remove_file(&path).await;
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
