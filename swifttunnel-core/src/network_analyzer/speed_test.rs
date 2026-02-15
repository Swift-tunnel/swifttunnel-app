//! Speed Test using Cloudflare
//!
//! Uses Cloudflare's speed test endpoints for download/upload measurement.
//! These are publicly available and don't require licensing like Ookla's Speedtest.

use super::types::{SpeedTestProgress, SpeedTestResults};
use log::{debug, error, info};
use reqwest::Client;
use std::sync::mpsc::Sender;
use std::time::{Duration, Instant};

/// Cloudflare speed test download endpoint
/// __down?bytes=N returns N random bytes
const DOWNLOAD_URL: &str = "https://speed.cloudflare.com/__down";

/// Cloudflare speed test upload endpoint
const UPLOAD_URL: &str = "https://speed.cloudflare.com/__up";

/// Download test size in bytes (10 MB for accurate measurement)
const DOWNLOAD_SIZE: u64 = 10_000_000;

/// Upload test size in bytes (5 MB - upload is typically slower)
const UPLOAD_SIZE: usize = 5_000_000;

/// HTTP client timeout
const REQUEST_TIMEOUT_SECS: u64 = 60;

/// Chunk size for streaming (64 KB)
const CHUNK_SIZE: usize = 65536;

/// Run a complete speed test (download + upload)
///
/// # Arguments
/// * `progress_tx` - Channel to send progress updates
///
/// # Returns
/// Result with SpeedTestResults on success
pub async fn run_speed_test(
    progress_tx: Sender<SpeedTestProgress>,
) -> Result<SpeedTestResults, String> {
    info!("Starting speed test");

    let client = Client::builder()
        .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

    // === DOWNLOAD TEST ===
    let _ = progress_tx.send(SpeedTestProgress::DownloadStarted);
    let download_mbps = match run_download_test(&client, &progress_tx).await {
        Ok(speed) => {
            info!("Download test complete: {:.2} Mbps", speed);
            let _ = progress_tx.send(SpeedTestProgress::DownloadComplete(speed));
            speed
        }
        Err(e) => {
            error!("Download test failed: {}", e);
            let _ = progress_tx.send(SpeedTestProgress::Error(format!("Download failed: {}", e)));
            return Err(e);
        }
    };

    // Brief pause between tests
    tokio::time::sleep(Duration::from_millis(500)).await;

    // === UPLOAD TEST ===
    let _ = progress_tx.send(SpeedTestProgress::UploadStarted);
    let upload_mbps = match run_upload_test(&client, &progress_tx).await {
        Ok(speed) => {
            info!("Upload test complete: {:.2} Mbps", speed);
            let _ = progress_tx.send(SpeedTestProgress::UploadComplete(speed));
            speed
        }
        Err(e) => {
            error!("Upload test failed: {}", e);
            let _ = progress_tx.send(SpeedTestProgress::Error(format!("Upload failed: {}", e)));
            return Err(e);
        }
    };

    // Build results
    let results = SpeedTestResults {
        download_mbps,
        upload_mbps,
        server: "Cloudflare".to_string(),
        timestamp: chrono::Utc::now(),
    };

    let _ = progress_tx.send(SpeedTestProgress::Completed(results.clone()));

    info!(
        "Speed test complete: Download={:.2} Mbps, Upload={:.2} Mbps",
        download_mbps, upload_mbps
    );

    Ok(results)
}

/// Run download speed test
async fn run_download_test(
    client: &Client,
    progress_tx: &Sender<SpeedTestProgress>,
) -> Result<f32, String> {
    let url = format!("{}?bytes={}", DOWNLOAD_URL, DOWNLOAD_SIZE);
    debug!("Starting download from: {}", url);

    let start = Instant::now();
    let mut bytes_received: u64 = 0;
    let mut last_progress_update = Instant::now();

    // Stream the download to track progress
    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("Download request failed: {}", e))?;

    if !response.status().is_success() {
        return Err(format!(
            "Download failed with status: {}",
            response.status()
        ));
    }

    let mut stream = response.bytes_stream();
    use futures_util::StreamExt;

    while let Some(chunk_result) = stream.next().await {
        let chunk = chunk_result.map_err(|e| format!("Download stream error: {}", e))?;
        bytes_received += chunk.len() as u64;

        // Send progress updates at most every 100ms
        if last_progress_update.elapsed() >= Duration::from_millis(100) {
            let progress = bytes_received as f32 / DOWNLOAD_SIZE as f32;
            let elapsed = start.elapsed().as_secs_f32();
            let current_speed = if elapsed > 0.0 {
                (bytes_received as f32 * 8.0) / (elapsed * 1_000_000.0) // Mbps
            } else {
                0.0
            };
            let _ = progress_tx.send(SpeedTestProgress::DownloadProgress(current_speed, progress));
            last_progress_update = Instant::now();
        }
    }

    let elapsed = start.elapsed().as_secs_f32();
    if elapsed == 0.0 {
        return Err("Download completed too fast to measure".to_string());
    }

    // Calculate speed in Mbps (megabits per second)
    let bits_downloaded = bytes_received as f32 * 8.0;
    let mbps = bits_downloaded / (elapsed * 1_000_000.0);

    Ok(mbps)
}

/// Run upload speed test
async fn run_upload_test(
    client: &Client,
    progress_tx: &Sender<SpeedTestProgress>,
) -> Result<f32, String> {
    debug!("Starting upload to: {}", UPLOAD_URL);

    // Generate random data to upload
    let upload_data: Vec<u8> = (0..UPLOAD_SIZE).map(|i| (i % 256) as u8).collect();

    let start = Instant::now();

    // For upload, we send the data in chunks and track progress
    // Cloudflare's __up endpoint accepts POST with body
    let response = client
        .post(UPLOAD_URL)
        .header("Content-Type", "application/octet-stream")
        .header("Content-Length", UPLOAD_SIZE.to_string())
        .body(upload_data)
        .send()
        .await
        .map_err(|e| format!("Upload request failed: {}", e))?;

    let elapsed = start.elapsed().as_secs_f32();

    if !response.status().is_success() {
        return Err(format!("Upload failed with status: {}", response.status()));
    }

    if elapsed == 0.0 {
        return Err("Upload completed too fast to measure".to_string());
    }

    // Send final progress
    let _ = progress_tx.send(SpeedTestProgress::UploadProgress(0.0, 1.0));

    // Calculate speed in Mbps
    let bits_uploaded = UPLOAD_SIZE as f32 * 8.0;
    let mbps = bits_uploaded / (elapsed * 1_000_000.0);

    Ok(mbps)
}

/// Format speed for display (e.g., "125.5 Mbps" or "1.2 Gbps")
pub fn format_speed(mbps: f32) -> String {
    if mbps >= 1000.0 {
        format!("{:.1} Gbps", mbps / 1000.0)
    } else if mbps >= 100.0 {
        format!("{:.0} Mbps", mbps)
    } else if mbps >= 10.0 {
        format!("{:.1} Mbps", mbps)
    } else {
        format!("{:.2} Mbps", mbps)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_speed_gbps() {
        assert_eq!(format_speed(1200.0), "1.2 Gbps");
        assert_eq!(format_speed(2500.5), "2.5 Gbps");
    }

    #[test]
    fn test_format_speed_high_mbps() {
        assert_eq!(format_speed(500.0), "500 Mbps");
        assert_eq!(format_speed(999.9), "1000 Mbps"); // rounds up
    }

    #[test]
    fn test_format_speed_medium_mbps() {
        assert_eq!(format_speed(50.5), "50.5 Mbps");
        assert_eq!(format_speed(99.9), "99.9 Mbps");
    }

    #[test]
    fn test_format_speed_low_mbps() {
        assert_eq!(format_speed(5.55), "5.55 Mbps");
        assert_eq!(format_speed(0.5), "0.50 Mbps");
    }
}
