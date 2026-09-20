//! Speed Test using Cloudflare
//!
//! Uses Cloudflare's public speed test endpoints (speed.cloudflare.com).
//!
//! Design: runs N parallel TCP streams, waits through a short warm-up
//! window (discarded — lets TCP slow-start ramp up), then measures
//! throughput over a fixed steady-state window. Counter-based so a
//! request that spans the window boundary still contributes every byte
//! that crossed the wire inside the window.
//!
//! Forces HTTP/1.1 so `STREAM_COUNT` actually yields that many TCP
//! connections instead of h2 multiplexing them over a single socket.

use super::types::{SpeedTestProgress, SpeedTestResults};
use futures_util::StreamExt;
use log::{debug, error, info};
use reqwest::Client;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::Sender;
use std::time::{Duration, Instant};

const DOWNLOAD_URL: &str = "https://speed.cloudflare.com/__down";
const UPLOAD_URL: &str = "https://speed.cloudflare.com/__up";

/// Parallel TCP streams. Ookla uses 16, Cloudflare's own uses 8.
const STREAM_COUNT: usize = 8;

/// Warm-up window before measurement begins (TCP slow-start ramp).
const WARMUP_SECS: f32 = 2.0;

/// Steady-state measurement window.
const MEASURE_SECS: f32 = 8.0;

/// Bytes per `__down` request. Oversized so a single request outlasts the
/// full test window on ~gigabit links. Workers re-GET on connection reuse
/// if they somehow drain it (cheap — connection is kept alive).
const DOWNLOAD_PER_REQUEST_BYTES: u64 = 1_000_000_000;

/// Chunk size for the streaming upload body.
const UPLOAD_CHUNK_BYTES: usize = 65_536;

/// Chunks per upload POST. ~50 MB — big enough to amortize request
/// overhead, small enough to re-POST a few times during the window on
/// fast uplinks.
const UPLOAD_CHUNKS_PER_POST: usize = 800;

/// HTTP timeout per request.
const REQUEST_TIMEOUT_SECS: u64 = 60;

/// Progress update cadence during measurement.
const PROGRESS_INTERVAL_MS: u64 = 100;

/// Run a complete speed test (download + upload).
pub async fn run_speed_test(
    progress_tx: Sender<SpeedTestProgress>,
) -> Result<SpeedTestResults, String> {
    info!(
        "Starting speed test: {} parallel streams, {:.1}s warm-up + {:.1}s measure per phase",
        STREAM_COUNT, WARMUP_SECS, MEASURE_SECS
    );

    let client = Client::builder()
        .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
        // Force HTTP/1.1 so STREAM_COUNT yields real TCP parallelism rather
        // than h2 streams multiplexed over a single connection.
        .http1_only()
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

    // === DOWNLOAD ===
    let _ = progress_tx.send(SpeedTestProgress::DownloadStarted);
    let download_url = format!("{}?bytes={}", DOWNLOAD_URL, DOWNLOAD_PER_REQUEST_BYTES);
    let warmup = Duration::from_secs_f32(WARMUP_SECS);
    let measurement = Duration::from_secs_f32(MEASURE_SECS);
    let download_mbps =
        match run_download_test(&client, &progress_tx, &download_url, warmup, measurement).await {
            Ok(mbps) => {
                info!("Download test complete: {:.2} Mbps", mbps);
                let _ = progress_tx.send(SpeedTestProgress::DownloadComplete(mbps));
                mbps
            }
            Err(e) => {
                error!("Download test failed: {}", e);
                let _ =
                    progress_tx.send(SpeedTestProgress::Error(format!("Download failed: {}", e)));
                return Err(e);
            }
        };

    // Brief pause between phases.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // === UPLOAD ===
    let _ = progress_tx.send(SpeedTestProgress::UploadStarted);
    let upload_mbps =
        match run_upload_test(&client, &progress_tx, UPLOAD_URL, warmup, measurement).await {
            Ok(mbps) => {
                info!("Upload test complete: {:.2} Mbps", mbps);
                let _ = progress_tx.send(SpeedTestProgress::UploadComplete(mbps));
                mbps
            }
            Err(e) => {
                error!("Upload test failed: {}", e);
                let _ = progress_tx.send(SpeedTestProgress::Error(format!("Upload failed: {}", e)));
                return Err(e);
            }
        };

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

async fn run_download_test(
    client: &Client,
    progress_tx: &Sender<SpeedTestProgress>,
    url: &str,
    warmup: Duration,
    measurement: Duration,
) -> Result<f32, String> {
    debug!("Download: spawning {} parallel streams", STREAM_COUNT);

    let counter = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));

    // JoinSet aborts its workers if this phase is cancelled or unwinds.
    let mut workers = tokio::task::JoinSet::new();
    for _ in 0..STREAM_COUNT {
        let client = client.clone();
        let url = url.to_owned();
        let counter = counter.clone();
        let stop = stop.clone();
        workers.spawn(async move {
            download_worker(client, url, counter, stop).await;
        });
    }

    // Warm-up: discarded. Keep the UI animating so it doesn't look frozen.
    let warmup_deadline = Instant::now() + warmup;
    while Instant::now() < warmup_deadline {
        tokio::time::sleep(Duration::from_millis(PROGRESS_INTERVAL_MS)).await;
        let _ = progress_tx.send(SpeedTestProgress::DownloadProgress(0.0, 0.0));
    }

    // Measurement.
    let start_bytes = counter.load(Ordering::Relaxed);
    let measure_start = Instant::now();
    let measure_deadline = measure_start + measurement;

    while Instant::now() < measure_deadline {
        tokio::time::sleep(Duration::from_millis(PROGRESS_INTERVAL_MS)).await;
        let bytes = counter.load(Ordering::Relaxed).saturating_sub(start_bytes);
        let elapsed = measure_start.elapsed().as_secs_f32();
        let mbps = if elapsed > 0.0 {
            (bytes as f32 * 8.0) / (elapsed * 1_000_000.0)
        } else {
            0.0
        };
        let progress = (elapsed / measurement.as_secs_f32()).min(1.0);
        let _ = progress_tx.send(SpeedTestProgress::DownloadProgress(mbps, progress));
    }

    let total_bytes = counter.load(Ordering::Relaxed).saturating_sub(start_bytes);
    let elapsed = measure_start.elapsed().as_secs_f32().max(0.001);
    let mbps = (total_bytes as f32 * 8.0) / (elapsed * 1_000_000.0);

    // Shut the workers down.
    stop.store(true, Ordering::Relaxed);
    // A stop flag cannot wake a worker awaiting HTTP headers or another chunk.
    // Measurement is finished, so cancel outstanding I/O and join the workers.
    workers.shutdown().await;

    if total_bytes == 0 {
        return Err("No data received during measurement window".to_string());
    }

    Ok(mbps)
}

async fn download_worker(
    client: Client,
    url: String,
    counter: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
) {
    while !stop.load(Ordering::Relaxed) {
        let resp = match client.get(&url).send().await {
            Ok(r) if r.status().is_success() => r,
            Ok(_) => return,
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let mut stream = resp.bytes_stream();
        while let Some(chunk) = stream.next().await {
            if stop.load(Ordering::Relaxed) {
                return;
            }
            match chunk {
                Ok(bytes) => {
                    counter.fetch_add(bytes.len() as u64, Ordering::Relaxed);
                }
                Err(_) => break,
            }
        }
    }
}

async fn run_upload_test(
    client: &Client,
    progress_tx: &Sender<SpeedTestProgress>,
    url: &str,
    warmup: Duration,
    measurement: Duration,
) -> Result<f32, String> {
    debug!("Upload: spawning {} parallel streams", STREAM_COUNT);

    let counter = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));

    let mut workers = tokio::task::JoinSet::new();
    for _ in 0..STREAM_COUNT {
        let client = client.clone();
        let url = url.to_owned();
        let counter = counter.clone();
        let stop = stop.clone();
        workers.spawn(async move {
            upload_worker(client, url, counter, stop).await;
        });
    }

    // Warm-up.
    let warmup_deadline = Instant::now() + warmup;
    while Instant::now() < warmup_deadline {
        tokio::time::sleep(Duration::from_millis(PROGRESS_INTERVAL_MS)).await;
        let _ = progress_tx.send(SpeedTestProgress::UploadProgress(0.0, 0.0));
    }

    // Measurement.
    let start_bytes = counter.load(Ordering::Relaxed);
    let measure_start = Instant::now();
    let measure_deadline = measure_start + measurement;

    while Instant::now() < measure_deadline {
        tokio::time::sleep(Duration::from_millis(PROGRESS_INTERVAL_MS)).await;
        let bytes = counter.load(Ordering::Relaxed).saturating_sub(start_bytes);
        let elapsed = measure_start.elapsed().as_secs_f32();
        let mbps = if elapsed > 0.0 {
            (bytes as f32 * 8.0) / (elapsed * 1_000_000.0)
        } else {
            0.0
        };
        let progress = (elapsed / measurement.as_secs_f32()).min(1.0);
        let _ = progress_tx.send(SpeedTestProgress::UploadProgress(mbps, progress));
    }

    let total_bytes = counter.load(Ordering::Relaxed).saturating_sub(start_bytes);
    let elapsed = measure_start.elapsed().as_secs_f32().max(0.001);
    let mbps = (total_bytes as f32 * 8.0) / (elapsed * 1_000_000.0);

    stop.store(true, Ordering::Relaxed);
    workers.shutdown().await;

    if total_bytes == 0 {
        return Err("No data sent during measurement window".to_string());
    }

    Ok(mbps)
}

async fn upload_worker(
    client: Client,
    url: String,
    counter: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
) {
    while !stop.load(Ordering::Relaxed) {
        let counter_for_stream = counter.clone();
        let stop_for_stream = stop.clone();
        // Streamed body: hyper pulls chunks at socket-write rate, so the
        // counter increments close to wire-time (small buffering ≪ 1 MB).
        let body_stream = futures_util::stream::iter(0..UPLOAD_CHUNKS_PER_POST).map(move |_| {
            if stop_for_stream.load(Ordering::Relaxed) {
                return Err(std::io::Error::other("stopped"));
            }
            let chunk = vec![0u8; UPLOAD_CHUNK_BYTES];
            counter_for_stream.fetch_add(chunk.len() as u64, Ordering::Relaxed);
            Ok::<Vec<u8>, std::io::Error>(chunk)
        });
        let body = reqwest::Body::wrap_stream(body_stream);

        match client
            .post(&url)
            .header("Content-Type", "application/octet-stream")
            .body(body)
            .send()
            .await
        {
            Ok(_) => {}
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
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

    async fn stalled_phase_releases_workers(upload: bool, cancel: bool) {
        use tokio::io::AsyncReadExt;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let (drain_tx, drain_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let mut sockets = Vec::new();
            for _ in 0..STREAM_COUNT {
                sockets.push(listener.accept().await.unwrap().0);
            }
            ready_tx.send(()).unwrap();
            // Never send response headers. Start draining only after cleanup,
            // so the upload test does not generate an unbounded local load.
            let _ = drain_rx.await;
            for mut socket in sockets {
                let mut buffer = [0; 4096];
                loop {
                    match socket.read(&mut buffer).await {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {}
                    }
                }
            }
        });
        let client = Client::builder()
            .no_proxy()
            .http1_only()
            .timeout(Duration::from_secs(60))
            .build()
            .unwrap();
        let (tx, _rx) = std::sync::mpsc::channel();
        let mut phase = tokio::spawn(async move {
            let measurement = if cancel {
                Duration::from_secs(30)
            } else {
                Duration::from_millis(200)
            };
            if upload {
                run_upload_test(&client, &tx, &url, Duration::ZERO, measurement).await
            } else {
                run_download_test(&client, &tx, &url, Duration::ZERO, measurement).await
            }
        });
        tokio::time::timeout(Duration::from_secs(3), ready_rx)
            .await
            .expect("workers must connect to the local fixture")
            .unwrap();
        if cancel {
            phase.abort();
            assert!(phase.await.unwrap_err().is_cancelled());
        } else {
            let completion = tokio::time::timeout(Duration::from_secs(2), &mut phase).await;
            if completion.is_err() {
                phase.abort();
            }
            assert!(
                completion.is_ok(),
                "measurement waited for a stalled HTTP response"
            );
        }
        drain_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("test workers kept their sockets open after cleanup")
            .unwrap();
    }

    #[tokio::test]
    async fn speed_workers_stop_stalled_download_after_measurement() {
        stalled_phase_releases_workers(false, false).await;
    }

    #[tokio::test]
    async fn speed_workers_stop_stalled_upload_after_measurement() {
        stalled_phase_releases_workers(true, false).await;
    }

    #[tokio::test]
    async fn speed_workers_stop_download_when_phase_is_cancelled() {
        stalled_phase_releases_workers(false, true).await;
    }

    #[tokio::test]
    async fn speed_workers_stop_upload_when_phase_is_cancelled() {
        stalled_phase_releases_workers(true, true).await;
    }

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
