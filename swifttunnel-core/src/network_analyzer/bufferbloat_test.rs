//! Bufferbloat Test
//!
//! Measures latency increase ("bufferbloat") when the network is under load.
//! We:
//! 1) Measure baseline/idle ping to a reliable target (Cloudflare 1.1.1.1)
//! 2) Generate upload + download traffic using Cloudflare speed test endpoints
//! 3) Measure ping while load is active
//! 4) Compute delta + grade

use super::types::{BufferbloatGrade, BufferbloatTestResults};
use crate::hidden_command;
use log::{debug, info, warn};
use reqwest::Client;
use std::sync::mpsc::Sender;
use std::time::Duration;

/// Target IP for ping (highly reliable)
const PING_TARGET: &str = "1.1.1.1";

/// Timeout for each ping in milliseconds (keep the test snappy)
const PING_TIMEOUT_MS: u64 = 1200;

/// Idle samples (median is used)
const IDLE_SAMPLES: usize = 5;

/// Loaded samples (median is used)
const LOADED_SAMPLES: usize = 8;

/// Interval between pings while sampling
const PING_SAMPLE_INTERVAL_MS: u64 = 250;

/// Cloudflare speed test endpoints
const DOWNLOAD_URL: &str = "https://speed.cloudflare.com/__down";
const UPLOAD_URL: &str = "https://speed.cloudflare.com/__up";

/// Per-request sizes (kept modest to avoid excessive data usage)
const DOWNLOAD_BYTES_PER_REQ: u64 = 3_000_000; // 3 MB
const UPLOAD_BYTES_PER_REQ: usize = 750_000; // 0.75 MB

/// HTTP client timeout
const REQUEST_TIMEOUT_SECS: u64 = 20;

/// Run a bufferbloat test.
///
/// `progress_tx` is accepted for API symmetry with other tests. The Tauri app
/// currently does not stream progress; callers can ignore it.
pub async fn run_bufferbloat_test(
    _progress_tx: Sender<()>,
) -> Result<BufferbloatTestResults, String> {
    info!("Starting bufferbloat test");

    let client = Client::builder()
        .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

    // 1) Idle latency
    let idle_latency = sample_latency(IDLE_SAMPLES).await?;
    debug!("Bufferbloat: idle median = {}ms", idle_latency);

    // 2) Start load generators. These run until we abort them.
    let download_handle = tokio::spawn(download_load_loop(client.clone()));
    let upload_handle = tokio::spawn(upload_load_loop(client.clone()));

    // 3) Loaded latency (ensure we always stop the load tasks)
    let loaded_latency_res = sample_latency(LOADED_SAMPLES).await;
    download_handle.abort();
    upload_handle.abort();

    if let Err(e) = download_handle.await {
        // abort() results in a join error; ignore unless it's a panic.
        if !e.is_cancelled() {
            warn!("Bufferbloat: download load task join error: {}", e);
        }
    }
    if let Err(e) = upload_handle.await {
        if !e.is_cancelled() {
            warn!("Bufferbloat: upload load task join error: {}", e);
        }
    }

    let loaded_latency = loaded_latency_res?;
    debug!("Bufferbloat: loaded median = {}ms", loaded_latency);

    let bufferbloat_ms = loaded_latency.saturating_sub(idle_latency);
    let grade = BufferbloatGrade::from_bufferbloat_ms(bufferbloat_ms);

    let results = BufferbloatTestResults {
        idle_latency,
        loaded_latency,
        bufferbloat_ms,
        grade,
        timestamp: chrono::Utc::now(),
    };

    info!(
        "Bufferbloat test complete: idle={}ms loaded={}ms bloat=+{}ms grade={}",
        results.idle_latency,
        results.loaded_latency,
        results.bufferbloat_ms,
        results.grade.label()
    );

    Ok(results)
}

async fn sample_latency(samples: usize) -> Result<u32, String> {
    let mut vals: Vec<u32> = Vec::with_capacity(samples);

    for i in 0..samples {
        if let Some(ms) = ping_once(PING_TARGET, PING_TIMEOUT_MS).await {
            vals.push(ms);
        }

        if i + 1 < samples {
            tokio::time::sleep(Duration::from_millis(PING_SAMPLE_INTERVAL_MS)).await;
        }
    }

    median_u32(&mut vals).ok_or_else(|| "All pings failed - no network connection".to_string())
}

fn median_u32(vals: &mut [u32]) -> Option<u32> {
    if vals.is_empty() {
        return None;
    }
    vals.sort_unstable();
    let mid = vals.len() / 2;
    if vals.len() % 2 == 1 {
        Some(vals[mid])
    } else {
        // Average the two middle samples.
        Some((vals[mid - 1] / 2) + (vals[mid] / 2) + ((vals[mid - 1] % 2 + vals[mid] % 2) / 2))
    }
}

/// Perform a single ping and return latency in milliseconds.
async fn ping_once(target: &str, timeout_ms: u64) -> Option<u32> {
    let target = target.to_string();
    let timeout = timeout_ms.to_string();
    let output = tokio::task::spawn_blocking(move || {
        hidden_command("ping")
            .args(["-n", "1", "-w", &timeout, &target])
            .output()
    })
    .await
    .ok()?
    .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Windows ping output:
    // "Reply from X.X.X.X: bytes=32 time=14ms TTL=56"
    // or "Reply from X.X.X.X: bytes=32 time<1ms TTL=56"
    for line in stdout.lines() {
        if line.contains("time=") {
            if let Some(time_start) = line.find("time=") {
                let time_str = &line[time_start + 5..];
                if let Some(ms_end) = time_str.find("ms") {
                    if let Ok(ms) = time_str[..ms_end].trim().parse::<u32>() {
                        return Some(ms);
                    }
                }
            }
        } else if line.contains("time<1ms") {
            return Some(1);
        }
    }

    None
}

async fn download_load_loop(client: Client) {
    use futures_util::StreamExt;

    let url = format!("{}?bytes={}", DOWNLOAD_URL, DOWNLOAD_BYTES_PER_REQ);
    debug!("Bufferbloat: download load url {}", url);

    loop {
        let resp = match client.get(&url).send().await {
            Ok(r) => r,
            Err(e) => {
                debug!("Bufferbloat: download request error: {}", e);
                continue;
            }
        };

        if !resp.status().is_success() {
            debug!("Bufferbloat: download non-200 status: {}", resp.status());
            continue;
        }

        let mut stream = resp.bytes_stream();
        loop {
            match stream.next().await {
                Some(Ok(_chunk)) => {
                    // Discard
                }
                Some(Err(e)) => {
                    debug!("Bufferbloat: download stream error: {}", e);
                    break;
                }
                None => break,
            }
        }
    }
}

async fn upload_load_loop(client: Client) {
    let base: Vec<u8> = (0..UPLOAD_BYTES_PER_REQ).map(|i| (i % 256) as u8).collect();
    debug!("Bufferbloat: upload load payload size {} bytes", base.len());

    loop {
        let body = base.clone();
        let resp = match client
            .post(UPLOAD_URL)
            .header("Content-Type", "application/octet-stream")
            .header("Content-Length", body.len().to_string())
            .body(body)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                debug!("Bufferbloat: upload request error: {}", e);
                continue;
            }
        };

        if !resp.status().is_success() {
            debug!("Bufferbloat: upload non-200 status: {}", resp.status());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_median_u32_odd() {
        let mut v = vec![10, 2, 7];
        assert_eq!(median_u32(&mut v), Some(7));
    }

    #[test]
    fn test_median_u32_even() {
        let mut v = vec![10, 2, 8, 4];
        assert_eq!(median_u32(&mut v), Some(6));
    }
}
