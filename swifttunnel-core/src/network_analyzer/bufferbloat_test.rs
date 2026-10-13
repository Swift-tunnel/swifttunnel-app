//! Bufferbloat Test
//!
//! Measures latency increase ("bufferbloat") when the network is under load.
//! We:
//! 1) Measure baseline/idle ping to a reliable target (Cloudflare 1.1.1.1)
//! 2) Generate upload + download traffic using Cloudflare speed test endpoints
//! 3) Measure ping while load is active
//! 4) Compute delta + grade

use super::icmp;
use super::types::{BufferbloatGrade, BufferbloatTestResults};
use log::{debug, info, warn};
use reqwest::Client;
use std::future::Future;
use std::sync::mpsc::Sender;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
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
const RETRY_DELAY: Duration = Duration::from_millis(500);

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

    // The owner aborts both generators on cancellation as well as completion.
    let download_transferred = Arc::new(AtomicBool::new(false));
    let upload_transferred = Arc::new(AtomicBool::new(false));
    let loaded_latency = sample_under_load(
        download_load_loop(client.clone(), download_transferred.clone()),
        upload_load_loop(client.clone(), upload_transferred.clone()),
        sample_latency(LOADED_SAMPLES),
    )
    .await?;
    // A blocked speed-test endpoint would otherwise turn idle pings into an
    // A grade, despite never generating load in one or both directions.
    if !download_transferred.load(Ordering::Relaxed) || !upload_transferred.load(Ordering::Relaxed)
    {
        return Err("Could not measure both download and upload traffic. Try the test again when the speed-test service is reachable.".into());
    }
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

async fn sample_under_load<D, U, S>(download: D, upload: U, sample: S) -> Result<u32, String>
where
    D: Future<Output = ()> + Send + 'static,
    U: Future<Output = ()> + Send + 'static,
    S: Future<Output = Result<u32, String>>,
{
    // Dropping raw JoinHandles detaches infinite workers. JoinSet aborts them
    // if the parent future is dropped, including during a runtime shutdown.
    let mut workers = tokio::task::JoinSet::new();
    workers.spawn(download);
    workers.spawn(upload);
    let result = sample.await;
    workers.abort_all();
    while let Some(result) = workers.join_next().await {
        if let Err(error) = result
            && !error.is_cancelled()
        {
            warn!("Bufferbloat: load worker failed: {error}");
        }
    }
    result
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
/// Uses raw ICMP (not `ping.exe`) so it works on any Windows display language.
async fn ping_once(target: &str, timeout_ms: u64) -> Option<u32> {
    icmp::ping_ms(target, timeout_ms as u32).await
}

async fn download_load_loop(client: Client, transferred: Arc<AtomicBool>) {
    use futures_util::StreamExt;

    let url = format!("{}?bytes={}", DOWNLOAD_URL, DOWNLOAD_BYTES_PER_REQ);
    debug!("Bufferbloat: download load url {}", url);

    loop {
        let resp = match client.get(&url).send().await {
            Ok(r) => r,
            Err(e) => {
                debug!("Bufferbloat: download request error: {}", e);
                tokio::time::sleep(RETRY_DELAY).await;
                continue;
            }
        };

        if !resp.status().is_success() {
            debug!("Bufferbloat: download non-200 status: {}", resp.status());
            tokio::time::sleep(RETRY_DELAY).await;
            continue;
        }

        let mut stream = resp.bytes_stream();
        loop {
            match stream.next().await {
                Some(Ok(chunk)) => {
                    if !chunk.is_empty() {
                        transferred.store(true, Ordering::Relaxed);
                    }
                }
                Some(Err(e)) => {
                    debug!("Bufferbloat: download stream error: {}", e);
                    tokio::time::sleep(RETRY_DELAY).await;
                    break;
                }
                None => break,
            }
        }
    }
}

async fn upload_load_loop(client: Client, transferred: Arc<AtomicBool>) {
    // A reusable body shares its bytes across requests, rather than copying
    // a 750 kB Vec every time the upload loop starts another request.
    let base = reqwest::Body::from(
        (0..UPLOAD_BYTES_PER_REQ)
            .map(|i| (i % 256) as u8)
            .collect::<Vec<_>>(),
    );
    let request = client
        .post(UPLOAD_URL)
        .header("Content-Type", "application/octet-stream")
        .header("Content-Length", UPLOAD_BYTES_PER_REQ.to_string())
        .body(base)
        .build();
    let Ok(request) = request else {
        return;
    };

    loop {
        let Some(next_request) = request.try_clone() else {
            return;
        };
        let resp = match client.execute(next_request).await {
            Ok(r) => r,
            Err(e) => {
                debug!("Bufferbloat: upload request error: {}", e);
                tokio::time::sleep(RETRY_DELAY).await;
                continue;
            }
        };

        if !resp.status().is_success() {
            debug!("Bufferbloat: upload non-200 status: {}", resp.status());
            tokio::time::sleep(RETRY_DELAY).await;
        } else {
            transferred.store(true, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct LoadWorker(Option<tokio::sync::oneshot::Sender<()>>);
    impl Drop for LoadWorker {
        fn drop(&mut self) {
            if let Some(sender) = self.0.take() {
                let _ = sender.send(());
            }
        }
    }

    fn fake_load() -> (
        impl Future<Output = ()> + Send + 'static,
        tokio::sync::oneshot::Receiver<()>,
    ) {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let worker = LoadWorker(Some(tx));
        (
            async move {
                let _worker = worker;
                std::future::pending::<()>().await;
            },
            rx,
        )
    }

    #[tokio::test]
    async fn cancelling_the_test_stops_both_load_generators() {
        let (download, download_stopped) = fake_load();
        let (upload, upload_stopped) = fake_load();
        let (started, ready) = tokio::sync::oneshot::channel();
        let parent = tokio::spawn(sample_under_load(download, upload, async {
            let _ = started.send(());
            std::future::pending::<Result<u32, String>>().await
        }));
        ready.await.unwrap();
        parent.abort();
        assert!(parent.await.unwrap_err().is_cancelled());
        tokio::time::timeout(Duration::from_secs(2), download_stopped)
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), upload_stopped)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn failed_sampling_stops_load_and_preserves_the_error() {
        let (download, download_stopped) = fake_load();
        let (upload, upload_stopped) = fake_load();
        let result = sample_under_load(download, upload, async { Err("No replies".into()) }).await;
        assert_eq!(result, Err("No replies".into()));
        download_stopped.await.unwrap();
        upload_stopped.await.unwrap();
    }

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
