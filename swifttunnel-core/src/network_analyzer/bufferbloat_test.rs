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
use std::time::Duration;
use tokio::sync::oneshot;

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
const LOAD_START_TIMEOUT: Duration = Duration::from_secs(10);

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
    let (download_started, download_ready) = oneshot::channel();
    let (upload_started, upload_ready) = oneshot::channel();
    let loaded_latency = sample_under_load(
        download_load_loop(
            client.clone(),
            download_started,
            format!("{}?bytes={}", DOWNLOAD_URL, DOWNLOAD_BYTES_PER_REQ),
        ),
        upload_load_loop(client.clone(), upload_started),
        sample_after_load_starts(
            download_ready,
            upload_ready,
            LOAD_START_TIMEOUT,
            sample_latency(LOADED_SAMPLES),
        ),
    )
    .await?;
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

async fn sample_after_load_starts(
    download: oneshot::Receiver<()>,
    upload: oneshot::Receiver<()>,
    startup_timeout: Duration,
    sample: impl Future<Output = Result<u32, String>>,
) -> Result<u32, String> {
    // Connection setup can take most of the sampling window. A final check
    // that some bytes arrived is too late: it cannot make earlier idle pings
    // into loaded samples. Wait for both directions before polling `sample`.
    let ready = tokio::time::timeout(startup_timeout, async {
        tokio::try_join!(download, upload)
    })
    .await;
    if !matches!(ready, Ok(Ok(((), ())))) {
        return Err("Could not start both download and upload traffic. Check your connection and try the test again.".into());
    }
    sample.await
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
    let result = tokio::select! {
        biased;
        finished = workers.join_next() => {
            if let Some(Err(error)) = finished {
                warn!("Bufferbloat: load worker failed during measurement: {error}");
            }
            Err("Download or upload traffic stopped before the measurement finished. Check your connection and try again.".into())
        }
        result = sample => result,
    };
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

    sampled_latency(&mut vals, samples)
}

fn sampled_latency(replies: &mut [u32], sent: usize) -> Result<u32, String> {
    let median = median_u32(replies).ok_or_else(|| {
        "The test server didn't answer any pings. Check your connection. Your network may block ping tests.".to_string()
    })?;
    if replies.len() <= sent / 2 {
        return Err(format!(
            "Only {} of {sent} pings got a reply. There aren't enough readings to grade the connection. Try the test again.",
            replies.len()
        ));
    }
    Ok(median)
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

async fn download_load_loop(client: Client, started: oneshot::Sender<()>, url: String) {
    use futures_util::StreamExt;

    debug!("Bufferbloat: download load url {}", url);
    let mut started = Some(started);

    loop {
        let resp = match client.get(&url).send().await {
            Ok(r) => r,
            Err(e) => {
                debug!("Bufferbloat: download request error: {}", e);
                if started.is_none() {
                    return;
                }
                tokio::time::sleep(RETRY_DELAY).await;
                continue;
            }
        };

        if !resp.status().is_success() {
            debug!("Bufferbloat: download non-200 status: {}", resp.status());
            return;
        }

        let mut stream = resp.bytes_stream();
        let mut received = false;
        let mut failed = false;
        loop {
            match stream.next().await {
                Some(Ok(chunk)) => {
                    if !chunk.is_empty() {
                        received = true;
                        if let Some(started) = started.take() {
                            let _ = started.send(());
                        }
                    }
                }
                Some(Err(e)) => {
                    debug!("Bufferbloat: download stream error: {}", e);
                    failed = true;
                    break;
                }
                None => break,
            }
        }
        // Pace retries after EOF too: an empty 200 response is not a working
        // load stream. Completed non-empty transfers can restart immediately.
        if failed || !received {
            if started.is_none() {
                return;
            }
            tokio::time::sleep(RETRY_DELAY).await;
        }
    }
}

async fn upload_load_loop(client: Client, started: oneshot::Sender<()>) {
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
    let mut started = Some(started);

    loop {
        let Some(next_request) = request.try_clone() else {
            return;
        };
        let resp = match client.execute(next_request).await {
            Ok(r) => r,
            Err(e) => {
                debug!("Bufferbloat: upload request error: {}", e);
                if started.is_none() {
                    return;
                }
                tokio::time::sleep(RETRY_DELAY).await;
                continue;
            }
        };

        if !resp.status().is_success() {
            debug!("Bufferbloat: upload non-200 status: {}", resp.status());
            return;
        } else if let Some(started) = started.take() {
            let _ = started.send(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn loaded_latency_waits_for_actual_traffic_in_both_directions() {
        let (download, download_ready) = oneshot::channel();
        let (upload, upload_ready) = oneshot::channel();
        download.send(()).unwrap();
        let worker = tokio::spawn(sample_after_load_starts(
            download_ready,
            upload_ready,
            Duration::from_secs(1),
            async { Ok(20) },
        ));
        tokio::task::yield_now().await;
        assert!(!worker.is_finished());
        upload.send(()).unwrap();
        assert_eq!(worker.await.unwrap(), Ok(20));
    }

    #[tokio::test]
    async fn a_stalled_load_start_fails_without_sampling_idle_latency_as_loaded() {
        let (download, download_ready) = oneshot::channel();
        let (_upload, upload_ready) = oneshot::channel();
        download.send(()).unwrap();
        let result = sample_after_load_starts(
            download_ready,
            upload_ready,
            Duration::from_millis(5),
            async { panic!("latency sampled before both workers transferred") },
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn bufferbloat_empty_download_does_not_create_a_fast_retry_loop() {
        use std::time::Instant;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0; 4096];
            assert!(socket.read(&mut request).await.unwrap() > 0);
            let first = Instant::now();
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            socket.shutdown().await.unwrap();
            drop(socket);
            let _next = listener.accept().await.unwrap();
            first.elapsed()
        });
        let client = Client::builder().no_proxy().build().unwrap();
        let (started, mut transferred) = oneshot::channel();
        let worker = tokio::spawn(download_load_loop(client, started, url));
        let next = tokio::time::timeout(Duration::from_secs(3), server).await;
        let load = transferred.try_recv();
        worker.abort();
        let _ = worker.await;
        assert_eq!(load, Err(oneshot::error::TryRecvError::Empty));
        assert!(
            next.unwrap().unwrap() >= Duration::from_millis(400),
            "empty load request retried without a pause"
        );
    }

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

    #[tokio::test]
    async fn a_stopped_load_worker_cannot_produce_a_successful_grade() {
        let (upload, upload_stopped) = fake_load();
        let result = sample_under_load(
            std::future::ready(()),
            upload,
            std::future::pending::<Result<u32, String>>(),
        )
        .await;
        assert!(result.unwrap_err().contains("traffic stopped"));
        upload_stopped.await.unwrap();
    }

    #[test]
    fn bufferbloat_needs_a_majority_of_ping_replies_for_each_phase() {
        assert!(sampled_latency(&mut [4], 8).unwrap_err().contains("1 of 8"));
        assert!(sampled_latency(&mut [4, 4, 5, 7], 8).is_err());
        assert_eq!(sampled_latency(&mut [4, 4, 5, 7, 9], 8), Ok(5));
        assert_eq!(sampled_latency(&mut [4, 6, 9], 5), Ok(6));
        assert!(
            sampled_latency(&mut [], 5)
                .unwrap_err()
                .contains("didn't answer")
        );
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
