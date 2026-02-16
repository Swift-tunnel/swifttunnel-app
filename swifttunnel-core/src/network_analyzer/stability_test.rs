//! Connection Stability Test
//!
//! Pings a reliable endpoint (Cloudflare 1.1.1.1) to measure:
//! - Average latency
//! - Min/Max latency
//! - Jitter (standard deviation)
//! - Packet loss percentage

use super::types::{ConnectionQuality, PingSample, StabilityTestProgress, StabilityTestResults};
use crate::hidden_command;
use log::{debug, error, info};
use std::sync::mpsc::Sender;
use std::time::{Duration, Instant};

/// Target IP for stability testing (Cloudflare DNS - highly reliable)
const PING_TARGET: &str = "1.1.1.1";

/// Interval between pings in milliseconds
const PING_INTERVAL_MS: u64 = 500;

/// Timeout for each ping in milliseconds
const PING_TIMEOUT_MS: u64 = 2000;

/// Run a connection stability test
///
/// # Arguments
/// * `duration_secs` - How long to run the test (30 seconds recommended)
/// * `progress_tx` - Channel to send progress updates
///
/// # Returns
/// Result with StabilityTestResults on success
pub async fn run_stability_test(
    duration_secs: u32,
    progress_tx: Sender<StabilityTestProgress>,
) -> Result<StabilityTestResults, String> {
    info!("Starting stability test for {} seconds", duration_secs);

    let total_pings = (duration_secs as u64 * 1000) / PING_INTERVAL_MS;
    let mut successful_pings: Vec<u32> = Vec::with_capacity(total_pings as usize);
    let mut all_samples: Vec<PingSample> = Vec::with_capacity(total_pings as usize);
    let mut total_attempts: u32 = 0;
    let mut packet_loss_count: u32 = 0;
    let test_start = Instant::now();

    for i in 0..total_pings {
        total_attempts += 1;

        // Perform single ping
        let ping_result = ping_once(PING_TARGET).await;
        let elapsed_secs = test_start.elapsed().as_secs_f32();

        // Record sample with timestamp
        all_samples.push(PingSample {
            elapsed_secs,
            latency_ms: ping_result,
        });

        // Send sample to UI
        let _ = progress_tx.send(StabilityTestProgress::PingSample(ping_result));

        // Track results
        match ping_result {
            Some(ms) => {
                successful_pings.push(ms);
                debug!("Ping #{}: {}ms", i + 1, ms);
            }
            None => {
                packet_loss_count += 1;
                debug!("Ping #{}: TIMEOUT", i + 1);
            }
        }

        // Send progress update
        let progress = (i + 1) as f32 / total_pings as f32;
        let _ = progress_tx.send(StabilityTestProgress::Progress(progress));

        // Wait for next ping interval
        if i + 1 < total_pings {
            tokio::time::sleep(Duration::from_millis(PING_INTERVAL_MS)).await;
        }
    }

    // Calculate statistics
    if successful_pings.is_empty() {
        let error_msg = "All pings failed - no network connection".to_string();
        error!("{}", error_msg);
        let _ = progress_tx.send(StabilityTestProgress::Error(error_msg.clone()));
        return Err(error_msg);
    }

    let results = calculate_statistics(&successful_pings, total_attempts, packet_loss_count, all_samples);
    info!(
        "Stability test complete: avg={}ms, jitter={}ms, loss={:.1}%, quality={:?}",
        results.avg_ping, results.jitter, results.packet_loss, results.quality
    );

    let _ = progress_tx.send(StabilityTestProgress::Completed(results.clone()));

    Ok(results)
}

/// Perform a single ping and return latency in milliseconds
async fn ping_once(target: &str) -> Option<u32> {
    // Use Windows ping command with:
    // -n 1: send only 1 packet
    // -w <timeout>: timeout in ms
    let output = tokio::task::spawn_blocking(move || {
        hidden_command("ping")
            .args(["-n", "1", "-w", &PING_TIMEOUT_MS.to_string(), PING_TARGET])
            .output()
    })
    .await
    .ok()?
    .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse ping output - look for "time=XXms" or "time<1ms"
    // Windows format: "Reply from X.X.X.X: bytes=32 time=14ms TTL=56"
    // Or for very fast: "Reply from X.X.X.X: bytes=32 time<1ms TTL=56"
    for line in stdout.lines() {
        if line.contains("time=") {
            // Extract time value
            if let Some(time_start) = line.find("time=") {
                let time_str = &line[time_start + 5..];
                if let Some(ms_end) = time_str.find("ms") {
                    if let Ok(ms) = time_str[..ms_end].trim().parse::<u32>() {
                        return Some(ms);
                    }
                }
            }
        } else if line.contains("time<1ms") {
            // Very fast ping, report as 1ms
            return Some(1);
        }
    }

    // Check for timeout patterns
    if stdout.contains("Request timed out") || stdout.contains("Destination host unreachable") {
        return None;
    }

    None
}

/// Calculate statistics from ping samples
fn calculate_statistics(
    successful_pings: &[u32],
    total_attempts: u32,
    packet_loss_count: u32,
    ping_samples: Vec<PingSample>,
) -> StabilityTestResults {
    let count = successful_pings.len();

    // Calculate average
    let sum: u32 = successful_pings.iter().sum();
    let avg_ping = sum as f32 / count as f32;

    // Find min/max
    let min_ping = *successful_pings.iter().min().unwrap_or(&0);
    let max_ping = *successful_pings.iter().max().unwrap_or(&0);

    // Calculate ping spread (max - min)
    let ping_spread = (max_ping - min_ping) as f32;

    // Calculate jitter (standard deviation)
    let variance: f32 = successful_pings
        .iter()
        .map(|&ms| {
            let diff = ms as f32 - avg_ping;
            diff * diff
        })
        .sum::<f32>()
        / count as f32;
    let jitter = variance.sqrt();

    // Calculate packet loss percentage
    let packet_loss = (packet_loss_count as f32 / total_attempts as f32) * 100.0;

    // Determine quality
    let quality = ConnectionQuality::from_metrics(avg_ping, packet_loss, jitter, ping_spread);

    StabilityTestResults {
        avg_ping,
        min_ping,
        max_ping,
        jitter,
        packet_loss,
        ping_spread,
        quality,
        sample_count: count,
        ping_samples,
        timestamp: chrono::Utc::now(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_statistics_normal() {
        let pings = vec![20, 25, 30, 22, 28];
        let results = calculate_statistics(&pings, 5, 0, vec![]);

        assert!((results.avg_ping - 25.0).abs() < 0.01);
        assert_eq!(results.min_ping, 20);
        assert_eq!(results.max_ping, 30);
        assert_eq!(results.ping_spread, 10.0);
        assert!(results.jitter > 0.0);
        assert_eq!(results.packet_loss, 0.0);
        // avg=25 (>=20), jitter≈3.7 (>=2), spread=10 (>=10) → Good
        assert!(matches!(results.quality, ConnectionQuality::Good));
    }

    #[test]
    fn test_calculate_statistics_with_loss() {
        let pings = vec![50, 60, 55, 58];
        let results = calculate_statistics(&pings, 5, 1, vec![]); // 1 lost out of 5

        assert_eq!(results.packet_loss, 20.0);
        // With 20% loss and ~55ms avg, should be Bad (loss >= 7%)
        assert!(matches!(results.quality, ConnectionQuality::Bad));
    }

    #[test]
    fn test_calculate_statistics_high_jitter() {
        let pings = vec![10, 100, 15, 90, 20, 85]; // High variance
        let results = calculate_statistics(&pings, 6, 0, vec![]);

        // Jitter should be high (>30ms)
        assert!(results.jitter > 30.0);
        // Spread = 90, should not be Excellent
        assert!(!matches!(results.quality, ConnectionQuality::Excellent));
    }

    #[test]
    fn test_calculate_statistics_records_ping_samples() {
        let samples = vec![
            PingSample { elapsed_secs: 0.0, latency_ms: Some(10) },
            PingSample { elapsed_secs: 0.5, latency_ms: None },
            PingSample { elapsed_secs: 1.0, latency_ms: Some(15) },
        ];
        let pings = vec![10, 15];
        let results = calculate_statistics(&pings, 3, 1, samples);

        assert_eq!(results.ping_samples.len(), 3);
        assert_eq!(results.ping_samples[0].latency_ms, Some(10));
        assert_eq!(results.ping_samples[1].latency_ms, None);
        assert_eq!(results.ping_samples[2].latency_ms, Some(15));
        assert_eq!(results.ping_spread, 5.0);
    }

    #[test]
    fn test_quality_thresholds() {
        // Excellent: < 20ms avg, < 0.5% loss, < 2ms jitter, < 10ms spread
        assert_eq!(
            ConnectionQuality::from_metrics(15.0, 0.3, 1.0, 5.0),
            ConnectionQuality::Excellent
        );

        // Good: < 40ms avg, < 1% loss, < 5ms jitter, < 25ms spread
        assert_eq!(
            ConnectionQuality::from_metrics(35.0, 0.7, 4.0, 20.0),
            ConnectionQuality::Good
        );

        // Fair: < 70ms avg, < 3% loss, < 15ms jitter, < 50ms spread
        assert_eq!(
            ConnectionQuality::from_metrics(60.0, 2.0, 10.0, 40.0),
            ConnectionQuality::Fair
        );

        // Poor: < 120ms avg, < 7% loss, < 30ms jitter, < 80ms spread
        assert_eq!(
            ConnectionQuality::from_metrics(100.0, 5.0, 25.0, 70.0),
            ConnectionQuality::Poor
        );

        // Bad: everything else
        assert_eq!(
            ConnectionQuality::from_metrics(150.0, 15.0, 50.0, 100.0),
            ConnectionQuality::Bad
        );
    }
}
