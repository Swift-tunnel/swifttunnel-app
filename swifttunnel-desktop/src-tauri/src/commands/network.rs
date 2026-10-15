use serde::Serialize;
use std::sync::mpsc;
use tauri::State;

use crate::state::AppState;

static NETWORK_TESTS: std::sync::LazyLock<super::network_control::NetworkTestControl> =
    std::sync::LazyLock::new(super::network_control::NetworkTestControl::default);

#[tauri::command]
pub fn network_cancel_test(test_id: String) -> Result<(), String> {
    NETWORK_TESTS.cancel(&test_id)
}

#[derive(Serialize)]
pub struct PingSampleResponse {
    pub elapsed_secs: f32,
    pub latency_ms: Option<u32>,
}

#[derive(Serialize)]
pub struct StabilityResultResponse {
    pub avg_ping: f32,
    pub min_ping: u32,
    pub max_ping: u32,
    pub jitter: f32,
    pub packet_loss: f32,
    pub ping_spread: f32,
    pub quality: String,
    pub sample_count: usize,
    pub ping_samples: Vec<PingSampleResponse>,
}

#[derive(Serialize)]
pub struct SpeedResultResponse {
    pub download_mbps: f32,
    pub upload_mbps: f32,
    pub server: String,
}

#[derive(Serialize)]
pub struct BufferbloatResultResponse {
    pub idle_latency: u32,
    pub loaded_latency: u32,
    pub bufferbloat_ms: u32,
    pub grade: String,
}

#[tauri::command]
pub async fn network_start_stability_test(
    state: State<'_, AppState>,
    duration_secs: u32,
    test_id: String,
) -> Result<StabilityResultResponse, String> {
    let (tx, rx) = mpsc::channel();
    drop(rx); // Progress is not streamed by this command; do not queue it.

    let result = state
        .runtime
        .spawn(async move {
            NETWORK_TESTS
                .run(
                    test_id,
                    swifttunnel_core::network_analyzer::run_stability_test(duration_secs, tx),
                )
                .await
        })
        .await
        .map_err(|e| format!("Task join error: {}", e))?
        .map_err(|e| e.to_string())?;

    Ok(StabilityResultResponse {
        avg_ping: result.avg_ping,
        min_ping: result.min_ping,
        max_ping: result.max_ping,
        jitter: result.jitter,
        packet_loss: result.packet_loss,
        ping_spread: result.ping_spread,
        quality: result.quality.label().to_string(),
        sample_count: result.sample_count,
        ping_samples: result
            .ping_samples
            .into_iter()
            .map(|s| PingSampleResponse {
                elapsed_secs: s.elapsed_secs,
                latency_ms: s.latency_ms,
            })
            .collect(),
    })
}

#[tauri::command]
pub async fn network_start_speed_test(
    state: State<'_, AppState>,
    test_id: String,
) -> Result<SpeedResultResponse, String> {
    let (tx, rx) = mpsc::channel();
    drop(rx);

    let result = state
        .runtime
        .spawn(async move {
            NETWORK_TESTS
                .run(
                    test_id,
                    swifttunnel_core::network_analyzer::run_speed_test(tx),
                )
                .await
        })
        .await
        .map_err(|e| format!("Task join error: {}", e))?
        .map_err(|e| e.to_string())?;

    Ok(SpeedResultResponse {
        download_mbps: result.download_mbps,
        upload_mbps: result.upload_mbps,
        server: result.server,
    })
}

#[tauri::command]
pub async fn network_start_bufferbloat_test(
    state: State<'_, AppState>,
    test_id: String,
) -> Result<BufferbloatResultResponse, String> {
    // Core API expects a channel for symmetry with other tests; UI doesn't stream yet.
    let (tx, rx) = mpsc::channel();
    drop(rx);

    let result = state
        .runtime
        .spawn(async move {
            NETWORK_TESTS
                .run(
                    test_id,
                    swifttunnel_core::network_analyzer::run_bufferbloat_test(tx),
                )
                .await
        })
        .await
        .map_err(|e| format!("Task join error: {}", e))?
        .map_err(|e| e.to_string())?;

    Ok(BufferbloatResultResponse {
        idle_latency: result.idle_latency,
        loaded_latency: result.loaded_latency,
        bufferbloat_ms: result.bufferbloat_ms,
        grade: result.grade.label().to_string(),
    })
}
