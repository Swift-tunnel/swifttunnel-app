//! Tauri commands for the Optimization tab. Thin wrappers over
//! `swifttunnel_core::optimizations` — the apply/revert work (registry, power
//! plan, services, scheduled tasks) runs on a blocking thread.

use serde::Serialize;

#[derive(Serialize)]
pub struct OptimizationApplyResponse {
    pub requires_reboot: bool,
}

#[tauri::command]
pub async fn optimization_apply(id: String) -> Result<OptimizationApplyResponse, String> {
    log::info!("optimization_apply called: {id}");
    let id_for_log = id.clone();
    let requires_reboot =
        tauri::async_runtime::spawn_blocking(move || swifttunnel_core::optimizations::apply(&id))
            .await
            .map_err(|e| format!("Apply task failed: {e}"))??;
    log::info!("optimization_apply done: {id_for_log} (requires_reboot={requires_reboot})");
    Ok(OptimizationApplyResponse { requires_reboot })
}

#[tauri::command]
pub async fn optimization_revert(id: String) -> Result<OptimizationApplyResponse, String> {
    let requires_reboot =
        tauri::async_runtime::spawn_blocking(move || swifttunnel_core::optimizations::revert(&id))
            .await
            .map_err(|e| format!("Revert task failed: {e}"))??;
    Ok(OptimizationApplyResponse { requires_reboot })
}

/// Ids of optimizations currently applied (have a persisted snapshot).
#[tauri::command]
pub fn optimization_get_active() -> Vec<String> {
    swifttunnel_core::optimizations::active_ids()
}
