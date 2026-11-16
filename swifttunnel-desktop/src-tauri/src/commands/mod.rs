pub mod auth;
pub mod game_launch;
pub mod games;
pub mod i18n;
pub mod launcher;
pub mod network;
mod network_control;
mod network_operation;
pub mod optimization;
pub mod optimizer;
pub mod overlay;
pub mod settings;
pub mod system;
mod update_download;
pub mod updater;
pub mod vpn;

/// Longest that quitting waits for an admitted connect, repair or boost.
const SHUTDOWN_DRAIN_LIMIT: std::time::Duration = std::time::Duration::from_secs(15);

pub(crate) async fn drain_for_shutdown() -> Option<(
    tokio::sync::OwnedSemaphorePermit,
    tokio::sync::OwnedSemaphorePermit,
)> {
    let drained = crate::operation_gate::drain_for_shutdown_within(
        network_operation::gate(),
        optimizer::config_gate(),
        SHUTDOWN_DRAIN_LIMIT,
    )
    .await;
    if drained.is_none() {
        log::warn!(
            "Exit: a connection, repair or boost was still running after {}s; skipping overlapping restoration and retaining recovery records for next startup",
            SHUTDOWN_DRAIN_LIMIT.as_secs()
        );
    }
    drained
}
