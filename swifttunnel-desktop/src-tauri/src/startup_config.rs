//! Startup recovery shares ownership with settings changes, never a detached reset.

use parking_lot::Mutex;
use swifttunnel_core::{
    network_booster::NetworkApplyOutcome, settings::AppSettings, structs::NetworkConfig,
};

pub(crate) fn recover<P, T>(operation: P, work: impl FnOnce() -> T) -> T {
    // The physical worker owns admission, including after its waiter is dropped.
    let _operation = operation;
    work()
}

pub(crate) fn reapply_network<T>(
    booster: &Mutex<T>,
    settings: &Mutex<AppSettings>,
    apply: impl FnOnce(&mut T, &NetworkConfig) -> NetworkApplyOutcome,
    persist: impl FnOnce(&AppSettings) -> Result<(), String>,
) -> Result<Vec<String>, String> {
    let mut booster = booster.lock();
    // A queued native operation must not start with a pre-lock config snapshot.
    let observed = settings.lock().config.network_settings.clone();
    let mut requested = observed.clone();
    requested.normalize_legacy_master_boost();
    let (applied, mut warnings) = if requested.has_enabled_boosts() {
        let outcome = apply(&mut booster, &requested);
        (outcome.applied_config, outcome.warnings)
    } else {
        (requested, Vec::new())
    };

    let mut current = settings.lock();
    if current.config.network_settings != observed {
        warnings.push(
            "Network preferences changed during startup. Apply them again from Roblox settings."
                .into(),
        );
        return Ok(warnings);
    }
    if applied != observed {
        let mut next = current.clone();
        next.config.network_settings = applied;
        // Keep the current snapshot and its disk publication under one writer
        // lock, including unrelated preferences changed during Windows work.
        persist(&next)?;
        *current = next;
    }
    Ok(warnings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, mpsc};
    use std::time::Duration;

    #[tokio::test]
    async fn cancelled_startup_waiter_does_not_release_an_active_recovery() {
        let gate = Arc::new(tokio::sync::Semaphore::new(1));
        let operation = gate.clone().try_acquire_owned().unwrap();
        let original = Arc::new(Mutex::new("stale"));
        let recovered = original.clone();
        let (started, ready) = tokio::sync::oneshot::channel();
        let (release, resume) = mpsc::channel();
        let (finished, done) = tokio::sync::oneshot::channel();
        let waiting = tokio::spawn(async move {
            tokio::task::spawn_blocking(move || {
                recover(operation, || {
                    started.send(()).unwrap();
                    resume.recv_timeout(Duration::from_secs(3)).unwrap();
                    *recovered.lock() = "restored";
                });
                let _ = finished.send(());
            })
            .await
            .unwrap();
        });
        ready.await.unwrap();
        waiting.abort();
        let _ = waiting.await;
        assert!(gate.clone().try_acquire_owned().is_err());
        release.send(()).unwrap();
        done.await.unwrap();
        let _apply = gate.try_acquire_owned().unwrap();
        assert_eq!(*original.lock(), "restored");
        *original.lock() = "new user apply";
        assert_eq!(*original.lock(), "new user apply");
    }

    #[test]
    fn startup_recovery_releases_admission_on_failure_and_panic() {
        let gate = Arc::new(tokio::sync::Semaphore::new(1));
        assert_eq!(
            recover(gate.clone().try_acquire_owned().unwrap(), || Err::<(), _>(
                "failed"
            )),
            Err("failed")
        );
        let panic = std::panic::catch_unwind(|| {
            recover(gate.clone().try_acquire_owned().unwrap(), || {
                panic!("fixture")
            });
        });
        assert!(panic.is_err());
        assert!(gate.try_acquire_owned().is_ok());
    }

    #[test]
    fn queued_reapply_reads_current_settings_and_persists_unrelated_edits_in_order() {
        let booster = Arc::new(Mutex::new(()));
        let held = booster.lock();
        let settings = Arc::new(Mutex::new(AppSettings::default()));
        settings.lock().config.network_settings.disable_nagle = true;
        let worker_booster = booster.clone();
        let worker_settings = settings.clone();
        let (queued, ready) = mpsc::channel();
        let task = std::thread::spawn(move || {
            queued.send(()).unwrap();
            reapply_network(
                &worker_booster,
                &worker_settings,
                |_, requested| {
                    assert!(!requested.disable_nagle);
                    assert!(requested.disable_network_throttling);
                    worker_settings.lock().minimize_to_tray = false;
                    let mut applied = requested.clone();
                    applied.disable_network_throttling = false;
                    applied.normalize_legacy_master_boost();
                    NetworkApplyOutcome {
                        applied_config: applied,
                        warnings: vec!["fixture verify failure".into()],
                    }
                },
                |next| {
                    assert!(worker_settings.try_lock().is_none());
                    assert!(!next.minimize_to_tray);
                    assert!(!next.config.network_settings.disable_network_throttling);
                    Ok(())
                },
            )
        });
        ready.recv_timeout(Duration::from_secs(2)).unwrap();
        settings.lock().config.network_settings = NetworkConfig {
            disable_network_throttling: true,
            ..Default::default()
        };
        drop(held);
        assert_eq!(task.join().unwrap().unwrap(), ["fixture verify failure"]);
        assert!(!settings.lock().minimize_to_tray);
        assert!(
            !settings
                .lock()
                .config
                .network_settings
                .disable_network_throttling
        );
    }

    #[test]
    fn reapply_preserves_newer_network_intent_and_keeps_memory_on_failed_save() {
        let settings = Mutex::new(AppSettings::default());
        settings.lock().config.network_settings.disable_nagle = true;
        let warnings = reapply_network(
            &Mutex::new(()),
            &settings,
            |_, requested| {
                settings
                    .lock()
                    .config
                    .network_settings
                    .disable_network_throttling = true;
                NetworkApplyOutcome {
                    applied_config: requested.clone(),
                    warnings: Vec::new(),
                }
            },
            |_| panic!("do not persist an obsolete network snapshot"),
        )
        .unwrap();
        assert_eq!(warnings.len(), 1);
        let before = serde_json::to_value(&*settings.lock()).unwrap();
        assert_eq!(
            reapply_network(
                &Mutex::new(()),
                &settings,
                |_, _| NetworkApplyOutcome {
                    applied_config: NetworkConfig::default(),
                    warnings: Vec::new()
                },
                |_| Err("disk unavailable".into()),
            ),
            Err("disk unavailable".into())
        );
        assert_eq!(serde_json::to_value(&*settings.lock()).unwrap(), before);
        let settings = Mutex::new(AppSettings::default());
        reapply_network(
            &Mutex::new(()),
            &settings,
            |_, _| panic!("no startup changes were requested"),
            |_| panic!("the normalized settings did not change"),
        )
        .unwrap();
    }
}
