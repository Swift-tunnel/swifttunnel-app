use crate::{
    commands::games::{self, ServerSearch},
    state::AppState,
};
use serde::Serialize;
use std::time::{Duration, Instant};
use swifttunnel_core::{
    roblox_directory::{self, Availability, Datacenter, ServerPage},
    roblox_library::{GamePreferences, RobloxClient, valid_job_id, valid_place_id},
    vpn::{
        ConnectionState,
        game_destination::{self, ObservedGame},
    },
};
use tauri::{Emitter, State};

mod matchmaking;
mod selection;
mod window_placement;

#[derive(Serialize)]
pub struct LaunchPlan {
    pub place_id: String,
    pub job_id: Option<String>,
    pub datacenter: Option<Datacenter>,
    pub preferences: GamePreferences,
    pub availability: Availability,
    pub needs_close: bool,
    pub relay_region: Option<String>,
}

struct LaunchGuard {
    games: std::sync::Arc<parking_lot::Mutex<games::GamesState>>,
    notify: Option<Box<dyn FnOnce() + Send>>,
    generation: u64,
    complete: bool,
}

fn launch_render_preferences(
    game: &GamePreferences,
    global: &swifttunnel_core::structs::RobloxSettingsConfig,
) -> (
    Option<u32>,
    Option<swifttunnel_core::structs::GraphicsQuality>,
) {
    (
        game.fps_cap.or(Some(if global.unlock_fps {
            global.target_fps
        } else {
            60
        })),
        game.graphics_quality.or(Some(global.graphics_quality)),
    )
}

#[tauri::command]
pub async fn games_suggest_server(
    state: State<'_, AppState>,
) -> Result<Option<LaunchPlan>, String> {
    let config = super::launcher::games_launcher_config().await?;
    if !config.matchmaker.offer_better_server {
        return Ok(None);
    }
    let snapshot = games::library_task(state.games.clone(), |games| {
        let Some(current) = games
            .current
            .clone()
            .filter(|g| g.fresh_join && g.location.is_some())
        else {
            return Ok(None);
        };
        let preferences = games
            .library()?
            .entries
            .iter()
            .find(|e| e.place_id == current.place_id && e.client == current.client)
            .map(|e| e.preferences.clone())
            .unwrap_or_default();
        Ok(Some((current, preferences)))
    })
    .await?;
    let Some((current, preferences)) = snapshot else {
        return Ok(None);
    };
    if !config.matchmaker.applies(&current.place_id) {
        return Ok(None);
    }
    if preferences.skip_matchmaker || preferences.datacenter_id.is_some() {
        return Ok(None);
    }
    let choice = matchmake(
        &state,
        &current.place_id,
        &config.matchmaker,
        preferences.use_tunnel || config.matchmaker.prepare_tunnel,
    )
    .await?;
    let center = state
        .games
        .lock()
        .search
        .as_ref()
        .filter(|s| s.center.id == choice.0)
        .map(|s| s.center.clone());
    if center
        .as_ref()
        .is_none_or(|c| Some(&c.city) == current.location.as_ref())
    {
        return Ok(None);
    }
    if state
        .games
        .lock()
        .current
        .as_ref()
        .is_none_or(|g| g.job_id != current.job_id)
    {
        return Ok(None);
    }
    games_launch_plan(
        state,
        current.place_id,
        current.client,
        Some(choice.1),
        Some(choice.0),
        false,
    )
    .await
    .map(Some)
}
impl Drop for LaunchGuard {
    fn drop(&mut self) {
        self.games
            .lock()
            .finish_native_launch(self.generation, self.complete);
        if let Some(notify) = self.notify.take() {
            notify();
        }
    }
}

fn launch_with_recovery(
    prepare: impl FnOnce() -> Result<(), String>,
    launch: impl FnOnce() -> Result<(), String>,
    restore: impl FnOnce() -> Result<bool, String>,
) -> Result<(), String> {
    if let Err(error) = prepare().and_then(|()| launch()) {
        if let Err(restore_error) = restore() {
            return Err(format!(
                "{error} The previous settings could not be restored: {restore_error}"
            ));
        }
        return Err(error);
    }
    Ok(())
}

fn validate_launch_connection(
    connection: &ConnectionState,
    requested: Option<&str>,
    servers: &swifttunnel_core::vpn::servers::DynamicServerList,
) -> Result<(), String> {
    let ConnectionState::Connected { server_region, .. } = connection else {
        return Err(
            "Connect SwiftTunnel before starting this game's automatic connection profile.".into(),
        );
    };
    if let Some(requested) = requested
        && !servers.regions().iter().any(|region| {
            region.id == requested
                && (server_region == &region.id || region.servers.contains(server_region))
        })
    {
        return Err("The current connection is not in this game's requested relay region. Reconnect before joining.".into());
    }
    Ok(())
}

#[cfg(test)]
mod native_worker_tests {
    use super::*;
    use std::cell::RefCell;
    use std::sync::{Arc, mpsc};

    #[tokio::test]
    async fn abandoned_request_keeps_native_progress_owned_until_the_worker_finishes() {
        let games = Arc::new(parking_lot::Mutex::new(games::GamesState::default()));
        let generation = {
            let mut games = games.lock();
            let generation = games.begin_launch(RobloxClient::Standard);
            games.native_launch_generation = Some(generation);
            generation
        };
        let guard = LaunchGuard {
            games: games.clone(),
            notify: None,
            generation,
            complete: false,
        };
        let (started, ready) = tokio::sync::oneshot::channel();
        let (release, waiting) = mpsc::channel();
        let (done, finished) = tokio::sync::oneshot::channel();
        let request = tokio::spawn(async move {
            tauri::async_runtime::spawn_blocking(move || {
                let mut guard = guard;
                started.send(()).unwrap();
                waiting.recv_timeout(Duration::from_secs(3)).unwrap();
                guard.complete = true;
                drop(guard);
                done.send(()).unwrap();
            })
            .await
            .unwrap();
        });
        ready.await.unwrap();
        request.abort();
        assert!(request.await.unwrap_err().is_cancelled());
        {
            let mut games = games.lock();
            let late = Instant::now() + Duration::from_secs(120);
            assert!(games.launch_request_in_progress(late));
            assert!(!games.track_launch(late, false, false));
            assert!(games.warning.is_none());
        }
        release.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(2), finished)
            .await
            .unwrap()
            .unwrap();
        let mut games = games.lock();
        assert!(games.native_launch_generation.is_none());
        // The ordinary player-observation deadline starts after the native
        // handoff, rather than after the earlier file/preparation work.
        assert!(games.launch_request_in_progress(Instant::now()));
        assert!(games.track_launch(Instant::now() + Duration::from_secs(61), false, false));
    }

    #[test]
    fn failed_native_work_releases_its_progress_without_clearing_a_newer_launch() {
        let games = Arc::new(parking_lot::Mutex::new(games::GamesState::default()));
        let generation = {
            let mut games = games.lock();
            let generation = games.begin_launch(RobloxClient::Standard);
            games.native_launch_generation = Some(generation);
            generation
        };
        let notified = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let callback_state = games.clone();
        let callback_notified = notified.clone();
        drop(LaunchGuard {
            games: games.clone(),
            notify: Some(Box::new(move || {
                assert!(callback_state.lock().native_launch_generation.is_none());
                callback_notified.store(true, std::sync::atomic::Ordering::Release);
            })),
            generation,
            complete: false,
        });
        assert!(games.lock().launch_started.is_none());
        assert!(games.lock().native_launch_generation.is_none());
        assert!(notified.load(std::sync::atomic::Ordering::Acquire));
        let guard = LaunchGuard {
            games: games.clone(),
            notify: None,
            generation,
            complete: false,
        };
        let next = games.lock().begin_launch(RobloxClient::Standard);
        games.lock().native_launch_generation = Some(next);
        drop(guard);
        assert_eq!(games.lock().native_launch_generation, Some(next));
        assert!(games.lock().launch_started.is_some());
    }

    #[test]
    fn final_connection_check_rejects_a_lost_or_changed_preferred_tunnel() {
        use swifttunnel_core::vpn::servers::{
            DynamicGamingRegion, DynamicServerList, ServerListSource,
        };
        let mut servers = DynamicServerList::new_empty();
        servers.update(
            Vec::new(),
            vec![DynamicGamingRegion {
                id: "fixture-native-region".into(),
                name: "Fixture".into(),
                description: String::new(),
                country_code: "XX".into(),
                servers: vec!["fixture-native-relay".into()],
            }],
            ServerListSource::Api,
        );
        let mut connection = ConnectionState::Connected {
            since: Instant::now(),
            server_region: "fixture-native-relay".into(),
            server_endpoint: "192.0.2.1:51821".into(),
            assigned_ip: "fixture".into(),
            relay_auth_mode: "authenticated".into(),
            split_tunnel_active: true,
            tunneled_processes: Vec::new(),
            relay_status: None,
        };
        assert!(
            validate_launch_connection(&connection, Some("fixture-native-region"), &servers)
                .is_ok()
        );
        if let ConnectionState::Connected { server_region, .. } = &mut connection {
            *server_region = "some-other-relay".into();
        }
        assert!(
            validate_launch_connection(&connection, Some("fixture-native-region"), &servers)
                .is_err()
        );
        assert!(validate_launch_connection(&connection, None, &servers).is_ok());
        assert!(
            validate_launch_connection(&ConnectionState::Disconnected, None, &servers).is_err()
        );
    }

    #[test]
    fn preparation_and_process_errors_recover_before_returning_and_success_keeps_the_profile() {
        for failed_stage in [None, Some("prepare"), Some("launch")] {
            let steps = RefCell::new(Vec::new());
            let result = launch_with_recovery(
                || {
                    steps.borrow_mut().push("prepare");
                    if failed_stage == Some("prepare") {
                        Err("prepare failed".into())
                    } else {
                        Ok(())
                    }
                },
                || {
                    steps.borrow_mut().push("launch");
                    if failed_stage == Some("launch") {
                        Err("launch failed".into())
                    } else {
                        Ok(())
                    }
                },
                || {
                    steps.borrow_mut().push("restore");
                    Ok(true)
                },
            );
            match failed_stage {
                None => {
                    assert!(result.is_ok());
                    assert_eq!(*steps.borrow(), ["prepare", "launch"]);
                }
                Some("prepare") => {
                    assert!(result.is_err());
                    assert_eq!(*steps.borrow(), ["prepare", "restore"]);
                }
                Some(_) => {
                    assert!(result.is_err());
                    assert_eq!(*steps.borrow(), ["prepare", "launch", "restore"]);
                }
            }
        }
        assert_eq!(
            launch_with_recovery(
                || Ok(()),
                || Err("launch failed".into()),
                || Err("backup locked".into())
            ),
            Err("launch failed The previous settings could not be restored: backup locked".into())
        );
    }

    #[tokio::test]
    async fn queued_launch_uses_current_render_settings_without_changing_reviewed_route() {
        use parking_lot::Mutex;
        use swifttunnel_core::structs::{GraphicsQuality, RobloxSettingsConfig};
        for explicit in [false, true] {
            let optimizer = Arc::new(Mutex::new(()));
            let held = optimizer.lock();
            let global = Arc::new(Mutex::new(RobloxSettingsConfig {
                target_fps: 600,
                graphics_quality: GraphicsQuality::Level1,
                ..Default::default()
            }));
            let saved = Arc::new(Mutex::new(GamePreferences::default()));
            let mut profile = GamePreferences {
                datacenter_id: Some(1),
                use_tunnel: true,
                borderless: true,
                ..Default::default()
            };
            (profile.fps_cap, profile.graphics_quality) =
                launch_render_preferences(&saved.lock(), &global.lock());
            assert_eq!(profile.fps_cap, Some(600));
            let (queued, ready) = tokio::sync::oneshot::channel();
            let worker_optimizer = optimizer.clone();
            let worker_global = global.clone();
            let worker_saved = saved.clone();
            let task = tauri::async_runtime::spawn_blocking(move || {
                let _ = queued.send(());
                let _optimizer = worker_optimizer.lock();
                (profile.fps_cap, profile.graphics_quality) =
                    launch_render_preferences(&worker_saved.lock(), &worker_global.lock());
                profile
            });
            ready.await.unwrap();
            global.lock().target_fps = 900;
            global.lock().graphics_quality = GraphicsQuality::Level10;
            if explicit {
                saved.lock().fps_cap = Some(400);
                saved.lock().graphics_quality = Some(GraphicsQuality::Level4);
            }
            saved.lock().datacenter_id = Some(2);
            drop(held);
            let applied = task.await.unwrap();
            assert_eq!(applied.fps_cap, Some(if explicit { 400 } else { 900 }));
            assert_eq!(
                applied.graphics_quality,
                Some(if explicit {
                    GraphicsQuality::Level4
                } else {
                    GraphicsQuality::Level10
                })
            );
            assert_eq!(applied.datacenter_id, Some(1));
            assert!(applied.use_tunnel && applied.borderless);
        }
        let global = RobloxSettingsConfig {
            unlock_fps: false,
            target_fps: u32::MAX,
            ..Default::default()
        };
        assert_eq!(
            launch_render_preferences(&GamePreferences::default(), &global).0,
            Some(60)
        );
    }
}

#[tauri::command]
pub async fn games_datacenters() -> Result<Vec<Datacenter>, String> {
    roblox_directory::datacenters().await
}

#[tauri::command]
pub async fn games_search_servers(
    state: State<'_, AppState>,
    place_id: String,
    datacenter_id: u32,
    cursor: Option<u32>,
) -> Result<ServerPage, String> {
    let page = roblox_directory::servers(&place_id, datacenter_id, cursor).await?;
    let center = roblox_directory::datacenters()
        .await?
        .into_iter()
        .find(|c| c.id == datacenter_id)
        .ok_or("Refresh the datacenter list.")?;
    let mut games = state.games.lock();
    match &mut games.search {
        Some(search)
            if search.place_id == place_id
                && search.center.id == datacenter_id
                && cursor.is_some() =>
        {
            search.append_servers(&page.servers);
        }
        _ => {
            games.search = Some(ServerSearch {
                place_id,
                center,
                servers: page.servers.clone(),
                fetched: Instant::now(),
            })
        }
    }
    Ok(page)
}

#[tauri::command]
pub async fn games_set_preferences(
    state: State<'_, AppState>,
    place_id: String,
    client: RobloxClient,
    preferences: GamePreferences,
) -> Result<(), String> {
    preferences.validate()?;
    let lookup_place = place_id.clone();
    let previous = games::library_task(state.games.clone(), move |games| {
        Ok(games
            .library()?
            .entries
            .iter()
            .find(|e| e.place_id == lookup_place && e.client == client)
            .and_then(|e| e.preferences.datacenter_id))
    })
    .await?;
    if preferences.datacenter_id != previous
        && let Some(id) = preferences.datacenter_id
        && !roblox_directory::datacenters()
            .await?
            .iter()
            .any(|c| c.id == id)
    {
        return Err("This datacenter is no longer listed. Choose another location.".into());
    }
    games::library_task(state.games.clone(), move |games| {
        games.mutate(|lib| lib.set_preferences(&place_id, client, preferences))
    })
    .await
}

/// Deduplicate reference hosts and cap blocking ICMP workers at four. Timed-out
/// Windows calls finish within their own two-second limit; no new work starts
/// after the search deadline.
async fn measure_direct_paths(
    targets: Vec<String>,
    deadline: tokio::time::Instant,
    probe: impl Fn(&str) -> Option<u32> + Send + Sync + 'static,
) -> std::collections::HashMap<String, u32> {
    let probe = std::sync::Arc::new(probe);
    let mut targets = targets
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter();
    let mut tasks = tokio::task::JoinSet::new();
    let mut readings = std::collections::HashMap::new();
    loop {
        while tasks.len() < 4 && tokio::time::Instant::now() < deadline {
            let Some(target) = targets.next() else {
                break;
            };
            let probe = probe.clone();
            tasks.spawn_blocking(move || {
                let reading = probe(&target);
                (target, reading)
            });
        }
        if tasks.is_empty() {
            break;
        }
        match tokio::time::timeout_at(deadline, tasks.join_next()).await {
            Ok(Some(Ok((target, Some(reading))))) => {
                readings.insert(target, reading);
            }
            Ok(Some(_)) => {}
            _ => break,
        }
    }
    readings
}

#[cfg(test)]
mod direct_probe_tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    #[tokio::test]
    async fn repeated_relay_targets_only_start_four_workers_and_probe_each_host_once() {
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let calls = Arc::new(AtomicUsize::new(0));
        let (in_use, maximum, started) = (active.clone(), peak.clone(), calls.clone());
        let targets = (0..12)
            .flat_map(|i| vec![format!("128.116.{i}.3"); 5])
            .collect();
        let results = measure_direct_paths(
            targets,
            tokio::time::Instant::now() + Duration::from_secs(2),
            move |_| {
                let count = in_use.fetch_add(1, Ordering::SeqCst) + 1;
                maximum.fetch_max(count, Ordering::SeqCst);
                started.fetch_add(1, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(5));
                in_use.fetch_sub(1, Ordering::SeqCst);
                Some(12)
            },
        )
        .await;
        assert_eq!(calls.load(Ordering::SeqCst), 12);
        assert_eq!(results.len(), 12);
        assert!(peak.load(Ordering::SeqCst) <= 4);
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn an_expired_search_does_not_launch_any_probes() {
        let results = measure_direct_paths(
            vec!["128.116.47.3".into()],
            tokio::time::Instant::now(),
            |_| {
                panic!("an expired search must not start a blocking worker");
            },
        )
        .await;
        assert!(results.is_empty());
    }
}

async fn matchmake(
    state: &AppState,
    place: &str,
    config: &swifttunnel_core::roblox_launcher::Matchmaker,
    tunnel: bool,
) -> Result<(u32, String), String> {
    static SEARCH: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);
    let _search = SEARCH
        .try_acquire()
        .map_err(|_| "Matchmaker is already searching. Wait a moment and try again.".to_string())?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let catalog = tokio::time::timeout_at(deadline, roblox_directory::datacenters())
        .await
        .map_err(|_| "The server search took too long. Try again.".to_string())??;
    let previews = state
        .games
        .lock()
        .previews
        .iter()
        .filter(|p| p.is_fresh())
        .cloned()
        .collect::<Vec<_>>();
    let mut measured = Vec::new();
    let direct = if tunnel {
        std::collections::HashMap::new()
    } else {
        measure_direct_paths(
            catalog
                .iter()
                .filter(|center| !config.blocked_datacenters.contains(&center.id))
                .filter_map(|center| {
                    center
                        .relay_region
                        .as_deref()
                        .and_then(swifttunnel_core::vpn::route_preview::reference_location)
                })
                .filter_map(|location| previews.iter().find(|p| p.location == location))
                .map(|p| p.target.to_string())
                .collect(),
            deadline.min(tokio::time::Instant::now() + Duration::from_secs(8)),
            swifttunnel_core::vpn::servers::measure_latency_icmp,
        )
        .await
    };
    // Direct launches compare measured PC-to-reference paths. Tunnel launches
    // use both measured legs. Never replace a missing sample with distance.
    for center in catalog
        .into_iter()
        .filter(|c| !config.blocked_datacenters.contains(&c.id))
    {
        let reference = center
            .relay_region
            .as_deref()
            .and_then(swifttunnel_core::vpn::route_preview::reference_location);
        let matches = previews
            .iter()
            .filter(|p| reference == Some(p.location.as_str()))
            .collect::<Vec<_>>();
        let score = if tunnel {
            matches.iter().map(|p| p.estimate.estimated_game_ms).min()
        } else if let Some(row) = matches.first() {
            direct.get(&row.target.to_string()).copied()
        } else {
            None
        };
        if score.is_some() || config.preferred_datacenter == Some(center.id) {
            measured.push((
                config.preferred_datacenter != Some(center.id),
                score.unwrap_or(u32::MAX),
                center,
            ));
        }
    }
    measured.sort_by_key(|(not_preferred, score, _)| (*not_preferred, *score));
    if measured.is_empty() {
        return Err("Matchmaker has no ping readings yet. Wait a moment, pick a preferred location, or Play normally.".into());
    }
    let mut lookup = roblox_directory::ServerLookup::new(place)?;
    let matchmaking::Candidate {
        center,
        servers,
        job,
    } = matchmaking::find_server(
        &mut lookup,
        measured
            .into_iter()
            .map(|(_, score, center)| (score, center))
            .collect(),
        config,
        deadline,
    )
    .await?;
    let id = center.id;
    state.games.lock().search = Some(ServerSearch {
        place_id: place.into(),
        center,
        servers,
        fetched: Instant::now(),
    });
    Ok((id, job))
}

#[tauri::command]
pub async fn games_launch_plan(
    state: State<'_, AppState>,
    place_id: String,
    client: RobloxClient,
    job_id: Option<String>,
    datacenter_id: Option<u32>,
    use_preferred_region: bool,
) -> Result<LaunchPlan, String> {
    if !valid_place_id(&place_id) || job_id.as_deref().is_some_and(|j| !valid_job_id(j)) {
        return Err("Choose a valid game and server.".into());
    }
    let rejoining = job_id.is_some();
    let (place_id, mut preferences) = games::library_task(state.games.clone(), move |games| {
        let library = games.library()?;
        let place_id = library.launch_place(&place_id, client, rejoining);
        let preferences = library
            .entry_for(&place_id, client)
            .map(|e| e.preferences.clone())
            .unwrap_or_default();
        Ok((place_id, preferences))
    })
    .await?;
    let launcher = super::launcher::games_launcher_config().await?;
    preferences.use_tunnel |= launcher.matchmaker.prepare_tunnel
        && launcher.matchmaker.applies(&place_id)
        && !preferences.skip_matchmaker;
    let global = state.settings.lock().config.roblox_settings.clone();
    (preferences.fps_cap, preferences.graphics_quality) =
        launch_render_preferences(&preferences, &global);
    let mut target = launch_datacenter(
        &preferences,
        datacenter_id,
        use_preferred_region,
        job_id.is_some(),
    );
    let mut automatic_job = None;
    if target.is_none()
        && job_id.is_none()
        && use_preferred_region
        && !preferences.skip_matchmaker
        && launcher.matchmaker.applies(&place_id)
    {
        if state.games.lock().previews.iter().all(|p| !p.is_fresh()) {
            crate::commands::vpn::server_get_latencies(state.clone()).await?;
        }
        let choice = matchmake(
            &state,
            &place_id,
            &launcher.matchmaker,
            preferences.use_tunnel,
        )
        .await?;
        target = Some(choice.0);
        automatic_job = Some(choice.1);
    }
    let center = if let Some(id) = target {
        Some(roblox_directory::datacenters().await?.into_iter().find(|c| c.id == id).ok_or("Your preferred datacenter is no longer listed. Choose another location or Play normally.".to_string())?)
    } else {
        None
    };
    let mut job_id = job_id.or(automatic_job);
    let mut availability = Availability::Unknown;
    if let Some(center) = &center {
        let cached = state.games.lock().search.clone();
        let mut directory = roblox_directory::ServerLookup::new(&place_id)?;
        let selected =
            selection::select_server(&mut directory, &place_id, center, job_id, cached).await?;
        job_id = Some(selected.job);
        availability = selected.availability;
        if let Some(search) = selected.search {
            state.games.lock().search = Some(search);
        }
    } else if let Some(job) = &job_id {
        availability = roblox_directory::availability(&place_id, job)
            .await
            .unwrap_or(Availability::Unknown);
    }
    let relay_region = center
        .as_ref()
        .and_then(|c| c.relay_region.clone())
        .filter(|_| preferences.use_tunnel);
    if preferences.use_tunnel && center.is_some() && relay_region.is_none() {
        return Err("SwiftTunnel has no relay for this location. Turn off 'Connect SwiftTunnel before playing' for this game to join anyway.".into());
    }
    if let Some(region) = &relay_region
        && !state
            .server_list
            .lock()
            .regions()
            .iter()
            .any(|r| r.id == *region && !r.servers.is_empty())
    {
        return Err("The matching relay region is currently unavailable. Choose another datacenter or use your current connection.".into());
    }
    let needs_close = preferences.fps_cap.is_some()
        || preferences.graphics_quality.is_some()
        || preferences.use_tunnel;
    Ok(LaunchPlan {
        place_id,
        job_id,
        datacenter: center,
        preferences,
        availability,
        needs_close,
        relay_region,
    })
}

fn launch_datacenter(
    preferences: &GamePreferences,
    explicit: Option<u32>,
    use_preferred: bool,
    specific_server: bool,
) -> Option<u32> {
    // Skip affects normal Play. An explicit server selection or Rejoin must
    // still go to the server the player chose, without applying a saved city.
    explicit.or_else(|| {
        if use_preferred && !preferences.skip_matchmaker && !specific_server {
            preferences.datacenter_id
        } else {
            None
        }
    })
}

#[cfg(test)]
mod launch_location_tests {
    use super::*;

    #[test]
    fn skipped_games_join_normally_but_explicit_server_choices_are_preserved() {
        let mut preferences = GamePreferences {
            datacenter_id: Some(7),
            ..Default::default()
        };
        assert_eq!(launch_datacenter(&preferences, None, true, false), Some(7));
        preferences.skip_matchmaker = true;
        assert_eq!(launch_datacenter(&preferences, None, true, false), None);
        assert_eq!(
            launch_datacenter(&preferences, Some(8), false, true),
            Some(8)
        );
        preferences.skip_matchmaker = false;
        assert_eq!(launch_datacenter(&preferences, None, false, false), None);
        assert_eq!(launch_datacenter(&preferences, None, true, true), None);
    }
}

#[tauri::command]
pub async fn games_launch(
    state: State<'_, AppState>,
    app: tauri::AppHandle,
    place_id: String,
    client: RobloxClient,
    job_id: Option<String>,
    datacenter_id: Option<u32>,
    allow_unverified: bool,
    safe_launch: Option<bool>,
) -> Result<(), String> {
    let plan = games_launch_plan(
        state.clone(),
        place_id.clone(),
        client,
        job_id,
        datacenter_id,
        false,
    )
    .await?;
    let place_id = plan.place_id.clone();
    if matches!(
        plan.availability,
        Availability::Full | Availability::Unavailable
    ) {
        return Err(
            "That server is full or closed. Use Play normally or choose another server.".into(),
        );
    }
    if plan.job_id.is_some() && plan.availability == Availability::Unknown && !allow_unverified {
        return Err(
            "Could not verify whether this server still has room. Try Play again to review it."
                .into(),
        );
    }
    // Native FastFlags preparation always requires a stopped player, even
    // when this game has no FPS/graphics overrides. Check before replacing
    // session state or writing either settings backup.
    let monitor = state.performance_monitor.clone();
    if tauri::async_runtime::spawn_blocking(move || monitor.lock().is_roblox_running())
        .await
        .map_err(|error| error.to_string())?
    {
        return Err("Close Roblox before starting another game.".into());
    }
    if plan.preferences.use_tunnel {
        let connection = state.vpn_state_handle.borrow().clone();
        validate_launch_connection(
            &connection,
            plan.relay_region.as_deref(),
            &state.server_list.lock(),
        )?;
    }
    let placement_generation = {
        let mut games = state.games.lock();
        if games.cleanup_scheduled {
            return Err("The previous game's settings are still being restored. Try Play again in a moment.".into());
        }
        if games.launch_request_in_progress(std::time::Instant::now()) {
            return Err("A Roblox launch is already in progress.".into());
        }
        let generation = games.begin_launch(client);
        games.native_launch_generation = Some(generation);
        generation
    };
    game_destination::clear();
    let launch_guard = LaunchGuard {
        games: state.games.clone(),
        notify: Some(Box::new({
            let app = app.clone();
            move || {
                let _ = app.emit(games::LIBRARY_CHANGED, ());
            }
        })),
        generation: placement_generation,
        complete: false,
    };
    let mut profile = plan.preferences.clone();
    let optimizer = state.roblox_optimizer.clone();
    let settings = state.settings.clone();
    let games = state.games.clone();
    let connection = state.vpn_state_handle.clone();
    let servers = state.server_list.clone();
    let requested_region = plan.relay_region.clone();
    let target_place = place_id.clone();
    let target_job = plan.job_id.clone();
    let target_center = plan.datacenter.as_ref().map(|center| center.id);
    // The worker owns progress and recovery until Windows finishes creating
    // the process. Dropping the awaiting IPC cannot release the launch early.
    tauri::async_runtime::spawn_blocking(move || {
        let mut launch_guard = launch_guard;
        let optimizer = optimizer.lock();
        let player = swifttunnel_core::roblox_native_launch::official_player_for(client)?;
        let global = settings.lock().config.roblox_settings.clone();
        let mut flags = if safe_launch.unwrap_or(false) {
            std::collections::HashMap::new()
        } else {
            swifttunnel_core::roblox_optimizer::RobloxOptimizer::native_launch_flags(&global)
                .map_err(|error| error.to_string())?
        };
        {
            let mut games = games.lock();
            if games.window_placement_generation != placement_generation || games.current.is_some()
            {
                return Err("This Roblox launch was replaced. Try Play again.".into());
            }
            let saved_preferences = games
                .library()?
                .entry_for(&target_place, client)
                .map(|entry| entry.preferences.clone())
                .unwrap_or_default();
            // The plan can predate a slow optimizer wait. Resolve the current
            // game's overrides against the same global snapshot as its flags,
            // while keeping the already reviewed route/window launch intent.
            (profile.fps_cap, profile.graphics_quality) =
                launch_render_preferences(&saved_preferences, &global);
            if saved_preferences.graphics_quality.is_some() {
                flags.remove("DFIntDebugFRMQualityLevelOverride");
            }
        }
        // The initial preflight may be old after file/optimizer waits. Check
        // again immediately before either temporary settings file is changed.
        if optimizer.is_roblox_running() {
            return Err("Close Roblox before starting another game.".into());
        }
        if profile.use_tunnel {
            validate_launch_connection(
                &connection.borrow().clone(),
                requested_region.as_deref(),
                &servers.lock(),
            )?;
        }
        launch_with_recovery(
            || {
                swifttunnel_core::roblox_game_profile::apply_native(client, &profile)?;
                swifttunnel_core::roblox_launch_flags::prepare(&player, flags)?;
                Ok(())
            },
            || {
                if profile.use_tunnel {
                    validate_launch_connection(
                        &connection.borrow().clone(),
                        requested_region.as_deref(),
                        &servers.lock(),
                    )?;
                }
                {
                    let games = games.lock();
                    if games.window_placement_generation != placement_generation
                        || games.current.is_some()
                    {
                        return Err("This Roblox launch was replaced. Try Play again.".into());
                    }
                    if let Some(job) = &target_job
                        && let Some(search) = &games.search
                        && search.place_id == target_place
                        && Some(search.center.id) == target_center
                        && search.fetched.elapsed() < Duration::from_secs(60)
                        && let Some(server) =
                            search.servers.iter().find(|server| &server.job_id == job)
                        && let Some(ip) = server.ip
                    {
                        game_destination::register(ObservedGame {
                            ip,
                            job_id: job.clone(),
                            location: Some(search.center.city.clone()),
                            region: native_region(&search.center),
                            prelaunch: true,
                        });
                    }
                }
                swifttunnel_core::roblox_native_launch::launch(
                    &player,
                    &target_place,
                    target_job.as_deref(),
                    client,
                )
                .map(|_| ())
            },
            || {
                if let Some(job) = target_job.as_deref() {
                    let games = games.lock();
                    if games
                        .current
                        .as_ref()
                        .is_none_or(|current| current.job_id != job)
                    {
                        game_destination::clear_for_session(job);
                    }
                }
                swifttunnel_core::roblox_game_profile::restore_launch_settings()
            },
        )?;
        // Completion belongs to the watcher after the process is handed off.
        launch_guard.complete = true;
        Ok::<_, String>(())
    })
    .await
    .map_err(|e| e.to_string())??;
    if plan.preferences.borderless || plan.preferences.monitor.is_some() {
        let monitor = state.performance_monitor.clone();
        let preferences = plan.preferences.clone();
        let window_app = app.clone();
        let games = state.games.clone();
        state.runtime.spawn(async move {
            let mut expected_pid = None;
            for _ in 0..45 {
                tokio::time::sleep(Duration::from_secs(2)).await;
                let worker_games = games.clone();
                let worker_monitor = monitor.clone();
                let worker_preferences = preferences.clone();
                // Process queries and another process's window messages can
                // block. Keep them off runtime workers and bind this attempt
                // to its launch and the first player process it observes.
                let placed = window_placement::run(move |current| {
                    let generation = worker_games.lock().window_placement_generation;
                    if generation != placement_generation {
                        return (expected_pid, Ok(true));
                    }
                    let pid = worker_monitor.lock().get_roblox_pid();
                    let (generation, mut updating) = {
                        let games = worker_games.lock();
                        (games.window_placement_generation, games.launch_updating)
                    };
                    if expected_pid.is_some() && expected_pid != pid && !updating {
                        updating = swifttunnel_core::roblox_native_launch::updater_running();
                    }
                    match placement_target(
                        placement_generation,
                        generation,
                        expected_pid,
                        pid,
                        updating,
                    ) {
                        PlacementTarget::Finished => (expected_pid, Ok(true)),
                        PlacementTarget::Waiting => (expected_pid, Ok(false)),
                        PlacementTarget::Updating => (None, Ok(false)),
                        PlacementTarget::Player(pid) => (
                            Some(pid),
                            swifttunnel_core::roblox_window::place(
                                pid,
                                worker_preferences.borderless,
                                worker_preferences.monitor.as_deref(),
                                || {
                                    current.load(std::sync::atomic::Ordering::Acquire)
                                        && worker_games.lock().window_placement_generation
                                            == placement_generation
                                },
                            ),
                        ),
                    }
                })
                .await;
                match placed {
                    Ok((pid, result)) => {
                        expected_pid = pid;
                        match result {
                            Ok(true) => break,
                            Ok(false) => {}
                            Err(error) => {
                                log::warn!("Roblox window placement: {error}");
                                let mut games = games.lock();
                                if games.window_placement_generation != placement_generation {
                                    break;
                                }
                                games.warning = Some(error);
                                drop(games);
                                let _ = window_app.emit(games::LIBRARY_CHANGED, ());
                                break;
                            }
                        }
                    }
                    Err(error) => {
                        log::warn!("Roblox window placement task failed: {error}");
                        let mut games = games.lock();
                        if games.window_placement_generation == placement_generation {
                            games.warning = Some(error);
                            drop(games);
                            let _ = window_app.emit(games::LIBRARY_CHANGED, ());
                        }
                        break;
                    }
                }
            }
        });
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
enum PlacementTarget {
    Waiting,
    Updating,
    Finished,
    Player(u32),
}

fn placement_target(
    request: u64,
    current: u64,
    expected_pid: Option<u32>,
    observed_pid: Option<u32>,
    updating: bool,
) -> PlacementTarget {
    if request != current {
        PlacementTarget::Finished
    } else if expected_pid.is_some() && expected_pid != observed_pid {
        if updating {
            PlacementTarget::Updating
        } else {
            PlacementTarget::Finished
        }
    } else if let Some(pid) = observed_pid {
        PlacementTarget::Player(pid)
    } else {
        PlacementTarget::Waiting
    }
}

#[cfg(test)]
mod window_placement_tests {
    use super::*;

    #[test]
    fn a_later_play_cancels_the_old_window_settings_even_without_new_window_preferences() {
        let mut games = games::GamesState::default();
        let old = games.cancel_window_placement();
        assert_eq!(
            placement_target(old, old, None, None, false),
            PlacementTarget::Waiting
        );
        assert_eq!(
            placement_target(old, old, None, Some(12), false),
            PlacementTarget::Player(12)
        );
        games.cancel_window_placement();
        assert_eq!(
            placement_target(
                old,
                games.window_placement_generation,
                None,
                Some(13),
                false
            ),
            PlacementTarget::Finished
        );
    }

    #[test]
    fn retries_cannot_follow_a_different_player_process_or_continue_after_exit() {
        assert_eq!(
            placement_target(1, 1, Some(12), Some(12), false),
            PlacementTarget::Player(12)
        );
        assert_eq!(
            placement_target(1, 1, Some(12), Some(13), false),
            PlacementTarget::Finished
        );
        assert_eq!(
            placement_target(1, 1, Some(12), None, false),
            PlacementTarget::Finished
        );
    }

    #[test]
    fn confirmed_updates_allow_a_new_player_but_do_not_revive_a_cancelled_launch() {
        assert_eq!(
            placement_target(1, 1, Some(12), None, true),
            PlacementTarget::Updating
        );
        assert_eq!(
            placement_target(1, 1, None, Some(13), false),
            PlacementTarget::Player(13)
        );
        assert_eq!(
            placement_target(1, 2, Some(12), Some(13), true),
            PlacementTarget::Finished
        );
    }
}

pub fn native_region(center: &Datacenter) -> Option<swifttunnel_core::geolocation::RobloxRegion> {
    use swifttunnel_core::geolocation::RobloxRegion::*;
    Some(match center.relay_region.as_deref()? {
        "singapore" => Singapore,
        "mumbai" => Mumbai,
        "tokyo" => Tokyo,
        "germany" => Frankfurt,
        "sydney" => Sydney,
        "london" => London,
        "amsterdam" => Amsterdam,
        "paris" => Paris,
        "jakarta" => Jakarta,
        "israel" => TelAviv,
        "brazil" => Brazil,
        "us-east" => UsEast,
        "us-central" => UsCentral,
        "us-west" => UsWest,
        _ => Unknown,
    })
}

pub fn update_session_location(
    state: &AppState,
    job: &str,
    ip: std::net::Ipv4Addr,
    location: String,
    source: &str,
    region: Option<swifttunnel_core::geolocation::RobloxRegion>,
) -> bool {
    let mut games = state.games.lock();
    let Some(current) = games
        .current
        .as_mut()
        .filter(|g| g.job_id == job && g.ip == ip.to_string())
    else {
        return false;
    };
    current.location = Some(location.clone());
    current.location_source = Some(source.into());
    game_destination::register(ObservedGame {
        ip,
        job_id: job.into(),
        location: Some(location),
        region,
        prelaunch: false,
    });
    true
}

pub async fn restore_game_profile(state: &AppState) {
    let generation = {
        let games = state.games.lock();
        if games.current.is_some()
            || games.launch_started.is_some()
            || games.native_launch_generation.is_some()
        {
            return;
        }
        games.window_placement_generation
    };
    // A connection holds this mutex throughout setup. Defer cleanup to the
    // watcher's next attempt rather than blocking Play behind that setup.
    let recent_traffic = match state.vpn_connection.try_lock() {
        Ok(vpn) => vpn
            .auto_router()
            .is_some_and(|router| router.has_recent_game_traffic()),
        Err(_) => return,
    };
    if recent_traffic {
        return;
    }
    let optimizer = state.roblox_optimizer.clone();
    let games = state.games.clone();
    let restored = tauri::async_runtime::spawn_blocking(move || {
        let _guard = optimizer.lock();
        restore_profile_if_current(&games, generation, || {
            swifttunnel_core::roblox_game_profile::restore_launch_settings()
        })
    })
    .await;
    let restored = match restored {
        Ok(Some(result)) => result,
        Ok(None) => return,
        Err(error) => Err(error.to_string()),
    };
    finish_profile_cleanup(
        &mut state.games.lock(),
        generation,
        restored,
        game_destination::clear,
    );
}

fn restore_profile_if_current(
    games: &parking_lot::Mutex<games::GamesState>,
    generation: u64,
    restore: impl FnOnce() -> Result<bool, String>,
) -> Option<Result<bool, String>> {
    {
        let current = games.lock();
        // This check runs under the optimizer lock, immediately before file
        // mutation. The earlier check can become stale while the worker waits
        // behind a new launch preparing its own profile/journal.
        if current.window_placement_generation != generation
            || current.current.is_some()
            || current.launch_started.is_some()
            || current.native_launch_generation.is_some()
        {
            return None;
        }
    }
    // Do not retain the library lock over slow file access. New launch
    // preparation shares the caller's optimizer lock and must wait its turn.
    Some(restore())
}

fn finish_profile_cleanup(
    games: &mut games::GamesState,
    generation: u64,
    restored: Result<bool, String>,
    clear_destination: impl FnOnce(),
) {
    // File recovery can wait for the optimizer while the player joins a game
    // outside SwiftTunnel. Never publish that older cleanup into a new session.
    if games.window_placement_generation != generation
        || games.current.is_some()
        || games.launch_started.is_some()
    {
        return;
    }
    if let Err(error) = restored {
        games.warning = Some(error);
    }
    clear_destination();
}

#[cfg(test)]
mod cleanup_completion_tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn queued_cleanup_rechecks_launch_ownership_before_mutating_files() {
        let games = std::sync::Arc::new(parking_lot::Mutex::new(games::GamesState::default()));
        let generation = games.lock().window_placement_generation;
        let optimizer = std::sync::Arc::new(parking_lot::Mutex::new(()));
        let busy = optimizer.lock();
        let worker_games = games.clone();
        let worker_optimizer = optimizer.clone();
        let (started, ready) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            started.send(()).unwrap();
            let _optimizer = worker_optimizer.lock();
            restore_profile_if_current(&worker_games, generation, || {
                panic!("old cleanup must not restore a replacement launch's files")
            })
        });
        ready.recv_timeout(Duration::from_secs(2)).unwrap();
        games.lock().begin_launch(RobloxClient::Standard);
        drop(busy);
        assert_eq!(worker.join().unwrap(), None);
    }

    #[test]
    fn current_idle_cleanup_runs_and_preserves_restore_failures() {
        let games = parking_lot::Mutex::new(games::GamesState::default());
        let generation = games.lock().window_placement_generation;
        assert_eq!(
            restore_profile_if_current(&games, generation, || Ok(true)),
            Some(Ok(true))
        );
        assert_eq!(
            restore_profile_if_current(&games, generation, || Err("locked file".into())),
            Some(Err("locked file".into()))
        );
        games.lock().cancel_window_placement();
        assert_eq!(
            restore_profile_if_current(&games, generation, || panic!("obsolete generation")),
            None
        );
    }

    #[test]
    fn old_cleanup_cannot_clear_a_join_or_publish_its_error_into_the_new_session() {
        let mut games = games::GamesState::default();
        let generation = games.window_placement_generation;
        games.current = Some(games::CurrentGame {
            place_id: "1818".into(),
            job_id: "550e8400-e29b-41d4-a716-446655440000".into(),
            ip: "34.1.2.3".into(),
            client: RobloxClient::Standard,
            fresh_join: true,
            observed_at: 1,
            location: None,
            location_source: None,
        });
        let cleared = Cell::new(false);
        finish_profile_cleanup(
            &mut games,
            generation,
            Err("old cleanup failed".into()),
            || cleared.set(true),
        );
        assert!(!cleared.get());
        assert!(games.warning.is_none());
    }

    #[test]
    fn a_new_launch_or_later_generation_retires_an_old_cleanup() {
        for has_pending_launch in [true, false] {
            let mut games = games::GamesState::default();
            let generation = games.window_placement_generation;
            games.begin_launch(RobloxClient::Standard);
            if !has_pending_launch {
                games.clear_launch();
            }
            let cleared = Cell::new(false);
            finish_profile_cleanup(&mut games, generation, Ok(true), || cleared.set(true));
            assert!(!cleared.get());
        }
    }

    #[test]
    fn cleanup_of_the_same_idle_session_keeps_its_warning_and_clears_the_old_route() {
        let mut games = games::GamesState::default();
        let generation = games.window_placement_generation;
        let cleared = Cell::new(false);
        finish_profile_cleanup(&mut games, generation, Err("restore failed".into()), || {
            cleared.set(true)
        });
        assert!(cleared.get());
        assert_eq!(games.warning.as_deref(), Some("restore failed"));
    }
}
