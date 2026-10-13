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
use tauri::{Emitter, Manager, State};

#[derive(Serialize)]
pub struct LaunchPlan {
    pub job_id: Option<String>,
    pub datacenter: Option<Datacenter>,
    pub preferences: GamePreferences,
    pub availability: Availability,
    pub needs_close: bool,
    pub relay_region: Option<String>,
}

struct LaunchGuard<'a> {
    state: &'a AppState,
    complete: bool,
}
#[tauri::command]
pub async fn games_suggest_server(
    state: State<'_, AppState>,
) -> Result<Option<LaunchPlan>, String> {
    let config = swifttunnel_core::roblox_launcher::LauncherConfig::load()?;
    let current = state.games.lock().current.clone();
    let Some(current) = current.filter(|g| g.fresh_join && g.location.is_some()) else {
        return Ok(None);
    };
    if !config.matchmaker.offer_better_server || !config.matchmaker.applies(&current.place_id) {
        return Ok(None);
    }
    let preferences = state
        .games
        .lock()
        .library()?
        .entries
        .iter()
        .find(|e| e.place_id == current.place_id && e.client == current.client)
        .map(|e| e.preferences.clone())
        .unwrap_or_default();
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
impl Drop for LaunchGuard<'_> {
    fn drop(&mut self) {
        if !self.complete {
            self.state.games.lock().clear_launch();
        }
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
            for server in &page.servers {
                if !search.servers.iter().any(|s| s.job_id == server.job_id)
                    && search.servers.len() < 200
                {
                    search.servers.push(server.clone());
                }
            }
            search.fetched = Instant::now();
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
    let previous = state
        .games
        .lock()
        .library()?
        .entries
        .iter()
        .find(|e| e.place_id == place_id && e.client == client)
        .and_then(|e| e.preferences.datacenter_id);
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
    use swifttunnel_core::roblox_launcher::{MatchMode, qualifies};
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
    let mut remaining = config.search_limit as usize;
    let mut best: Option<(
        u32,
        u32,
        Datacenter,
        Vec<roblox_directory::GameServer>,
        String,
    )> = None;
    for (_, score, center) in measured.into_iter().take(4) {
        if remaining == 0 || tokio::time::Instant::now() >= deadline {
            break;
        }
        let page = match tokio::time::timeout_at(deadline, lookup.servers(center.id, None)).await {
            Ok(Ok(p)) => p,
            _ => continue,
        };
        let rows = page
            .servers
            .into_iter()
            .take(remaining.min(50))
            .collect::<Vec<_>>();
        remaining = remaining.saturating_sub(rows.len().max(1));
        let candidate = rows
            .iter()
            .filter(|s| qualifies(s, config.minimum_free_slots))
            .min_by_key(|s| s.playing.unwrap_or(u32::MAX));
        if let Some(candidate) = candidate {
            let population = candidate.playing.unwrap_or(u32::MAX);
            let job = candidate.job_id.clone();
            let better =
                best.as_ref()
                    .is_none_or(|(old_score, old_population, ..)| match config.mode {
                        MatchMode::Closest => score < *old_score,
                        MatchMode::FewerPlayers => {
                            (population, score) < (*old_population, *old_score)
                        }
                    });
            if better {
                best = Some((score, population, center, rows, job));
            }
            if config.mode == MatchMode::Closest {
                break;
            }
        }
    }
    let Some((_, _, center, servers, job)) = best else {
        return Err(
            "No server matched your Matchmaker settings. Try another location or Play normally."
                .into(),
        );
    };
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
    let mut preferences = state
        .games
        .lock()
        .library()?
        .entries
        .iter()
        .find(|e| e.place_id == place_id && e.client == client)
        .map(|e| e.preferences.clone())
        .unwrap_or_default();
    let launcher = swifttunnel_core::roblox_launcher::LauncherConfig::load()?;
    preferences.use_tunnel |= launcher.matchmaker.prepare_tunnel
        && launcher.matchmaker.applies(&place_id)
        && !preferences.skip_matchmaker;
    let global = state.settings.lock().config.roblox_settings.clone();
    // Keep old library files readable, but removed named profiles no longer apply.
    preferences.flag_profile = None;
    preferences.fps_cap = preferences.fps_cap.or(Some(if global.unlock_fps {
        global.target_fps
    } else {
        60
    }));
    preferences.graphics_quality = preferences
        .graphics_quality
        .or(Some(global.graphics_quality));
    let mut target = datacenter_id.or(if use_preferred_region {
        preferences.datacenter_id
    } else {
        None
    });
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
        let cached = state.games.lock().search.as_ref().is_some_and(|s| {
            s.place_id == place_id
                && s.center.id == center.id
                && s.fetched.elapsed() < Duration::from_secs(30)
        });
        if !cached {
            games_search_servers(state.clone(), place_id.clone(), center.id, None).await?;
        }
        let games = state.games.lock();
        let search = games
            .search
            .as_ref()
            .filter(|s| s.place_id == place_id && s.center.id == center.id)
            .ok_or("The server search changed. Refresh this game's server list.")?;
        if job_id.is_none() {
            job_id = search
                .servers
                .iter()
                .filter(|s| {
                    matches!(
                        s.availability,
                        Availability::Available | Availability::Unknown
                    )
                })
                .min_by_key(|s| {
                    (
                        s.availability != Availability::Available,
                        s.playing.unwrap_or(u32::MAX),
                    )
                })
                .map(|s| s.job_id.clone());
            if job_id.is_none() {
                return Err(if search.servers.is_empty() {
                    format!(
                        "No {} servers are listed for this game. Try another location or Play normally.",
                        center.city
                    )
                } else {
                    format!(
                        "No joinable {} server was found in this search. Refresh, choose another location or Play normally.",
                        center.city
                    )
                });
            }
        }
        let server = search
            .servers
            .iter()
            .find(|s| Some(&s.job_id) == job_id.as_ref())
            .ok_or("This server is no longer in the current search. Refresh the list.")?;
        availability = server.availability;
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
        job_id,
        datacenter: center,
        preferences,
        availability,
        needs_close,
        relay_region,
    })
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
            "Server availability could not be verified. Review the warning before joining.".into(),
        );
    }
    if plan.needs_close && state.performance_monitor.lock().is_roblox_running() {
        return Err("Close Roblox first so this game's settings can be applied.".into());
    }
    if plan.preferences.use_tunnel {
        let connection = state.vpn_state_handle.borrow().clone();
        let ConnectionState::Connected { server_region, .. } = connection else {
            return Err(
                "Connect SwiftTunnel before starting this game's automatic connection profile."
                    .into(),
            );
        };
        if let Some(requested) = &plan.relay_region
            && !state.server_list.lock().regions().iter().any(|region| {
                region.id == *requested
                    && (server_region == region.id || region.servers.contains(&server_region))
            })
        {
            return Err("The current connection is not in this game's requested relay region. Reconnect before joining.".into());
        }
    }
    {
        let mut games = state.games.lock();
        if games.cleanup_scheduled {
            return Err("The previous game's settings are still being restored. Try Play again in a moment.".into());
        }
        if games.launch_pending()
            && games
                .launch_started
                .is_some_and(|at| games.launch_updating || at.elapsed() < Duration::from_secs(60))
        {
            return Err("A Roblox launch is already in progress.".into());
        }
        games.launch_started = Some(Instant::now());
        games.launch_player_seen = false;
        games.launch_updating = false;
        games.launch_gone_since = None;
        games.warning = None;
        games.status = Some(
            match client {
                RobloxClient::Standard => "Roblox is opening.",
                RobloxClient::Vng => "Roblox VNG is opening.",
            }
            .into(),
        );
        games.recovery = None;
        games.idle_since = None;
        games.left_confirmed = false;
        games.game_traffic_seen = false;
    }
    let mut launch_guard = LaunchGuard {
        state: &state,
        complete: false,
    };
    let profile = plan.preferences.clone();
    let player = swifttunnel_core::roblox_native_launch::official_player_for(client)?;
    let global = state.settings.lock().config.roblox_settings.clone();
    let mut flags = if safe_launch.unwrap_or(false) {
        std::collections::HashMap::new()
    } else {
        swifttunnel_core::roblox_optimizer::RobloxOptimizer::native_launch_flags(&global)
            .map_err(|e| e.to_string())?
    };
    let explicit_graphics = state
        .games
        .lock()
        .library()?
        .entries
        .iter()
        .find(|e| e.place_id == place_id && e.client == client)
        .is_some_and(|e| e.preferences.graphics_quality.is_some());
    if explicit_graphics {
        flags.remove("DFIntDebugFRMQualityLevelOverride");
    }
    let profile_player = player.clone();
    let optimizer = state.roblox_optimizer.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _guard = optimizer.lock();
        match (|| {
            let applied = swifttunnel_core::roblox_game_profile::apply_native(client, &profile)?;
            swifttunnel_core::roblox_launch_flags::prepare(&profile_player, flags)?;
            Ok::<_, String>(applied)
        })() {
            Ok(applied) => Ok(applied),
            Err(error) => {
                swifttunnel_core::roblox_launch_flags::restore()?;
                if let Err(restore_error) = swifttunnel_core::roblox_game_profile::restore() {
                    return Err(format!(
                        "{error} The previous settings could not be restored: {restore_error}"
                    ));
                }
                Err(error)
            }
        }
    })
    .await
    .map_err(|e| e.to_string())??;
    if let Some(job) = &plan.job_id {
        let games = state.games.lock();
        if let Some(search) = &games.search
            && search.place_id == place_id
            && plan
                .datacenter
                .as_ref()
                .is_some_and(|center| center.id == search.center.id)
            && search.fetched.elapsed() < Duration::from_secs(60)
            && let Some(server) = search.servers.iter().find(|s| &s.job_id == job)
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
    let launched = swifttunnel_core::roblox_native_launch::launch(
        &player,
        &place_id,
        plan.job_id.as_deref(),
        client,
    )
    .map(|_| ());
    if let Err(error) = launched {
        let _guard = state.roblox_optimizer.lock();
        let restored = swifttunnel_core::roblox_game_profile::restore();
        swifttunnel_core::roblox_launch_flags::restore()?;
        game_destination::clear();
        if let Err(restore_error) = restored {
            return Err(format!(
                "{error} The previous settings could not be restored: {restore_error}"
            ));
        }
        return Err(error);
    }
    // The watcher owns completion. Do not revive a launch it already saw close,
    // or mistake an older session in the same place for this new launch.
    launch_guard.complete = true;
    if plan.preferences.borderless || plan.preferences.monitor.is_some() {
        let monitor = state.performance_monitor.clone();
        let preferences = plan.preferences.clone();
        let window_app = app.clone();
        state.runtime.spawn(async move {
            for _ in 0..45 {
                tokio::time::sleep(Duration::from_secs(2)).await;
                let pid = monitor.lock().get_roblox_pid();
                if let Some(pid) = pid {
                    match swifttunnel_core::roblox_window::place(
                        pid,
                        preferences.borderless,
                        preferences.monitor.as_deref(),
                    ) {
                        Ok(true) => break,
                        Ok(false) => {}
                        Err(error) => {
                            log::warn!("Roblox window placement: {error}");
                            window_app.state::<AppState>().games.lock().warning = Some(error);
                            let _ = window_app.emit(games::LIBRARY_CHANGED, ());
                            break;
                        }
                    }
                }
            }
        });
    }
    let _ = app.emit(games::LIBRARY_CHANGED, ());
    Ok(())
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
    {
        let games = state.games.lock();
        if games.current.is_some() || games.launch_started.is_some() {
            return;
        }
    }
    if state
        .vpn_connection
        .lock()
        .await
        .auto_router()
        .is_some_and(|router| router.has_recent_game_traffic())
    {
        return;
    }
    let optimizer = state.roblox_optimizer.clone();
    let restored = tauri::async_runtime::spawn_blocking(move || {
        let _guard = optimizer.lock();
        swifttunnel_core::roblox_game_profile::restore()
            .and_then(|restored| swifttunnel_core::roblox_launch_flags::restore().map(|_| restored))
    })
    .await
    .map_err(|error| error.to_string())
    .and_then(|result| result);
    if let Err(error) = restored {
        state.games.lock().warning = Some(error);
    }
    game_destination::clear();
}
