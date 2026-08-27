//! The decisions taken between "the user clicked Connect" and `VpnConnection`.
//!
//! Which physical adapter to bind, which region to actually connect to when
//! auto-routing is on, and which relays to offer as candidates. None of it is
//! transport: it is policy, and it is the part a second client is most likely
//! to get subtly wrong.
//!
//! # Why this lives in core
//!
//! It used to live in the desktop app's Tauri command layer, where SwiftTunnel
//! Lite could not reach it. Lite therefore connected with `binding_preference:
//! None`, an empty `forced_servers`, no latency on any candidate and the raw
//! saved region, which meant the adapter you picked was ignored, auto-routing
//! had nothing to sort by, and the two clients could disagree about where they
//! were sending your traffic on the same machine.
//!
//! There is one implementation now and both clients call it. Anything that
//! should be true of a SwiftTunnel connection is true of both, which is the
//! only way that claim survives contact with a second client.

use std::collections::HashMap;
use std::net::SocketAddr;

use crate::settings::{AdapterBindingMode, AppSettings};
use crate::vpn::parallel_interceptor::{
    AdapterBindingPreference, BindingPreferenceSource, NetworkAdapterInfo, list_network_adapters,
    preflight_binding,
};
use crate::vpn::servers::DynamicServerList;

// ── Adapter binding ─────────────────────────────────────────────────────────

/// Why an adapter cannot carry game traffic, or `None` when it can.
pub fn manual_adapter_unusable_reason(adapter: &NetworkAdapterInfo) -> Option<&'static str> {
    if !adapter.is_up {
        return Some("adapter is down");
    }

    match adapter.kind.as_str() {
        "loopback" => Some("loopback adapters cannot carry game traffic"),
        "tunnel" => Some("VPN/tunnel adapters cannot be used as the physical adapter"),
        _ => None,
    }
}

/// The best name to show a person for an adapter.
pub fn manual_adapter_label(adapter: &NetworkAdapterInfo) -> &str {
    if !adapter.friendly_name.trim().is_empty() {
        adapter.friendly_name.as_str()
    } else if !adapter.description.trim().is_empty() {
        adapter.description.as_str()
    } else {
        adapter.guid.as_str()
    }
}

/// Refuse a saved adapter that cannot work, before the tunnel is attempted.
pub fn validate_manual_adapter_selection(guid: &str) -> Result<(), String> {
    let normalized_guid = guid.trim().to_ascii_lowercase();
    if normalized_guid.is_empty() {
        return Ok(());
    }

    let adapters = list_network_adapters()
        .map_err(|e| format!("Failed to validate manual adapter selection: {}", e))?;

    let Some(adapter) = adapters
        .iter()
        .find(|adapter| adapter.guid.eq_ignore_ascii_case(&normalized_guid))
    else {
        // Missing saved adapters are still allowed to fall back later. This
        // can happen after a driver reinstall, or when Windows recreates an
        // adapter GUID.
        return Ok(());
    };

    if let Some(reason) = manual_adapter_unusable_reason(adapter) {
        return Err(format!(
            "Selected adapter is not usable for SwiftTunnel ({}: {}). Choose an [OK] adapter or switch to Smart Auto.",
            manual_adapter_label(adapter),
            reason
        ));
    }

    Ok(())
}

/// Which adapter this connection should bind to, from the saved settings.
///
/// `None` means "let the driver pick", which is the right answer both when the
/// user asked for Smart Auto with nothing remembered for this network, and
/// when Manual is set but the saved adapter has gone.
pub fn current_binding_preference(
    settings: &mut AppSettings,
) -> Result<Option<AdapterBindingPreference>, String> {
    match settings.adapter_binding_mode {
        AdapterBindingMode::Manual => {
            let Some(guid) = settings.preferred_physical_adapter_guid.clone() else {
                log::warn!(
                    "Adapter binding mode is Manual but no adapter GUID is selected; using Smart Auto selection."
                );
                return Ok(None);
            };

            validate_manual_adapter_selection(&guid)?;

            Ok(Some(AdapterBindingPreference {
                guid,
                source: BindingPreferenceSource::Manual,
                network_signature: None,
            }))
        }
        AdapterBindingMode::SmartAuto => {
            let base = preflight_binding(None).map_err(|e| e.to_string())?;
            let Some(guid) = settings
                .network_binding_overrides
                .get(&base.network_signature)
                .cloned()
            else {
                return Ok(None);
            };

            Ok(Some(AdapterBindingPreference {
                guid,
                source: BindingPreferenceSource::RememberedAuto,
                network_signature: Some(base.network_signature),
            }))
        }
    }
}

// ── Region and candidate selection ──────────────────────────────────────────

/// The region with the lowest measured round trip.
///
/// A region the user has forced to a specific relay is scored by that relay
/// rather than by the region's best, since the forced one is where the traffic
/// would actually go.
pub fn select_best_region_by_latency(
    sl: &DynamicServerList,
    forced_servers: &HashMap<String, String>,
) -> Option<String> {
    sl.regions()
        .iter()
        .filter_map(|region| {
            let latency = forced_servers
                .get(&region.id)
                .and_then(|server_id| sl.get_latency(server_id))
                .or_else(|| {
                    if forced_servers.contains_key(&region.id) {
                        None
                    } else {
                        sl.get_region_best_latency(&region.id)
                    }
                });
            latency.map(|latency| (region.id.clone(), latency))
        })
        .min_by(|(region_a, latency_a), (region_b, latency_b)| {
            latency_a
                .cmp(latency_b)
                .then_with(|| region_a.cmp(region_b))
        })
        .map(|(region_id, _)| region_id)
}

/// Where to connect, given what the user picked and whether auto-routing is on.
pub fn resolve_initial_connect_region(
    sl: &DynamicServerList,
    requested_region: &str,
    auto_routing: bool,
    forced_servers: &HashMap<String, String>,
) -> String {
    if !auto_routing {
        return requested_region.to_string();
    }

    if forced_servers.contains_key(requested_region) {
        return requested_region.to_string();
    }

    select_best_region_by_latency(sl, forced_servers)
        .unwrap_or_else(|| requested_region.to_string())
}

/// The relays a connection may use, with their measured round trips.
///
/// The latency matters: auto-routing sorts by it mid-session, so handing this
/// over without it leaves the router unable to tell one relay from another.
pub fn build_available_servers(sl: &DynamicServerList) -> Vec<(String, SocketAddr, Option<u32>)> {
    sl.servers()
        .iter()
        .filter(|s| s.relay_available)
        .filter_map(|s| {
            let addr: SocketAddr = format!("{}:{}", s.ip, s.effective_relay_port())
                .parse()
                .ok()?;
            let latency = sl.get_latency(&s.region);
            Some((s.region.clone(), addr, latency))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vpn::servers::{DynamicGamingRegion, DynamicServerInfo, ServerListSource};

    fn make_server(region: &str, ip: &str) -> DynamicServerInfo {
        DynamicServerInfo {
            region: region.to_string(),
            name: region.to_string(),
            country_code: "sg".to_string(),
            ip: ip.to_string(),
            port: 51820,
            phantun_available: false,
            phantun_port: None,
            relay_available: true,
            relay_port: Some(8443),
            active_users: None,
            busy: false,
            metered: false,
        }
    }

    fn make_region(id: &str, servers: &[&str]) -> DynamicGamingRegion {
        DynamicGamingRegion {
            id: id.to_string(),
            name: id.to_string(),
            description: String::new(),
            country_code: "sg".to_string(),
            servers: servers.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn make_dynamic_server_list() -> DynamicServerList {
        let mut list = DynamicServerList::new_empty();
        list.update(
            vec![
                make_server("singapore", "1.1.1.1"),
                make_server("singapore-02", "1.1.1.2"),
                make_server("tokyo-01", "2.2.2.1"),
            ],
            vec![
                make_region("singapore", &["singapore", "singapore-02"]),
                make_region("tokyo", &["tokyo-01"]),
            ],
            ServerListSource::Api,
        );
        list
    }

    fn make_network_adapter(kind: &str, is_up: bool) -> NetworkAdapterInfo {
        NetworkAdapterInfo {
            guid: format!("{kind}-guid"),
            friendly_name: kind.to_string(),
            description: kind.to_string(),
            if_index: 10,
            is_up,
            is_default_route: false,
            kind: kind.to_string(),
        }
    }

    #[test]
    fn manual_adapter_validation_rejects_unusable_adapter_kinds() {
        assert_eq!(
            manual_adapter_unusable_reason(&make_network_adapter("loopback", true)),
            Some("loopback adapters cannot carry game traffic")
        );
        assert_eq!(
            manual_adapter_unusable_reason(&make_network_adapter("tunnel", true)),
            Some("VPN/tunnel adapters cannot be used as the physical adapter")
        );
        assert_eq!(
            manual_adapter_unusable_reason(&make_network_adapter("wifi", false)),
            Some("adapter is down")
        );
        assert_eq!(
            manual_adapter_unusable_reason(&make_network_adapter("ethernet", true)),
            None
        );
    }

    #[test]
    fn select_best_region_by_latency_uses_ping_test_region_best() {
        let mut list = make_dynamic_server_list();
        list.set_latency("singapore", Some(28));
        list.set_latency("tokyo-01", Some(90));

        assert_eq!(
            select_best_region_by_latency(&list, &HashMap::new()),
            Some("singapore".to_string())
        );
    }

    #[test]
    fn select_best_region_by_latency_scores_forced_region_by_forced_server() {
        let mut list = make_dynamic_server_list();
        // The region's best relay is fast, but the user forced the slow one,
        // so the region must be scored by what would actually be used.
        list.set_latency("singapore", Some(10));
        list.set_latency("singapore-02", Some(200));
        list.set_latency("tokyo-01", Some(90));

        let forced = HashMap::from([("singapore".to_string(), "singapore-02".to_string())]);
        assert_eq!(
            select_best_region_by_latency(&list, &forced),
            Some("tokyo".to_string())
        );
    }

    #[test]
    fn resolve_initial_connect_region_keeps_manual_region() {
        let mut list = make_dynamic_server_list();
        list.set_latency("singapore", Some(12));
        list.set_latency("tokyo-01", Some(90));

        assert_eq!(
            resolve_initial_connect_region(&list, "tokyo", false, &HashMap::new()),
            "tokyo"
        );
    }

    #[test]
    fn resolve_initial_connect_region_uses_ping_test_best_for_auto_routing() {
        let mut list = make_dynamic_server_list();
        list.set_latency("singapore", Some(12));
        list.set_latency("tokyo-01", Some(90));

        assert_eq!(
            resolve_initial_connect_region(&list, "tokyo", true, &HashMap::new()),
            "singapore"
        );
    }

    #[test]
    fn resolve_initial_connect_region_falls_back_without_ping_results() {
        let list = make_dynamic_server_list();
        assert_eq!(
            resolve_initial_connect_region(&list, "tokyo", true, &HashMap::new()),
            "tokyo"
        );
    }

    #[test]
    fn resolve_initial_connect_region_keeps_requested_region_with_forced_server() {
        let mut list = make_dynamic_server_list();
        list.set_latency("singapore", Some(12));
        list.set_latency("tokyo-01", Some(90));

        let forced = HashMap::from([("tokyo".to_string(), "tokyo-01".to_string())]);
        assert_eq!(
            resolve_initial_connect_region(&list, "tokyo", true, &forced),
            "tokyo"
        );
    }

    #[test]
    fn available_servers_carry_their_latency() {
        // The bug this guards: handing the candidates over without latency
        // leaves auto-routing unable to sort them, which is how Lite was
        // connecting before this module existed.
        let mut list = make_dynamic_server_list();
        list.set_latency("singapore", Some(28));

        let available = build_available_servers(&list);
        let singapore = available
            .iter()
            .find(|(region, _, _)| region == "singapore")
            .expect("singapore should be a candidate");
        assert_eq!(singapore.2, Some(28));
    }
}
