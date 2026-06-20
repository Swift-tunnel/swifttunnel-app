//! Windows hosts-file management for Roblox bootstrap DNS repair.
//!
//! Adds / removes marker-delimited entries for the small set of Roblox launch
//! and API hostnames that must resolve before Roblox can open its launch-time
//! HTTPS connections. The marker names are retained from the legacy local-proxy
//! implementation so old `127.66.0.1` entries are removed reliably.

use futures_util::stream::{FuturesUnordered, StreamExt};
use log::{debug, info, warn};
use serde::Deserialize;
use std::collections::HashSet;
use std::fs;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{OnceLock, RwLock};
use std::time::Duration;

const MARKER_START: &str = "# SwiftTunnel Roblox Proxy - START";
const MARKER_END: &str = "# SwiftTunnel Roblox Proxy - END";
const DNS_REPAIR_TIMEOUT: Duration = Duration::from_secs(3);
const DNS_REPAIR_TOTAL_TIMEOUT: Duration = Duration::from_secs(10);

/// Budget for the single extra resolution pass that runs when a launch-critical
/// direct-only host (clientsettings*, versioncompatibility) was not pinned by
/// the main pass. An unpinned direct-only host loses its "never relay" guard,
/// so it is worth a few more seconds at connect time — but only one pass, so a
/// broken resolver can never loop or stall the connect indefinitely.
const DIRECT_ONLY_RETRY_TOTAL_TIMEOUT: Duration = Duration::from_secs(8);
const DNS_REPAIR_RESOLVERS: &[&str] = &[
    // IP literals avoid depending on the user's broken local DNS to find
    // the DNS-over-HTTPS resolver itself.
    "https://1.1.1.1/dns-query",
    "https://8.8.8.8/resolve",
    // Fallbacks for countries whose censors null-route the big two resolvers
    // (Egypt-style full blocks commonly cover 1.1.1.1/8.8.8.8 DoH). Without a
    // working resolver there are no pins, system DNS may be poisoned, and the
    // whole bypass silently degrades. Quad9 serves the JSON API on :5053;
    // AdGuard mirrors Google's /resolve API.
    "https://9.9.9.9:5053/dns-query",
    "https://94.140.14.14/resolve",
];

/// Maximum IPs pinned per Roblox bootstrap domain.
///
/// Roblox serves these hostnames from a CDN/anycast pool, so a single edge IP
/// resolved from a public DoH resolver may be unreachable from the user's ISP
/// path. Pinning a few verified IPs gives connection fail-over headroom without
/// bloating the hosts file.
// Route Assist splits Roblox traffic by host, but Roblox frequently serves
// unrelated hosts from shared CDN/edge IPs. Keeping a few extra candidates gives
// the allocator room to avoid relaying avatar/chat/asset hosts just because they
// share one edge with gamejoin.
const MAX_PINNED_IPS_PER_DOMAIN: usize = 6;

/// Per-IP TCP reachability probe timeout. Short so a dead edge is skipped fast;
/// the whole repair still runs under `DNS_REPAIR_TOTAL_TIMEOUT`.
const REACHABILITY_PROBE_TIMEOUT: Duration = Duration::from_millis(1200);

/// Port used to confirm a resolved Roblox edge actually accepts connections.
const ROBLOX_HTTPS_PORT: u16 = 443;

static ACTIVE_BOOTSTRAP_IPS: OnceLock<RwLock<HashSet<Ipv4Addr>>> = OnceLock::new();
static DIRECT_ONLY_BOOTSTRAP_IPS: OnceLock<RwLock<HashSet<Ipv4Addr>>> = OnceLock::new();
/// The host overrides currently written to the hosts file, so a later
/// relay-resolved DNS pass can merge into them instead of clobbering them.
static LAST_APPLIED_OVERRIDES: OnceLock<RwLock<Vec<HostOverride>>> = OnceLock::new();

fn last_applied_overrides() -> &'static RwLock<Vec<HostOverride>> {
    LAST_APPLIED_OVERRIDES.get_or_init(|| RwLock::new(Vec::new()))
}

/// True while the current session deliberately relays the launch-critical
/// settings hosts (country-ban bypass). Runtime SNI learning must not undo
/// that routing decision.
static COUNTRY_BAN_BYPASS_ROUTING: AtomicBool = AtomicBool::new(false);

// Launch-critical + sign-in-critical hosts that must stay DIRECT under Route
// Assist / Partial bypass and are important enough to PIN back into the Windows
// hosts file (see `allocate_route_assist_pins`), so the OS resolves them to our
// de-conflicted, reachability-verified direct edge instead of whatever the
// user's resolver hands out.
//
// Why pin these specifically (and not the broad UI/asset set):
//   - `clientsettings*` / `versioncompatibility`: Roblox fails startup with
//     "Failed to download or apply critical settings" if these one-shot
//     bootstrap HTTPS fetches are relayed unreliably.
//   - `auth.roblox.com`: a fresh sign-in routed out a relay's foreign datacenter
//     IP trips Roblox's new-location/geo login defenses (FunCaptcha, 2SV,
//     suspicious-login soft-block). Already-authenticated sessions don't re-auth,
//     so the breakage is sign-in-only — matching the user reports. Relaying it is
//     only correct under FULL country-ban bypass (where auth is blocked directly
//     and a solvable relay-IP challenge beats no login at all); that path does
//     not call this function.
//
// Roblox fronts these on shared anycast edges (128.116.0.0/17, CloudFront), so a
// user-DNS answer can collide with a relayed control-plane pin; pinning the
// de-conflicted IP here is what keeps these flows off the relay. FULL bypass
// relays everything and never reaches `allocate_route_assist_pins`.
const DIRECT_ONLY_BOOTSTRAP_DOMAINS: &[&str] = &[
    "clientsettingscdn.roblox.com",
    "clientsettings.roblox.com",
    "clientsettings.api.roblox.com",
    "versioncompatibility.api.roblox.com",
    "auth.roblox.com",
];

// Heavy Roblox CDN/asset hosts that ride the user's DIRECT path (not the relay)
// under Route Assist and PARTIAL country-ban bypass: textures, avatar clothing,
// thumbnails, cutscene/model payloads. These named roblox.com endpoints are the
// asset entry points that aren't under rbxcdn; every `*.rbxcdn.com` host also
// qualifies via `is_asset_direct_domain`, so we don't have to chase each CDN
// shard name (c#, t#, tr, fts, images, css, ...) forever. FULL country-ban
// bypass relays these too — in a fully-blocked country the CDN is blocked as
// well, and "direct" means assets simply never load.
const ASSET_DIRECT_ROBLOX_DOMAINS: &[&str] = &[
    "assetgame.roblox.com",
    "assetdelivery.roblox.com",
    "thumbnails.roblox.com",
    "setup.roblox.com",
];

// Route Assist only needs the region/join control plane on the relay. Roblox
// UI/social/chat/avatar/catalog traffic has no placement value and can break
// when it rides a shared relay NAT, showing as missing chat, empty menus, and
// unloaded player icons. Full country-ban bypass ignores this split and relays
// every pinned host.
const ROUTE_ASSIST_RELAY_DOMAINS: &[&str] = &[
    "gamejoin.roblox.com",
    "games.roblox.com",
    // Roblox latency measurement influences placement. Keep it on the relay so
    // Route Assist measures the selected tunnel path instead of the user's ISP.
    "lms.roblox.com",
];

/// Exact Roblox hostnames repaired when API tunneling is enabled.
///
/// This intentionally stays as an allowlist of concrete launch/API names. Do
/// not add bare `roblox.com` or lookalike domains: hosts-file repair is a DNS
/// bypass for known Roblox bootstrap dependencies, not a wildcard resolver.
pub const ROBLOX_BOOTSTRAP_DOMAINS: &[&str] = &[
    "api.roblox.com",
    "clientsettingscdn.roblox.com",
    "clientsettings.roblox.com",
    "clientsettings.api.roblox.com",
    "versioncompatibility.api.roblox.com",
    "www.roblox.com",
    "web.roblox.com",
    "apis.roblox.com",
    "auth.roblox.com",
    "accountsettings.roblox.com",
    "accountinformation.roblox.com",
    "users.roblox.com",
    "avatar.roblox.com",
    "badges.roblox.com",
    "catalog.roblox.com",
    "contacts.roblox.com",
    "inventory.roblox.com",
    "economy.roblox.com",
    "followings.roblox.com",
    "gameinternationalization.roblox.com",
    "games.roblox.com",
    "gamejoin.roblox.com",
    "groups.roblox.com",
    "lms.roblox.com",
    "notifications.roblox.com",
    "assetgame.roblox.com",
    "assetdelivery.roblox.com",
    "thumbnails.roblox.com",
    "presence.roblox.com",
    "friends.roblox.com",
    "chat.roblox.com",
    "chatsite.roblox.com",
    "locale.roblox.com",
    "setup.roblox.com",
    "captcha.roblox.com",
    "setup.rbxcdn.com",
    "apis.rbxcdn.com",
    "js.rbxcdn.com",
    "static.rbxcdn.com",
    "c0.rbxcdn.com",
    "c1.rbxcdn.com",
    "c2.rbxcdn.com",
    "c3.rbxcdn.com",
    "c4.rbxcdn.com",
    "c5.rbxcdn.com",
    "c6.rbxcdn.com",
    "c7.rbxcdn.com",
    // Thumbnail/avatar-image and asset-payload CDN edges. assetdelivery returns
    // payload URLs on fts.rbxcdn.com; thumbnails returns image URLs on
    // tr/t0-t7.rbxcdn.com. Pinning these keeps cutscene/texture/clothing loads
    // off the relay under Route Assist (any other *.rbxcdn.com host is still
    // caught direct at runtime via SNI - see is_asset_direct_domain).
    "tr.rbxcdn.com",
    "fts.rbxcdn.com",
    "t0.rbxcdn.com",
    "t1.rbxcdn.com",
    "t2.rbxcdn.com",
    "t3.rbxcdn.com",
    "t4.rbxcdn.com",
    "t5.rbxcdn.com",
    "t6.rbxcdn.com",
    "t7.rbxcdn.com",
    "images.rbxcdn.com",
    "css.rbxcdn.com",
    // Roblox account verification/FunCaptcha. Arkose can load the challenge
    // script, iframe, verification API, and failover status endpoint from
    // separate exact hosts; Full Country Ban must relay all of them.
    "cdn.arkoselabs.com",
    "client-api.arkoselabs.com",
    "roblox-api.arkoselabs.com",
    "roblox-verify.arkoselabs.com",
    "status.arkoselabs.com",
];

fn hosts_path() -> PathBuf {
    PathBuf::from(r"C:\Windows\System32\drivers\etc\hosts")
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HostOverride {
    ip: Ipv4Addr,
    domain: String,
}

#[derive(Debug, Deserialize)]
struct DohJsonResponse {
    #[serde(rename = "Status")]
    status: u32,
    #[serde(rename = "Answer", default)]
    answer: Vec<DohJsonAnswer>,
}

#[derive(Debug, Deserialize)]
struct DohJsonAnswer {
    #[serde(rename = "type")]
    record_type: u16,
    data: String,
}

/// Resolve and append Roblox bootstrap overrides to the Windows hosts file.
///
/// Existing SwiftTunnel entries are removed first (idempotent).
///
/// `country_ban_bypass` (FULL bypass): relay every pinned Roblox host —
/// control plane, settings, and asset/CDN — because in a fully-blocked
/// country none of them are reachable directly.
pub async fn apply_bootstrap_overrides(country_ban_bypass: bool) -> Result<(), String> {
    // Full bypass relays every Roblox host. Lock that routing decision in BEFORE
    // the fallible DoH resolution below. Under a full block the censor commonly
    // blocks public DoH too, so resolution can fail — and if it does, we must
    // still be in country-ban routing. Otherwise the country-ban flag stays
    // unset, runtime SNI-learning treats the session like Route Assist, and it
    // demotes clientsettings/asset hosts onto the (censored) direct path
    // mid-session: they relay once, then get RST'd — the "plays 20s then dies"
    // report. Setting the flag up front (and clearing any stale direct-only pins
    // a prior Route Assist/partial session left behind) keeps those hosts on the
    // relay even when we get zero pins; recognized Roblox/strapper flows relay on
    // process identity alone, so the pins are an optimization, not a prerequisite.
    if country_ban_bypass {
        enter_country_ban_routing();
    }

    let resolved = resolve_bootstrap_overrides().await?;
    // Route Assist (and PARTIAL bypass, which shares this classification)
    // keeps heavy asset/CDN hosts, launch-critical settings hosts, and Roblox
    // UI/social/chat/avatar APIs DIRECT for fast textures and reliable in-game
    // menus; only the region/join control plane relays. FULL bypass relays
    // everything.
    //
    // In the Route Assist/Partial case, only relayed control-plane hosts are
    // written to hosts. Direct hosts still contribute to the direct-only IP set,
    // but they use the user's normal DNS path so stale SwiftTunnel pins cannot
    // break Roblox app startup/home loading on Vietnam-style partial blocks.
    let (overrides, active_ips, direct_only_ips) = if country_ban_bypass {
        let (active, direct_only) = country_ban_split_ips_from_overrides(&resolved);
        (resolved, active, direct_only)
    } else {
        allocate_route_assist_pins(resolved)
    };

    if let Ok(mut last) = last_applied_overrides().write() {
        *last = overrides.clone();
    }
    tokio::task::spawn_blocking(move || write_overrides(&overrides))
        .await
        .map_err(|e| format!("Failed to join hosts repair task: {e}"))??;

    COUNTRY_BAN_BYPASS_ROUTING.store(country_ban_bypass, Ordering::Relaxed);
    set_active_bootstrap_ips(active_ips);
    set_direct_only_bootstrap_ips(direct_only_ips);
    Ok(())
}

/// Merge relay-resolved Roblox IPs into the hosts-file pins and the active
/// (relayed) IP set. The relay resolves Roblox's real IPs from outside the
/// censorship, so this is the fallback for full country-ban when local DoH is
/// blocked/poisoned: without it the player connects to poisoned addresses the
/// relay can't reach ("problem reaching our servers"). Every merged IP becomes
/// an active pin — full bypass relays every Roblox host.
pub async fn apply_relay_resolved_overrides(
    resolved: std::collections::HashMap<String, Vec<Ipv4Addr>>,
) -> Result<(), String> {
    let mut new_entries: Vec<HostOverride> = Vec::new();
    let mut new_ips: HashSet<Ipv4Addr> = HashSet::new();
    for (domain, ips) in resolved {
        for ip in ips.into_iter().take(MAX_PINNED_IPS_PER_DOMAIN) {
            new_entries.push(HostOverride {
                ip,
                domain: domain.clone(),
            });
            new_ips.insert(ip);
        }
    }
    if new_entries.is_empty() {
        return Ok(());
    }

    // Merge with the pins already written (DoH results), de-duping by (domain, ip).
    let existing = last_applied_overrides()
        .read()
        .map(|g| g.clone())
        .unwrap_or_default();
    let mut seen: HashSet<(String, Ipv4Addr)> = HashSet::new();
    let mut merged: Vec<HostOverride> = Vec::with_capacity(existing.len() + new_entries.len());
    for entry in existing.into_iter().chain(new_entries.into_iter()) {
        if seen.insert((entry.domain.to_ascii_lowercase(), entry.ip)) {
            merged.push(entry);
        }
    }

    let merged_for_write = merged.clone();
    tokio::task::spawn_blocking(move || write_overrides(&merged_for_write))
        .await
        .map_err(|e| format!("Failed to join relay-resolved hosts write: {e}"))??;

    if let Ok(mut last) = last_applied_overrides().write() {
        *last = merged;
    }
    if let Ok(mut active) = active_bootstrap_ips().write() {
        active.extend(new_ips);
    }
    Ok(())
}

/// Enter full country-ban routing: mark the session as relaying every Roblox
/// host and drop any stale direct-only pins from a prior Route Assist/partial
/// session. Idempotent. Kept separate from [`apply_bootstrap_overrides`] so this
/// routing decision survives a DoH-resolution failure (which returns early) and
/// is unit-testable without touching the network.
fn enter_country_ban_routing() {
    COUNTRY_BAN_BYPASS_ROUTING.store(true, Ordering::Relaxed);
    set_direct_only_bootstrap_ips(HashSet::new());
}

pub fn is_active_bootstrap_ip(ip: Ipv4Addr) -> bool {
    active_bootstrap_ips()
        .read()
        .map(|ips| ips.contains(&ip))
        .unwrap_or(false)
}

pub fn is_direct_only_bootstrap_ip(ip: Ipv4Addr) -> bool {
    direct_only_bootstrap_ips()
        .read()
        .map(|ips| ips.contains(&ip))
        .unwrap_or(false)
}

pub fn is_country_ban_bypass_routing_active() -> bool {
    COUNTRY_BAN_BYPASS_ROUTING.load(Ordering::Relaxed)
}

/// Record that `ip` serves a host that should stay DIRECT under Route Assist —
/// either a launch-critical settings host or a heavy asset/CDN host (any
/// `*.rbxcdn.com`) — learned from the TLS SNI of a flow Route Assist had already
/// relayed (because the connect-time pin was missing, or system DNS handed out a
/// shard not in our list). This is the "stop chasing CDN shard names" path: any
/// `*.rbxcdn.com` flow teaches its IP as direct for next time.
///
/// The flow that taught us keeps its current route — half-moving an
/// established TCP connection would break it. Only NEW connections to `ip` go
/// direct, which is exactly what a Roblox retry/next-asset-fetch needs.
///
/// Returns `true` only when `ip` was newly recorded. Returns `false` (and
/// learns nothing) when `server_name` is neither a launch-critical settings
/// host nor an asset/CDN host, while country-ban bypass is active — that mode
/// relays settings to escape the block and routes assets by the reachability-
/// filtered pins instead — or when `ip` is pinned for a relayed control-plane
/// host. Demoting a control-plane pin because a shared CDN edge also served an
/// asset SNI silently breaks server-region placement and banned-game discovery
/// (the v2.2.x Route Assist regression); pin allocation keeps the sets
/// disjoint, so a hit here means a genuinely shared edge, where relay is the
/// safe side.
pub fn learn_direct_only_bootstrap_ip(server_name: &str, ip: Ipv4Addr) -> bool {
    if !is_route_assist_direct_domain(server_name) {
        return false;
    }
    if COUNTRY_BAN_BYPASS_ROUTING.load(Ordering::Relaxed) {
        return false;
    }
    if is_active_bootstrap_ip(ip) {
        debug!(
            "Route Assist: not learning {server_name} at {ip} as direct - the IP is \
             pinned for a relayed control-plane host (shared edge)"
        );
        return false;
    }

    match direct_only_bootstrap_ips().write() {
        Ok(mut direct_only) => direct_only.insert(ip),
        Err(e) => {
            warn!("Failed to learn direct-only Roblox bootstrap IP {ip}: {e}");
            false
        }
    }
}

async fn resolve_bootstrap_overrides() -> Result<Vec<HostOverride>, String> {
    let client = reqwest::Client::builder()
        .timeout(DNS_REPAIR_TIMEOUT)
        .build()
        .map_err(|e| format!("Failed to build DNS repair client: {e}"))?;

    let mut overrides = Vec::new();
    let mut failures = Vec::new();

    drain_domain_lookups(
        spawn_domain_lookups(&client, ROBLOX_BOOTSTRAP_DOMAINS.iter().copied()),
        DNS_REPAIR_TOTAL_TIMEOUT,
        &mut overrides,
        &mut failures,
    )
    .await;

    // The direct-only hosts are the ones a missing pin actually hurts: without
    // their IPs published, Route Assist can relay the launch-critical settings
    // fetches it is supposed to keep direct. Give just those hosts one more
    // bounded pass before giving up on them.
    let missing = missing_direct_only_domains(&overrides);
    if !overrides.is_empty() && !missing.is_empty() {
        warn!(
            "Retrying DNS repair for launch-critical Roblox host(s): {}",
            missing.join(", ")
        );
        drain_domain_lookups(
            spawn_domain_lookups(&client, missing.into_iter()),
            DIRECT_ONLY_RETRY_TOTAL_TIMEOUT,
            &mut overrides,
            &mut failures,
        )
        .await;

        let still_missing = missing_direct_only_domains(&overrides);
        if !still_missing.is_empty() {
            warn!(
                "Launch-critical Roblox settings host(s) unpinned after retry: {}; \
                 Route Assist will learn their IPs from TLS SNI at runtime",
                still_missing.join(", ")
            );
        }
    }

    if overrides.is_empty() {
        return Err(format!(
            "No Roblox bootstrap hosts resolved via DNS-over-HTTPS: {}",
            failures.join("; ")
        ));
    }

    if !failures.is_empty() {
        warn!(
            "Partial Roblox bootstrap DNS repair: {}",
            failures.join("; ")
        );
    }

    Ok(overrides)
}

/// Direct-only domains that have no resolved override yet.
fn missing_direct_only_domains(overrides: &[HostOverride]) -> Vec<&'static str> {
    DIRECT_ONLY_BOOTSTRAP_DOMAINS
        .iter()
        .filter(|domain| {
            !overrides
                .iter()
                .any(|entry| entry.domain.eq_ignore_ascii_case(domain))
        })
        .copied()
        .collect()
}

fn spawn_domain_lookups(
    client: &reqwest::Client,
    domains: impl Iterator<Item = &'static str>,
) -> FuturesUnordered<
    impl std::future::Future<Output = (&'static str, Result<Vec<Ipv4Addr>, String>)>,
> {
    domains
        .map(|domain| {
            let client = client.clone();
            async move { (domain, resolve_reachable_domain_ips(&client, domain).await) }
        })
        .collect()
}

/// Run a batch of domain lookups under one total deadline, appending resolved
/// IPs to `overrides` and failure descriptions to `failures`.
async fn drain_domain_lookups<F>(
    mut lookups: FuturesUnordered<F>,
    total_timeout: Duration,
    overrides: &mut Vec<HostOverride>,
    failures: &mut Vec<String>,
) where
    F: std::future::Future<Output = (&'static str, Result<Vec<Ipv4Addr>, String>)>,
{
    let total_deadline = tokio::time::sleep(total_timeout);
    tokio::pin!(total_deadline);

    loop {
        tokio::select! {
            biased;

            result = lookups.next() => {
                match result {
                    Some((domain, Ok(ips))) => {
                        for ip in ips {
                            overrides.push(HostOverride {
                                ip,
                                domain: domain.to_string(),
                            });
                        }
                    }
                    Some((_domain, Err(e))) => failures.push(e),
                    None => break,
                }
            }
            _ = &mut total_deadline => {
                let remaining = lookups.len();
                if remaining > 0 {
                    failures.push(format!(
                        "{} Roblox bootstrap DNS lookup(s) exceeded {}s total timeout",
                        remaining,
                        total_timeout.as_secs()
                    ));
                }
                break;
            }
        }
    }
}

/// Resolve a domain and keep only the IPs that are actually reachable on :443
/// from THIS machine, preserving DNS preference order.
///
/// Returns `Err` when the domain cannot be resolved at all, or when none of the
/// resolved IPs are reachable. Callers treat that as "skip pinning this domain"
/// and fall back to normal system DNS — so we never pin a dead IP, which is what
/// used to break Roblox bootstrappers (clientsettings.roblox.com timeouts).
async fn resolve_reachable_domain_ips(
    client: &reqwest::Client,
    domain: &str,
) -> Result<Vec<Ipv4Addr>, String> {
    let candidates = resolve_domain_ips(client, domain).await?;
    let reachable = filter_reachable_ips(candidates).await;
    if reachable.is_empty() {
        return Err(format!(
            "{domain} resolved but no IP answered on :{ROBLOX_HTTPS_PORT}"
        ));
    }
    Ok(reachable)
}

/// Resolve a domain to up to `MAX_PINNED_IPS_PER_DOMAIN` usable public IPv4s via
/// DNS-over-HTTPS. Returns the first resolver's usable answers (deduped, capped).
async fn resolve_domain_ips(
    client: &reqwest::Client,
    domain: &str,
) -> Result<Vec<Ipv4Addr>, String> {
    let mut failures = Vec::new();

    for resolver in DNS_REPAIR_RESOLVERS {
        let url = build_doh_url(resolver, domain);
        let response = match client
            .get(&url)
            .header("accept", "application/dns-json")
            .send()
            .await
        {
            Ok(response) => response,
            Err(e) => {
                failures.push(format!("{resolver}: request failed: {e}"));
                continue;
            }
        };

        if !response.status().is_success() {
            failures.push(format!("{resolver}: HTTP {}", response.status()));
            continue;
        }

        let body = match response.text().await {
            Ok(body) => body,
            Err(e) => {
                failures.push(format!("{resolver}: response read failed: {e}"));
                continue;
            }
        };

        match parse_usable_a_records(&body) {
            Ok(ips) if !ips.is_empty() => {
                return Ok(dedup_and_cap_ips(ips, MAX_PINNED_IPS_PER_DOMAIN));
            }
            Ok(_) => failures.push(format!("{resolver}: no usable public A records")),
            Err(e) => failures.push(format!("{resolver}: {e}")),
        }
    }

    Err(format!(
        "{domain} could not be repaired via DNS-over-HTTPS ({})",
        failures.join("; ")
    ))
}

/// Deduplicate IPs (preserving first-seen order) and cap the count.
fn dedup_and_cap_ips(ips: Vec<Ipv4Addr>, cap: usize) -> Vec<Ipv4Addr> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for ip in ips {
        if seen.insert(ip) {
            out.push(ip);
            if out.len() >= cap {
                break;
            }
        }
    }
    out
}

/// Probe each candidate IP on :443 concurrently and return the reachable ones,
/// preserving the original (DNS preference) order so the most-preferred
/// reachable IP is pinned first.
///
/// This runs once at connect time, off the packet-forwarding path, so it never
/// affects tunneling throughput or latency.
async fn filter_reachable_ips(ips: Vec<Ipv4Addr>) -> Vec<Ipv4Addr> {
    filter_reachable_ips_on_port(ips, ROBLOX_HTTPS_PORT).await
}

async fn filter_reachable_ips_on_port(ips: Vec<Ipv4Addr>, port: u16) -> Vec<Ipv4Addr> {
    if ips.is_empty() {
        return Vec::new();
    }

    let mut probes: FuturesUnordered<_> = ips
        .into_iter()
        .enumerate()
        .map(|(idx, ip)| async move { (idx, ip, probe_tcp_reachable(ip, port).await) })
        .collect();

    let mut reachable: Vec<(usize, Ipv4Addr)> = Vec::new();
    while let Some((idx, ip, ok)) = probes.next().await {
        if ok {
            reachable.push((idx, ip));
        }
    }

    reachable.sort_by_key(|(idx, _)| *idx);
    reachable.into_iter().map(|(_, ip)| ip).collect()
}

/// Returns `true` if a TCP connection to `ip:port` completes within the probe
/// timeout. A timeout or refusal means "not reachable from this machine".
async fn probe_tcp_reachable(ip: Ipv4Addr, port: u16) -> bool {
    let addr = SocketAddr::from((ip, port));
    matches!(
        tokio::time::timeout(
            REACHABILITY_PROBE_TIMEOUT,
            tokio::net::TcpStream::connect(addr),
        )
        .await,
        Ok(Ok(_))
    )
}

fn write_overrides(overrides: &[HostOverride]) -> Result<(), String> {
    if overrides.is_empty() {
        return Err("No hosts overrides to write".to_string());
    }

    let path = hosts_path();

    let content =
        fs::read_to_string(&path).map_err(|e| format!("Failed to read hosts file: {e}"))?;

    let clean = remove_marker_block(&content);
    let block = build_hosts_block(overrides);

    let mut out = clean;
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(&block);

    fs::write(&path, &out).map_err(|e| format!("Failed to write hosts file: {e}"))?;

    info!(
        "Applied {} Roblox bootstrap DNS override(s) to hosts file",
        overrides.len()
    );

    flush_dns_cache();
    Ok(())
}

/// Synchronous version used from startup recovery and `Drop`.
/// Call `remove_overrides_async` from async contexts.
pub fn remove_overrides() -> Result<(), String> {
    let result = remove_overrides_inner();
    clear_bootstrap_ip_sets();
    result
}

fn remove_overrides_inner() -> Result<(), String> {
    let path = hosts_path();

    let content =
        fs::read_to_string(&path).map_err(|e| format!("Failed to read hosts file: {e}"))?;

    let clean = remove_marker_block(&content);

    if clean != content {
        fs::write(&path, &clean).map_err(|e| format!("Failed to write hosts file: {e}"))?;
        info!("Removed Roblox proxy overrides from hosts file");
        flush_dns_cache();
    }

    Ok(())
}

fn active_bootstrap_ips() -> &'static RwLock<HashSet<Ipv4Addr>> {
    ACTIVE_BOOTSTRAP_IPS.get_or_init(|| RwLock::new(HashSet::new()))
}

fn direct_only_bootstrap_ips() -> &'static RwLock<HashSet<Ipv4Addr>> {
    DIRECT_ONLY_BOOTSTRAP_IPS.get_or_init(|| RwLock::new(HashSet::new()))
}

fn set_active_bootstrap_ips(ips: HashSet<Ipv4Addr>) {
    match active_bootstrap_ips().write() {
        Ok(mut active) => *active = ips,
        Err(e) => warn!("Failed to publish Roblox bootstrap route IPs: {e}"),
    }
}

fn set_direct_only_bootstrap_ips(ips: HashSet<Ipv4Addr>) {
    match direct_only_bootstrap_ips().write() {
        Ok(mut direct_only) => *direct_only = ips,
        Err(e) => warn!("Failed to publish direct-only Roblox bootstrap IPs: {e}"),
    }
}

/// Allocate Route Assist pins so relayed control-plane hosts and direct hosts
/// (launch-critical settings + asset/CDN) don't share routing IPs, then split
/// the kept pins into (hosts-file overrides, relayed-active IPs, direct-only
/// IPs).
///
/// Roblox fronts many hostnames with shared edges (its own 128.116.x edge and
/// CloudFront POPs), so `gamejoin.roblox.com` (must relay for region steering
/// and game discovery) can resolve to the same IP as `assetgame.roblox.com`
/// (must stay direct for fast textures). Routing is per-IP, so a shared pin
/// forces one side onto the wrong path. Since we control the hosts file, the
/// conflict is resolved at pin time: a domain whose candidate list contains
/// both shared and unshared IPs keeps only the unshared ones, so each side
/// gets its own edge and BOTH behaviors hold.
///
/// Two classes of pin are written to the hosts file: the relayed control-plane
/// hosts, AND the launch-critical settings + auth hosts
/// (`DIRECT_ONLY_BOOTSTRAP_DOMAINS`) at a *de-conflicted* direct IP. The broad
/// UI/chat/avatar/asset set is deliberately left unwritten: pinning those to
/// public DoH results can send the app to stale or wrong CDN/API edges on
/// Vietnam-style networks, and a mis-relayed asset/UI fetch is merely slow.
///
/// Why the launch-critical/auth subset MUST be pinned (the v2.5.11 regression
/// this fixes): when these resolve via the user's own DNS, Roblox's shared
/// anycast edges (128.116.0.0/17, CloudFront) can hand a *direct* host an IP
/// that is also a relayed control-plane pin. The interceptor routes per-IP, so
/// it then relays a flow that must stay direct — sign-in challenged from a
/// foreign relay IP ("can't sign in"), or "Failed to apply critical settings"
/// at launch — and `learn_direct_only_bootstrap_ip` is forbidden from rescuing
/// an active IP, so it stays broken all session. Pinning the de-conflicted IP
/// makes the OS resolve these to a guaranteed direct-only edge.
///
/// De-confliction is load-bearing: a launch-critical/auth entry is only written
/// when its IP made it into `direct_only` (i.e. is NOT also an active/relay
/// edge). On a genuinely shared edge (every candidate conflicts) relay still
/// wins and the host is left to the user's DNS rather than pinned at a relayed
/// IP. The remaining direct IPs are still published into the direct-only set so
/// the interceptor avoids pulling those destinations into the relay.
///
/// NOTE: `resolve_reachable_domain_ips` only confirms a `:443` TCP connect, not
/// that the edge serves fresh/correct content — a DNS-poisoned IP that ACKs
/// :443 would pass. That bounds, but does not eliminate, the stale-edge risk;
/// it is acceptable here because it is confined to launch-critical hosts that
/// are otherwise broken, and FULL bypass (the censored case) never reaches this
/// function.
///
/// For an IP that is still shared after allocation (a domain whose every
/// candidate conflicts), RELAY wins — the same precedence country-ban mode
/// uses. Control-plane traffic leaking direct silently breaks server-region
/// placement and banned-game discovery (the v2.2.3/v2.2.4 Route Assist
/// regression); a relayed asset fetch is merely slower.
fn allocate_route_assist_pins(
    overrides: Vec<HostOverride>,
) -> (Vec<HostOverride>, HashSet<Ipv4Addr>, HashSet<Ipv4Addr>) {
    let direct_pool: HashSet<Ipv4Addr> = overrides
        .iter()
        .filter(|entry| is_route_assist_direct_domain(&entry.domain))
        .map(|entry| entry.ip)
        .collect();
    let active_pool: HashSet<Ipv4Addr> = overrides
        .iter()
        .filter(|entry| !is_route_assist_direct_domain(&entry.domain))
        .map(|entry| entry.ip)
        .collect();

    let mut domains: Vec<&str> = Vec::new();
    for entry in &overrides {
        if !domains
            .iter()
            .any(|d| d.eq_ignore_ascii_case(&entry.domain))
        {
            domains.push(&entry.domain);
        }
    }

    let mut kept: Vec<HostOverride> = Vec::with_capacity(overrides.len());
    for domain in domains {
        let other_pool = if is_route_assist_direct_domain(domain) {
            &active_pool
        } else {
            &direct_pool
        };
        let candidates: Vec<&HostOverride> = overrides
            .iter()
            .filter(|entry| entry.domain.eq_ignore_ascii_case(domain))
            .collect();
        let conflict_free: Vec<&HostOverride> = candidates
            .iter()
            .copied()
            .filter(|entry| !other_pool.contains(&entry.ip))
            .collect();
        if conflict_free.is_empty() {
            debug!(
                "Route Assist pins: every candidate IP for {domain} is shared with the \
                 other routing class; keeping shared pins (relay wins per-IP conflicts)"
            );
            kept.extend(candidates.into_iter().cloned());
        } else {
            if conflict_free.len() < candidates.len() {
                debug!(
                    "Route Assist pins: dropped {} shared candidate IP(s) for {domain}",
                    candidates.len() - conflict_free.len()
                );
            }
            kept.extend(conflict_free.into_iter().cloned());
        }
    }

    let active: HashSet<Ipv4Addr> = kept
        .iter()
        .filter(|entry| !is_route_assist_direct_domain(&entry.domain))
        .map(|entry| entry.ip)
        .collect();
    let direct_only: HashSet<Ipv4Addr> = kept
        .iter()
        .filter(|entry| is_route_assist_direct_domain(&entry.domain))
        .map(|entry| entry.ip)
        .filter(|ip| !active.contains(ip))
        .collect();

    // Write the relayed control-plane pins, plus the launch-critical settings +
    // auth pins at a de-conflicted direct IP (one that survived into
    // `direct_only`, so never a relayed edge). The broad UI/asset direct set is
    // left to the user's DNS.
    let writable_overrides = kept
        .iter()
        .filter(|entry| {
            !is_route_assist_direct_domain(&entry.domain)
                || (is_direct_only_bootstrap_domain(&entry.domain)
                    && direct_only.contains(&entry.ip))
        })
        .cloned()
        .collect();

    (writable_overrides, active, direct_only)
}

/// FULL country-ban bypass: relay EVERY pinned Roblox host — control plane,
/// settings, and asset/CDN alike. This mode exists for countries where the
/// whole platform is blocked (e.g. Egypt), and there the asset CDN is blocked
/// too: keeping assets "direct" meant they simply never loaded, so games died
/// seconds after join ("plays for 20s", "assets don't load"). Bandwidth-
/// conscious asset splitting belongs to Route Assist and PARTIAL bypass, whose
/// users can actually reach the CDN directly.
fn country_ban_split_ips_from_overrides(
    overrides: &[HostOverride],
) -> (HashSet<Ipv4Addr>, HashSet<Ipv4Addr>) {
    let active: HashSet<Ipv4Addr> = overrides.iter().map(|entry| entry.ip).collect();
    (active, HashSet::new())
}

fn is_direct_only_bootstrap_domain(domain: &str) -> bool {
    DIRECT_ONLY_BOOTSTRAP_DOMAINS
        .iter()
        .any(|direct_only| domain.eq_ignore_ascii_case(direct_only))
}

/// Heavy asset/CDN host kept direct in both modes: any `*.rbxcdn.com` shard, or
/// one of the named roblox.com asset entry points. The `*.rbxcdn.com` suffix
/// match means new CDN shard names are covered without editing this list.
fn is_asset_direct_domain(domain: &str) -> bool {
    let d = domain.trim_end_matches('.');
    ASSET_DIRECT_ROBLOX_DOMAINS
        .iter()
        .any(|asset| d.eq_ignore_ascii_case(asset))
        || d.to_ascii_lowercase().ends_with(".rbxcdn.com")
}

fn is_route_assist_relay_domain(domain: &str) -> bool {
    let d = domain.trim_end_matches('.');
    ROUTE_ASSIST_RELAY_DOMAINS
        .iter()
        .any(|relay| d.eq_ignore_ascii_case(relay))
}

/// Direct under Route Assist = every known Roblox helper/UI/asset host except
/// the small region/join relay set.
fn is_route_assist_direct_domain(domain: &str) -> bool {
    let d = domain.trim_end_matches('.');
    if is_route_assist_relay_domain(d) {
        return false;
    }

    is_direct_only_bootstrap_domain(d)
        || is_asset_direct_domain(d)
        || ROBLOX_BOOTSTRAP_DOMAINS
            .iter()
            .any(|known| d.eq_ignore_ascii_case(known))
}

fn clear_bootstrap_ip_sets() {
    COUNTRY_BAN_BYPASS_ROUTING.store(false, Ordering::Relaxed);
    match active_bootstrap_ips().write() {
        Ok(mut active) => active.clear(),
        Err(e) => warn!("Failed to clear Roblox bootstrap route IPs: {e}"),
    }
    match direct_only_bootstrap_ips().write() {
        Ok(mut direct_only) => direct_only.clear(),
        Err(e) => warn!("Failed to clear direct-only Roblox bootstrap IPs: {e}"),
    }
}

#[cfg(test)]
pub(crate) fn set_active_bootstrap_ips_for_test(ips: impl IntoIterator<Item = Ipv4Addr>) {
    set_active_bootstrap_ips(ips.into_iter().collect());
}

#[cfg(test)]
pub(crate) fn set_direct_only_bootstrap_ips_for_test(ips: impl IntoIterator<Item = Ipv4Addr>) {
    set_direct_only_bootstrap_ips(ips.into_iter().collect());
}

#[cfg(test)]
pub(crate) fn clear_active_bootstrap_ips_for_test() {
    clear_bootstrap_ip_sets();
}

#[cfg(test)]
pub(crate) fn set_country_ban_bypass_routing_for_test(active: bool) {
    COUNTRY_BAN_BYPASS_ROUTING.store(active, Ordering::Relaxed);
}

/// Serializes every test (in this crate) that touches the process-global
/// bootstrap IP sets, across modules. Tests must hold this for their entire
/// mutate-assert-clear sequence.
#[cfg(test)]
pub(crate) static BOOTSTRAP_IP_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Remove any SwiftTunnel Roblox Proxy entries without blocking a Tokio worker.
pub async fn remove_overrides_async() -> Result<(), String> {
    tokio::task::spawn_blocking(remove_overrides)
        .await
        .map_err(|e| format!("Failed to join hosts cleanup task: {e}"))?
}

/// Called on app startup to clean up entries left by a previous crash.
pub fn recover_stale() {
    if let Err(e) = remove_overrides() {
        warn!("Failed to recover stale hosts entries: {e}");
    }
}

/// Returns `true` if the hosts file currently contains SwiftTunnel entries.
pub fn has_overrides() -> bool {
    let path = hosts_path();
    match fs::read_to_string(&path) {
        Ok(content) => content.contains(MARKER_START),
        Err(_) => false,
    }
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

/// Remove the marker-delimited block from the hosts file content.
fn remove_marker_block(content: &str) -> String {
    let mut result = String::with_capacity(content.len());
    let mut inside_block = false;

    for line in content.lines() {
        let trimmed = line.trim();

        if trimmed == MARKER_START {
            inside_block = true;
            continue;
        }
        if trimmed == MARKER_END {
            inside_block = false;
            continue;
        }

        if !inside_block {
            result.push_str(line);
            result.push('\n');
        }
    }

    // Collapse trailing blank lines to a single newline
    let trimmed = result.trim_end_matches('\n');
    if trimmed.is_empty() {
        return String::new();
    }
    let mut out = trimmed.to_string();
    out.push('\n');
    out
}

fn build_hosts_block(overrides: &[HostOverride]) -> String {
    let mut block = String::new();
    block.push_str(MARKER_START);
    block.push('\n');
    for entry in overrides {
        block.push_str(&format!("{} {}\n", entry.ip, entry.domain));
    }
    block.push_str(MARKER_END);
    block.push('\n');
    block
}

fn build_doh_url(resolver: &str, domain: &str) -> String {
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("name", domain)
        .append_pair("type", "A")
        .finish();
    format!("{resolver}?{query}")
}

fn parse_usable_a_records(body: &str) -> Result<Vec<Ipv4Addr>, String> {
    let response: DohJsonResponse =
        serde_json::from_str(body).map_err(|e| format!("invalid DNS JSON: {e}"))?;

    if response.status != 0 {
        return Err(format!("DNS status {}", response.status));
    }

    Ok(response
        .answer
        .into_iter()
        .filter(|answer| answer.record_type == 1)
        .filter_map(|answer| answer.data.parse::<Ipv4Addr>().ok())
        .filter(|ip| is_usable_public_ipv4(*ip))
        .collect())
}

fn is_usable_public_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || octets[0] == 0
        || octets[0] >= 240
        || (octets[0] == 100 && (64..=127).contains(&octets[1]))
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
        || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
        || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
        || (octets[0] == 198 && (18..=19).contains(&octets[1])))
}

/// Flush the Windows DNS resolver cache (`ipconfig /flushdns`).
fn flush_dns_cache() {
    let output = crate::hidden_command("ipconfig").arg("/flushdns").output();

    match output {
        Ok(o) if o.status.success() => debug!("DNS cache flushed"),
        Ok(o) => warn!(
            "ipconfig /flushdns exited {}: {}",
            o.status,
            String::from_utf8_lossy(&o.stderr)
        ),
        Err(e) => warn!("Failed to run ipconfig /flushdns: {e}"),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remove_marker_block_empty_input() {
        assert_eq!(remove_marker_block(""), "");
    }

    #[test]
    fn remove_marker_block_no_markers() {
        let input = "127.0.0.1 localhost\n::1 localhost\n";
        assert_eq!(remove_marker_block(input), input);
    }

    #[test]
    fn remove_marker_block_with_entries() {
        let input = "\
127.0.0.1 localhost
# SwiftTunnel Roblox Proxy - START
127.66.0.1 clientsettings.roblox.com
127.66.0.1 roblox.com
# SwiftTunnel Roblox Proxy - END
::1 localhost
";
        let expected = "127.0.0.1 localhost\n::1 localhost\n";
        assert_eq!(remove_marker_block(input), expected);
    }

    #[test]
    fn remove_marker_block_at_end_of_file() {
        let input = "\
127.0.0.1 localhost
# SwiftTunnel Roblox Proxy - START
127.66.0.1 clientsettings.roblox.com
# SwiftTunnel Roblox Proxy - END
";
        let expected = "127.0.0.1 localhost\n";
        assert_eq!(remove_marker_block(input), expected);
    }

    #[test]
    fn remove_marker_block_only_markers() {
        let input = "\
# SwiftTunnel Roblox Proxy - START
127.66.0.1 clientsettings.roblox.com
# SwiftTunnel Roblox Proxy - END
";
        assert_eq!(remove_marker_block(input), "");
    }

    #[test]
    fn domain_list_is_not_empty() {
        assert!(!ROBLOX_BOOTSTRAP_DOMAINS.is_empty());
    }

    #[test]
    fn domain_list_contains_launch_entries() {
        assert!(ROBLOX_BOOTSTRAP_DOMAINS.contains(&"clientsettings.roblox.com"));
        assert!(ROBLOX_BOOTSTRAP_DOMAINS.contains(&"clientsettingscdn.roblox.com"));
        assert!(ROBLOX_BOOTSTRAP_DOMAINS.contains(&"clientsettings.api.roblox.com"));
        assert!(ROBLOX_BOOTSTRAP_DOMAINS.contains(&"versioncompatibility.api.roblox.com"));
        assert!(ROBLOX_BOOTSTRAP_DOMAINS.contains(&"www.roblox.com"));
        assert!(ROBLOX_BOOTSTRAP_DOMAINS.contains(&"api.roblox.com"));
        assert!(ROBLOX_BOOTSTRAP_DOMAINS.contains(&"apis.roblox.com"));
        assert!(ROBLOX_BOOTSTRAP_DOMAINS.contains(&"auth.roblox.com"));
        assert!(ROBLOX_BOOTSTRAP_DOMAINS.contains(&"avatar.roblox.com"));
        assert!(ROBLOX_BOOTSTRAP_DOMAINS.contains(&"badges.roblox.com"));
        assert!(ROBLOX_BOOTSTRAP_DOMAINS.contains(&"catalog.roblox.com"));
        assert!(ROBLOX_BOOTSTRAP_DOMAINS.contains(&"contacts.roblox.com"));
        assert!(ROBLOX_BOOTSTRAP_DOMAINS.contains(&"inventory.roblox.com"));
        assert!(ROBLOX_BOOTSTRAP_DOMAINS.contains(&"economy.roblox.com"));
        assert!(ROBLOX_BOOTSTRAP_DOMAINS.contains(&"followings.roblox.com"));
        assert!(ROBLOX_BOOTSTRAP_DOMAINS.contains(&"gameinternationalization.roblox.com"));
        assert!(ROBLOX_BOOTSTRAP_DOMAINS.contains(&"gamejoin.roblox.com"));
        assert!(ROBLOX_BOOTSTRAP_DOMAINS.contains(&"groups.roblox.com"));
        assert!(ROBLOX_BOOTSTRAP_DOMAINS.contains(&"lms.roblox.com"));
        assert!(ROBLOX_BOOTSTRAP_DOMAINS.contains(&"notifications.roblox.com"));
        assert!(ROBLOX_BOOTSTRAP_DOMAINS.contains(&"assetgame.roblox.com"));
        assert!(ROBLOX_BOOTSTRAP_DOMAINS.contains(&"chatsite.roblox.com"));
        assert!(ROBLOX_BOOTSTRAP_DOMAINS.contains(&"setup.rbxcdn.com"));
        assert!(ROBLOX_BOOTSTRAP_DOMAINS.contains(&"js.rbxcdn.com"));
        assert!(ROBLOX_BOOTSTRAP_DOMAINS.contains(&"static.rbxcdn.com"));
        for raw_cdn_domain in [
            "c0.rbxcdn.com",
            "c1.rbxcdn.com",
            "c2.rbxcdn.com",
            "c3.rbxcdn.com",
            "c4.rbxcdn.com",
            "c5.rbxcdn.com",
            "c6.rbxcdn.com",
            "c7.rbxcdn.com",
        ] {
            assert!(ROBLOX_BOOTSTRAP_DOMAINS.contains(&raw_cdn_domain));
            assert!(is_asset_direct_domain(raw_cdn_domain));
        }
        assert!(ROBLOX_BOOTSTRAP_DOMAINS.contains(&"captcha.roblox.com"));
        assert!(ROBLOX_BOOTSTRAP_DOMAINS.contains(&"cdn.arkoselabs.com"));
        assert!(ROBLOX_BOOTSTRAP_DOMAINS.contains(&"client-api.arkoselabs.com"));
        assert!(ROBLOX_BOOTSTRAP_DOMAINS.contains(&"roblox-api.arkoselabs.com"));
        assert!(ROBLOX_BOOTSTRAP_DOMAINS.contains(&"roblox-verify.arkoselabs.com"));
        assert!(ROBLOX_BOOTSTRAP_DOMAINS.contains(&"status.arkoselabs.com"));
    }

    #[test]
    fn domain_list_stays_allowlisted_and_exact() {
        assert_eq!(ROBLOX_BOOTSTRAP_DOMAINS.len(), 64);
        assert!(!ROBLOX_BOOTSTRAP_DOMAINS.contains(&"roblox.com"));
        assert!(!ROBLOX_BOOTSTRAP_DOMAINS.contains(&"rbxcdn.com"));
        assert!(!ROBLOX_BOOTSTRAP_DOMAINS.contains(&"arkoselabs.com"));
        assert!(!ROBLOX_BOOTSTRAP_DOMAINS.contains(&"evilroblox.com"));
        assert!(!ROBLOX_BOOTSTRAP_DOMAINS.contains(&"roblox.com.evil.test"));
    }

    #[test]
    fn domain_list_has_no_duplicates() {
        let unique: std::collections::HashSet<_> = ROBLOX_BOOTSTRAP_DOMAINS.iter().collect();
        assert_eq!(unique.len(), ROBLOX_BOOTSTRAP_DOMAINS.len());
    }

    #[test]
    fn route_assist_keeps_settings_and_assets_direct_and_relays_control_plane() {
        let overrides = vec![
            HostOverride {
                ip: Ipv4Addr::new(65, 9, 168, 80),
                domain: "clientsettingscdn.roblox.com".to_string(),
            },
            HostOverride {
                ip: Ipv4Addr::new(128, 116, 46, 3),
                domain: "clientsettings.roblox.com".to_string(),
            },
            HostOverride {
                ip: Ipv4Addr::new(128, 116, 121, 3),
                domain: "www.roblox.com".to_string(),
            },
            HostOverride {
                ip: Ipv4Addr::new(128, 116, 121, 4),
                domain: "gamejoin.roblox.com".to_string(),
            },
            HostOverride {
                ip: Ipv4Addr::new(128, 116, 121, 5),
                domain: "lms.roblox.com".to_string(),
            },
            HostOverride {
                ip: Ipv4Addr::new(23, 61, 202, 142),
                domain: "setup.rbxcdn.com".to_string(),
            },
            HostOverride {
                ip: Ipv4Addr::new(65, 9, 168, 81),
                domain: "apis.roblox.com".to_string(),
            },
            HostOverride {
                ip: Ipv4Addr::new(65, 9, 168, 82),
                domain: "chat.roblox.com".to_string(),
            },
            HostOverride {
                ip: Ipv4Addr::new(65, 9, 168, 83),
                domain: "avatar.roblox.com".to_string(),
            },
        ];

        let (kept, active_ips, direct_ips) = allocate_route_assist_pins(overrides);

        // No shared edges here: the relayed control-plane hosts AND the
        // launch-critical settings hosts are written to the hosts file (the
        // latter at their de-conflicted direct IP). The broad UI host
        // (www.roblox.com) and the asset/CDN host (setup.rbxcdn.com) are left
        // to the user's DNS, but still published in the direct-only set.
        assert_eq!(kept.len(), 4);
        assert!(
            kept.iter()
                .any(|entry| entry.domain == "gamejoin.roblox.com")
        );
        assert!(kept.iter().any(|entry| entry.domain == "lms.roblox.com"));
        assert!(!kept.iter().any(|entry| entry.domain == "apis.roblox.com"));
        // Launch-critical settings hosts ARE re-pinned direct (v2.5.11 fix).
        assert!(
            kept.iter()
                .any(|entry| entry.domain == "clientsettingscdn.roblox.com"
                    && entry.ip == Ipv4Addr::new(65, 9, 168, 80))
        );
        assert!(
            kept.iter()
                .any(|entry| entry.domain == "clientsettings.roblox.com"
                    && entry.ip == Ipv4Addr::new(128, 116, 46, 3))
        );
        // Broad UI/auth/API + asset hosts stay unwritten (user DNS picks the local edge).
        assert!(!kept.iter().any(|entry| entry.domain == "www.roblox.com"));
        assert!(!kept.iter().any(|entry| entry.domain == "apis.roblox.com"));
        assert!(!kept.iter().any(|entry| entry.domain == "setup.rbxcdn.com"));
        // Launch-critical settings hosts stay direct.
        assert!(direct_ips.contains(&Ipv4Addr::new(65, 9, 168, 80)));
        assert!(direct_ips.contains(&Ipv4Addr::new(128, 116, 46, 3)));
        assert!(!active_ips.contains(&Ipv4Addr::new(65, 9, 168, 80)));
        // Region/join control-plane relays.
        assert!(active_ips.contains(&Ipv4Addr::new(128, 116, 121, 4)));
        assert!(active_ips.contains(&Ipv4Addr::new(128, 116, 121, 5)));
        assert!(!active_ips.contains(&Ipv4Addr::new(65, 9, 168, 81)));
        // UI/social/auth/API/avatar hosts stay direct so Roblox menus, chat,
        // security checks, and player icons do not ride the shared relay NAT.
        assert!(direct_ips.contains(&Ipv4Addr::new(128, 116, 121, 3)));
        assert!(!active_ips.contains(&Ipv4Addr::new(128, 116, 121, 3)));
        assert!(direct_ips.contains(&Ipv4Addr::new(65, 9, 168, 81)));
        assert!(!active_ips.contains(&Ipv4Addr::new(65, 9, 168, 81)));
        assert!(direct_ips.contains(&Ipv4Addr::new(65, 9, 168, 82)));
        assert!(!active_ips.contains(&Ipv4Addr::new(65, 9, 168, 82)));
        assert!(direct_ips.contains(&Ipv4Addr::new(65, 9, 168, 83)));
        assert!(!active_ips.contains(&Ipv4Addr::new(65, 9, 168, 83)));
        // Asset/CDN host (setup.rbxcdn.com) stays DIRECT under Route Assist
        // (the textures/clothing slow-load fix).
        assert!(direct_ips.contains(&Ipv4Addr::new(23, 61, 202, 142)));
        assert!(!active_ips.contains(&Ipv4Addr::new(23, 61, 202, 142)));
    }

    #[test]
    fn route_assist_relays_control_plane_on_unavoidably_shared_edges() {
        // The v2.2.3/v2.2.4 regression: gamejoin.roblox.com (placement) and
        // assetgame.roblox.com (asset endpoint) resolve to the SAME Roblox edge
        // IP with no alternatives. Direct must NOT steal the control-plane pin
        // - relay wins, or region steering and banned-game discovery silently
        // break.
        let shared = Ipv4Addr::new(128, 116, 99, 3);
        let overrides = vec![
            HostOverride {
                ip: shared,
                domain: "gamejoin.roblox.com".to_string(),
            },
            HostOverride {
                ip: shared,
                domain: "assetgame.roblox.com".to_string(),
            },
        ];

        let (kept, active_ips, direct_ips) = allocate_route_assist_pins(overrides);

        assert_eq!(kept.len(), 1);
        assert!(
            kept.iter()
                .all(|entry| entry.domain == "gamejoin.roblox.com")
        );
        assert!(active_ips.contains(&shared));
        assert!(!direct_ips.contains(&shared));
    }

    #[test]
    fn route_assist_repins_auth_direct_at_deconflicted_ip() {
        // auth.roblox.com must stay DIRECT under Route Assist: a fresh sign-in
        // relayed out a foreign relay IP trips Roblox's new-location login
        // defenses ("can't sign in", while already-signed-in users are fine).
        // With a private edge it is written to the hosts file (pinned direct)
        // and published in the direct-only set, never active/relayed.
        let auth_ip = Ipv4Addr::new(128, 116, 70, 9);
        let gamejoin_ip = Ipv4Addr::new(128, 116, 121, 4);
        let overrides = vec![
            HostOverride {
                ip: auth_ip,
                domain: "auth.roblox.com".to_string(),
            },
            HostOverride {
                ip: gamejoin_ip,
                domain: "gamejoin.roblox.com".to_string(),
            },
        ];

        let (kept, active_ips, direct_ips) = allocate_route_assist_pins(overrides);

        assert!(
            kept.iter()
                .any(|e| e.domain == "auth.roblox.com" && e.ip == auth_ip),
            "auth.roblox.com should be re-pinned direct in the hosts file"
        );
        assert!(direct_ips.contains(&auth_ip));
        assert!(!active_ips.contains(&auth_ip));
        // gamejoin still relays.
        assert!(active_ips.contains(&gamejoin_ip));
        assert!(kept.iter().any(|e| e.domain == "gamejoin.roblox.com"));
    }

    #[test]
    fn route_assist_does_not_repin_launch_critical_on_unavoidably_shared_edge() {
        // Mandatory negative case (de-confliction): clientsettings.roblox.com
        // and the relayed gamejoin.roblox.com resolve to the SAME edge with no
        // alternative. Relay wins (control-plane region steering must not
        // break), and the settings host is NOT pinned direct at that relayed IP
        // — pinning it would point a "direct" host at the relay, re-creating the
        // bug in reverse. The host falls back to the user's DNS instead.
        let shared = Ipv4Addr::new(128, 116, 99, 7);
        let overrides = vec![
            HostOverride {
                ip: shared,
                domain: "gamejoin.roblox.com".to_string(),
            },
            HostOverride {
                ip: shared,
                domain: "clientsettings.roblox.com".to_string(),
            },
        ];

        let (kept, active_ips, direct_ips) = allocate_route_assist_pins(overrides);

        assert!(active_ips.contains(&shared));
        assert!(!direct_ips.contains(&shared));
        assert!(
            !kept.iter().any(|e| e.domain == "clientsettings.roblox.com"),
            "a launch-critical host on a genuinely shared edge must not be \
             pinned direct at a relayed IP"
        );
        assert!(
            kept.iter()
                .any(|e| e.domain == "gamejoin.roblox.com" && e.ip == shared)
        );
    }

    #[test]
    fn route_assist_repins_settings_at_private_edge_when_shared_one_exists() {
        // clientsettings shares edge `a` with relayed gamejoin.roblox.com but also
        // has a private edge `b`. The shared `a` is dropped from both;
        // clientsettings is pinned direct at `b`, gamejoin relays at its own
        // private edge `d`. Both behaviors hold.
        let a = Ipv4Addr::new(65, 9, 168, 80); // shared
        let b = Ipv4Addr::new(65, 9, 168, 90); // clientsettings private
        let d = Ipv4Addr::new(65, 9, 168, 100); // gamejoin private
        let overrides = vec![
            HostOverride {
                ip: a,
                domain: "gamejoin.roblox.com".to_string(),
            },
            HostOverride {
                ip: d,
                domain: "gamejoin.roblox.com".to_string(),
            },
            HostOverride {
                ip: a,
                domain: "clientsettings.roblox.com".to_string(),
            },
            HostOverride {
                ip: b,
                domain: "clientsettings.roblox.com".to_string(),
            },
        ];

        let (kept, active_ips, direct_ips) = allocate_route_assist_pins(overrides);

        // Shared edge `a` is pinned for neither class.
        assert!(!kept.iter().any(|e| e.ip == a));
        // clientsettings re-pinned direct at its private edge `b`.
        assert!(
            kept.iter()
                .any(|e| e.domain == "clientsettings.roblox.com" && e.ip == b)
        );
        assert!(direct_ips.contains(&b));
        assert!(!active_ips.contains(&b));
        // gamejoin relays at its private edge `d`.
        assert!(
            kept.iter()
                .any(|e| e.domain == "gamejoin.roblox.com" && e.ip == d)
        );
        assert!(active_ips.contains(&d));
    }

    #[test]
    fn full_bypass_relays_auth_and_settings() {
        // Mandatory mode negative: FULL country-ban bypass relays EVERYTHING
        // (auth + settings included) — they are blocked directly there, so the
        // relay IS the bypass. This path (country_ban_split_ips_from_overrides)
        // is untouched by the Route Assist re-pin: nothing is direct-only.
        let auth_ip = Ipv4Addr::new(128, 116, 70, 9);
        let settings_ip = Ipv4Addr::new(128, 116, 46, 3);
        let overrides = vec![
            HostOverride {
                ip: auth_ip,
                domain: "auth.roblox.com".to_string(),
            },
            HostOverride {
                ip: settings_ip,
                domain: "clientsettings.roblox.com".to_string(),
            },
        ];

        let (active, direct_only) = country_ban_split_ips_from_overrides(&overrides);

        assert!(active.contains(&auth_ip));
        assert!(active.contains(&settings_ip));
        assert!(direct_only.is_empty());
    }

    #[test]
    fn route_assist_allocation_prefers_disjoint_pins_when_alternatives_exist() {
        // gamejoin.roblox.com (control-plane) and t3.rbxcdn.com (asset) share a
        // CloudFront edge IP `a`, but each also has its own candidate. The
        // shared candidate is dropped from BOTH so each class gets a private
        // pin: control-plane relays AND assets stay direct.
        let a = Ipv4Addr::new(65, 9, 168, 80);
        let b = Ipv4Addr::new(65, 9, 168, 90);
        let c = Ipv4Addr::new(65, 9, 168, 100);
        let overrides = vec![
            HostOverride {
                ip: a,
                domain: "gamejoin.roblox.com".to_string(),
            },
            HostOverride {
                ip: b,
                domain: "gamejoin.roblox.com".to_string(),
            },
            HostOverride {
                ip: a,
                domain: "t3.rbxcdn.com".to_string(),
            },
            HostOverride {
                ip: c,
                domain: "t3.rbxcdn.com".to_string(),
            },
        ];

        let (kept, active_ips, direct_ips) = allocate_route_assist_pins(overrides);

        // The shared candidate is not pinned for either domain.
        assert!(!kept.iter().any(|entry| entry.ip == a));
        assert!(
            kept.iter()
                .any(|entry| entry.domain == "gamejoin.roblox.com" && entry.ip == b)
        );
        assert!(
            !kept
                .iter()
                .any(|entry| entry.domain == "t3.rbxcdn.com" && entry.ip == c),
            "Direct asset pins should not be written to hosts under Route Assist"
        );
        assert!(active_ips.contains(&b));
        assert!(!active_ips.contains(&a));
        assert!(direct_ips.contains(&c));
        assert!(!direct_ips.contains(&a));
    }

    #[test]
    fn missing_direct_only_domains_reports_unresolved_launch_hosts() {
        // Nothing resolved: every launch-critical host is missing.
        assert_eq!(
            missing_direct_only_domains(&[]),
            DIRECT_ONLY_BOOTSTRAP_DOMAINS.to_vec()
        );

        // Case-insensitive coverage counts, and non-direct-only hosts are
        // ignored entirely.
        let overrides = vec![
            HostOverride {
                ip: Ipv4Addr::new(65, 9, 168, 80),
                domain: "ClientSettingsCDN.Roblox.com".to_string(),
            },
            HostOverride {
                ip: Ipv4Addr::new(128, 116, 46, 3),
                domain: "clientsettings.roblox.com".to_string(),
            },
            HostOverride {
                ip: Ipv4Addr::new(128, 116, 121, 3),
                domain: "www.roblox.com".to_string(),
            },
        ];
        assert_eq!(
            missing_direct_only_domains(&overrides),
            vec![
                "clientsettings.api.roblox.com",
                "versioncompatibility.api.roblox.com",
                "auth.roblox.com",
            ]
        );
    }

    #[test]
    fn missing_direct_only_domains_empty_when_all_pinned() {
        let overrides: Vec<HostOverride> = DIRECT_ONLY_BOOTSTRAP_DOMAINS
            .iter()
            .map(|domain| HostOverride {
                ip: Ipv4Addr::new(65, 9, 168, 80),
                domain: domain.to_string(),
            })
            .collect();
        assert!(missing_direct_only_domains(&overrides).is_empty());
    }

    #[test]
    fn learn_direct_only_ip_records_unpinned_settings_host() {
        let _guard = BOOTSTRAP_IP_TEST_LOCK.lock().unwrap();
        clear_active_bootstrap_ips_for_test();

        // An IP we never pinned (system DNS handed it out) that serves a
        // launch-critical settings host: learned direct so the bootstrapper's
        // retry stays off the relay.
        let unpinned_ip = Ipv4Addr::new(65, 9, 168, 90);

        assert!(learn_direct_only_bootstrap_ip(
            "clientsettingscdn.roblox.com",
            unpinned_ip
        ));
        assert!(is_direct_only_bootstrap_ip(unpinned_ip));

        // Re-learning the same IP is a no-op, not an infinite teaching loop.
        assert!(!learn_direct_only_bootstrap_ip(
            "clientsettingscdn.roblox.com",
            unpinned_ip
        ));

        clear_active_bootstrap_ips_for_test();
    }

    #[test]
    fn learn_direct_only_ip_refuses_to_demote_control_plane_pin() {
        let _guard = BOOTSTRAP_IP_TEST_LOCK.lock().unwrap();
        clear_active_bootstrap_ips_for_test();

        // A shared CDN edge: pinned ACTIVE for a relayed control-plane host
        // (e.g. gamejoin), then seen serving an asset SNI. Demoting it used to
        // silently break region steering / banned-game discovery - it must
        // stay relayed.
        let shared_ip = Ipv4Addr::new(65, 9, 168, 95);
        set_active_bootstrap_ips_for_test([shared_ip]);

        assert!(!learn_direct_only_bootstrap_ip("t3.rbxcdn.com", shared_ip));
        assert!(!learn_direct_only_bootstrap_ip(
            "clientsettingscdn.roblox.com",
            shared_ip
        ));
        assert!(is_active_bootstrap_ip(shared_ip));
        assert!(!is_direct_only_bootstrap_ip(shared_ip));

        clear_active_bootstrap_ips_for_test();
    }

    #[test]
    fn learn_direct_only_ip_rejects_non_direct_only_hosts() {
        let _guard = BOOTSTRAP_IP_TEST_LOCK.lock().unwrap();
        clear_active_bootstrap_ips_for_test();

        let ip = Ipv4Addr::new(65, 9, 168, 91);
        // Roblox hosts that are deliberately route-assisted must not be
        // learned as direct-only, and neither may arbitrary lookalikes.
        assert!(!learn_direct_only_bootstrap_ip("gamejoin.roblox.com", ip));
        assert!(!learn_direct_only_bootstrap_ip(
            "clientsettingscdn.roblox.com.evil.test",
            ip
        ));
        assert!(!learn_direct_only_bootstrap_ip("example.com", ip));
        assert!(!is_direct_only_bootstrap_ip(ip));

        clear_active_bootstrap_ips_for_test();
    }

    #[test]
    fn learn_direct_only_ip_is_disabled_during_country_ban_bypass() {
        let _guard = BOOTSTRAP_IP_TEST_LOCK.lock().unwrap();
        clear_active_bootstrap_ips_for_test();
        set_country_ban_bypass_routing_for_test(true);

        let ip = Ipv4Addr::new(65, 9, 168, 92);
        assert!(!learn_direct_only_bootstrap_ip(
            "clientsettings.roblox.com",
            ip
        ));
        assert!(!is_direct_only_bootstrap_ip(ip));

        // Teardown (clear_bootstrap_ip_sets) re-enables learning.
        clear_active_bootstrap_ips_for_test();
        assert!(learn_direct_only_bootstrap_ip(
            "clientsettings.roblox.com",
            ip
        ));

        clear_active_bootstrap_ips_for_test();
    }

    #[test]
    fn entering_country_ban_routing_clears_stale_direct_only_pins() {
        let _guard = BOOTSTRAP_IP_TEST_LOCK.lock().unwrap();
        clear_active_bootstrap_ips_for_test();

        // A prior Route Assist/partial session pinned clientsettings as
        // direct-only, and country-ban routing is currently off (e.g. a fresh
        // full-mode connect whose DoH resolution then fails under the block).
        let stale = Ipv4Addr::new(10, 11, 12, 13);
        set_direct_only_bootstrap_ips_for_test([stale]);
        COUNTRY_BAN_BYPASS_ROUTING.store(false, Ordering::Relaxed);
        assert!(is_direct_only_bootstrap_ip(stale));

        enter_country_ban_routing();

        assert!(
            COUNTRY_BAN_BYPASS_ROUTING.load(Ordering::Relaxed),
            "full bypass must mark country-ban routing even before/without pins"
        );
        assert!(
            !is_direct_only_bootstrap_ip(stale),
            "stale direct-only pin must be dropped so full bypass keeps clientsettings/assets on the relay"
        );

        clear_active_bootstrap_ips_for_test();
    }

    #[test]
    fn direct_only_bootstrap_domain_match_is_case_insensitive() {
        assert!(is_direct_only_bootstrap_domain(
            "ClientSettingsCDN.Roblox.com"
        ));
        assert!(is_direct_only_bootstrap_domain("Auth.Roblox.Com"));
        assert!(!is_direct_only_bootstrap_domain("www.roblox.com"));
        // Exact match only: suffix-spoof / prefix lookalikes must NOT be
        // treated as launch-critical/auth direct hosts.
        assert!(!is_direct_only_bootstrap_domain(
            "auth.roblox.com.evil.test"
        ));
        assert!(!is_direct_only_bootstrap_domain("notauth.roblox.com"));
    }

    #[test]
    fn country_bypass_routes_critical_hosts_through_relay() {
        let critical = HostOverride {
            ip: Ipv4Addr::new(128, 116, 46, 3),
            domain: "clientsettings.roblox.com".to_string(),
        };
        let normal = HostOverride {
            ip: Ipv4Addr::new(128, 116, 121, 3),
            domain: "gamejoin.roblox.com".to_string(),
        };
        let asset = HostOverride {
            ip: Ipv4Addr::new(23, 61, 202, 142),
            domain: "assetdelivery.roblox.com".to_string(),
        };
        let overrides = vec![critical.clone(), normal.clone(), asset.clone()];

        // Default (Route Assist): the launch-critical host AND the asset/CDN
        // host stay direct; only region/join control-plane relays.
        let (_, active, direct_only) = allocate_route_assist_pins(overrides.clone());
        assert!(direct_only.contains(&critical.ip));
        assert!(!active.contains(&critical.ip));
        assert!(active.contains(&normal.ip));
        assert!(direct_only.contains(&asset.ip));
        assert!(!active.contains(&asset.ip));

        // FULL country-ban bypass: EVERYTHING relays, including asset/CDN
        // hosts — in a fully-blocked country the CDN is blocked too, and a
        // "direct" asset host means assets never load (Egypt: games died
        // ~20s after join).
        let (active, direct_only) = country_ban_split_ips_from_overrides(&overrides);
        assert!(active.contains(&critical.ip));
        assert!(active.contains(&normal.ip));
        assert!(active.contains(&asset.ip));
        assert!(direct_only.is_empty());
    }

    #[test]
    fn country_bypass_relays_shared_control_and_asset_ips() {
        let shared_ip = Ipv4Addr::new(128, 116, 121, 3);
        let overrides = vec![
            HostOverride {
                ip: shared_ip,
                domain: "www.roblox.com".to_string(),
            },
            HostOverride {
                ip: shared_ip,
                domain: "assetdelivery.roblox.com".to_string(),
            },
        ];

        let (active, direct_only) = country_ban_split_ips_from_overrides(&overrides);

        assert!(active.contains(&shared_ip));
        assert!(!direct_only.contains(&shared_ip));
    }

    #[test]
    fn asset_direct_domain_matches_rbxcdn_suffix_and_named() {
        // Any *.rbxcdn.com shard (pinned or not) plus the named asset endpoints
        // are treated as heavy asset/CDN traffic that should stay direct.
        for d in [
            "c3.rbxcdn.com",
            "tr.rbxcdn.com",
            "fts.rbxcdn.com",
            "t5.rbxcdn.com",
            "images.rbxcdn.com",
            "css.rbxcdn.com",
            "c12.rbxcdn.com", // a shard we never pinned - still matches via suffix
            "AssetDelivery.Roblox.Com",
            "assetgame.roblox.com",
            "thumbnails.roblox.com",
            "setup.roblox.com",
        ] {
            assert!(is_asset_direct_domain(d), "{d} should be asset-direct");
        }
        // Control-plane hosts and suffix-spoof lookalikes must NOT match.
        for d in [
            "www.roblox.com",
            "auth.roblox.com",
            "apis.roblox.com",
            "gamejoin.roblox.com",
            "clientsettings.roblox.com",
            "rbxcdn.com",           // bare apex, no leading dot
            "evilrbxcdn.com",       // not a subdomain
            "rbxcdn.com.evil.test", // suffix spoof
        ] {
            assert!(!is_asset_direct_domain(d), "{d} must NOT be asset-direct");
        }
    }

    #[test]
    fn dedup_and_cap_ips_preserves_order_and_caps() {
        let ips = vec![
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(1, 1, 1, 1), // duplicate, dropped
            Ipv4Addr::new(2, 2, 2, 2),
            Ipv4Addr::new(3, 3, 3, 3),
            Ipv4Addr::new(4, 4, 4, 4), // over the cap, dropped
        ];

        assert_eq!(
            dedup_and_cap_ips(ips, 3),
            vec![
                Ipv4Addr::new(1, 1, 1, 1),
                Ipv4Addr::new(2, 2, 2, 2),
                Ipv4Addr::new(3, 3, 3, 3),
            ]
        );
    }

    #[test]
    fn dedup_and_cap_ips_handles_empty_and_small() {
        assert!(dedup_and_cap_ips(Vec::new(), 3).is_empty());

        let single = vec![Ipv4Addr::new(9, 9, 9, 9)];
        assert_eq!(dedup_and_cap_ips(single.clone(), 3), single);
    }

    #[tokio::test]
    async fn filter_reachable_ips_keeps_only_reachable_and_preserves_order() {
        // Bind a real listener on loopback so that port is genuinely reachable.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        // 127.0.0.2 has nothing listening on `port`, so it must be probed out.
        // Order: dead IP first, reachable IP second -> result keeps only the
        // reachable one (proving dead IPs are dropped and order is preserved).
        let ips = vec![Ipv4Addr::new(127, 0, 0, 2), Ipv4Addr::new(127, 0, 0, 1)];
        let reachable = filter_reachable_ips_on_port(ips, port).await;

        assert_eq!(reachable, vec![Ipv4Addr::new(127, 0, 0, 1)]);
    }

    #[tokio::test]
    async fn filter_reachable_ips_empty_input_returns_empty() {
        assert!(
            filter_reachable_ips_on_port(Vec::new(), 443)
                .await
                .is_empty()
        );
    }

    // Live end-to-end check of the real production path: DoH multi-IP resolve ->
    // :443 reachability probe -> reachable-first pin list. Ignored by default
    // because it hits the public internet; run locally with:
    //   cargo test -p swifttunnel-core roblox_proxy::hosts::live -- --ignored --nocapture
    #[tokio::test]
    #[ignore = "hits the live network; run with --ignored to verify DNS repair"]
    async fn live_dns_repair_pins_multiple_reachable_ips() {
        let client = reqwest::Client::builder()
            .timeout(DNS_REPAIR_TIMEOUT)
            .build()
            .unwrap();

        for domain in [
            "clientsettings.roblox.com",
            "clientsettingscdn.roblox.com",
            "www.roblox.com",
            "setup.rbxcdn.com",
        ] {
            match resolve_reachable_domain_ips(&client, domain).await {
                Ok(ips) => {
                    println!("{domain} -> {} reachable IP(s): {:?}", ips.len(), ips);
                    assert!(!ips.is_empty(), "{domain} returned an empty pin list");
                }
                Err(e) => {
                    println!("{domain} -> skipped, falls back to normal DNS: {e}");
                }
            }
        }
    }

    #[test]
    fn build_hosts_block_uses_resolved_public_ips() {
        let overrides = vec![
            HostOverride {
                ip: Ipv4Addr::new(65, 9, 168, 80),
                domain: "clientsettingscdn.roblox.com".to_string(),
            },
            HostOverride {
                ip: Ipv4Addr::new(128, 116, 46, 3),
                domain: "clientsettings.roblox.com".to_string(),
            },
            HostOverride {
                ip: Ipv4Addr::new(128, 116, 121, 3),
                domain: "www.roblox.com".to_string(),
            },
        ];

        let block = build_hosts_block(&overrides);

        assert!(block.contains(MARKER_START));
        assert!(block.contains("65.9.168.80 clientsettingscdn.roblox.com"));
        assert!(block.contains("128.116.46.3 clientsettings.roblox.com"));
        assert!(block.contains("128.116.121.3 www.roblox.com"));
        assert!(block.contains(MARKER_END));
        assert!(!block.contains("127.66.0.1"));
    }

    #[test]
    fn active_bootstrap_ips_are_exact_and_clearable() {
        let _guard = BOOTSTRAP_IP_TEST_LOCK.lock().unwrap();
        clear_active_bootstrap_ips_for_test();

        let bootstrap_ip = Ipv4Addr::new(65, 9, 168, 80);
        set_active_bootstrap_ips_for_test([bootstrap_ip]);

        assert!(is_active_bootstrap_ip(bootstrap_ip));
        assert!(!is_direct_only_bootstrap_ip(bootstrap_ip));
        assert!(!is_active_bootstrap_ip(Ipv4Addr::new(65, 9, 168, 81)));

        clear_active_bootstrap_ips_for_test();
        assert!(!is_active_bootstrap_ip(bootstrap_ip));
    }

    #[test]
    fn direct_only_bootstrap_ips_are_exact_and_clearable() {
        let _guard = BOOTSTRAP_IP_TEST_LOCK.lock().unwrap();
        clear_active_bootstrap_ips_for_test();

        let bootstrap_ip = Ipv4Addr::new(128, 116, 46, 3);
        set_direct_only_bootstrap_ips_for_test([bootstrap_ip]);

        assert!(is_direct_only_bootstrap_ip(bootstrap_ip));
        assert!(!is_active_bootstrap_ip(bootstrap_ip));
        assert!(!is_direct_only_bootstrap_ip(Ipv4Addr::new(128, 116, 46, 4)));

        clear_active_bootstrap_ips_for_test();
        assert!(!is_direct_only_bootstrap_ip(bootstrap_ip));
    }

    #[test]
    fn build_doh_url_encodes_domain_query_value() {
        assert_eq!(
            build_doh_url("https://1.1.1.1/dns-query", "clientsettingscdn.roblox.com"),
            "https://1.1.1.1/dns-query?name=clientsettingscdn.roblox.com&type=A"
        );
        assert_eq!(
            build_doh_url("https://1.1.1.1/dns-query", "bad&name=wrong"),
            "https://1.1.1.1/dns-query?name=bad%26name%3Dwrong&type=A"
        );
    }

    #[test]
    fn parse_usable_a_records_accepts_cname_chain_with_public_answers() {
        let body = r#"{
            "Status": 0,
            "Answer": [
                {"name":"clientsettingscdn.roblox.com","type":5,"TTL":60,"data":"example.cloudfront.net."},
                {"name":"example.cloudfront.net","type":1,"TTL":60,"data":"65.9.168.80"},
                {"name":"example.cloudfront.net","type":1,"TTL":60,"data":"65.9.168.121"}
            ]
        }"#;

        assert_eq!(
            parse_usable_a_records(body).unwrap(),
            vec![
                Ipv4Addr::new(65, 9, 168, 80),
                Ipv4Addr::new(65, 9, 168, 121)
            ]
        );
    }

    #[test]
    fn parse_usable_a_records_rejects_non_repairable_private_answer() {
        let body = r#"{
            "Status": 0,
            "Answer": [
                {"name":"clientsettingscdn.roblox.com","type":1,"TTL":60,"data":"127.0.0.1"},
                {"name":"clientsettingscdn.roblox.com","type":1,"TTL":60,"data":"192.168.0.10"},
                {"name":"clientsettingscdn.roblox.com","type":1,"TTL":60,"data":"240.0.0.1"}
            ]
        }"#;

        assert!(parse_usable_a_records(body).unwrap().is_empty());
    }

    #[test]
    fn parse_usable_a_records_rejects_nxdomain() {
        let body = r#"{"Status": 3, "Answer": []}"#;

        assert_eq!(parse_usable_a_records(body).unwrap_err(), "DNS status 3");
    }
}
