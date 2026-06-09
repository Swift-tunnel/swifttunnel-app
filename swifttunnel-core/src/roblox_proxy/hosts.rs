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
use std::sync::{OnceLock, RwLock};
use std::time::Duration;

const MARKER_START: &str = "# SwiftTunnel Roblox Proxy - START";
const MARKER_END: &str = "# SwiftTunnel Roblox Proxy - END";
const DNS_REPAIR_TIMEOUT: Duration = Duration::from_secs(3);
const DNS_REPAIR_TOTAL_TIMEOUT: Duration = Duration::from_secs(10);
const DNS_REPAIR_RESOLVERS: &[&str] = &[
    // IP literals avoid depending on the user's broken local DNS to find
    // the DNS-over-HTTPS resolver itself.
    "https://1.1.1.1/dns-query",
    "https://8.8.8.8/resolve",
];

/// Maximum IPs pinned per Roblox bootstrap domain.
///
/// Roblox serves these hostnames from a CDN/anycast pool, so a single edge IP
/// resolved from a public DoH resolver may be unreachable from the user's ISP
/// path. Pinning a few verified IPs gives connection fail-over headroom without
/// bloating the hosts file.
const MAX_PINNED_IPS_PER_DOMAIN: usize = 3;

/// Per-IP TCP reachability probe timeout. Short so a dead edge is skipped fast;
/// the whole repair still runs under `DNS_REPAIR_TOTAL_TIMEOUT`.
const REACHABILITY_PROBE_TIMEOUT: Duration = Duration::from_millis(1200);

/// Port used to confirm a resolved Roblox edge actually accepts connections.
const ROBLOX_HTTPS_PORT: u16 = 443;

static ACTIVE_BOOTSTRAP_IPS: OnceLock<RwLock<HashSet<Ipv4Addr>>> = OnceLock::new();
static DIRECT_ONLY_BOOTSTRAP_IPS: OnceLock<RwLock<HashSet<Ipv4Addr>>> = OnceLock::new();

// Keep DNS repair for these launch-critical hosts, but do not publish their IPs
// to Route Assist. Roblox can fail startup with "Failed to download or apply
// critical settings" if these bootstrap HTTPS requests are relayed unreliably.
const DIRECT_ONLY_BOOTSTRAP_DOMAINS: &[&str] = &[
    "clientsettingscdn.roblox.com",
    "clientsettings.roblox.com",
    "clientsettings.api.roblox.com",
    "versioncompatibility.api.roblox.com",
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
    "catalog.roblox.com",
    "inventory.roblox.com",
    "economy.roblox.com",
    "games.roblox.com",
    "gamejoin.roblox.com",
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
    "cdn.arkoselabs.com",
    "roblox-api.arkoselabs.com",
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
/// `country_ban_bypass`: when the user is bypassing a country ban, the
/// launch-critical hosts (clientsettings*, versioncompatibility) MUST be routed
/// through the relay to escape the ISP block — otherwise keeping them "direct"
/// (the default, which avoids flaky-relay "Failed to apply critical settings")
/// sends them straight into the block and the game won't launch.
pub async fn apply_bootstrap_overrides(country_ban_bypass: bool) -> Result<(), String> {
    let overrides = resolve_bootstrap_overrides().await?;
    let (active_ips, direct_only_ips) = classify_bootstrap_ips(&overrides, country_ban_bypass);

    tokio::task::spawn_blocking(move || write_overrides(&overrides))
        .await
        .map_err(|e| format!("Failed to join hosts repair task: {e}"))??;

    set_active_bootstrap_ips(active_ips);
    set_direct_only_bootstrap_ips(direct_only_ips);
    Ok(())
}

/// Split resolved overrides into (route-assist active, direct-only) IP sets.
///
/// When bypassing a country ban, nothing is direct-only — every bootstrap IP
/// (including the launch-critical hosts) is routed through Route Assist so it
/// can escape the block. Otherwise the launch-critical hosts stay direct.
fn classify_bootstrap_ips(
    overrides: &[HostOverride],
    country_ban_bypass: bool,
) -> (HashSet<Ipv4Addr>, HashSet<Ipv4Addr>) {
    if country_ban_bypass {
        let all: HashSet<Ipv4Addr> = overrides.iter().map(|entry| entry.ip).collect();
        (all, HashSet::new())
    } else {
        (
            route_assist_active_ips_from_overrides(overrides),
            direct_only_ips_from_overrides(overrides),
        )
    }
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

async fn resolve_bootstrap_overrides() -> Result<Vec<HostOverride>, String> {
    let client = reqwest::Client::builder()
        .timeout(DNS_REPAIR_TIMEOUT)
        .build()
        .map_err(|e| format!("Failed to build DNS repair client: {e}"))?;

    let mut lookups: FuturesUnordered<_> = ROBLOX_BOOTSTRAP_DOMAINS
        .iter()
        .map(|domain| {
            let client = client.clone();
            let domain = *domain;
            async move { (domain, resolve_reachable_domain_ips(&client, domain).await) }
        })
        .collect();

    let mut overrides = Vec::new();
    let mut failures = Vec::new();
    let total_deadline = tokio::time::sleep(DNS_REPAIR_TOTAL_TIMEOUT);
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
                        DNS_REPAIR_TOTAL_TIMEOUT.as_secs()
                    ));
                }
                break;
            }
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

fn route_assist_active_ips_from_overrides(overrides: &[HostOverride]) -> HashSet<Ipv4Addr> {
    let direct_only_ips = direct_only_ips_from_overrides(overrides);

    overrides
        .iter()
        .filter(|entry| !is_direct_only_bootstrap_domain(&entry.domain))
        .filter(|entry| !direct_only_ips.contains(&entry.ip))
        .map(|entry| entry.ip)
        .collect()
}

fn direct_only_ips_from_overrides(overrides: &[HostOverride]) -> HashSet<Ipv4Addr> {
    overrides
        .iter()
        .filter(|entry| is_direct_only_bootstrap_domain(&entry.domain))
        .map(|entry| entry.ip)
        .collect()
}

fn is_direct_only_bootstrap_domain(domain: &str) -> bool {
    DIRECT_ONLY_BOOTSTRAP_DOMAINS
        .iter()
        .any(|direct_only| domain.eq_ignore_ascii_case(direct_only))
}

fn clear_bootstrap_ip_sets() {
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
        assert!(ROBLOX_BOOTSTRAP_DOMAINS.contains(&"catalog.roblox.com"));
        assert!(ROBLOX_BOOTSTRAP_DOMAINS.contains(&"inventory.roblox.com"));
        assert!(ROBLOX_BOOTSTRAP_DOMAINS.contains(&"economy.roblox.com"));
        assert!(ROBLOX_BOOTSTRAP_DOMAINS.contains(&"gamejoin.roblox.com"));
        assert!(ROBLOX_BOOTSTRAP_DOMAINS.contains(&"assetgame.roblox.com"));
        assert!(ROBLOX_BOOTSTRAP_DOMAINS.contains(&"chatsite.roblox.com"));
        assert!(ROBLOX_BOOTSTRAP_DOMAINS.contains(&"setup.rbxcdn.com"));
        assert!(ROBLOX_BOOTSTRAP_DOMAINS.contains(&"js.rbxcdn.com"));
        assert!(ROBLOX_BOOTSTRAP_DOMAINS.contains(&"static.rbxcdn.com"));
        assert!(ROBLOX_BOOTSTRAP_DOMAINS.contains(&"captcha.roblox.com"));
        assert!(ROBLOX_BOOTSTRAP_DOMAINS.contains(&"cdn.arkoselabs.com"));
        assert!(ROBLOX_BOOTSTRAP_DOMAINS.contains(&"roblox-api.arkoselabs.com"));
    }

    #[test]
    fn domain_list_stays_allowlisted_and_exact() {
        assert_eq!(ROBLOX_BOOTSTRAP_DOMAINS.len(), 34);
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
    fn route_assist_active_ips_exclude_launch_critical_settings_hosts() {
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
                ip: Ipv4Addr::new(23, 61, 202, 142),
                domain: "setup.rbxcdn.com".to_string(),
            },
            HostOverride {
                ip: Ipv4Addr::new(65, 9, 168, 80),
                domain: "apis.roblox.com".to_string(),
            },
        ];

        let active_ips = route_assist_active_ips_from_overrides(&overrides);
        let direct_only_ips = direct_only_ips_from_overrides(&overrides);

        assert!(!active_ips.contains(&Ipv4Addr::new(65, 9, 168, 80)));
        assert!(!active_ips.contains(&Ipv4Addr::new(128, 116, 46, 3)));
        assert!(active_ips.contains(&Ipv4Addr::new(128, 116, 121, 3)));
        assert!(active_ips.contains(&Ipv4Addr::new(23, 61, 202, 142)));
        assert!(direct_only_ips.contains(&Ipv4Addr::new(65, 9, 168, 80)));
        assert!(direct_only_ips.contains(&Ipv4Addr::new(128, 116, 46, 3)));
        assert!(!direct_only_ips.contains(&Ipv4Addr::new(128, 116, 121, 3)));
    }

    #[test]
    fn direct_only_bootstrap_domain_match_is_case_insensitive() {
        assert!(is_direct_only_bootstrap_domain(
            "ClientSettingsCDN.Roblox.com"
        ));
        assert!(!is_direct_only_bootstrap_domain("www.roblox.com"));
    }

    #[test]
    fn country_bypass_routes_critical_hosts_through_relay() {
        let critical = HostOverride {
            ip: Ipv4Addr::new(128, 116, 46, 3),
            domain: "clientsettings.roblox.com".to_string(),
        };
        let normal = HostOverride {
            ip: Ipv4Addr::new(128, 116, 121, 3),
            domain: "www.roblox.com".to_string(),
        };
        let overrides = vec![critical.clone(), normal.clone()];

        // Default: the launch-critical host stays direct (not on the relay).
        let (active, direct_only) = classify_bootstrap_ips(&overrides, false);
        assert!(direct_only.contains(&critical.ip));
        assert!(!active.contains(&critical.ip));
        assert!(active.contains(&normal.ip));

        // Bypassing a country ban: nothing is direct-only, and the critical
        // host now goes through Route Assist so it can escape the block.
        let (active, direct_only) = classify_bootstrap_ips(&overrides, true);
        assert!(direct_only.is_empty());
        assert!(active.contains(&critical.ip));
        assert!(active.contains(&normal.ip));
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
