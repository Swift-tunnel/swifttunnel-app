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
use std::net::Ipv4Addr;
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

static ACTIVE_BOOTSTRAP_IPS: OnceLock<RwLock<HashSet<Ipv4Addr>>> = OnceLock::new();

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
pub async fn apply_bootstrap_overrides() -> Result<(), String> {
    let overrides = resolve_bootstrap_overrides().await?;
    let active_ips: HashSet<Ipv4Addr> = overrides.iter().map(|entry| entry.ip).collect();

    tokio::task::spawn_blocking(move || write_overrides(&overrides))
        .await
        .map_err(|e| format!("Failed to join hosts repair task: {e}"))??;

    set_active_bootstrap_ips(active_ips);
    Ok(())
}

pub fn is_active_bootstrap_ip(ip: Ipv4Addr) -> bool {
    active_bootstrap_ips()
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
            async move { (domain, resolve_domain_ipv4(&client, domain).await) }
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
                    Some((domain, Ok(ip))) => overrides.push(HostOverride {
                        ip,
                        domain: domain.to_string(),
                    }),
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

async fn resolve_domain_ipv4(client: &reqwest::Client, domain: &str) -> Result<Ipv4Addr, String> {
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
            Ok(ips) if !ips.is_empty() => return Ok(ips[0]),
            Ok(_) => failures.push(format!("{resolver}: no usable public A records")),
            Err(e) => failures.push(format!("{resolver}: {e}")),
        }
    }

    Err(format!(
        "{domain} could not be repaired via DNS-over-HTTPS ({})",
        failures.join("; ")
    ))
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
    clear_active_bootstrap_ips();
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

fn set_active_bootstrap_ips(ips: HashSet<Ipv4Addr>) {
    match active_bootstrap_ips().write() {
        Ok(mut active) => *active = ips,
        Err(e) => warn!("Failed to publish Roblox bootstrap route IPs: {e}"),
    }
}

fn clear_active_bootstrap_ips() {
    match active_bootstrap_ips().write() {
        Ok(mut active) => active.clear(),
        Err(e) => warn!("Failed to clear Roblox bootstrap route IPs: {e}"),
    }
}

#[cfg(test)]
pub(crate) fn set_active_bootstrap_ips_for_test(ips: impl IntoIterator<Item = Ipv4Addr>) {
    set_active_bootstrap_ips(ips.into_iter().collect());
}

#[cfg(test)]
pub(crate) fn clear_active_bootstrap_ips_for_test() {
    clear_active_bootstrap_ips();
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
        assert!(!is_active_bootstrap_ip(Ipv4Addr::new(65, 9, 168, 81)));

        clear_active_bootstrap_ips_for_test();
        assert!(!is_active_bootstrap_ip(bootstrap_ip));
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
