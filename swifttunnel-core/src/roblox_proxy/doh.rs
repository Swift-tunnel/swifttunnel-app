//! DNS-over-HTTPS (DoH) resolver.
//!
//! Resolves hostnames via RFC 8484 `application/dns-message` POST requests
//! to Cloudflare (1.1.1.1) with Google (8.8.8.8) as fallback.
//! Falls back to system DNS if both DoH endpoints are unreachable.
//!
//! Uses a TTL-aware in-memory cache to avoid repeated lookups.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use log::{debug, warn};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

pub struct DohResolver {
    client: reqwest::Client,
    cache: Mutex<HashMap<String, CacheEntry>>,
}

struct CacheEntry {
    addrs: Vec<IpAddr>,
    expires: Instant,
}

impl DohResolver {
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .no_proxy() // bypass any system proxy for DoH
            .build()
            .expect("failed to create DoH HTTP client");

        Self {
            client,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Resolve `hostname` to one or more IPv4 addresses.
    ///
    /// Resolution order: cache -> Cloudflare DoH -> Google DoH -> system DNS.
    pub async fn resolve(&self, hostname: &str) -> Result<Vec<IpAddr>, String> {
        // 1. Cache hit
        if let Some(addrs) = self.check_cache(hostname) {
            debug!("DoH cache hit for {}", hostname);
            return Ok(addrs);
        }

        // 2. DoH endpoints
        let endpoints = ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"];

        for endpoint in &endpoints {
            match self.query_doh(endpoint, hostname).await {
                Ok((addrs, ttl)) => {
                    debug!(
                        "DoH resolved {} via {} -> {:?} (TTL {}s)",
                        hostname, endpoint, addrs, ttl
                    );
                    self.insert_cache(hostname, addrs.clone(), ttl);
                    return Ok(addrs);
                }
                Err(e) => {
                    warn!("DoH query to {} for {} failed: {}", endpoint, hostname, e);
                }
            }
        }

        // 3. System DNS fallback
        debug!(
            "All DoH endpoints failed, falling back to system DNS for {}",
            hostname
        );
        self.resolve_system(hostname).await
    }

    // -- cache helpers ------------------------------------------------------

    fn check_cache(&self, hostname: &str) -> Option<Vec<IpAddr>> {
        let cache = self.cache.lock().unwrap();
        cache
            .get(hostname)
            .filter(|e| e.expires > Instant::now())
            .map(|e| e.addrs.clone())
    }

    fn insert_cache(&self, hostname: &str, addrs: Vec<IpAddr>, ttl_secs: u32) {
        let ttl = Duration::from_secs(ttl_secs.max(60) as u64); // floor at 60 s
        let mut cache = self.cache.lock().unwrap();
        cache.insert(
            hostname.to_string(),
            CacheEntry {
                addrs,
                expires: Instant::now() + ttl,
            },
        );
    }

    // -- DoH ----------------------------------------------------------------

    async fn query_doh(
        &self,
        endpoint: &str,
        hostname: &str,
    ) -> Result<(Vec<IpAddr>, u32), String> {
        let wire = build_dns_query(hostname);

        let resp = self
            .client
            .post(endpoint)
            .header("Content-Type", "application/dns-message")
            .header("Accept", "application/dns-message")
            .body(wire)
            .send()
            .await
            .map_err(|e| format!("HTTP error: {e}"))?;

        if !resp.status().is_success() {
            return Err(format!("HTTP {}", resp.status()));
        }

        let body = resp
            .bytes()
            .await
            .map_err(|e| format!("body read error: {e}"))?;

        parse_dns_response(&body)
    }

    // -- system DNS ---------------------------------------------------------

    async fn resolve_system(&self, hostname: &str) -> Result<Vec<IpAddr>, String> {
        let host_port = format!("{hostname}:443");
        let addrs: Vec<IpAddr> = tokio::net::lookup_host(&host_port)
            .await
            .map_err(|e| format!("system DNS failed for {hostname}: {e}"))?
            .map(|sa| sa.ip())
            .collect();

        if addrs.is_empty() {
            return Err(format!("no addresses for {hostname}"));
        }

        self.insert_cache(hostname, addrs.clone(), 300);
        Ok(addrs)
    }
}

// ---------------------------------------------------------------------------
// DNS wire-format helpers (A-record only)
// ---------------------------------------------------------------------------

/// Build a minimal DNS query (A record, class IN) in wire format.
fn build_dns_query(hostname: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);

    // Header: ID(2) Flags(2) QD(2) AN(2) NS(2) AR(2)
    buf.extend_from_slice(&[0x00, 0x01]); // ID
    buf.extend_from_slice(&[0x01, 0x00]); // Flags: standard query, RD=1
    buf.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
    buf.extend_from_slice(&[0x00, 0x00]); // ANCOUNT
    buf.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
    buf.extend_from_slice(&[0x00, 0x00]); // ARCOUNT

    // QNAME: length-prefixed labels
    for label in hostname.split('.') {
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0x00); // root

    buf.extend_from_slice(&[0x00, 0x01]); // QTYPE  = A
    buf.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN

    buf
}

/// Parse a DNS response and extract A-record addresses + minimum TTL.
fn parse_dns_response(buf: &[u8]) -> Result<(Vec<IpAddr>, u32), String> {
    if buf.len() < 12 {
        return Err("response too short".into());
    }

    let rcode = buf[3] & 0x0F;
    if rcode != 0 {
        return Err(format!("RCODE={rcode}"));
    }

    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;

    if ancount == 0 {
        return Err("no answers".into());
    }

    let mut pos = 12;

    // Skip question section
    for _ in 0..qdcount {
        pos = skip_dns_name(buf, pos)?;
        pos += 4; // QTYPE + QCLASS
        if pos > buf.len() {
            return Err("truncated question".into());
        }
    }

    // Parse answers
    let mut addrs = Vec::new();
    let mut min_ttl = u32::MAX;

    for _ in 0..ancount {
        if pos >= buf.len() {
            break;
        }

        pos = skip_dns_name(buf, pos)?;

        if pos + 10 > buf.len() {
            break;
        }

        let rtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let ttl = u32::from_be_bytes([buf[pos + 4], buf[pos + 5], buf[pos + 6], buf[pos + 7]]);
        let rdlen = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
        pos += 10;

        if pos + rdlen > buf.len() {
            break;
        }

        if rtype == 1 && rdlen == 4 {
            addrs.push(IpAddr::V4(Ipv4Addr::new(
                buf[pos],
                buf[pos + 1],
                buf[pos + 2],
                buf[pos + 3],
            )));
            min_ttl = min_ttl.min(ttl);
        }

        pos += rdlen;
    }

    if addrs.is_empty() {
        return Err("no A records".into());
    }

    Ok((addrs, min_ttl))
}

/// Advance past a DNS name, handling compression pointers.
fn skip_dns_name(buf: &[u8], mut pos: usize) -> Result<usize, String> {
    loop {
        if pos >= buf.len() {
            return Err("name truncated".into());
        }

        let b = buf[pos];

        if b == 0 {
            return Ok(pos + 1); // root label
        }

        if b & 0xC0 == 0xC0 {
            return Ok(pos + 2); // compression pointer (2 bytes)
        }

        // Regular label
        pos += 1 + b as usize;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_query_structure() {
        let q = build_dns_query("example.com");
        // Header = 12, QNAME = 1+7+1+3+1 = 13, QTYPE+QCLASS = 4
        assert_eq!(q.len(), 12 + 13 + 4);
        assert_eq!(q[0..2], [0x00, 0x01]); // ID
        assert_eq!(q[2..4], [0x01, 0x00]); // Flags
        assert_eq!(q[4..6], [0x00, 0x01]); // QDCOUNT
        // QNAME starts at 12: \x07example\x03com\x00
        assert_eq!(q[12], 7);
        assert_eq!(&q[13..20], b"example");
        assert_eq!(q[20], 3);
        assert_eq!(&q[21..24], b"com");
        assert_eq!(q[24], 0);
    }

    #[test]
    fn build_query_subdomain() {
        let q = build_dns_query("clientsettings.roblox.com");
        // Labels: \x0eclientsettings \x06roblox \x03com \x00
        assert_eq!(q[12], 14); // "clientsettings" length
    }

    #[test]
    fn parse_response_a_record() {
        // Minimal response: 1 question, 1 A answer for "example.com" -> 93.184.216.34
        let query = build_dns_query("example.com");
        let mut resp = Vec::new();

        // Header
        resp.extend_from_slice(&[0x00, 0x01]); // ID
        resp.extend_from_slice(&[0x81, 0x80]); // Flags: response, RD, RA
        resp.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
        resp.extend_from_slice(&[0x00, 0x01]); // ANCOUNT = 1
        resp.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
        resp.extend_from_slice(&[0x00, 0x00]); // ARCOUNT

        // Question: copy QNAME + QTYPE + QCLASS from query
        resp.extend_from_slice(&query[12..]);

        // Answer: compressed name pointer to offset 12 (question QNAME)
        resp.extend_from_slice(&[0xC0, 0x0C]); // NAME (pointer)
        resp.extend_from_slice(&[0x00, 0x01]); // TYPE = A
        resp.extend_from_slice(&[0x00, 0x01]); // CLASS = IN
        resp.extend_from_slice(&[0x00, 0x00, 0x01, 0x2C]); // TTL = 300
        resp.extend_from_slice(&[0x00, 0x04]); // RDLENGTH = 4
        resp.extend_from_slice(&[93, 184, 216, 34]); // RDATA

        let (addrs, ttl) = parse_dns_response(&resp).unwrap();
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0], IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
        assert_eq!(ttl, 300);
    }

    #[test]
    fn parse_response_multiple_a_records() {
        let query = build_dns_query("example.com");
        let mut resp = Vec::new();

        // Header
        resp.extend_from_slice(&[0x00, 0x01, 0x81, 0x80]);
        resp.extend_from_slice(&[0x00, 0x01]); // QDCOUNT
        resp.extend_from_slice(&[0x00, 0x02]); // ANCOUNT = 2
        resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        // Question
        resp.extend_from_slice(&query[12..]);

        // Answer 1: 1.2.3.4, TTL=600
        resp.extend_from_slice(&[0xC0, 0x0C]);
        resp.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        resp.extend_from_slice(&[0x00, 0x00, 0x02, 0x58]); // TTL 600
        resp.extend_from_slice(&[0x00, 0x04]);
        resp.extend_from_slice(&[1, 2, 3, 4]);

        // Answer 2: 5.6.7.8, TTL=120
        resp.extend_from_slice(&[0xC0, 0x0C]);
        resp.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x78]); // TTL 120
        resp.extend_from_slice(&[0x00, 0x04]);
        resp.extend_from_slice(&[5, 6, 7, 8]);

        let (addrs, ttl) = parse_dns_response(&resp).unwrap();
        assert_eq!(addrs.len(), 2);
        assert_eq!(addrs[0], IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
        assert_eq!(addrs[1], IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)));
        assert_eq!(ttl, 120); // min TTL
    }

    #[test]
    fn parse_response_nxdomain() {
        let mut resp = vec![0x00, 0x01, 0x81, 0x83]; // RCODE = 3 (NXDOMAIN)
        resp.extend_from_slice(&[0x00, 0x00; 4]);
        assert!(parse_dns_response(&resp).is_err());
    }

    #[test]
    fn parse_response_too_short() {
        assert!(parse_dns_response(&[0; 8]).is_err());
    }

    #[test]
    fn skip_name_regular_labels() {
        // \x03www\x07example\x03com\x00
        let buf = b"\x03www\x07example\x03com\x00REST";
        let end = skip_dns_name(buf, 0).unwrap();
        assert_eq!(end, 17); // 1+3 + 1+7 + 1+3 + 1 = 17
    }

    #[test]
    fn skip_name_compression_pointer() {
        let buf = [0xC0, 0x0C, 0x99];
        let end = skip_dns_name(&buf, 0).unwrap();
        assert_eq!(end, 2);
    }

    #[test]
    fn cache_hit_and_expiry() {
        let resolver = DohResolver::new();

        // Insert an entry
        resolver.insert_cache(
            "test.com",
            vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))],
            300,
        );

        // Cache hit
        let cached = resolver.check_cache("test.com");
        assert!(cached.is_some());
        assert_eq!(cached.unwrap()[0], IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));

        // Miss for unknown host
        assert!(resolver.check_cache("other.com").is_none());
    }
}
