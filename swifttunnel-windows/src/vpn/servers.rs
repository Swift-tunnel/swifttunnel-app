//! Server list and latency measurement
//!
//! Fetches the server list dynamically from the SwiftTunnel API.
//! No hardcoded server data - the app MUST fetch from API or use cached data.
//!
//! Server list is cached locally and refreshed periodically.
//! If API is unavailable and no cache exists, the app shows an error.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};

/// API endpoint for fetching server list
const SERVERS_API_URL: &str = "https://swifttunnel.net/api/vpn/servers";

/// Cache TTL in seconds (1 hour)
const CACHE_TTL_SECONDS: i64 = 3600;

/// Measured latency for a server
#[derive(Debug, Clone)]
pub struct ServerLatency {
    pub region: String,
    pub latency_ms: Option<u32>,
    pub last_measured: Instant,
}

/// Measure latency to a server using UDP ping
pub async fn measure_latency(endpoint: &str) -> Option<u32> {
    use tokio::net::UdpSocket;
    use tokio::time::timeout;

    let addr: SocketAddr = match endpoint.parse() {
        Ok(a) => a,
        Err(_) => return None,
    };

    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(_) => return None,
    };

    // Send a small ping packet
    let ping_data = [0u8; 1];
    let start = Instant::now();

    if socket.send_to(&ping_data, addr).await.is_err() {
        return None;
    }

    // Wait for response with timeout
    let mut buf = [0u8; 64];
    match timeout(Duration::from_secs(2), socket.recv_from(&mut buf)).await {
        Ok(Ok(_)) => {
            let elapsed = start.elapsed();
            Some(elapsed.as_millis() as u32)
        }
        _ => None,
    }
}

/// Measure latency using ICMP ping (fallback)
pub fn measure_latency_icmp(ip: &str) -> Option<u32> {
    use crate::hidden_command;

    // Use Windows ping command with 1 packet and 2 second timeout
    let output = hidden_command("ping")
        .args(["-n", "1", "-w", "2000", ip])
        .output()
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse "time=XXms" or "time<1ms" from output
    for line in stdout.lines() {
        if let Some(time_idx) = line.find("time=") {
            let rest = &line[time_idx + 5..];
            if let Some(ms_idx) = rest.find("ms") {
                let time_str = &rest[..ms_idx];
                if let Ok(ms) = time_str.parse::<u32>() {
                    return Some(ms);
                }
            }
        } else if line.contains("time<1ms") {
            return Some(0);
        }
    }

    None
}

// No hardcoded server data - everything is fetched from the API
// See: https://swifttunnel.net/api/vpn/servers


// =============================================================================
// DYNAMIC SERVER LIST (Fetched from API)
// =============================================================================

/// Dynamic server info with owned strings (for API deserialization)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicServerInfo {
    pub region: String,
    pub name: String,
    pub country_code: String,
    pub ip: String,
    pub port: u16,
    pub phantun_available: bool,
    pub phantun_port: Option<u16>,
}


/// Dynamic gaming region with owned strings (for API deserialization)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicGamingRegion {
    pub id: String,
    pub name: String,
    pub description: String,
    pub country_code: String,
    pub servers: Vec<String>,
}

/// API response structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerListResponse {
    pub servers: Vec<DynamicServerInfo>,
    pub regions: Vec<DynamicGamingRegion>,
    pub version: String,
}

/// Cached server list with timestamp
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedServerList {
    pub data: ServerListResponse,
    pub cached_at: DateTime<Utc>,
}

impl CachedServerList {
    /// Check if the cache is still fresh
    pub fn is_fresh(&self) -> bool {
        let age = Utc::now().signed_duration_since(self.cached_at);
        age.num_seconds() < CACHE_TTL_SECONDS
    }
}

/// Get the cache file path
fn get_cache_path() -> Option<PathBuf> {
    dirs::data_local_dir().map(|d| d.join("SwiftTunnel").join("servers.json"))
}

/// Load cached server list from disk
pub fn load_cached_servers() -> Option<CachedServerList> {
    let cache_path = get_cache_path()?;

    if !cache_path.exists() {
        log::debug!("Server cache file does not exist: {:?}", cache_path);
        return None;
    }

    match std::fs::read_to_string(&cache_path) {
        Ok(content) => {
            match serde_json::from_str::<CachedServerList>(&content) {
                Ok(cached) => {
                    log::info!("Loaded server cache from {:?}, age: {} seconds",
                        cache_path,
                        Utc::now().signed_duration_since(cached.cached_at).num_seconds()
                    );
                    Some(cached)
                }
                Err(e) => {
                    log::warn!("Failed to parse server cache: {}", e);
                    None
                }
            }
        }
        Err(e) => {
            log::warn!("Failed to read server cache file: {}", e);
            None
        }
    }
}

/// Save server list to disk cache
pub fn save_servers_to_cache(data: &ServerListResponse) -> Result<(), std::io::Error> {
    let cache_path = match get_cache_path() {
        Some(p) => p,
        None => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Could not determine cache directory",
            ));
        }
    };

    // Create directory if it doesn't exist
    if let Some(parent) = cache_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let cached = CachedServerList {
        data: data.clone(),
        cached_at: Utc::now(),
    };

    let content = serde_json::to_string_pretty(&cached)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    std::fs::write(&cache_path, content)?;
    log::info!("Saved server list to cache: {:?}", cache_path);

    Ok(())
}

/// Fetch server list from API
pub async fn fetch_server_list() -> Result<ServerListResponse, String> {
    log::info!("Fetching server list from API: {}", SERVERS_API_URL);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

    let response = client
        .get(SERVERS_API_URL)
        .send()
        .await
        .map_err(|e| format!("Failed to fetch server list: {}", e))?;

    if !response.status().is_success() {
        return Err(format!("API returned error status: {}", response.status()));
    }

    let data: ServerListResponse = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse server list JSON: {}", e))?;

    log::info!(
        "Fetched {} servers and {} regions from API (version: {})",
        data.servers.len(),
        data.regions.len(),
        data.version
    );

    // Save to cache
    if let Err(e) = save_servers_to_cache(&data) {
        log::warn!("Failed to save server list to cache: {}", e);
    }

    Ok(data)
}

/// Load server list from API or cache.
///
/// Strategy:
/// 1. Try to load fresh cache
/// 2. If cache is stale or missing, fetch from API
/// 3. If API fails and cache exists (even stale), use cache
/// 4. If all else fails, return Error - no hardcoded fallback!
pub async fn load_server_list() -> Result<(Vec<DynamicServerInfo>, Vec<DynamicGamingRegion>, ServerListSource), String> {
    // Try to load from cache first
    if let Some(cached) = load_cached_servers() {
        if cached.is_fresh() {
            log::info!("Using fresh cached server list");
            return Ok((
                cached.data.servers,
                cached.data.regions,
                ServerListSource::Cache,
            ));
        }

        // Cache is stale, try to refresh from API
        log::info!("Cache is stale, attempting to refresh from API");
        match fetch_server_list().await {
            Ok(data) => {
                return Ok((data.servers, data.regions, ServerListSource::Api));
            }
            Err(e) => {
                log::warn!("Failed to fetch from API, using stale cache: {}", e);
                return Ok((
                    cached.data.servers,
                    cached.data.regions,
                    ServerListSource::StaleCache,
                ));
            }
        }
    }

    // No cache, try API
    log::info!("No cache found, fetching from API");
    match fetch_server_list().await {
        Ok(data) => {
            return Ok((data.servers, data.regions, ServerListSource::Api));
        }
        Err(e) => {
            log::error!("Failed to fetch server list from API: {}", e);
            return Err(format!("Could not load server list: {}. Please check your internet connection.", e));
        }
    }
}

/// Source of the server list data
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerListSource {
    /// Still loading from API
    Loading,
    /// Fetched from API
    Api,
    /// Loaded from fresh local cache
    Cache,
    /// Loaded from stale cache (API failed)
    StaleCache,
    /// Failed to load (no cache, API failed)
    Error(String),
}

impl std::fmt::Display for ServerListSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServerListSource::Loading => write!(f, "Loading..."),
            ServerListSource::Api => write!(f, "API"),
            ServerListSource::Cache => write!(f, "Cache"),
            ServerListSource::StaleCache => write!(f, "Stale Cache"),
            ServerListSource::Error(msg) => write!(f, "Error: {}", msg),
        }
    }
}

/// Dynamic server list manager for GUI usage
pub struct DynamicServerList {
    pub servers: Vec<DynamicServerInfo>,
    pub regions: Vec<DynamicGamingRegion>,
    pub source: ServerListSource,
    latencies: HashMap<String, ServerLatency>,
}

impl DynamicServerList {
    /// Create a new empty server list (loading state).
    /// The list will be populated when data is fetched from the API.
    pub fn new_empty() -> Self {
        Self {
            servers: Vec::new(),
            regions: Vec::new(),
            source: ServerListSource::Loading,
            latencies: HashMap::new(),
        }
    }

    /// Create a new server list with error state
    pub fn new_error(error: String) -> Self {
        Self {
            servers: Vec::new(),
            regions: Vec::new(),
            source: ServerListSource::Error(error),
            latencies: HashMap::new(),
        }
    }

    /// Check if the server list is empty (still loading or error)
    pub fn is_empty(&self) -> bool {
        self.servers.is_empty()
    }

    /// Check if there was an error loading
    pub fn has_error(&self) -> bool {
        matches!(self.source, ServerListSource::Error(_))
    }

    /// Get the error message if any
    pub fn error_message(&self) -> Option<&str> {
        match &self.source {
            ServerListSource::Error(msg) => Some(msg),
            _ => None,
        }
    }

    /// Update with fetched data
    pub fn update(
        &mut self,
        servers: Vec<DynamicServerInfo>,
        regions: Vec<DynamicGamingRegion>,
        source: ServerListSource,
    ) {
        self.servers = servers;
        self.regions = regions;
        self.source = source;
    }

    /// Get all servers
    pub fn servers(&self) -> &[DynamicServerInfo] {
        &self.servers
    }

    /// Get all regions
    pub fn regions(&self) -> &[DynamicGamingRegion] {
        &self.regions
    }

    /// Get server by region ID
    pub fn get_server(&self, region: &str) -> Option<&DynamicServerInfo> {
        self.servers.iter().find(|s| s.region == region)
    }

    /// Get region by ID
    pub fn get_region(&self, id: &str) -> Option<&DynamicGamingRegion> {
        self.regions.iter().find(|r| r.id == id)
    }

    /// Get latency for a server
    pub fn get_latency(&self, region: &str) -> Option<u32> {
        self.latencies.get(region).and_then(|l| l.latency_ms)
    }

    /// Set latency for a server
    pub fn set_latency(&mut self, region: &str, latency_ms: Option<u32>) {
        self.latencies.insert(
            region.to_string(),
            ServerLatency {
                region: region.to_string(),
                latency_ms,
                last_measured: Instant::now(),
            },
        );
    }

    /// Get servers in a gaming region
    pub fn servers_in_region(&self, region_id: &str) -> Vec<&DynamicServerInfo> {
        if let Some(region) = self.get_region(region_id) {
            region
                .servers
                .iter()
                .filter_map(|server_id| self.get_server(server_id))
                .collect()
        } else {
            vec![]
        }
    }

    /// Get best latency for a gaming region
    pub fn get_region_best_latency(&self, region_id: &str) -> Option<u32> {
        if let Some(region) = self.get_region(region_id) {
            region
                .servers
                .iter()
                .filter_map(|server_id| self.get_latency(server_id))
                .min()
        } else {
            None
        }
    }

    /// Find best server in a gaming region using multi-ping average
    pub async fn find_best_server_in_region(&mut self, region_id: &str) -> Option<(String, u32)> {
        let region = self.get_region(region_id)?;
        let server_ids: Vec<String> = region.servers.clone();

        let mut best_server: Option<String> = None;
        let mut best_avg_latency = u32::MAX;

        for server_id in &server_ids {
            if let Some(server) = self.get_server(server_id) {
                let endpoint = format!("{}:{}", server.ip, server.port);

                // Perform 3 pings and average
                let mut total_latency = 0u32;
                let mut successful_pings = 0u32;

                for _ in 0..3 {
                    if let Some(latency) = measure_latency(&endpoint).await {
                        total_latency += latency;
                        successful_pings += 1;
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }

                if successful_pings > 0 {
                    let avg = total_latency / successful_pings;
                    self.set_latency(server_id, Some(avg));

                    if avg < best_avg_latency {
                        best_avg_latency = avg;
                        best_server = Some(server_id.clone());
                    }
                }
            }
        }

        best_server.map(|s| (s, best_avg_latency))
    }
}
