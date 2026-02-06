//! macOS Split Tunnel Coordinator
//!
//! Orchestrates all split tunnel components on macOS:
//! - ProcessTracker: Maps network connections to PIDs via libproc
//! - ProcessWatcher: Detects game process start/exit via sysinfo + kqueue
//! - PfFirewall: Manages pf routing rules for game traffic
//! - PacketMonitor: BPF capture for connection discovery
//!
//! ## Architecture
//!
//! Unlike Windows (which uses ndisapi to intercept packets inline), macOS uses
//! a different approach:
//!
//! 1. **PacketMonitor** (BPF) passively captures packets to discover active connections
//! 2. **ProcessTracker** (libproc) maps those connections to PIDs
//! 3. **ProcessWatcher** (sysinfo+kqueue) detects when game processes start/stop
//! 4. **PfFirewall** (pfctl) creates routing rules for game traffic ports
//!
//! The coordination loop runs in a background thread:
//! 1. PacketMonitor discovers active connections on the physical interface
//! 2. ProcessTracker identifies which connections belong to game processes
//! 3. PfFirewall routes those specific ports through the utun VPN interface
//! 4. Loop refreshes every 100ms to track new connections
//!
//! ## Key difference from Windows
//!
//! Windows (ndisapi):  Packet arrives -> check process -> route inline (< 0.1ms)
//! macOS (pf):         Discover ports -> update pf rules -> pf routes (< 1ms rule update)
//!
//! The macOS approach has slightly higher latency for the first packet of a new
//! connection (until pf rules are updated), but subsequent packets are routed
//! by pf in kernel space with near-zero latency.

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use super::process_tracker::{ProcessTracker, Protocol};
use super::process_watcher::{ProcessWatcher, ProcessStartEvent};
use super::firewall::{PfFirewall, detect_physical_interface};
use super::packet_interceptor::{PacketMonitor, ThroughputStats};
use super::{VpnError, VpnResult};
use crate::settings::RoutingMode;

// ═══════════════════════════════════════════════════════════════════════════════
//  GAME PRESETS (macOS process names - no .exe extension)
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GamePreset {
    Roblox,
    Valorant,
    Fortnite,
}

impl GamePreset {
    pub fn all() -> &'static [GamePreset] {
        &[GamePreset::Roblox, GamePreset::Valorant, GamePreset::Fortnite]
    }

    /// Process names that should use VPN (macOS binary names)
    pub fn process_names(&self) -> &'static [&'static str] {
        match self {
            GamePreset::Roblox => &[
                // Main game client
                "robloxplayer",
                "robloxplayerbeta",
                // Universal binary (newer versions)
                "roblox",
                // Studio
                "robloxstudio",
                "robloxstudiobeta",
            ],
            GamePreset::Valorant => &[
                // Valorant is not natively on macOS, but may run via CrossOver/Parallels
                "valorant",
                "riotclientservices",
                "riotclientux",
            ],
            GamePreset::Fortnite => &[
                // Fortnite is not natively on macOS anymore, but may run via emulation
                "fortnite",
                "fortniteclient",
                "epicgameslauncher",
            ],
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            GamePreset::Roblox => "Roblox",
            GamePreset::Valorant => "Valorant",
            GamePreset::Fortnite => "Fortnite",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            GamePreset::Roblox => "Roblox Player & Studio",
            GamePreset::Valorant => "Valorant + Riot Client",
            GamePreset::Fortnite => "Fortnite + Epic Launcher",
        }
    }
}

/// Get all process names that should use VPN for given presets
pub fn get_tunnel_apps_for_presets(presets: &HashSet<GamePreset>) -> HashSet<String> {
    presets
        .iter()
        .flat_map(|p| p.process_names())
        .map(|s| s.to_lowercase())
        .collect()
}

/// Get apps for preset slice
pub fn get_apps_for_presets(presets: &[GamePreset]) -> Vec<String> {
    presets
        .iter()
        .flat_map(|p| p.process_names())
        .map(|s| s.to_string())
        .collect()
}

pub fn get_apps_for_preset_set(presets: &HashSet<GamePreset>) -> Vec<String> {
    presets
        .iter()
        .flat_map(|p| p.process_names())
        .map(|s| s.to_string())
        .collect()
}

// ═══════════════════════════════════════════════════════════════════════════════
//  SPLIT TUNNEL CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
pub struct SplitTunnelConfig {
    /// Apps that SHOULD use VPN (process names, lowercase)
    pub tunnel_apps: HashSet<String>,
    /// VPN tunnel IP address (assigned by VPN server)
    pub tunnel_ip: String,
    /// Real internet IP address (from default gateway interface)
    pub internet_ip: String,
    /// Name of the utun interface (e.g., "utun5")
    pub utun_name: String,
    /// Routing mode
    pub routing_mode: RoutingMode,
}

impl SplitTunnelConfig {
    pub fn new(
        tunnel_apps: Vec<String>,
        tunnel_ip: String,
        internet_ip: String,
        utun_name: String,
        routing_mode: RoutingMode,
    ) -> Self {
        Self {
            tunnel_apps: tunnel_apps.into_iter().map(|s| s.to_lowercase()).collect(),
            tunnel_ip,
            internet_ip,
            utun_name,
            routing_mode,
        }
    }

    pub fn include_apps(&self) -> Vec<String> {
        self.tunnel_apps.iter().cloned().collect()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  DRIVER STATE
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriverState {
    NotAvailable,
    NotConfigured,
    Initialized,
    Active,
    Error(String),
}

// ═══════════════════════════════════════════════════════════════════════════════
//  MACOS SPLIT TUNNEL
// ═══════════════════════════════════════════════════════════════════════════════

/// macOS Split Tunnel Driver
///
/// Coordinates ProcessTracker, ProcessWatcher, PfFirewall, and PacketMonitor
/// to implement per-process split tunneling on macOS.
pub struct MacSplitTunnel {
    /// pf firewall manager
    firewall: PfFirewall,
    /// Packet monitor (BPF capture)
    packet_monitor: Option<PacketMonitor>,
    /// Process watcher (sysinfo + kqueue)
    process_watcher: Option<ProcessWatcher>,
    /// Current configuration
    pub config: Option<SplitTunnelConfig>,
    /// Current state
    state: DriverState,
    /// Stop flag for the coordination loop
    stop_flag: Arc<AtomicBool>,
    /// Coordination thread
    coordination_thread: Option<std::thread::JoinHandle<()>>,
    /// Throughput stats for GUI
    throughput_stats: ThroughputStats,
    /// List of currently tunneled process names
    tunneled_processes: Arc<parking_lot::RwLock<Vec<String>>>,
}

unsafe impl Send for MacSplitTunnel {}
unsafe impl Sync for MacSplitTunnel {}

impl MacSplitTunnel {
    pub fn new() -> Self {
        Self {
            firewall: PfFirewall::new(),
            packet_monitor: None,
            process_watcher: None,
            config: None,
            state: DriverState::NotAvailable,
            stop_flag: Arc::new(AtomicBool::new(false)),
            coordination_thread: None,
            throughput_stats: ThroughputStats::default(),
            tunneled_processes: Arc::new(parking_lot::RwLock::new(Vec::new())),
        }
    }

    /// Check if split tunneling is available (requires root for pf)
    pub fn is_available() -> bool {
        // Check if we can run pfctl (requires root)
        match std::process::Command::new("pfctl")
            .arg("-si")
            .output()
        {
            Ok(output) => output.status.success(),
            Err(_) => false,
        }
    }

    /// Clean up stale state from previous sessions
    pub fn cleanup_stale_state() {
        log::info!("Cleaning up stale macOS split tunnel state...");
        let _ = PfFirewall::cleanup();
        log::info!("Stale state cleanup complete");
    }

    /// Configure the split tunnel with the given settings
    pub fn configure(&mut self, config: SplitTunnelConfig) -> VpnResult<()> {
        log::info!(
            "Configuring macOS split tunnel: {} apps, utun={}, tunnel_ip={}",
            config.tunnel_apps.len(),
            config.utun_name,
            config.tunnel_ip,
        );

        // Detect physical interface
        let physical_interface = detect_physical_interface().ok_or_else(|| {
            VpnError::SplitTunnel("Could not detect physical network interface".to_string())
        })?;
        log::info!("Detected physical interface: {}", physical_interface);

        // Parse tunnel gateway (assume .1 suffix for the VPN subnet)
        let tunnel_gateway = parse_gateway(&config.tunnel_ip)?;

        // Set up pf firewall
        self.firewall.enable_split_tunnel(
            &config.utun_name,
            &physical_interface,
            tunnel_gateway,
        )?;

        // Start packet monitor on the physical interface
        let monitor = PacketMonitor::start_monitoring(&physical_interface)?;
        self.packet_monitor = Some(monitor);

        // Start process watcher for game processes
        let watch_list: HashSet<String> = config.tunnel_apps.clone();
        match ProcessWatcher::start(watch_list) {
            Ok(watcher) => {
                self.process_watcher = Some(watcher);
            }
            Err(e) => {
                log::warn!("Failed to start process watcher: {}. Will rely on polling.", e);
            }
        }

        self.state = DriverState::Initialized;
        self.config = Some(config);

        Ok(())
    }

    /// Start the split tunnel coordination loop
    pub fn start(&mut self) -> VpnResult<()> {
        if self.state == DriverState::Active {
            log::warn!("Split tunnel already active");
            return Ok(());
        }

        let config = self.config.as_ref().ok_or_else(|| {
            VpnError::SplitTunnel("Split tunnel not configured".to_string())
        })?;

        log::info!("Starting macOS split tunnel coordination loop");

        self.stop_flag.store(false, Ordering::SeqCst);
        self.throughput_stats.reset();

        let tunnel_apps: HashSet<String> = config.tunnel_apps.clone();
        let utun_name = config.utun_name.clone();
        let tunnel_ip = config.tunnel_ip.clone();
        let stop_flag = self.stop_flag.clone();
        let tunneled_procs = self.tunneled_processes.clone();

        // Detect physical interface for the coordination loop
        let physical_interface = detect_physical_interface().unwrap_or_else(|| "en0".to_string());

        // Start the coordination thread
        let thread = std::thread::Builder::new()
            .name("split-tunnel-coord".to_string())
            .spawn(move || {
                coordination_loop(
                    tunnel_apps,
                    utun_name,
                    tunnel_ip,
                    physical_interface,
                    stop_flag,
                    tunneled_procs,
                );
            })
            .map_err(|e| {
                VpnError::SplitTunnel(format!("Failed to spawn coordination thread: {}", e))
            })?;

        self.coordination_thread = Some(thread);
        self.state = DriverState::Active;

        log::info!("macOS split tunnel active");
        Ok(())
    }

    /// Stop the split tunnel
    pub fn stop(&mut self) -> VpnResult<()> {
        if self.state != DriverState::Active {
            return Ok(());
        }

        log::info!("Stopping macOS split tunnel");

        self.stop_flag.store(true, Ordering::SeqCst);

        // Stop coordination thread
        if let Some(handle) = self.coordination_thread.take() {
            let _ = handle.join();
        }

        // Stop packet monitor
        if let Some(mut monitor) = self.packet_monitor.take() {
            monitor.stop();
        }

        // Stop process watcher
        if let Some(mut watcher) = self.process_watcher.take() {
            watcher.stop();
        }

        // Disable pf rules
        if let Err(e) = self.firewall.disable_split_tunnel() {
            log::error!("Failed to disable pf rules: {}", e);
        }

        self.state = DriverState::NotConfigured;
        self.tunneled_processes.write().clear();

        log::info!("macOS split tunnel stopped");
        Ok(())
    }

    /// Get names of currently running tunnel apps
    pub fn get_running_tunnel_apps(&self) -> Vec<String> {
        self.tunneled_processes.read().clone()
    }

    /// Alias for compatibility with Windows API
    pub fn get_running_target_names(&self) -> Vec<String> {
        self.get_running_tunnel_apps()
    }

    /// Get current state
    pub fn state(&self) -> &DriverState {
        &self.state
    }

    /// Get current configuration
    pub fn config(&self) -> Option<&SplitTunnelConfig> {
        self.config.as_ref()
    }

    /// Get throughput stats for GUI display
    pub fn get_throughput_stats(&self) -> ThroughputStats {
        self.throughput_stats.clone()
    }

    /// Get driver state value (for compatibility)
    pub fn get_driver_state(&self) -> VpnResult<u64> {
        match &self.state {
            DriverState::NotAvailable => Ok(0),
            DriverState::NotConfigured => Ok(1),
            DriverState::Initialized => Ok(2),
            DriverState::Active => Ok(4),
            DriverState::Error(_) => Ok(0),
        }
    }

    /// Clear configuration
    pub fn clear(&mut self) -> VpnResult<()> {
        self.stop()?;
        self.config = None;
        self.state = DriverState::NotConfigured;
        log::info!("Split tunnel configuration cleared");
        Ok(())
    }

    /// Close the split tunnel (full cleanup)
    pub fn close(&mut self) -> VpnResult<()> {
        log::info!("Closing macOS split tunnel");
        self.stop()?;
        self.state = DriverState::NotAvailable;
        log::info!("macOS split tunnel closed");
        Ok(())
    }

    /// Immediately register a process for tunneling (called by process watcher callback)
    pub fn register_process_immediate(&self, pid: u32, name: String) {
        log::info!(
            "Immediately registered process {} (PID: {}) for tunneling",
            name, pid
        );
        let mut procs = self.tunneled_processes.write();
        if !procs.contains(&name) {
            procs.push(name);
        }
    }

    /// Refresh process exclusions
    pub fn refresh_exclusions(&self) -> VpnResult<bool> {
        let running = !self.tunneled_processes.read().is_empty();
        Ok(running)
    }

    /// Get diagnostic info
    pub fn get_diagnostics(&self) -> Option<(Option<String>, bool, u64, u64)> {
        let interface = detect_physical_interface();
        let stats = &self.throughput_stats;
        Some((
            interface,
            self.state == DriverState::Active,
            stats.get_packets_tunneled(),
            stats.get_packets_bypassed(),
        ))
    }
}

impl Default for MacSplitTunnel {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for MacSplitTunnel {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

/// The main coordination loop that ties everything together.
///
/// Runs in a background thread and periodically:
/// 1. Refreshes the process tracker to find game connections
/// 2. Identifies which local ports belong to game processes
/// 3. Updates pf firewall rules to route those ports through VPN
fn coordination_loop(
    tunnel_apps: HashSet<String>,
    utun_name: String,
    tunnel_ip: String,
    physical_interface: String,
    stop_flag: Arc<AtomicBool>,
    tunneled_processes: Arc<parking_lot::RwLock<Vec<String>>>,
) {
    log::info!("Coordination loop started");

    let mut process_tracker = ProcessTracker::new(tunnel_apps.iter().cloned().collect());

    // Create a firewall instance configured with the same utun/physical interface
    // so it can write pf rules targeting the correct interfaces.
    let mut firewall = PfFirewall::new();
    let tunnel_gateway = parse_gateway(&tunnel_ip).unwrap_or(std::net::Ipv4Addr::new(10, 0, 0, 1));
    if let Err(e) = firewall.enable_split_tunnel(&utun_name, &physical_interface, tunnel_gateway) {
        log::error!("Coordination loop: Failed to configure firewall: {}", e);
        return;
    }

    // Refresh interval: 100ms for responsive game connection detection
    let refresh_interval = std::time::Duration::from_millis(100);

    // Log stats every 10 seconds
    let mut stats_timer = std::time::Instant::now();
    let stats_interval = std::time::Duration::from_secs(10);

    // Populate cache immediately
    if let Err(e) = process_tracker.refresh() {
        log::warn!("Initial process tracker refresh failed: {}", e);
    } else {
        let stats = process_tracker.stats();
        log::info!(
            "Process tracker initialized: {} TCP, {} UDP connections",
            stats.tcp_connections, stats.udp_connections
        );
    }

    while !stop_flag.load(Ordering::Relaxed) {
        // Refresh process tracker
        if let Err(e) = process_tracker.refresh() {
            log::warn!("Process tracker refresh error: {}", e);
            std::thread::sleep(refresh_interval);
            continue;
        }

        // Find game connections: iterate all cached connections and find game ports
        let mut game_udp_ports = HashSet::new();
        let mut game_tcp_ports = HashSet::new();
        let mut running_tunnel_apps = Vec::new();

        // Get running tunnel apps for the GUI
        running_tunnel_apps = process_tracker.get_running_tunnel_apps();

        // Scan all connections in the tracker to find which ports belong to game processes
        // We need to check every connection for whether it should be tunneled
        // This is done by the process_tracker's should_tunnel method
        let stats = process_tracker.stats();
        // Since we can't iterate the internal cache directly, we use a different approach:
        // Check each PID name against tunnel apps, then find all ports for those PIDs
        for pid in get_tunnel_pids(&process_tracker, &tunnel_apps) {
            // Find all connections for this PID by scanning the connection cache
            // We iterate known connections via refresh data
            // Note: The ProcessTracker caches connections internally. We need the ports.
            // For now, we scan via the tracker's internal state indirectly.
            //
            // The process tracker already has the mapping. We check ports by brute-forcing
            // the port range that game processes typically use (ephemeral ports 49152-65535).
            // This is more efficient than it sounds because we only check ports that are
            // actually in the connection cache.
        }

        // Better approach: Get all connections from the process tracker
        // We need to enumerate all (ip, port, protocol) -> pid mappings
        // and filter for tunnel PIDs
        collect_game_ports(
            &process_tracker,
            &tunnel_apps,
            &mut game_udp_ports,
            &mut game_tcp_ports,
        );

        // Update pf rules with current game ports
        // Note: PfFirewall tracks changes internally and only reloads if ports changed
        if let Err(e) = firewall.update_game_ports(game_udp_ports, game_tcp_ports) {
            log::warn!("Failed to update pf game ports: {}", e);
        }

        // Update tunneled process names for GUI
        {
            let mut procs = tunneled_processes.write();
            *procs = running_tunnel_apps;
        }

        // Periodic stats logging
        if stats_timer.elapsed() > stats_interval {
            let tracker_stats = process_tracker.stats();
            log::info!(
                "Split tunnel stats: {} TCP, {} UDP connections, {} tracked PIDs, {} tunneled apps",
                tracker_stats.tcp_connections,
                tracker_stats.udp_connections,
                tracker_stats.tracked_pids,
                tunneled_processes.read().len(),
            );
            stats_timer = std::time::Instant::now();
        }

        std::thread::sleep(refresh_interval);
    }

    // Clean up firewall rules on exit
    let _ = firewall.disable_split_tunnel();

    log::info!("Coordination loop stopped");
}

/// Get PIDs that belong to tunnel apps
fn get_tunnel_pids(tracker: &ProcessTracker, tunnel_apps: &HashSet<String>) -> Vec<u32> {
    // Enumerate all processes and find ones matching tunnel apps
    let pids = match libproc::proc_pid::listpids(libproc::proc_pid::ProcFilter::All) {
        Ok(pids) => pids,
        Err(_) => return Vec::new(),
    };

    let mut result = Vec::new();
    for pid in pids {
        if pid == 0 {
            continue;
        }
        if let Some(name) = super::process_tracker::get_process_name(pid) {
            let name_lower = name.to_lowercase();
            for app in tunnel_apps {
                if name_lower.contains(app.as_str()) || app.contains(name_lower.as_str()) {
                    result.push(pid);
                    break;
                }
            }
        }
    }
    result
}

/// Collect all local ports belonging to game processes
fn collect_game_ports(
    tracker: &ProcessTracker,
    tunnel_apps: &HashSet<String>,
    udp_ports: &mut HashSet<u16>,
    tcp_ports: &mut HashSet<u16>,
) {
    // Get all tunnel PIDs
    let tunnel_pids: HashSet<u32> = get_tunnel_pids(tracker, tunnel_apps).into_iter().collect();

    if tunnel_pids.is_empty() {
        return;
    }

    // Enumerate file descriptors for tunnel PIDs and extract their bound ports
    for &pid in &tunnel_pids {
        let fds = match libproc::proc_pid::pidinfo::<libproc::proc_pid::ListFDs>(pid as i32, 0) {
            Ok(fds) => fds,
            Err(_) => continue,
        };

        for fd in &fds {
            if fd.proc_fdtype != libproc::proc_pid::ProcFDType::Socket as u32 {
                continue;
            }

            let socket_info = match libproc::proc_pid::pidfdinfo::<libproc::net_info::SocketFdInfo>(
                pid as i32,
                fd.proc_fd,
            ) {
                Ok(info) => info,
                Err(_) => continue,
            };

            let soi = &socket_info.psi;
            if soi.soi_family != libc::AF_INET as i32 {
                continue;
            }

            match soi.soi_kind {
                1 => {
                    // TCP
                    let tcp_info = unsafe { &soi.soi_proto.pri_tcp };
                    let port = unsafe { u16::from_be(tcp_info.tcpsi_ini.insi_lport as u16) };
                    if port > 0 {
                        tcp_ports.insert(port);
                    }
                }
                2 => {
                    // UDP
                    let in_info = unsafe { &soi.soi_proto.pri_in };
                    let port = unsafe { u16::from_be(in_info.insi_lport as u16) };
                    if port > 0 {
                        udp_ports.insert(port);
                    }
                }
                _ => {}
            }
        }
    }
}

/// Parse a tunnel IP to derive the gateway address (assumes .1 in the subnet)
fn parse_gateway(tunnel_ip: &str) -> VpnResult<std::net::Ipv4Addr> {
    let ip: std::net::Ipv4Addr = tunnel_ip
        .parse()
        .map_err(|e| VpnError::SplitTunnel(format!("Invalid tunnel IP '{}': {}", tunnel_ip, e)))?;

    let octets = ip.octets();
    // Gateway is typically .1 in the same /24 subnet
    Ok(std::net::Ipv4Addr::new(octets[0], octets[1], octets[2], 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_game_preset_names() {
        assert!(!GamePreset::Roblox.process_names().is_empty());
        assert!(!GamePreset::Valorant.process_names().is_empty());
        assert!(!GamePreset::Fortnite.process_names().is_empty());
    }

    #[test]
    fn test_macos_game_names_no_exe() {
        // macOS process names should NOT have .exe extension
        for preset in GamePreset::all() {
            for name in preset.process_names() {
                assert!(
                    !name.ends_with(".exe"),
                    "macOS process name should not have .exe: {}",
                    name
                );
            }
        }
    }

    #[test]
    fn test_config_creation() {
        let config = SplitTunnelConfig::new(
            vec!["robloxplayer".to_string()],
            "10.0.0.2".to_string(),
            "192.168.1.100".to_string(),
            "utun5".to_string(),
            RoutingMode::V1,
        );
        assert!(config.tunnel_apps.contains("robloxplayer"));
    }

    #[test]
    fn test_parse_gateway() {
        let gw = parse_gateway("10.0.42.15").unwrap();
        assert_eq!(gw, std::net::Ipv4Addr::new(10, 0, 42, 1));

        let gw = parse_gateway("10.0.0.2").unwrap();
        assert_eq!(gw, std::net::Ipv4Addr::new(10, 0, 0, 1));
    }

    #[test]
    fn test_driver_state() {
        let driver = MacSplitTunnel::new();
        assert_eq!(*driver.state(), DriverState::NotAvailable);
    }

    #[test]
    fn test_tunnel_apps_for_presets() {
        let mut presets = HashSet::new();
        presets.insert(GamePreset::Roblox);

        let apps = get_tunnel_apps_for_presets(&presets);
        assert!(apps.contains("robloxplayer"));
        assert!(!apps.iter().any(|a| a.ends_with(".exe")));
    }
}
