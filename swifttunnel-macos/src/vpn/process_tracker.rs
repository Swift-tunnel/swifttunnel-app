//! Process Tracker - Maps network connections to process IDs (macOS)
//!
//! Uses libproc (macOS proc_info API) to track which processes own which network
//! connections. This allows us to determine which packets belong to which
//! applications for split tunneling.
//!
//! macOS equivalent of the Windows IP Helper APIs (GetExtendedTcpTable/GetExtendedUdpTable).
//! Uses libproc::proc_pid to enumerate all processes and their socket file descriptors.
//!
//! Key features:
//! - O(1) lookup via HashMap cache
//! - Tracks both TCP and UDP connections
//! - Configurable refresh interval
//! - Process name caching for efficiency

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use super::{VpnError, VpnResult};

/// Protocol type for connection tracking
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Tcp,
    Udp,
}

/// Connection key for cache lookup
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConnectionKey {
    pub local_ip: Ipv4Addr,
    pub local_port: u16,
    pub protocol: Protocol,
}

impl ConnectionKey {
    pub fn new(local_ip: Ipv4Addr, local_port: u16, protocol: Protocol) -> Self {
        Self {
            local_ip,
            local_port,
            protocol,
        }
    }
}

/// Process tracker that maps network connections to PIDs
pub struct ProcessTracker {
    /// Cache: (local_ip, local_port, protocol) -> PID
    connection_cache: HashMap<ConnectionKey, u32>,
    /// Apps that should be tunneled (process names, lowercase, no .exe extension)
    tunnel_apps: HashSet<String>,
    /// PID -> process name cache
    pid_names: HashMap<u32, String>,
    /// Recently seen connections (kept for 5 seconds after disappearing)
    stale_connections: HashMap<ConnectionKey, (u32, std::time::Instant)>,
    /// Stale entry timeout
    stale_timeout: std::time::Duration,
}

impl ProcessTracker {
    /// Create a new process tracker
    pub fn new(tunnel_apps: Vec<String>) -> Self {
        Self {
            connection_cache: HashMap::with_capacity(1024),
            tunnel_apps: tunnel_apps.into_iter().map(|s| s.to_lowercase()).collect(),
            pid_names: HashMap::with_capacity(256),
            stale_connections: HashMap::with_capacity(256),
            stale_timeout: std::time::Duration::from_secs(5),
        }
    }

    /// Update the list of apps to tunnel
    pub fn set_tunnel_apps(&mut self, apps: Vec<String>) {
        self.tunnel_apps = apps.into_iter().map(|s| s.to_lowercase()).collect();
    }

    /// Get the current tunnel apps
    pub fn tunnel_apps(&self) -> &HashSet<String> {
        &self.tunnel_apps
    }

    /// Refresh the connection-to-PID mappings using libproc
    pub fn refresh(&mut self) -> VpnResult<()> {
        // Clear stale entries older than timeout
        let now = std::time::Instant::now();
        self.stale_connections
            .retain(|_, (_, timestamp)| now.duration_since(*timestamp) < self.stale_timeout);

        // Move current cache to stale before refreshing
        let old_cache = std::mem::take(&mut self.connection_cache);
        for (key, pid) in old_cache {
            self.stale_connections.insert(key, (pid, now));
        }

        // Enumerate all PIDs
        let pids = match libproc::processes::pids_by_type(libproc::processes::ProcFilter::All) {
            Ok(pids) => pids,
            Err(e) => {
                return Err(VpnError::SplitTunnel(format!(
                    "Failed to enumerate processes: {}",
                    e
                )));
            }
        };

        // For each PID, enumerate file descriptors and find sockets
        for pid in &pids {
            let pid = *pid as i32;
            if pid <= 0 {
                continue;
            }

            // Get number of file descriptors via TaskAllInfo, then list them
            let max_fds = match libproc::proc_pid::pidinfo::<libproc::task_info::TaskAllInfo>(pid, 0) {
                Ok(info) => info.pbsd.pbi_nfiles as usize,
                Err(_) => continue,
            };

            let fds = match libproc::proc_pid::listpidinfo::<libproc::file_info::ListFDs>(pid, max_fds) {
                Ok(fds) => fds,
                Err(_) => continue, // Can't access this process (permission denied, zombie, etc.)
            };

            for fd in &fds {
                // Only interested in socket file descriptors
                if fd.proc_fdtype != libproc::file_info::ProcFDType::Socket as u32 {
                    continue;
                }

                // Get socket info for this FD
                let socket_info = match libproc::file_info::pidfdinfo::<libproc::net_info::SocketFDInfo>(
                    pid,
                    fd.proc_fd,
                ) {
                    Ok(info) => info,
                    Err(_) => continue,
                };

                // Extract connection info based on socket family and protocol
                let soi = &socket_info.psi;

                // We only care about AF_INET (IPv4) sockets
                if soi.soi_family != libc::AF_INET as i32 {
                    continue;
                }

                match soi.soi_kind {
                    // TCP socket
                    1 => {
                        // SOCK_STREAM
                        let tcp_info = unsafe { &soi.soi_proto.pri_tcp };
                        let in_si = unsafe { &tcp_info.tcpsi_ini.insi_laddr.ina_46.i46a_addr4 };
                        let local_ip = Ipv4Addr::from(u32::from_be(in_si.s_addr));
                        let local_port = unsafe {
                            u16::from_be(tcp_info.tcpsi_ini.insi_lport as u16)
                        };

                        if local_port > 0 {
                            let key = ConnectionKey::new(local_ip, local_port, Protocol::Tcp);
                            self.connection_cache.insert(key, pid as u32);
                        }
                    }
                    // UDP socket
                    2 => {
                        // SOCK_DGRAM
                        let in_info = unsafe { &soi.soi_proto.pri_in };
                        let in_si = unsafe { &in_info.insi_laddr.ina_46.i46a_addr4 };
                        let local_ip = Ipv4Addr::from(u32::from_be(in_si.s_addr));
                        let local_port = unsafe {
                            u16::from_be(in_info.insi_lport as u16)
                        };

                        if local_port > 0 {
                            let key = ConnectionKey::new(local_ip, local_port, Protocol::Udp);
                            self.connection_cache.insert(key, pid as u32);
                        }
                    }
                    _ => continue,
                }
            }
        }

        // Refresh PID name cache
        self.refresh_pid_names(&pids)?;

        Ok(())
    }

    /// Check if a packet should be tunneled based on local IP:port
    pub fn should_tunnel(&self, local_ip: Ipv4Addr, local_port: u16, protocol: Protocol) -> bool {
        let key = ConnectionKey::new(local_ip, local_port, protocol);

        // First check active cache with exact IP match
        if let Some(&pid) = self.connection_cache.get(&key) {
            return self.is_tunnel_pid(pid);
        }

        // Check stale cache with exact IP match
        if let Some(&(pid, _)) = self.stale_connections.get(&key) {
            return self.is_tunnel_pid(pid);
        }

        // Check for 0.0.0.0 (INADDR_ANY) bindings
        // Apps often bind to 0.0.0.0 which matches any interface, but packets
        // have the actual interface IP.
        if local_ip != Ipv4Addr::UNSPECIFIED {
            let any_key = ConnectionKey::new(Ipv4Addr::UNSPECIFIED, local_port, protocol);

            if let Some(&pid) = self.connection_cache.get(&any_key) {
                return self.is_tunnel_pid(pid);
            }

            if let Some(&(pid, _)) = self.stale_connections.get(&any_key) {
                return self.is_tunnel_pid(pid);
            }
        }

        // Unknown connection - default to NOT tunneling (passthrough)
        false
    }

    /// Check if a PID belongs to a tunnel app
    fn is_tunnel_pid(&self, pid: u32) -> bool {
        if let Some(name) = self.pid_names.get(&pid) {
            let name_lower = name.to_lowercase();
            // Check exact match
            if self.tunnel_apps.contains(&name_lower) {
                return true;
            }
            // Check partial match (e.g., "roblox" matches "robloxplayer")
            for app in &self.tunnel_apps {
                if name_lower.contains(app.as_str()) || app.contains(name_lower.as_str()) {
                    return true;
                }
            }
        }
        false
    }

    /// Get PID for a connection (for debugging)
    pub fn get_pid(&self, local_ip: Ipv4Addr, local_port: u16, protocol: Protocol) -> Option<u32> {
        let key = ConnectionKey::new(local_ip, local_port, protocol);
        self.connection_cache
            .get(&key)
            .copied()
            .or_else(|| self.stale_connections.get(&key).map(|(pid, _)| *pid))
    }

    /// Get process name for a PID
    pub fn get_process_name(&self, pid: u32) -> Option<&String> {
        self.pid_names.get(&pid)
    }

    /// Get names of currently running tunnel apps
    pub fn get_running_tunnel_apps(&self) -> Vec<String> {
        let mut running = Vec::new();
        for (_pid, name) in &self.pid_names {
            let name_lower = name.to_lowercase();
            for tunnel_app in &self.tunnel_apps {
                if name_lower.contains(tunnel_app.as_str()) || tunnel_app.contains(name_lower.as_str()) {
                    running.push(name.clone());
                    break;
                }
            }
        }
        running.sort();
        running.dedup();
        running
    }

    /// Refresh PID to process name mapping using libproc pidpath
    fn refresh_pid_names(&mut self, pids: &[u32]) -> VpnResult<()> {
        // Update name cache for PIDs in connection cache
        let pids_in_cache: HashSet<u32> = self
            .connection_cache
            .values()
            .copied()
            .chain(self.stale_connections.values().map(|(pid, _)| *pid))
            .collect();

        for &pid in &pids_in_cache {
            if !self.pid_names.contains_key(&pid) {
                if let Some(name) = get_process_name(pid) {
                    self.pid_names.insert(pid, name);
                }
            }
        }

        // Also scan all PIDs for tunnel apps that might be running but not in cache
        for &pid in pids {
            if pid == 0 {
                continue;
            }
            if self.pid_names.contains_key(&pid) {
                continue;
            }
            if let Some(name) = get_process_name(pid) {
                let name_lower = name.to_lowercase();
                for tunnel_app in &self.tunnel_apps {
                    if name_lower.contains(tunnel_app.as_str()) {
                        self.pid_names.insert(pid, name);
                        break;
                    }
                }
            }
        }

        Ok(())
    }

    /// Get statistics about the cache
    pub fn stats(&self) -> TrackerStats {
        TrackerStats {
            tcp_connections: self
                .connection_cache
                .keys()
                .filter(|k| k.protocol == Protocol::Tcp)
                .count(),
            udp_connections: self
                .connection_cache
                .keys()
                .filter(|k| k.protocol == Protocol::Udp)
                .count(),
            stale_connections: self.stale_connections.len(),
            tracked_pids: self.pid_names.len(),
        }
    }
}

/// Get process executable name by PID using libproc
///
/// Returns just the binary name (e.g., "RobloxPlayer"), not the full path.
pub fn get_process_name(pid: u32) -> Option<String> {
    match libproc::proc_pid::pidpath(pid as i32) {
        Ok(path) => {
            // Extract just the filename from the full path
            // e.g., "/Applications/Roblox.app/Contents/MacOS/RobloxPlayer" -> "RobloxPlayer"
            path.rsplit('/').next().map(|s| s.to_string())
        }
        Err(_) => None,
    }
}

/// Get full executable path by PID using libproc
pub fn get_process_path(pid: u32) -> Option<String> {
    libproc::proc_pid::pidpath(pid as i32).ok()
}

/// Look up PID for a specific connection by scanning proc info
///
/// This is an expensive synchronous call - only use when cache misses.
/// Scans all processes to find which one owns a specific local port.
pub fn lookup_pid_for_connection(
    local_ip: Ipv4Addr,
    local_port: u16,
    protocol: Protocol,
) -> Option<u32> {
    let pids = libproc::processes::pids_by_type(libproc::processes::ProcFilter::All).ok()?;

    for pid in &pids {
        let pid = *pid as i32;
        if pid <= 0 {
            continue;
        }

        let max_fds = match libproc::proc_pid::pidinfo::<libproc::task_info::TaskAllInfo>(pid, 0) {
            Ok(info) => info.pbsd.pbi_nfiles as usize,
            Err(_) => continue,
        };

        let fds = match libproc::proc_pid::listpidinfo::<libproc::file_info::ListFDs>(pid, max_fds) {
            Ok(fds) => fds,
            Err(_) => continue,
        };

        for fd in &fds {
            if fd.proc_fdtype != libproc::file_info::ProcFDType::Socket as u32 {
                continue;
            }

            let socket_info =
                match libproc::file_info::pidfdinfo::<libproc::net_info::SocketFDInfo>(
                    pid,
                    fd.proc_fd,
                ) {
                    Ok(info) => info,
                    Err(_) => continue,
                };

            let soi = &socket_info.psi;
            if soi.soi_family != libc::AF_INET as i32 {
                continue;
            }

            let (found_ip, found_port, found_proto) = match soi.soi_kind {
                1 => {
                    // TCP
                    let tcp_info = unsafe { &soi.soi_proto.pri_tcp };
                    let in_si =
                        unsafe { &tcp_info.tcpsi_ini.insi_laddr.ina_46.i46a_addr4 };
                    let ip = Ipv4Addr::from(u32::from_be(in_si.s_addr));
                    let port =
                        unsafe { u16::from_be(tcp_info.tcpsi_ini.insi_lport as u16) };
                    (ip, port, Protocol::Tcp)
                }
                2 => {
                    // UDP
                    let in_info = unsafe { &soi.soi_proto.pri_in };
                    let in_si =
                        unsafe { &in_info.insi_laddr.ina_46.i46a_addr4 };
                    let ip = Ipv4Addr::from(u32::from_be(in_si.s_addr));
                    let port = unsafe { u16::from_be(in_info.insi_lport as u16) };
                    (ip, port, Protocol::Udp)
                }
                _ => continue,
            };

            if found_proto == protocol
                && found_port == local_port
                && (found_ip == local_ip || found_ip == Ipv4Addr::UNSPECIFIED)
            {
                return Some(pid as u32);
            }
        }
    }

    None
}

/// Statistics about the process tracker
#[derive(Debug, Clone)]
pub struct TrackerStats {
    pub tcp_connections: usize,
    pub udp_connections: usize,
    pub stale_connections: usize,
    pub tracked_pids: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_key() {
        let key1 = ConnectionKey::new(Ipv4Addr::new(192, 168, 1, 1), 8080, Protocol::Tcp);
        let key2 = ConnectionKey::new(Ipv4Addr::new(192, 168, 1, 1), 8080, Protocol::Tcp);
        let key3 = ConnectionKey::new(Ipv4Addr::new(192, 168, 1, 1), 8080, Protocol::Udp);

        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_tracker_creation() {
        let tracker = ProcessTracker::new(vec!["robloxplayer".to_string()]);
        assert!(tracker.tunnel_apps.contains("robloxplayer"));
    }

    #[test]
    fn test_get_current_process_name() {
        let pid = std::process::id();
        let name = get_process_name(pid);
        assert!(name.is_some(), "Should be able to get our own process name");
    }
}
