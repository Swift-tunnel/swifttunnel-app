//! Process Tracker - Maps network connections to process IDs
//!
//! Uses Windows IP Helper APIs (GetExtendedTcpTable, GetExtendedUdpTable) to
//! track which processes own which network connections. This allows us to
//! determine which packets belong to which applications for split tunneling.
//!
//! Key features:
//! - O(1) lookup via HashMap cache
//! - Tracks both TCP and UDP connections
//! - Configurable refresh interval
//! - Process name caching for efficiency

use super::{VpnError, VpnResult};
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::ptr;
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};
use windows::Win32::Foundation::*;
use windows::Win32::NetworkManagement::IpHelper::*;

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
    /// Cache: (local_ip, local_port, protocol) → PID
    connection_cache: HashMap<ConnectionKey, u32>,
    /// Apps that should be tunneled (exe names, lowercase)
    tunnel_apps: HashSet<String>,
    /// PID → exe name cache
    pid_names: HashMap<u32, String>,
    /// System info for process enumeration
    system: System,
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
            system: System::new(),
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

    /// Refresh the connection-to-PID mappings
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

        // Refresh tables
        self.refresh_tcp_table()?;
        self.refresh_udp_table()?;
        self.refresh_pid_names()?;

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

        // CRITICAL FIX: Check for 0.0.0.0 (INADDR_ANY) bindings
        // Apps often bind to 0.0.0.0 which matches any interface, but packets
        // have the actual interface IP. Check if there's a 0.0.0.0 binding for this port.
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
        // This is safer: if we can't identify the process, let it bypass VPN
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
            // Check partial match (e.g., "roblox" matches "robloxplayerbeta.exe")
            for app in &self.tunnel_apps {
                let app_stem = app.trim_end_matches(".exe");
                let name_stem = name_lower.trim_end_matches(".exe");
                if name_stem.contains(app_stem) || app_stem.contains(name_stem) {
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
        for (pid, name) in &self.pid_names {
            let name_lower = name.to_lowercase();
            if self.tunnel_apps.contains(&name_lower) {
                running.push(name.clone());
            }
        }
        // Deduplicate
        running.sort();
        running.dedup();
        running
    }

    /// Refresh TCP connection table
    fn refresh_tcp_table(&mut self) -> VpnResult<()> {
        unsafe {
            // First call to get required size
            let mut size: u32 = 0;
            let result = GetExtendedTcpTable(
                None,
                &mut size,
                false,
                2, // AF_INET (IPv4)
                TCP_TABLE_CLASS(TCP_TABLE_OWNER_PID_ALL.0),
                0,
            );

            if result != ERROR_INSUFFICIENT_BUFFER.0 && result != NO_ERROR.0 {
                return Err(VpnError::SplitTunnel(format!(
                    "GetExtendedTcpTable size query failed: 0x{:08X}",
                    result
                )));
            }

            if size == 0 {
                return Ok(());
            }

            // Allocate buffer
            let mut buffer = vec![0u8; size as usize];
            let result = GetExtendedTcpTable(
                Some(buffer.as_mut_ptr() as *mut _),
                &mut size,
                false,
                2, // AF_INET
                TCP_TABLE_CLASS(TCP_TABLE_OWNER_PID_ALL.0),
                0,
            );

            if result != NO_ERROR.0 {
                return Err(VpnError::SplitTunnel(format!(
                    "GetExtendedTcpTable failed: 0x{:08X}",
                    result
                )));
            }

            // Parse the table
            let table = &*(buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
            let entries =
                std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize);

            for entry in entries {
                let local_ip = Ipv4Addr::from(entry.dwLocalAddr.to_ne_bytes());
                let local_port = u16::from_be(entry.dwLocalPort as u16);
                let pid = entry.dwOwningPid;

                let key = ConnectionKey::new(local_ip, local_port, Protocol::Tcp);
                self.connection_cache.insert(key, pid);
            }
        }

        Ok(())
    }

    /// Refresh UDP endpoint table
    fn refresh_udp_table(&mut self) -> VpnResult<()> {
        unsafe {
            // First call to get required size
            let mut size: u32 = 0;
            let result = GetExtendedUdpTable(
                None,
                &mut size,
                false,
                2, // AF_INET (IPv4)
                UDP_TABLE_CLASS(UDP_TABLE_OWNER_PID.0),
                0,
            );

            if result != ERROR_INSUFFICIENT_BUFFER.0 && result != NO_ERROR.0 {
                return Err(VpnError::SplitTunnel(format!(
                    "GetExtendedUdpTable size query failed: 0x{:08X}",
                    result
                )));
            }

            if size == 0 {
                return Ok(());
            }

            // Allocate buffer
            let mut buffer = vec![0u8; size as usize];
            let result = GetExtendedUdpTable(
                Some(buffer.as_mut_ptr() as *mut _),
                &mut size,
                false,
                2, // AF_INET
                UDP_TABLE_CLASS(UDP_TABLE_OWNER_PID.0),
                0,
            );

            if result != NO_ERROR.0 {
                return Err(VpnError::SplitTunnel(format!(
                    "GetExtendedUdpTable failed: 0x{:08X}",
                    result
                )));
            }

            // Parse the table
            let table = &*(buffer.as_ptr() as *const MIB_UDPTABLE_OWNER_PID);
            let entries =
                std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize);

            for entry in entries {
                let local_ip = Ipv4Addr::from(entry.dwLocalAddr.to_ne_bytes());
                let local_port = u16::from_be(entry.dwLocalPort as u16);
                let pid = entry.dwOwningPid;

                let key = ConnectionKey::new(local_ip, local_port, Protocol::Udp);
                self.connection_cache.insert(key, pid);
            }
        }

        Ok(())
    }

    /// Refresh PID to process name mapping
    fn refresh_pid_names(&mut self) -> VpnResult<()> {
        // Refresh process list
        self.system.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::new().with_exe(UpdateKind::OnlyIfNotSet),
        );

        // Update name cache for PIDs we care about
        let pids_in_cache: HashSet<u32> = self
            .connection_cache
            .values()
            .copied()
            .chain(self.stale_connections.values().map(|(pid, _)| *pid))
            .collect();

        for pid in pids_in_cache {
            if !self.pid_names.contains_key(&pid) {
                if let Some(process) = self.system.process(sysinfo::Pid::from_u32(pid)) {
                    self.pid_names
                        .insert(pid, process.name().to_string_lossy().to_string());
                }
            }
        }

        // Also scan for any tunnel apps that might be running but not in cache
        for (_pid, process) in self.system.processes() {
            let name = process.name().to_string_lossy().to_lowercase();
            for tunnel_app in &self.tunnel_apps {
                if name.contains(tunnel_app.trim_end_matches(".exe")) {
                    self.pid_names
                        .insert(_pid.as_u32(), process.name().to_string_lossy().to_string());
                    break;
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
        let tracker = ProcessTracker::new(vec!["robloxplayerbeta.exe".to_string()]);
        assert!(tracker.tunnel_apps.contains("robloxplayerbeta.exe"));
    }
}
