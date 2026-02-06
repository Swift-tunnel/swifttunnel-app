//! Packet Monitor - BPF-based packet capture for connection tracking (macOS)
//!
//! Uses the `pcap` crate (which wraps libpcap/BPF) to capture packets on the
//! physical network interface. This is used for connection tracking - identifying
//! which local ports are actively sending traffic so we can update pf rules.
//!
//! **Important**: Unlike the Windows ndisapi interceptor, this does NOT route packets.
//! Actual routing is handled by pf firewall rules (see firewall.rs). This module
//! only monitors traffic to discover active game connections.
//!
//! ## Architecture difference from Windows
//!
//! Windows: ndisapi intercepts -> parse headers -> check process -> route (inline)
//! macOS:   BPF captures (passive) -> parse headers -> identify connections -> pf routes
//!
//! The macOS approach is split into observation (this module) and action (firewall.rs).

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use super::process_tracker::Protocol;

/// Information about an observed active connection
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConnectionInfo {
    pub src_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_ip: Ipv4Addr,
    pub dst_port: u16,
    pub protocol: Protocol,
}

/// Throughput statistics for GUI display
#[derive(Debug, Clone, Default)]
pub struct ThroughputStats {
    bytes_tx: Arc<AtomicU64>,
    bytes_rx: Arc<AtomicU64>,
    packets_tunneled: Arc<AtomicU64>,
    packets_bypassed: Arc<AtomicU64>,
}

impl ThroughputStats {
    pub fn add_tx(&self, bytes: u64) {
        self.bytes_tx.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn add_rx(&self, bytes: u64) {
        self.bytes_rx.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn add_tunneled(&self) {
        self.packets_tunneled.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add_bypassed(&self) {
        self.packets_bypassed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn get_bytes_tx(&self) -> u64 {
        self.bytes_tx.load(Ordering::Relaxed)
    }

    pub fn get_bytes_rx(&self) -> u64 {
        self.bytes_rx.load(Ordering::Relaxed)
    }

    pub fn get_packets_tunneled(&self) -> u64 {
        self.packets_tunneled.load(Ordering::Relaxed)
    }

    pub fn get_packets_bypassed(&self) -> u64 {
        self.packets_bypassed.load(Ordering::Relaxed)
    }

    pub fn reset(&self) {
        self.bytes_tx.store(0, Ordering::Relaxed);
        self.bytes_rx.store(0, Ordering::Relaxed);
        self.packets_tunneled.store(0, Ordering::Relaxed);
        self.packets_bypassed.store(0, Ordering::Relaxed);
    }
}

/// Parsed IP packet info (from raw packet data)
#[derive(Debug, Clone)]
pub struct PacketInfo {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: Protocol,
    pub payload_len: usize,
}

impl PacketInfo {
    /// Parse from raw IP packet (no Ethernet header - macOS BPF on utun gives raw IP)
    pub fn from_ip_packet(data: &[u8]) -> Option<Self> {
        if data.len() < 20 {
            return None;
        }

        let version = (data[0] >> 4) & 0xF;
        if version != 4 {
            return None; // Only IPv4
        }

        let ihl = (data[0] & 0xF) as usize * 4;
        if data.len() < ihl {
            return None;
        }

        let protocol_num = data[9];
        let protocol = match protocol_num {
            6 => Protocol::Tcp,
            17 => Protocol::Udp,
            _ => return None,
        };

        let total_len = u16::from_be_bytes([data[2], data[3]]) as usize;
        let src_ip = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
        let dst_ip = Ipv4Addr::new(data[16], data[17], data[18], data[19]);

        if data.len() < ihl + 4 {
            return None;
        }

        let transport = &data[ihl..];
        let src_port = u16::from_be_bytes([transport[0], transport[1]]);
        let dst_port = u16::from_be_bytes([transport[2], transport[3]]);

        let payload_len = total_len.saturating_sub(ihl);

        Some(PacketInfo {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            payload_len,
        })
    }

    /// Parse from Ethernet frame (for captures on en0 etc.)
    pub fn from_ethernet_frame(data: &[u8]) -> Option<Self> {
        if data.len() < 14 {
            return None;
        }

        let ethertype = u16::from_be_bytes([data[12], data[13]]);
        if ethertype != 0x0800 {
            return None; // Not IPv4
        }

        Self::from_ip_packet(&data[14..])
    }
}

/// BPF-based packet monitor for connection tracking
///
/// Captures packets on the physical interface to identify which local ports
/// are actively sending game traffic. This information is used by the split
/// tunnel coordinator to update pf routing rules.
pub struct PacketMonitor {
    /// Name of the interface being monitored
    interface: String,
    /// Stop flag
    stop_flag: Arc<AtomicBool>,
    /// Capture thread handle
    capture_thread: Option<std::thread::JoinHandle<()>>,
    /// Active connections observed (shared with capture thread)
    active_connections: Arc<parking_lot::RwLock<HashMap<ConnectionInfo, std::time::Instant>>>,
    /// Throughput stats
    throughput_stats: ThroughputStats,
}

impl PacketMonitor {
    /// Start monitoring packets on the given interface
    ///
    /// # Arguments
    /// * `interface` - Network interface to capture on (e.g., "en0")
    pub fn start_monitoring(interface: &str) -> super::VpnResult<Self> {
        log::info!("Starting packet monitor on {}", interface);

        let stop_flag = Arc::new(AtomicBool::new(false));
        let active_connections = Arc::new(parking_lot::RwLock::new(HashMap::new()));
        let throughput_stats = ThroughputStats::default();

        let iface = interface.to_string();
        let stop = stop_flag.clone();
        let conns = active_connections.clone();
        let stats = throughput_stats.clone();

        let capture_thread = std::thread::Builder::new()
            .name(format!("pcap-{}", interface))
            .spawn(move || {
                if let Err(e) = capture_loop(&iface, stop, conns, stats) {
                    log::error!("Packet capture loop error on {}: {}", iface, e);
                }
            })
            .map_err(|e| {
                super::VpnError::SplitTunnel(format!("Failed to spawn capture thread: {}", e))
            })?;

        Ok(Self {
            interface: interface.to_string(),
            stop_flag,
            capture_thread: Some(capture_thread),
            active_connections,
            throughput_stats,
        })
    }

    /// Get currently active connections observed in the last N seconds
    pub fn get_active_connections(&self, max_age_secs: u64) -> Vec<ConnectionInfo> {
        let cutoff = std::time::Instant::now() - std::time::Duration::from_secs(max_age_secs);
        let conns = self.active_connections.read();
        conns
            .iter()
            .filter(|(_, last_seen)| **last_seen > cutoff)
            .map(|(info, _)| info.clone())
            .collect()
    }

    /// Get the set of active source ports for a given protocol
    pub fn get_active_source_ports(&self, protocol: Protocol, max_age_secs: u64) -> std::collections::HashSet<u16> {
        let cutoff = std::time::Instant::now() - std::time::Duration::from_secs(max_age_secs);
        let conns = self.active_connections.read();
        conns
            .iter()
            .filter(|(info, last_seen)| info.protocol == protocol && **last_seen > cutoff)
            .map(|(info, _)| info.src_port)
            .collect()
    }

    /// Get throughput statistics
    pub fn get_throughput_stats(&self) -> &ThroughputStats {
        &self.throughput_stats
    }

    /// Stop the packet monitor
    pub fn stop(&mut self) {
        if self.stop_flag.load(Ordering::Relaxed) {
            return;
        }

        log::info!("Stopping packet monitor on {}", self.interface);
        self.stop_flag.store(true, Ordering::SeqCst);

        if let Some(handle) = self.capture_thread.take() {
            // pcap has a read timeout, so the thread should exit within that timeout
            let _ = handle.join();
        }
    }
}

impl Drop for PacketMonitor {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Main capture loop using pcap/BPF
fn capture_loop(
    interface: &str,
    stop_flag: Arc<AtomicBool>,
    active_connections: Arc<parking_lot::RwLock<HashMap<ConnectionInfo, std::time::Instant>>>,
    stats: ThroughputStats,
) -> Result<(), String> {
    use pcap::{Capture, Device};

    log::info!("Opening pcap capture on {}", interface);

    // Find the device
    let device = Device::list()
        .map_err(|e| format!("Failed to list pcap devices: {}", e))?
        .into_iter()
        .find(|d| d.name == interface)
        .ok_or_else(|| format!("Interface {} not found", interface))?;

    // Open capture with:
    // - Snap length: 128 bytes (we only need headers, not payload)
    // - Promiscuous: false (we only want our own traffic)
    // - Timeout: 100ms (so we can check stop_flag)
    let mut cap = Capture::from_device(device)
        .map_err(|e| format!("Failed to open capture on {}: {}", interface, e))?
        .snaplen(128)
        .promisc(false)
        .timeout(100)
        .open()
        .map_err(|e| format!("Failed to activate capture on {}: {}", interface, e))?;

    // Only capture outbound IPv4 TCP/UDP traffic
    cap.filter("ip and (tcp or udp)", true)
        .map_err(|e| format!("Failed to set BPF filter: {}", e))?;

    log::info!("Packet capture active on {}", interface);

    // Connection expiry cleanup interval
    let mut last_cleanup = std::time::Instant::now();
    let cleanup_interval = std::time::Duration::from_secs(10);
    let connection_ttl = std::time::Duration::from_secs(30);

    while !stop_flag.load(Ordering::Relaxed) {
        match cap.next_packet() {
            Ok(packet) => {
                // Parse the packet (pcap on macOS Ethernet interfaces includes Ethernet header)
                if let Some(info) = PacketInfo::from_ethernet_frame(packet.data) {
                    let conn = ConnectionInfo {
                        src_ip: info.src_ip,
                        src_port: info.src_port,
                        dst_ip: info.dst_ip,
                        dst_port: info.dst_port,
                        protocol: info.protocol,
                    };

                    // Update the connection's last-seen timestamp
                    active_connections
                        .write()
                        .insert(conn, std::time::Instant::now());

                    stats.add_tx(info.payload_len as u64);
                }
            }
            Err(pcap::Error::TimeoutExpired) => {
                // Normal - just check stop_flag and continue
            }
            Err(e) => {
                if !stop_flag.load(Ordering::Relaxed) {
                    log::warn!("pcap capture error: {}", e);
                }
                // Brief sleep to avoid tight error loop
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        }

        // Periodic cleanup of stale connections
        if last_cleanup.elapsed() > cleanup_interval {
            let cutoff = std::time::Instant::now() - connection_ttl;
            active_connections
                .write()
                .retain(|_, last_seen| *last_seen > cutoff);
            last_cleanup = std::time::Instant::now();
        }
    }

    log::info!("Packet capture stopped on {}", interface);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_info_parsing() {
        // Minimal IPv4 TCP packet
        let mut ip_packet = vec![0u8; 40];
        ip_packet[0] = 0x45; // IPv4, IHL=5
        ip_packet[2..4].copy_from_slice(&40u16.to_be_bytes()); // total len
        ip_packet[9] = 6; // TCP
        ip_packet[12..16].copy_from_slice(&[192, 168, 1, 1]); // src IP
        ip_packet[16..20].copy_from_slice(&[10, 0, 0, 1]); // dst IP
        ip_packet[20..22].copy_from_slice(&1234u16.to_be_bytes()); // src port
        ip_packet[22..24].copy_from_slice(&80u16.to_be_bytes()); // dst port

        let info = PacketInfo::from_ip_packet(&ip_packet).unwrap();
        assert_eq!(info.src_ip, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(info.dst_ip, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(info.src_port, 1234);
        assert_eq!(info.dst_port, 80);
        assert_eq!(info.protocol, Protocol::Tcp);
    }

    #[test]
    fn test_ethernet_frame_parsing() {
        let mut frame = vec![0u8; 54];
        // Ethernet header
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes()); // IPv4
        // IP header
        frame[14] = 0x45;
        frame[16..18].copy_from_slice(&40u16.to_be_bytes()); // total len
        frame[23] = 17; // UDP
        frame[26..30].copy_from_slice(&[10, 0, 0, 1]); // src
        frame[30..34].copy_from_slice(&[8, 8, 8, 8]); // dst
        frame[34..36].copy_from_slice(&5000u16.to_be_bytes());
        frame[36..38].copy_from_slice(&53u16.to_be_bytes());

        let info = PacketInfo::from_ethernet_frame(&frame).unwrap();
        assert_eq!(info.src_ip, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(info.protocol, Protocol::Udp);
        assert_eq!(info.src_port, 5000);
        assert_eq!(info.dst_port, 53);
    }

    #[test]
    fn test_throughput_stats() {
        let stats = ThroughputStats::default();
        stats.add_tx(100);
        stats.add_tx(200);
        stats.add_rx(50);
        stats.add_tunneled();
        stats.add_tunneled();
        stats.add_bypassed();

        assert_eq!(stats.get_bytes_tx(), 300);
        assert_eq!(stats.get_bytes_rx(), 50);
        assert_eq!(stats.get_packets_tunneled(), 2);
        assert_eq!(stats.get_packets_bypassed(), 1);

        stats.reset();
        assert_eq!(stats.get_bytes_tx(), 0);
    }

    #[test]
    fn test_connection_info_hash() {
        let conn1 = ConnectionInfo {
            src_ip: Ipv4Addr::new(192, 168, 1, 1),
            src_port: 50000,
            dst_ip: Ipv4Addr::new(128, 116, 50, 1),
            dst_port: 55000,
            protocol: Protocol::Udp,
        };
        let conn2 = conn1.clone();

        let mut set = std::collections::HashSet::new();
        set.insert(conn1);
        assert!(set.contains(&conn2));
    }
}
