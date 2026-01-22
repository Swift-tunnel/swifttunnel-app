//! Packet Interceptor - ndisapi-based split tunneling
//!
//! Uses Windows Packet Filter (ndisapi) for NDIS-level packet interception.
//! Combined with process tracking, this enables per-application split tunneling
//! without the complexity of WFP callouts.
//!
//! Architecture:
//! 1. Intercept outbound packets on physical adapter
//! 2. Parse IP headers to extract source IP:port
//! 3. Look up owning process via ProcessTracker
//! 4. Route tunnel app packets through VPN, others passthrough
//!
//! This replaces the Mullvad WFP-based driver with a simpler approach.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::net::Ipv4Addr;
use super::process_tracker::{ProcessTracker, Protocol};
use super::{VpnError, VpnResult};

/// Packet direction
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketDirection {
    Outbound,
    Inbound,
}

/// Parsed IP packet info
#[derive(Debug, Clone)]
pub struct PacketInfo {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: Protocol,
    pub direction: PacketDirection,
}

impl PacketInfo {
    /// Parse from raw IP packet (after Ethernet header)
    pub fn from_ip_packet(data: &[u8], direction: PacketDirection) -> Option<Self> {
        if data.len() < 20 {
            return None; // Too short for IP header
        }

        let version = (data[0] >> 4) & 0xF;
        if version != 4 {
            return None; // Only IPv4 supported
        }

        let ihl = (data[0] & 0xF) as usize * 4;
        if data.len() < ihl {
            return None;
        }

        let protocol_num = data[9];
        let protocol = match protocol_num {
            6 => Protocol::Tcp,
            17 => Protocol::Udp,
            _ => return None, // Only TCP/UDP supported
        };

        let src_ip = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
        let dst_ip = Ipv4Addr::new(data[16], data[17], data[18], data[19]);

        // Parse transport layer header
        if data.len() < ihl + 4 {
            return None;
        }

        let transport_header = &data[ihl..];
        let src_port = u16::from_be_bytes([transport_header[0], transport_header[1]]);
        let dst_port = u16::from_be_bytes([transport_header[2], transport_header[3]]);

        Some(PacketInfo {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            direction,
        })
    }

    /// Parse from raw Ethernet frame
    pub fn from_ethernet_frame(data: &[u8], direction: PacketDirection) -> Option<Self> {
        if data.len() < 14 {
            return None; // Too short for Ethernet header
        }

        // Check EtherType (bytes 12-13)
        let ethertype = u16::from_be_bytes([data[12], data[13]]);
        if ethertype != 0x0800 {
            return None; // Not IPv4
        }

        // Skip Ethernet header (14 bytes)
        Self::from_ip_packet(&data[14..], direction)
    }
}

/// Split tunnel interceptor using ndisapi
pub struct PacketInterceptor {
    /// ndisapi driver handle (raw handle for now, will be replaced with actual ndisapi types)
    driver_available: bool,
    /// Physical adapter index
    physical_adapter_idx: Option<usize>,
    /// VPN adapter index
    vpn_adapter_idx: Option<usize>,
    /// Process tracker for PID lookups
    process_tracker: ProcessTracker,
    /// Stop flag for packet processing loop
    stop_flag: Arc<AtomicBool>,
    /// Whether interception is active
    active: bool,
}

impl PacketInterceptor {
    /// Create a new packet interceptor
    pub fn new(tunnel_apps: Vec<String>) -> Self {
        Self {
            driver_available: false,
            physical_adapter_idx: None,
            vpn_adapter_idx: None,
            process_tracker: ProcessTracker::new(tunnel_apps),
            stop_flag: Arc::new(AtomicBool::new(false)),
            active: false,
        }
    }

    /// Check if WinpkFilter driver is available
    pub fn check_driver_available() -> bool {
        // Try to initialize ndisapi
        match ndisapi::Ndisapi::new("NDISRD") {
            Ok(_) => {
                log::info!("Windows Packet Filter driver is available");
                true
            }
            Err(e) => {
                log::warn!("Windows Packet Filter driver not available: {}", e);
                false
            }
        }
    }

    /// Initialize the interceptor
    pub fn initialize(&mut self) -> VpnResult<()> {
        log::info!("Initializing packet interceptor...");

        // Check driver availability
        if !Self::check_driver_available() {
            return Err(VpnError::SplitTunnelNotAvailable);
        }

        self.driver_available = true;
        log::info!("Packet interceptor initialized");
        Ok(())
    }

    /// Configure split tunneling with the given VPN adapter
    pub fn configure(&mut self, vpn_adapter_name: &str, tunnel_apps: Vec<String>) -> VpnResult<()> {
        if !self.driver_available {
            return Err(VpnError::SplitTunnelNotAvailable);
        }

        log::info!("Configuring split tunnel for VPN adapter: {}", vpn_adapter_name);

        // Update tunnel apps
        self.process_tracker.set_tunnel_apps(tunnel_apps);

        // Open ndisapi and enumerate adapters
        let driver = ndisapi::Ndisapi::new("NDISRD")
            .map_err(|e| VpnError::SplitTunnel(format!("Failed to open driver: {}", e)))?;

        // Get adapter list
        let adapters = driver.get_tcpip_bound_adapters_info()
            .map_err(|e| VpnError::SplitTunnel(format!("Failed to enumerate adapters: {}", e)))?;

        log::info!("Found {} adapters", adapters.len());

        // Find physical adapter (first non-VPN adapter with an IP)
        // and VPN adapter (by name match)
        for (idx, adapter) in adapters.iter().enumerate() {
            let name = adapter.get_name();
            log::debug!("  Adapter {}: {}", idx, name);

            if name.contains(vpn_adapter_name) || name.contains("SwiftTunnel") || name.contains("Wintun") {
                self.vpn_adapter_idx = Some(idx);
                log::info!("Found VPN adapter at index {}: {}", idx, name);
            } else if self.physical_adapter_idx.is_none() && !name.contains("Loopback") {
                // Use first non-loopback, non-VPN adapter as physical
                self.physical_adapter_idx = Some(idx);
                log::info!("Using physical adapter at index {}: {}", idx, name);
            }
        }

        if self.physical_adapter_idx.is_none() {
            return Err(VpnError::SplitTunnel(
                "No physical network adapter found".to_string(),
            ));
        }

        if self.vpn_adapter_idx.is_none() {
            return Err(VpnError::SplitTunnel(format!(
                "VPN adapter '{}' not found",
                vpn_adapter_name
            )));
        }

        log::info!("Split tunnel configured - physical: {:?}, VPN: {:?}",
            self.physical_adapter_idx, self.vpn_adapter_idx);

        Ok(())
    }

    /// Start packet interception
    pub fn start(&mut self) -> VpnResult<()> {
        if self.active {
            log::warn!("Packet interceptor already active");
            return Ok(());
        }

        let physical_idx = self.physical_adapter_idx
            .ok_or_else(|| VpnError::SplitTunnel("Physical adapter not configured".to_string()))?;

        let vpn_idx = self.vpn_adapter_idx
            .ok_or_else(|| VpnError::SplitTunnel("VPN adapter not configured".to_string()))?;

        log::info!("Starting packet interception (physical: {}, VPN: {})", physical_idx, vpn_idx);

        // Open driver
        let mut driver = ndisapi::Ndisapi::new("NDISRD")
            .map_err(|e| VpnError::SplitTunnel(format!("Failed to open driver: {}", e)))?;

        // Get adapter handles
        let adapters = driver.get_tcpip_bound_adapters_info()
            .map_err(|e| VpnError::SplitTunnel(format!("Failed to get adapters: {}", e)))?;

        if physical_idx >= adapters.len() || vpn_idx >= adapters.len() {
            return Err(VpnError::SplitTunnel("Adapter index out of range".to_string()));
        }

        let physical_handle = adapters[physical_idx].get_handle();
        let vpn_handle = adapters[vpn_idx].get_handle();

        // Set packet filter mode on physical adapter
        // FILTER_PACKET_DROP_RDR: Intercept and redirect to user-mode
        driver.set_packet_filter_table(&[(physical_handle, ndisapi::FilterFlags::MSTCP_FLAG_SENT_TUNNEL)])
            .map_err(|e| VpnError::SplitTunnel(format!("Failed to set filter mode: {}", e)))?;

        self.stop_flag.store(false, Ordering::SeqCst);
        self.active = true;

        // Spawn packet processing task
        let stop_flag = Arc::clone(&self.stop_flag);
        let tunnel_apps = self.process_tracker.tunnel_apps().clone();

        std::thread::spawn(move || {
            Self::packet_processing_loop(
                driver,
                physical_handle,
                vpn_handle,
                tunnel_apps,
                stop_flag,
            );
        });

        log::info!("Packet interception started");
        Ok(())
    }

    /// Stop packet interception
    pub fn stop(&mut self) {
        if !self.active {
            return;
        }

        log::info!("Stopping packet interception...");
        self.stop_flag.store(true, Ordering::SeqCst);
        self.active = false;

        // Note: The processing thread will exit on its own
        // We could add a channel for cleaner shutdown if needed
    }

    /// Refresh process tracker
    pub fn refresh(&mut self) -> VpnResult<bool> {
        self.process_tracker.refresh()?;
        let running = !self.process_tracker.get_running_tunnel_apps().is_empty();
        Ok(running)
    }

    /// Get running tunnel apps
    pub fn get_running_tunnel_apps(&mut self) -> Vec<String> {
        self.process_tracker.get_running_tunnel_apps()
    }

    /// Update tunnel apps list
    pub fn set_tunnel_apps(&mut self, apps: Vec<String>) {
        self.process_tracker.set_tunnel_apps(apps);
    }

    /// Packet processing loop (runs in separate thread)
    fn packet_processing_loop(
        mut driver: ndisapi::Ndisapi,
        physical_handle: ndisapi::Handle,
        vpn_handle: ndisapi::Handle,
        tunnel_apps: std::collections::HashSet<String>,
        stop_flag: Arc<AtomicBool>,
    ) {
        use ndisapi::{IntermediateBuffer, EthRequest, DirectionFlags};

        log::info!("Packet processing loop started");

        let mut process_tracker = ProcessTracker::new(tunnel_apps.into_iter().collect());
        let mut refresh_counter = 0u32;

        // Allocate packet buffer
        let mut packet = IntermediateBuffer::default();
        let mut request = EthRequest::new(physical_handle);

        loop {
            if stop_flag.load(Ordering::SeqCst) {
                break;
            }

            // Refresh process tracker periodically (every ~50 iterations @ 1ms = 50ms)
            refresh_counter += 1;
            if refresh_counter >= 50 {
                refresh_counter = 0;
                if let Err(e) = process_tracker.refresh() {
                    log::warn!("Process tracker refresh error: {}", e);
                }
            }

            // Read packet with timeout
            request.set_packet(&mut packet);
            match driver.read_packets(&mut request) {
                Ok(count) if count > 0 => {
                    // Process packet
                    let action = Self::process_packet(
                        &packet,
                        &process_tracker,
                    );

                    match action {
                        PacketAction::PassThrough => {
                            // Send packet back to adapter (let it through)
                            request.set_packet(&mut packet);
                            if let Err(e) = driver.send_packets_to_adapter(&mut request) {
                                log::warn!("Failed to send packet to adapter: {}", e);
                            }
                        }
                        PacketAction::RouteToVpn => {
                            // Forward to VPN adapter
                            let mut vpn_request = EthRequest::new(vpn_handle);
                            vpn_request.set_packet(&mut packet);
                            if let Err(e) = driver.send_packets_to_adapter(&mut vpn_request) {
                                log::warn!("Failed to send packet to VPN: {}", e);
                            }
                        }
                        PacketAction::Drop => {
                            // Don't forward (packet is dropped)
                        }
                    }
                }
                Ok(_) => {
                    // No packets, sleep briefly
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(e) => {
                    if !stop_flag.load(Ordering::SeqCst) {
                        log::warn!("Read packet error: {}", e);
                    }
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
            }
        }

        // Cleanup: reset filter mode
        let _ = driver.set_packet_filter_table(&[(physical_handle, ndisapi::FilterFlags::empty())]);

        log::info!("Packet processing loop stopped");
    }

    /// Process a packet and determine action
    fn process_packet(
        packet: &ndisapi::IntermediateBuffer,
        process_tracker: &ProcessTracker,
    ) -> PacketAction {
        // Parse packet to get IP info
        let data = packet.get_data();
        if data.len() < 14 {
            return PacketAction::PassThrough;
        }

        // Determine direction
        let direction = if packet.get_device_flags().contains(ndisapi::DirectionFlags::PACKET_FLAG_ON_SEND) {
            PacketDirection::Outbound
        } else {
            PacketDirection::Inbound
        };

        // Only intercept outbound packets for split tunneling
        if direction != PacketDirection::Outbound {
            return PacketAction::PassThrough;
        }

        // Parse packet info
        let info = match PacketInfo::from_ethernet_frame(data, direction) {
            Some(i) => i,
            None => return PacketAction::PassThrough,
        };

        // Check if this packet belongs to a tunnel app
        if process_tracker.should_tunnel(info.src_ip, info.src_port, info.protocol) {
            log::trace!(
                "Routing to VPN: {}:{} -> {}:{} ({})",
                info.src_ip, info.src_port,
                info.dst_ip, info.dst_port,
                match info.protocol {
                    Protocol::Tcp => "TCP",
                    Protocol::Udp => "UDP",
                }
            );
            PacketAction::RouteToVpn
        } else {
            PacketAction::PassThrough
        }
    }

    /// Check if interceptor is active
    pub fn is_active(&self) -> bool {
        self.active
    }
}

impl Drop for PacketInterceptor {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Action to take for a packet
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PacketAction {
    /// Let packet pass through normally
    PassThrough,
    /// Route packet through VPN tunnel
    RouteToVpn,
    /// Drop the packet
    Drop,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_info_parsing() {
        // Minimal IPv4 TCP packet (IP header + TCP header start)
        let mut ip_packet = vec![0u8; 40];
        ip_packet[0] = 0x45; // IPv4, IHL=5
        ip_packet[9] = 6;    // TCP
        ip_packet[12..16].copy_from_slice(&[192, 168, 1, 1]); // src IP
        ip_packet[16..20].copy_from_slice(&[10, 0, 0, 1]);    // dst IP
        ip_packet[20..22].copy_from_slice(&1234u16.to_be_bytes()); // src port
        ip_packet[22..24].copy_from_slice(&80u16.to_be_bytes());   // dst port

        let info = PacketInfo::from_ip_packet(&ip_packet, PacketDirection::Outbound).unwrap();
        assert_eq!(info.src_ip, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(info.dst_ip, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(info.src_port, 1234);
        assert_eq!(info.dst_port, 80);
        assert_eq!(info.protocol, Protocol::Tcp);
    }

    #[test]
    fn test_ethernet_frame_parsing() {
        // Ethernet frame with IPv4 TCP packet
        let mut frame = vec![0u8; 54];
        // Ethernet header (14 bytes)
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes()); // EtherType: IPv4
        // IP header
        frame[14] = 0x45; // IPv4, IHL=5
        frame[23] = 17;   // UDP
        frame[26..30].copy_from_slice(&[10, 0, 0, 1]);   // src IP
        frame[30..34].copy_from_slice(&[8, 8, 8, 8]);    // dst IP
        frame[34..36].copy_from_slice(&5000u16.to_be_bytes()); // src port
        frame[36..38].copy_from_slice(&53u16.to_be_bytes());   // dst port

        let info = PacketInfo::from_ethernet_frame(&frame, PacketDirection::Outbound).unwrap();
        assert_eq!(info.src_ip, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(info.dst_ip, Ipv4Addr::new(8, 8, 8, 8));
        assert_eq!(info.src_port, 5000);
        assert_eq!(info.dst_port, 53);
        assert_eq!(info.protocol, Protocol::Udp);
    }
}
