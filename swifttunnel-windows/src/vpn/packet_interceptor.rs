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
use windows::Win32::Foundation::{HANDLE, CloseHandle};
use windows::Win32::System::Threading::{CreateEventW, ResetEvent, WaitForSingleObject};
use windows::Win32::NetworkManagement::IpHelper::{GetAdaptersInfo, IP_ADAPTER_INFO};

/// Get the friendly name for an adapter given its internal name (device GUID)
fn get_adapter_friendly_name(internal_name: &str) -> Option<String> {
    // Extract GUID from internal name like "\DEVICE\{GUID}"
    let guid = internal_name
        .rsplit('\\')
        .next()
        .unwrap_or("")
        .trim_matches(|c| c == '{' || c == '}');

    if guid.is_empty() {
        return None;
    }

    // Use GetAdaptersInfo to find the adapter by GUID
    unsafe {
        let mut buf_len: u32 = 0;
        // First call to get required buffer size
        let _ = GetAdaptersInfo(None, &mut buf_len);

        if buf_len == 0 {
            return None;
        }

        // Allocate buffer
        let mut buffer: Vec<u8> = vec![0; buf_len as usize];
        let adapter_info_ptr = buffer.as_mut_ptr() as *mut IP_ADAPTER_INFO;

        // Second call to get actual data
        let result = GetAdaptersInfo(Some(adapter_info_ptr), &mut buf_len);
        if result != 0 {
            log::debug!("GetAdaptersInfo failed with error: {}", result);
            return None;
        }

        // Iterate through adapters
        let mut current = adapter_info_ptr;
        while !current.is_null() {
            let adapter = &*current;

            // Get adapter name (GUID) - null-terminated string
            let adapter_name_bytes: Vec<u8> = adapter.AdapterName
                .iter()
                .take_while(|&&b| b != 0)
                .map(|&b| b as u8)
                .collect();
            let adapter_guid = String::from_utf8_lossy(&adapter_name_bytes);

            // Check if this is our adapter
            if adapter_guid.to_lowercase().contains(&guid.to_lowercase()) {
                // Get description (friendly name) - null-terminated string
                let desc_bytes: Vec<u8> = adapter.Description
                    .iter()
                    .take_while(|&&b| b != 0)
                    .map(|&b| b as u8)
                    .collect();
                return Some(String::from_utf8_lossy(&desc_bytes).to_string());
            }

            current = adapter.Next;
        }
    }

    None
}

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

        // Collect all adapters with their info
        let mut vpn_adapter: Option<(usize, String, String)> = None;
        let mut physical_candidates: Vec<(usize, String, String, i32)> = Vec::new();

        // Find physical adapter (prefer real NICs) and VPN adapter (by name match)
        for (idx, adapter) in adapters.iter().enumerate() {
            let internal_name = adapter.get_name();

            // Try to get the friendly name using Windows API
            let friendly_name = get_adapter_friendly_name(&internal_name).unwrap_or_default();

            log::info!("  Adapter {}: internal='{}' friendly='{}'", idx, internal_name, friendly_name);

            let name_lower = internal_name.to_lowercase();
            let friendly_lower = friendly_name.to_lowercase();

            // Check if this is the VPN adapter
            let is_vpn_adapter = name_lower.contains(&vpn_adapter_name.to_lowercase())
                || name_lower.contains("swifttunnel")
                || name_lower.contains("wintun")
                || friendly_lower.contains(&vpn_adapter_name.to_lowercase())
                || friendly_lower.contains("swifttunnel")
                || friendly_lower.contains("wintun");

            // Check if this looks like a virtual/loopback adapter
            let is_virtual = name_lower.contains("loopback")
                || friendly_lower.contains("loopback")
                || friendly_lower.contains("isatap")
                || friendly_lower.contains("teredo")
                || friendly_lower.contains("6to4")
                || friendly_lower.is_empty(); // Adapters with no friendly name are often virtual

            // Calculate priority score for physical adapter selection
            // Higher score = more likely to be the real NIC
            let priority = if is_virtual || is_vpn_adapter {
                -1 // Skip these
            } else {
                let mut score = 0;
                // Prefer adapters with known physical NIC names
                if friendly_lower.contains("ethernet")
                    || friendly_lower.contains("intel")
                    || friendly_lower.contains("realtek")
                    || friendly_lower.contains("broadcom")
                    || friendly_lower.contains("qualcomm")
                    || friendly_lower.contains("virtio")
                    || friendly_lower.contains("vmxnet")
                    || friendly_lower.contains("mellanox")
                    || friendly_lower.contains("marvell")
                    || friendly_lower.contains("atheros")
                    || friendly_lower.contains("killer")
                    || friendly_lower.contains("aquantia")
                {
                    score += 100;
                }
                // Prefer adapters with non-empty friendly names
                if !friendly_name.is_empty() {
                    score += 50;
                }
                // Slightly prefer lower indices (first adapters are often primary)
                score += (10 - idx.min(10)) as i32;
                score
            };

            if is_vpn_adapter {
                vpn_adapter = Some((idx, friendly_name.clone(), internal_name.to_string()));
            } else if priority > 0 {
                physical_candidates.push((idx, friendly_name.clone(), internal_name.to_string(), priority));
            }
        }

        // Select best physical adapter (highest priority)
        if let Some((idx, name, internal, _priority)) = physical_candidates.into_iter().max_by_key(|x| x.3) {
            self.physical_adapter_idx = Some(idx);
            log::info!("Selected physical adapter at index {}: {} ({})", idx, name, internal);
        }

        // Set VPN adapter
        if let Some((idx, name, internal)) = vpn_adapter {
            self.vpn_adapter_idx = Some(idx);
            log::info!("Found VPN adapter at index {}: {} ({})", idx, name, internal);
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

        self.stop_flag.store(false, Ordering::SeqCst);
        self.active = true;

        // Spawn packet processing task
        let stop_flag = Arc::clone(&self.stop_flag);
        let tunnel_apps = self.process_tracker.tunnel_apps().clone();

        std::thread::spawn(move || {
            if let Err(e) = Self::packet_processing_loop(
                physical_idx,
                vpn_idx,
                tunnel_apps,
                stop_flag,
            ) {
                log::error!("Packet processing loop error: {}", e);
            }
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
        physical_idx: usize,
        vpn_idx: usize,
        tunnel_apps: std::collections::HashSet<String>,
        stop_flag: Arc<AtomicBool>,
    ) -> VpnResult<()> {
        use ndisapi::{DirectionFlags, EthMRequest, EthMRequestMut, FilterFlags, IntermediateBuffer};

        const PACKET_BUFFER_SIZE: usize = 64;

        log::info!("Packet processing loop started");

        // Initialize driver
        let driver = ndisapi::Ndisapi::new("NDISRD")
            .map_err(|e| VpnError::SplitTunnel(format!("Failed to open driver: {}", e)))?;

        // Get adapters
        let adapters = driver.get_tcpip_bound_adapters_info()
            .map_err(|e| VpnError::SplitTunnel(format!("Failed to get adapters: {}", e)))?;

        if physical_idx >= adapters.len() || vpn_idx >= adapters.len() {
            return Err(VpnError::SplitTunnel("Adapter index out of range".to_string()));
        }

        let physical_handle = adapters[physical_idx].get_handle();
        let _vpn_handle = adapters[vpn_idx].get_handle();

        // Create event for packet notification
        let event: HANDLE = unsafe {
            CreateEventW(None, true, false, None)
                .map_err(|e| VpnError::SplitTunnel(format!("Failed to create event: {}", e)))?
        };

        // Set event for the physical adapter
        driver.set_packet_event(physical_handle, event)
            .map_err(|e| VpnError::SplitTunnel(format!("Failed to set packet event: {}", e)))?;

        // Set adapter mode to tunnel mode (intercept sent and received packets)
        driver.set_adapter_mode(physical_handle, FilterFlags::MSTCP_FLAG_SENT_RECEIVE_TUNNEL)
            .map_err(|e| VpnError::SplitTunnel(format!("Failed to set adapter mode: {}", e)))?;

        let mut process_tracker = ProcessTracker::new(tunnel_apps.into_iter().collect());
        let mut refresh_counter = 0u32;

        // Allocate packet buffers
        let mut packets: Vec<IntermediateBuffer> = vec![Default::default(); PACKET_BUFFER_SIZE];

        loop {
            if stop_flag.load(Ordering::SeqCst) {
                break;
            }

            // Refresh process tracker periodically (every ~50 iterations @ 20ms = 1s)
            refresh_counter += 1;
            if refresh_counter >= 50 {
                refresh_counter = 0;
                if let Err(e) = process_tracker.refresh() {
                    log::warn!("Process tracker refresh error: {}", e);
                }
            }

            // Wait for packets (with timeout)
            unsafe {
                WaitForSingleObject(event, 20); // 20ms timeout
            }

            // Read packets
            let mut to_read = EthMRequestMut::from_iter(
                physical_handle,
                packets.iter_mut(),
            );

            let packets_read = driver
                .read_packets::<PACKET_BUFFER_SIZE>(&mut to_read)
                .unwrap_or(0);

            if packets_read == 0 {
                // Reset event and continue
                unsafe { let _ = ResetEvent(event); }
                continue;
            }

            // Create requests for sending packets
            let mut to_mstcp: EthMRequest<PACKET_BUFFER_SIZE> = EthMRequest::new(physical_handle);
            let mut to_adapter: EthMRequest<PACKET_BUFFER_SIZE> = EthMRequest::new(physical_handle);

            // Process each packet
            for i in 0..packets_read {
                let direction_flags = packets[i].get_device_flags();

                // Determine packet direction
                let is_outbound = direction_flags == DirectionFlags::PACKET_FLAG_ON_SEND;

                // Get packet data
                let data = packets[i].get_data();

                // For inbound packets or non-tunnel apps, pass through normally
                let should_vpn = if is_outbound {
                    // Parse packet to check if it belongs to tunnel app
                    Self::should_route_to_vpn(data, &process_tracker)
                } else {
                    false
                };

                if should_vpn {
                    // TODO: For now, we still pass through but log
                    // Full VPN routing requires modifying packet destination
                    log::trace!("Would route to VPN (outbound tunnel app packet)");
                }

                // Route packet based on direction
                if is_outbound {
                    // Outbound: send to adapter
                    if let Err(e) = to_adapter.push(&packets[i]) {
                        log::warn!("Failed to queue packet for adapter: {}", e);
                    }
                } else {
                    // Inbound: send to MSTCP (TCP/IP stack)
                    if let Err(e) = to_mstcp.push(&packets[i]) {
                        log::warn!("Failed to queue packet for MSTCP: {}", e);
                    }
                }
            }

            // Send queued packets
            if to_adapter.get_packet_number() > 0 {
                if let Err(e) = driver.send_packets_to_adapter::<PACKET_BUFFER_SIZE>(&to_adapter) {
                    log::warn!("Failed to send packets to adapter: {}", e);
                }
            }

            if to_mstcp.get_packet_number() > 0 {
                if let Err(e) = driver.send_packets_to_mstcp::<PACKET_BUFFER_SIZE>(&to_mstcp) {
                    log::warn!("Failed to send packets to MSTCP: {}", e);
                }
            }

            // Reset event
            unsafe { let _ = ResetEvent(event); }
        }

        // Cleanup: reset adapter mode
        let _ = driver.set_adapter_mode(physical_handle, FilterFlags::default());

        // Close event handle
        unsafe { let _ = CloseHandle(event); }

        log::info!("Packet processing loop stopped");
        Ok(())
    }

    /// Check if a packet should be routed to VPN based on process tracking
    fn should_route_to_vpn(data: &[u8], process_tracker: &ProcessTracker) -> bool {
        // Parse packet info
        let info = match PacketInfo::from_ethernet_frame(data, PacketDirection::Outbound) {
            Some(i) => i,
            None => return false,
        };

        // Check if this packet belongs to a tunnel app
        process_tracker.should_tunnel(info.src_ip, info.src_port, info.protocol)
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
