//! Connection-tracking primitives shared by `process_cache` and the parallel
//! interceptor.
//!
//! The original `ProcessTracker` struct that lived here parsed Windows
//! `MIB_TCPTABLE_OWNER_PID` / `MIB_UDPTABLE_OWNER_PID` buffers via raw
//! `slice::from_raw_parts` without bounds-checking `dwNumEntries`. The
//! cache refresher thread now does the same enumeration via `process_cache`
//! and the live data path uses ETW (`process_watcher.rs`), so the legacy
//! tracker has been removed. Only the small key/stat types are kept here
//! because they're referenced from `process_cache` and `parallel_interceptor`.

use std::net::Ipv4Addr;

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

/// Statistics about the (legacy) process tracker. Still emitted by the
/// process cache refresher and read by diagnostics.
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
}
