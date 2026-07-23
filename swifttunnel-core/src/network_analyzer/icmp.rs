//! Locale-independent ICMP echo (ping) via the Win32 `IcmpSendEcho` API.
//!
//! The old implementation shelled out to `ping.exe` and parsed its English
//! output ("time=14ms"). On non-English Windows (Arabic, German, French, …)
//! ping prints localized text, every reply failed to parse, and the stability
//! and bufferbloat tests reported "all pings failed" on a perfectly healthy
//! connection. `IcmpSendEcho` returns structured data — no subprocess, no
//! text parsing, no locale dependence, and no console window to hide.

use std::net::Ipv4Addr;
use std::str::FromStr;

/// Send one ICMP echo to `target` (IPv4 literal) and return the round-trip
/// time in milliseconds, or `None` on timeout/unreachable. Sub-millisecond
/// replies report as 1 ms, matching the old `time<1ms` convention so
/// downstream statistics never see a 0 ms sample.
pub async fn ping_ms(target: &str, timeout_ms: u32) -> Option<u32> {
    let addr = Ipv4Addr::from_str(target).ok()?;
    tokio::task::spawn_blocking(move || ping_blocking(addr, timeout_ms))
        .await
        .ok()?
}

fn ping_blocking(addr: Ipv4Addr, timeout_ms: u32) -> Option<u32> {
    use windows::Win32::NetworkManagement::IpHelper::{
        IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho, ICMP_ECHO_REPLY,
    };

    // IP_STATUS success code (IP_SUCCESS) for ICMP_ECHO_REPLY.Status.
    const IP_SUCCESS: u32 = 0;
    const PAYLOAD: &[u8] = b"SwiftTunnelPing.";

    let handle = unsafe { IcmpCreateFile() }.ok()?;

    // Per IcmpSendEcho docs the reply buffer must hold at least one
    // ICMP_ECHO_REPLY plus the echoed payload plus 8 spare bytes.
    let mut reply_buf =
        vec![0u8; std::mem::size_of::<ICMP_ECHO_REPLY>() + PAYLOAD.len() + 8];
    // IPAddr is a u32 laid out in network byte order.
    let dest = u32::from_le_bytes(addr.octets());

    let replies = unsafe {
        IcmpSendEcho(
            handle,
            dest,
            PAYLOAD.as_ptr() as *const _,
            PAYLOAD.len() as u16,
            None,
            reply_buf.as_mut_ptr() as *mut _,
            reply_buf.len() as u32,
            timeout_ms,
        )
    };

    let result = if replies > 0 {
        let reply = unsafe { &*(reply_buf.as_ptr() as *const ICMP_ECHO_REPLY) };
        if reply.Status == IP_SUCCESS {
            Some(reply.RoundTripTime.max(1))
        } else {
            None
        }
    } else {
        None
    };

    unsafe {
        let _ = IcmpCloseHandle(handle);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    // Loopback answers ICMP without any network, so this is deterministic
    // offline — and it proves the reply parsing works on any system locale.
    #[tokio::test]
    async fn loopback_ping_succeeds_regardless_of_locale() {
        let rtt = ping_ms("127.0.0.1", 2000).await;
        assert!(rtt.is_some(), "loopback ICMP echo should always succeed");
        assert!(rtt.unwrap() >= 1, "RTT reports at least 1ms");
    }

    #[tokio::test]
    async fn invalid_target_returns_none() {
        assert_eq!(ping_ms("not-an-ip", 500).await, None);
    }
}
