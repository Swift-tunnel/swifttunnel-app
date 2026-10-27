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
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

// Cancelling an async diagnostic cannot interrupt an already running Win32
// echo. Keep admission with its native worker until that call actually exits.
static PING_SLOTS: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(4)));

/// Send one ICMP echo to `target` (IPv4 literal) and return the round-trip
/// time in milliseconds, or `None` on timeout/unreachable. Sub-millisecond
/// replies report as 1 ms, matching the old `time<1ms` convention so
/// downstream statistics never see a 0 ms sample.
pub async fn ping_ms(target: &str, timeout_ms: u32) -> Option<u32> {
    let addr = Ipv4Addr::from_str(target).ok()?;
    bounded_probe(
        PING_SLOTS.clone(),
        Duration::from_millis(u64::from(timeout_ms)),
        move |remaining_ms| ping_blocking(addr, remaining_ms),
    )
    .await
}

async fn bounded_probe(
    slots: Arc<Semaphore>,
    timeout: Duration,
    probe: impl FnOnce(u32) -> Option<u32> + Send + 'static,
) -> Option<u32> {
    if timeout.is_zero() {
        return None;
    }
    let deadline = Instant::now().checked_add(timeout)?;
    tokio::time::timeout(timeout, async move {
        let permit = slots.acquire_owned().await.ok()?;
        // Dropping the owner aborts work still waiting in the blocking pool.
        // A running call keeps its permit through completion even after Stop.
        let mut worker = tokio::task::JoinSet::new();
        worker.spawn_blocking(move || {
            let _permit = permit;
            let remaining_ms = deadline
                .saturating_duration_since(Instant::now())
                .as_millis()
                .min(u128::from(u32::MAX)) as u32;
            if remaining_ms == 0 {
                return None;
            }
            probe(remaining_ms)
        });
        worker.join_next().await?.ok()?
    })
    .await
    .ok()?
}

fn ping_blocking(addr: Ipv4Addr, timeout_ms: u32) -> Option<u32> {
    use windows::Win32::NetworkManagement::IpHelper::{
        ICMP_ECHO_REPLY, IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho,
    };

    // IP_STATUS success code (IP_SUCCESS) for ICMP_ECHO_REPLY.Status.
    const IP_SUCCESS: u32 = 0;
    const PAYLOAD: &[u8] = b"SwiftTunnelPing.";

    let handle = unsafe { IcmpCreateFile() }.ok()?;

    // Per IcmpSendEcho docs the reply buffer must hold at least one
    // ICMP_ECHO_REPLY plus the echoed payload plus 8 spare bytes.
    let mut reply_buf = vec![0u8; std::mem::size_of::<ICMP_ECHO_REPLY>() + PAYLOAD.len() + 8];
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

    #[tokio::test]
    async fn cancelled_native_probe_keeps_its_slot_until_work_finishes() {
        let slots = Arc::new(Semaphore::new(1));
        let (started, ready) = tokio::sync::oneshot::channel();
        let (release, resume) = std::sync::mpsc::channel();
        let task = tokio::spawn(bounded_probe(
            slots.clone(),
            Duration::from_secs(3),
            move |_| {
                let _ = started.send(());
                let _ = resume.recv_timeout(Duration::from_secs(3));
                Some(1)
            },
        ));
        ready.await.unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(slots.available_permits(), 0);
        assert_eq!(
            bounded_probe(slots.clone(), Duration::from_millis(20), |_| {
                panic!("cancelled native work still owns the only slot")
            })
            .await,
            None
        );
        release.send(()).unwrap();
        let permit = tokio::time::timeout(Duration::from_secs(2), slots.acquire())
            .await
            .unwrap()
            .unwrap();
        drop(permit);
        assert_eq!(
            bounded_probe(slots, Duration::from_secs(1), |remaining| {
                assert!((1..=1000).contains(&remaining));
                Some(21)
            })
            .await,
            Some(21)
        );
    }

    #[tokio::test]
    async fn a_probe_deadline_bounds_admission_and_an_unresponsive_worker() {
        let slots = Arc::new(Semaphore::new(1));
        assert_eq!(
            bounded_probe(slots.clone(), Duration::ZERO, |_| panic!("zero budget")).await,
            None
        );
        let held = slots.clone().acquire_owned().await.unwrap();
        assert_eq!(
            bounded_probe(slots.clone(), Duration::from_millis(20), |_| panic!(
                "no admission"
            ))
            .await,
            None
        );
        drop(held);
        let (release, resume) = std::sync::mpsc::channel();
        let (started, ready) = tokio::sync::oneshot::channel();
        let work = tokio::spawn(bounded_probe(
            slots.clone(),
            Duration::from_millis(100),
            move |_| {
                let _ = started.send(());
                let _ = resume.recv_timeout(Duration::from_secs(3));
                Some(1)
            },
        ));
        ready.await.unwrap();
        assert_eq!(work.await.unwrap(), None);
        assert_eq!(slots.available_permits(), 0);
        release.send(()).unwrap();
        let _permit = tokio::time::timeout(Duration::from_secs(2), slots.acquire())
            .await
            .unwrap()
            .unwrap();
    }

    #[test]
    fn an_expired_probe_waiting_in_the_blocking_pool_does_not_start_later() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .max_blocking_threads(1)
            .build()
            .unwrap();
        let (started, ready) = std::sync::mpsc::channel();
        let (release, resume) = std::sync::mpsc::channel();
        let blocker = runtime.spawn_blocking(move || {
            started.send(()).unwrap();
            let _ = resume.recv_timeout(Duration::from_secs(3));
        });
        ready.recv_timeout(Duration::from_secs(2)).unwrap();
        let slots = Arc::new(Semaphore::new(1));
        let called = Arc::new(AtomicBool::new(false));
        let observed = called.clone();
        assert_eq!(
            runtime.block_on(bounded_probe(
                slots.clone(),
                Duration::from_millis(20),
                move |_| {
                    observed.store(true, Ordering::SeqCst);
                    Some(1)
                }
            )),
            None
        );
        release.send(()).unwrap();
        runtime.block_on(blocker).unwrap();
        runtime.block_on(runtime.spawn_blocking(|| {})).unwrap();
        assert!(!called.load(Ordering::SeqCst));
        assert_eq!(slots.available_permits(), 1);
    }

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
