//! Optional cloud-server lookup, advanced without blocking the log consumer.

use std::{future::Future, net::Ipv4Addr, pin::Pin, time::Duration};
use swifttunnel_core::roblox_directory::{self, Datacenter};

type Lookup = Pin<Box<dyn Future<Output = Option<Datacenter>>>>;

struct Pending {
    ip: Ipv4Addr,
    job_id: String,
    lookup: Lookup,
}

pub struct ResolvedLocation {
    pub ip: Ipv4Addr,
    pub job_id: String,
    pub center: Datacenter,
}

#[derive(Default)]
pub struct GameLocation(Option<Pending>);

impl GameLocation {
    pub fn replace(&mut self, ip: Ipv4Addr, place_id: String, job_id: String) {
        let lookup_job = job_id.clone();
        self.replace_with(ip, job_id, async move {
            roblox_directory::resolve_session(&place_id, &lookup_job, ip).await
        });
    }

    fn replace_with(
        &mut self,
        ip: Ipv4Addr,
        job_id: String,
        lookup: impl Future<Output = Option<Datacenter>> + 'static,
    ) {
        self.0 = Some(Pending {
            ip,
            job_id,
            lookup: Box::pin(lookup),
        });
    }

    pub fn clear(&mut self) {
        self.0 = None;
    }

    pub fn clear_for_session(&mut self, job_id: &str) {
        if self
            .0
            .as_ref()
            .is_some_and(|pending| pending.job_id.eq_ignore_ascii_case(job_id))
        {
            self.clear();
        }
    }

    /// A timeout borrows the pending future, so it resumes on the next turn
    /// instead of restarting the HTTP request. Replacing/clearing drops it.
    pub async fn advance(&mut self, cadence: Duration) -> Option<ResolvedLocation> {
        let Some(pending) = self.0.as_mut() else {
            tokio::time::sleep(cadence).await;
            return None;
        };
        let center = tokio::time::timeout(cadence, &mut pending.lookup)
            .await
            .ok()?;
        let pending = self.0.take()?;
        center.map(|center| ResolvedLocation {
            ip: pending.ip,
            job_id: pending.job_id,
            center,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    struct Dropped(Arc<AtomicBool>);
    impl Drop for Dropped {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    fn center() -> Datacenter {
        Datacenter {
            id: 1,
            city: "City".into(),
            country: "Country".into(),
            datacenter_ids: vec![1],
            relay_region: None,
        }
    }

    #[tokio::test]
    async fn a_stalled_lookup_returns_to_log_processing_and_is_dropped_on_leave() {
        let dropped = Arc::new(AtomicBool::new(false));
        let guard = Dropped(dropped.clone());
        let mut location = GameLocation::default();
        location.replace_with("34.1.2.3".parse().unwrap(), "first".into(), async move {
            let _guard = guard;
            std::future::pending().await
        });
        let next_log_turn = tokio::time::timeout(
            Duration::from_secs(1),
            location.advance(Duration::from_millis(5)),
        )
        .await
        .expect("optional metadata blocked log processing");
        assert!(next_log_turn.is_none());
        assert!(!dropped.load(Ordering::SeqCst));
        location.clear_for_session("other");
        assert!(!dropped.load(Ordering::SeqCst));
        location.clear_for_session("FIRST");
        assert!(dropped.load(Ordering::SeqCst));
        assert!(location.0.is_none());
    }

    #[tokio::test]
    async fn replacing_a_session_discards_the_old_future_and_returns_only_current_metadata() {
        let dropped = Arc::new(AtomicBool::new(false));
        let guard = Dropped(dropped.clone());
        let mut location = GameLocation::default();
        let ip = "34.1.2.3".parse().unwrap();
        location.replace_with(ip, "old".into(), async move {
            let _guard = guard;
            Some(center())
        });
        location.replace_with(ip, "new".into(), async { Some(center()) });
        assert!(dropped.load(Ordering::SeqCst));
        let resolved = location.advance(Duration::from_secs(1)).await.unwrap();
        assert_eq!(resolved.job_id, "new");
        assert_eq!(resolved.ip, ip);
        assert!(location.0.is_none());
    }

    #[tokio::test]
    async fn a_lookup_resumes_after_a_log_turn_instead_of_restarting() {
        let (send, receive) = tokio::sync::oneshot::channel();
        let mut location = GameLocation::default();
        location.replace_with("34.1.2.3".parse().unwrap(), "job".into(), async move {
            receive.await.ok()
        });
        assert!(location.advance(Duration::from_millis(5)).await.is_none());
        send.send(center()).unwrap();
        assert_eq!(
            location
                .advance(Duration::from_secs(1))
                .await
                .unwrap()
                .center
                .city,
            "City"
        );
        assert!(location.0.is_none());
    }
}
