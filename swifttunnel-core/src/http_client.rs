//! Shared HTTP clients and bounded ownership of duplicate requests.

use std::{
    collections::HashMap,
    hash::Hash,
    sync::{Arc, OnceLock, Weak},
    time::Duration,
};

/// Retry-After for bounded background requests. Prefer the server's Date when
/// the player's clock is incorrect; malformed/missing values use one minute.
pub(crate) fn retry_delay(headers: &reqwest::header::HeaderMap) -> Duration {
    let raw = headers
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim);
    let delay = raw.and_then(|raw| {
        if let Ok(seconds) = raw.parse::<u64>() {
            return Some(Duration::from_secs(seconds));
        }
        let deadline = chrono::DateTime::parse_from_rfc2822(raw).ok()?;
        let now = headers
            .get(reqwest::header::DATE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| chrono::DateTime::parse_from_rfc2822(value).ok())
            .map(|value| value.with_timezone(&chrono::Utc))
            .unwrap_or_else(chrono::Utc::now);
        Some(
            (deadline.with_timezone(&chrono::Utc) - now)
                .to_std()
                .unwrap_or_default(),
        )
    });
    delay
        .unwrap_or(Duration::from_secs(60))
        .clamp(Duration::from_secs(1), Duration::from_secs(300))
}

pub(crate) struct RequestSlots<K> {
    slots: HashMap<K, Weak<tokio::sync::Mutex<()>>>,
}

impl<K> Default for RequestSlots<K> {
    fn default() -> Self {
        Self {
            slots: HashMap::new(),
        }
    }
}

impl<K: Eq + Hash> RequestSlots<K> {
    pub(crate) fn request(&mut self, key: K, limit: usize) -> Option<Arc<tokio::sync::Mutex<()>>> {
        self.slots.retain(|_, slot| slot.strong_count() > 0);
        if let Some(slot) = self.slots.get(&key).and_then(Weak::upgrade) {
            return Some(slot);
        }
        if self.slots.len() >= limit {
            return None;
        }
        let slot = Arc::new(tokio::sync::Mutex::new(()));
        self.slots.insert(key, Arc::downgrade(&slot));
        Some(slot)
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.slots.len()
    }
}

pub(crate) fn cached_client(
    cache: &OnceLock<reqwest::Client>,
    build: impl FnOnce() -> reqwest::ClientBuilder,
) -> Result<&reqwest::Client, reqwest::Error> {
    if let Some(client) = cache.get() {
        return Ok(client);
    }
    let client = build().build()?;
    // A concurrent caller can win initialization. Return the same pooled
    // client in either case; failed builds leave the cache available for retry.
    Ok(cache.get_or_init(|| client))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failed_build_can_be_retried_and_a_success_is_reused() {
        let cache = OnceLock::new();
        assert!(
            cached_client(&cache, || reqwest::Client::builder()
                .user_agent("bad\nheader"))
            .is_err()
        );
        assert!(cache.get().is_none());
        let first = cached_client(&cache, reqwest::Client::builder).unwrap();
        let second = cached_client(&cache, || panic!("must reuse the initialized pool")).unwrap();
        assert!(std::ptr::eq(first, second));
    }

    #[test]
    fn concurrent_initialization_returns_one_shared_pool() {
        let cache = std::sync::Arc::new(OnceLock::new());
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
        let workers: Vec<_> = (0..8)
            .map(|_| {
                let cache = cache.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    cached_client(&cache, reqwest::Client::builder).unwrap() as *const _ as usize
                })
            })
            .collect();
        let addresses: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect();
        assert!(addresses.iter().all(|address| *address == addresses[0]));
    }
}
