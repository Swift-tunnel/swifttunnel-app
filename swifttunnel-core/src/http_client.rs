//! Reuse successful HTTP clients without making initialization failures permanent.

use std::sync::OnceLock;

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
