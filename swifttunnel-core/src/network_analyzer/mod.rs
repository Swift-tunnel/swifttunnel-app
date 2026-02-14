//! Network Analyzer Module
//!
//! Provides network diagnostics including:
//! - Connection stability test (ping, jitter, packet loss)
//! - Speed test using Cloudflare's speed test endpoints
//! - Bufferbloat test (latency under load)

pub mod bufferbloat_test;
pub mod speed_test;
pub mod stability_test;
pub mod types;

pub use bufferbloat_test::run_bufferbloat_test;
pub use speed_test::run_speed_test;
pub use stability_test::run_stability_test;
pub use types::*;
