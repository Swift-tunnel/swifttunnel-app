//! Network Analyzer Module
//!
//! Provides network diagnostics including:
//! - Connection stability test (ping, jitter, packet loss)
//! - Speed test using Cloudflare's speed test endpoints

pub mod types;
pub mod stability_test;
pub mod speed_test;

pub use types::*;
pub use stability_test::run_stability_test;
pub use speed_test::run_speed_test;
