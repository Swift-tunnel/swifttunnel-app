//! Network Analyzer Module
//!
//! Provides network diagnostics including:
//! - Connection stability test (ping, jitter, packet loss)
//! - Speed test using Cloudflare's speed test endpoints

pub mod speed_test;
pub mod stability_test;
pub mod types;

pub use speed_test::run_speed_test;
pub use stability_test::run_stability_test;
pub use types::*;
