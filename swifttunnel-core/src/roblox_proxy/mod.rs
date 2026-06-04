//! Roblox bootstrap DNS repair.
//!
//! API tunneling can carry Roblox HTTPS traffic through a SwiftTunnel
//! relay, but Roblox still needs a working local hostname lookup before
//! it opens that TCP connection. This module keeps a narrow hosts-file
//! repair for launch/API endpoints and also removes stale
//! entries from older local-proxy builds.

pub mod hosts;
pub(crate) mod legacy_goodbyedpi;
