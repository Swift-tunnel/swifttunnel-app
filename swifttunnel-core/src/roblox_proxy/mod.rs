//! Roblox bootstrap DNS repair and browser-side DPI helper.
//!
//! API tunneling can carry Roblox-owned HTTPS traffic through a SwiftTunnel
//! relay, but Roblox still needs a working local hostname lookup before it opens
//! that TCP connection. Browser-owned Roblox HTTP(S) is intentionally left out
//! of the relay path. Bypass country bans can start a scoped GoodbyeDPI helper
//! for both browser and Roblox app traffic when available.
//! This module keeps a narrow hosts-file repair for launch/API endpoints and
//! also removes stale entries from older local-proxy builds.

pub mod goodbyedpi;
pub mod hosts;
