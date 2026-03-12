//! Roblox proxy hosts-file cleanup (legacy migration).
//!
//! The local TCP proxy feature has been removed. This module only
//! retains the hosts-file cleanup logic so that users upgrading from
//! older versions have any stale `127.66.0.1` entries removed
//! automatically on first launch.

pub mod hosts;
