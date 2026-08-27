//! What the window knows.
//!
//! Deliberately a plain snapshot with no behaviour: the engine fills it from
//! background threads, `screens` reads it to build a view, and the window
//! paints. Nothing here reaches out to core, so a screen can be laid out in the
//! preview harness with no network, no driver and no account.

use crate::view::Screen;

/// Where the tunnel is, flattened from core's richer state machine.
///
/// Lite shows one line about the connection, so the distinction between
/// "creating adapter" and "configuring routes" buys it nothing; both are
/// `Working`, with core's own wording carried in `detail`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Status {
    #[default]
    Disconnected,
    Working,
    Connected,
    Error,
}

/// A view pushed over the current screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Push {
    #[default]
    None,
    Regions,
    Adapters,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Tunnel {
    pub status: Status,
    /// Core's own description of what it is doing, or why it failed.
    pub detail: String,
    /// Region actually connected to, which auto-routing can make different
    /// from the one that was asked for.
    pub region: Option<String>,
    pub ping_ms: Option<u32>,
    pub bytes_up: u64,
    pub bytes_down: u64,
    /// Seconds since the tunnel came up.
    pub elapsed: u64,
}

/// One row of the region list.
#[derive(Debug, Clone)]
pub struct RegionRow {
    pub id: String,
    pub name: String,
    /// Two-letter code, e.g. `IN`. Windows draws regional-indicator pairs as
    /// letters rather than flags, so the code is what a flag emoji would have
    /// come out as anyway, minus the substitution.
    pub country: String,
    pub ping_ms: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct AdapterRow {
    pub guid: String,
    pub name: String,
    pub detail: String,
}

/// A reason this client must not be used, whatever else is true.
///
/// Both are enforced by the server regardless of what the client does: a
/// banned account is refused a relay ticket, and a locked-out build is refused
/// by the API with a 426. This is here so the window says which of the two it
/// is, rather than leaving somebody to interpret a connect that keeps failing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lockout {
    Banned(String),
    UpdateRequired(String),
}

/// Roblox's own settings, read from its file rather than remembered here, so
/// the switches reflect reality even when the full app or the player changed
/// them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Roblox {
    pub installed: bool,
    pub running: bool,
    pub unlock_fps: bool,
    pub target_fps: u32,
    /// 0 = automatic, otherwise Roblox's own 1..=10 quality level.
    pub quality: u32,
    pub ultraboost: bool,
    pub fullscreen: bool,
    /// Set when a write failed, shown under the group.
    pub error: Option<String>,
}

/// Everything the three screens read.
#[derive(Debug, Clone, Default)]
pub struct State {
    pub screen: Screen,
    pub push: Push,
    pub tunnel: Tunnel,
    pub regions: Vec<RegionRow>,
    pub adapters: Vec<AdapterRow>,
    pub roblox: Roblox,
    /// Set when this client must not connect at all.
    pub lockout: Option<Lockout>,

    // ── From the shared settings file ──
    pub selected_region: String,
    pub auto_routing: bool,
    pub route_assist: bool,
    pub country_ban: bool,
    pub run_on_startup: bool,
    pub close_to_tray: bool,
    pub auto_reconnect: bool,
    /// `None` when the adapter is picked automatically.
    pub adapter_guid: Option<String>,

    // ── Account ──
    pub email: Option<String>,
    pub signed_in: bool,
    /// Seconds of free tunnel time left, when the server is enforcing a limit.
    pub free_tier_secs: Option<u32>,
}

impl Default for Screen {
    fn default() -> Self {
        Screen::Connect
    }
}

impl State {
    /// The region row currently selected, if the list has arrived.
    pub fn selected(&self) -> Option<&RegionRow> {
        self.regions.iter().find(|r| r.id == self.selected_region)
    }

    /// The region the tunnel actually landed in.
    pub fn connected_region(&self) -> Option<&RegionRow> {
        let id = self.tunnel.region.as_deref()?;
        self.regions
            .iter()
            .find(|r| r.id == id)
            // Core reports the relay's region id, which for a multi-relay
            // region is a member rather than the group, so fall back to a
            // prefix match before giving up and showing the raw id.
            .or_else(|| self.regions.iter().find(|r| id.starts_with(&r.id)))
    }
}
