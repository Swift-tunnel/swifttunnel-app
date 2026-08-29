//! What the window knows.
//!
//! Deliberately a plain snapshot with no behaviour: the engine fills it from
//! background threads, `screens` reads it to build a view, and the window
//! paints. Nothing here reaches out to core, so a screen can be laid out in the
//! preview harness with no network, no driver and no account.

use crate::view::{FieldId, Screen};

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
    /// The advice half of a failure: what to do about it.
    ///
    /// Core writes failures for a dialog, so they arrive as two paragraphs.
    /// The status line here is one line, so it takes the first and this
    /// carries the remainder to a note that wraps.
    pub hint: String,
    /// Region actually connected to, which auto-routing can make different
    /// from the one that was asked for.
    pub region: Option<String>,
    pub ping_ms: Option<u32>,
    pub bytes_up: u64,
    pub bytes_down: u64,
    /// Seconds since the tunnel came up.
    pub elapsed: u64,
}

/// One editable line of text.
///
/// The first version of the sign-in form appended and popped characters and
/// nothing else, which meant no caret to move, nothing to select, and no way
/// to fix a typo except to delete back to it. Positions are in characters, not
/// bytes, so an accented letter counts once and cannot land mid-codepoint.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TextField {
    pub text: String,
    /// Where the caret sits, counted in characters from the start.
    pub caret: usize,
    /// The other end of the selection. Equal to the caret when nothing is
    /// selected, which is the only thing that distinguishes the two states.
    pub anchor: usize,
}

impl TextField {
    pub fn len(&self) -> usize {
        self.text.chars().count()
    }

    /// The selection as an ordered pair, since the anchor may be either side.
    pub fn selection(&self) -> (usize, usize) {
        (self.caret.min(self.anchor), self.caret.max(self.anchor))
    }

    pub fn has_selection(&self) -> bool {
        self.caret != self.anchor
    }

    fn byte_of(&self, chars: usize) -> usize {
        self.text
            .char_indices()
            .nth(chars)
            .map(|(i, _)| i)
            .unwrap_or(self.text.len())
    }

    /// Put the caret somewhere, dragging the selection with it or collapsing it.
    pub fn move_to(&mut self, pos: usize, extend: bool) {
        self.caret = pos.min(self.len());
        if !extend {
            self.anchor = self.caret;
        }
    }

    pub fn select_all(&mut self) {
        self.anchor = 0;
        self.caret = self.len();
    }

    /// Where the previous or next word boundary is, for ctrl-arrow and
    /// ctrl-backspace. A word ends where a run of non-spaces meets a space.
    pub fn word_left(&self) -> usize {
        let chars: Vec<char> = self.text.chars().collect();
        let mut i = self.caret;
        while i > 0 && chars[i - 1].is_whitespace() {
            i -= 1;
        }
        while i > 0 && !chars[i - 1].is_whitespace() {
            i -= 1;
        }
        i
    }

    pub fn word_right(&self) -> usize {
        let chars: Vec<char> = self.text.chars().collect();
        let mut i = self.caret;
        while i < chars.len() && !chars[i].is_whitespace() {
            i += 1;
        }
        while i < chars.len() && chars[i].is_whitespace() {
            i += 1;
        }
        i
    }

    /// Drop whatever is selected. Returns whether anything went.
    pub fn delete_selection(&mut self) -> bool {
        if !self.has_selection() {
            return false;
        }
        let (start, end) = self.selection();
        let (a, b) = (self.byte_of(start), self.byte_of(end));
        self.text.replace_range(a..b, "");
        self.caret = start;
        self.anchor = start;
        true
    }

    /// Type something, replacing the selection the way every other field does.
    pub fn insert(&mut self, value: &str, limit: usize) {
        self.delete_selection();
        let room = limit.saturating_sub(self.len());
        if room == 0 {
            return;
        }
        let value: String = value.chars().filter(|c| !c.is_control()).take(room).collect();
        if value.is_empty() {
            return;
        }
        let at = self.byte_of(self.caret);
        self.text.insert_str(at, &value);
        self.caret += value.chars().count();
        self.anchor = self.caret;
    }

    pub fn backspace(&mut self, word: bool) {
        if self.delete_selection() {
            return;
        }
        if self.caret == 0 {
            return;
        }
        let from = if word { self.word_left() } else { self.caret - 1 };
        let (a, b) = (self.byte_of(from), self.byte_of(self.caret));
        self.text.replace_range(a..b, "");
        self.caret = from;
        self.anchor = from;
    }

    pub fn delete(&mut self) {
        if self.delete_selection() {
            return;
        }
        if self.caret >= self.len() {
            return;
        }
        let (a, b) = (self.byte_of(self.caret), self.byte_of(self.caret + 1));
        self.text.replace_range(a..b, "");
    }
}

/// What the sign-in form is holding.
///
/// Kept in the window's state rather than the engine snapshot: it is text
/// somebody is typing, and the poller has no business overwriting it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Login {
    pub email: TextField,
    pub password: TextField,
    pub error: Option<String>,
    /// A sign-in is in flight, so the button says so and cannot be pressed twice.
    pub busy: bool,
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

/// Where the split tunnel driver stands.
///
/// The tunnel cannot come up without it, and the ways it breaks (a Windows
/// update, another VPN's older copy of the same driver, a half-finished
/// install) are not things a person can be expected to diagnose. Lite says
/// what it sees and offers to reinstall.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Driver {
    /// What core's health check reported, e.g. "Ready" or the reason it is not.
    pub status: String,
    pub ready: bool,
    /// A repair is running.
    pub repairing: bool,
    /// What the last repair said, success or failure.
    pub note: Option<String>,
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
    /// Nobody is signed in.
    ///
    /// The full app swaps its whole UI for a login screen when the auth state
    /// is anything but logged in. Lite showed the tabs regardless, so signing
    /// out left every control sitting there looking usable.
    SignedOut,
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
    /// Whether a custom FFlag payload is currently applied.
    pub custom_fflags: bool,
    /// The payload itself, so editing it starts from what is there.
    pub custom_json: String,
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
    /// Pending Roblox edits. `None` means the screen mirrors the disk.
    pub roblox_draft: Option<RobloxDraft>,
    /// Which field has the caret, if any.
    pub focus: Option<FieldId>,
    /// The sign-in form.
    pub login: Login,
    pub driver: Driver,
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
    pub discord_rpc: bool,
    /// `None` when the adapter is picked automatically.
    pub adapter_guid: Option<String>,

    // ── Account ──
    pub email: Option<String>,
    pub signed_in: bool,
    /// Seconds of free tunnel time left, when the server is enforcing a limit.
    pub free_tier_secs: Option<u32>,
    /// The allowance and its grace are spent, so a connect would be refused.
    ///
    /// Deliberately not a lockout: the full app keeps its whole interface
    /// usable and simply lets the connect fail, and there is plenty here worth
    /// reaching without a tunnel, Roblox settings and the log among it.
    pub free_tier_spent: bool,
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

/// Pending Roblox edits, before they are written.
///
/// # Why a draft
///
/// Every control on the Roblox screen used to write Roblox's settings file the
/// moment it was touched, each on its own thread, with a busy flag swallowing
/// anything clicked while a write was in flight. Changing three things meant
/// three writes and three re-reads racing each other, and clicks that appeared
/// to do nothing. It was, correctly, described as buggy.
///
/// Nothing is written now until Apply. `None` means the screen is showing what
/// is actually on disk; the first edit materialises a draft, and applying
/// clears it so the truth flows back through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RobloxDraft {
    pub unlock_fps: bool,
    /// The frame cap as typed, which may not be a number yet.
    pub fps_text: String,
    pub quality: u32,
    pub fullscreen: bool,
    pub ultraboost: bool,
    pub custom_fflags: bool,
    pub custom_json: String,
    /// What validating `custom_json` said, shown under the group.
    pub fflag_note: Option<String>,
    pub fflag_ok: bool,
}

impl RobloxDraft {
    /// Start from what is actually applied to the client.
    pub fn from_truth(truth: &Roblox) -> Self {
        Self {
            unlock_fps: truth.unlock_fps,
            fps_text: truth.target_fps.to_string(),
            quality: truth.quality,
            fullscreen: truth.fullscreen,
            ultraboost: truth.ultraboost,
            custom_fflags: truth.custom_fflags,
            custom_json: truth.custom_json.clone(),
            fflag_note: None,
            fflag_ok: truth.custom_fflags,
        }
    }

    /// The typed cap, if it is a number Roblox will accept.
    ///
    /// Roblox stores this as an integer and treats anything at or below 60 as
    /// no unlock at all. The ceiling is not Roblox's, it is ours: an uncapped
    /// client will render thousands of frames a second on a menu, which heats
    /// the GPU and buys nothing a monitor can show.
    pub fn fps(&self) -> Option<u32> {
        let value: u32 = self.fps_text.trim().parse().ok()?;
        (30..=1000).contains(&value).then_some(value)
    }
}

impl State {
    /// What the Roblox screen should show: the draft if there is one, the
    /// truth otherwise.
    pub fn roblox_view(&self) -> RobloxDraft {
        self.roblox_draft
            .clone()
            .unwrap_or_else(|| RobloxDraft::from_truth(&self.roblox))
    }

    /// Edit the draft, creating it from the truth on the first change.
    pub fn edit_roblox(&mut self, edit: impl FnOnce(&mut RobloxDraft)) {
        let mut draft = self.roblox_view();
        edit(&mut draft);
        self.roblox_draft = Some(draft);
    }

    /// Whether there is anything to apply.
    pub fn roblox_dirty(&self) -> bool {
        match &self.roblox_draft {
            None => false,
            Some(draft) => *draft != RobloxDraft::from_truth(&self.roblox),
        }
    }
}

impl RobloxDraft {
    /// Whether this draft can be written at all.
    ///
    /// A cap that is not a number, or a custom payload that failed its check,
    /// would be rejected by core anyway. Refusing here means the button says
    /// so rather than the failure arriving after a game restart.
    pub fn ready(&self) -> bool {
        if self.unlock_fps && self.fps().is_none() {
            return false;
        }
        if self.custom_fflags && !self.fflag_ok {
            return false;
        }
        true
    }
}
