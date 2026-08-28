//! Each screen, as a list of items.
//!
//! This is the whole interface. Everything about how it is measured, drawn and
//! clicked lives in `view`, so what is left here is what the screen actually
//! says, which is the part worth being able to read and change quickly.

use crate::state::{Lockout, Push, Roblox, RobloxDraft, State, Status};
use crate::theme;
use crate::view::{Action, Chip, FieldId, Flag, Item, Right, Row, Screen, Tone, Variant};

/// Build the current screen, or whatever is pushed over it.
pub fn build(state: &State) -> Vec<Item> {
    // A lockout takes the whole window. Tabs would imply there is something
    // useful behind them, and there is not: the account or the build is the
    // problem and nothing on the other screens changes that.
    if let Some(lockout) = &state.lockout {
        return locked_out(state, lockout);
    }

    match state.push {
        Push::Regions => regions(state),
        Push::Adapters => adapters(state),
        Push::None => match state.screen {
            Screen::Connect => connect(state),
            Screen::Roblox => roblox(state),
            Screen::Settings => settings(state),
        },
    }
}

/// The screen shown instead of everything else.
fn locked_out(state: &State, lockout: &Lockout) -> Vec<Item> {
    let (headline, detail) = match lockout {
        Lockout::Banned(reason) => (
            "Account suspended",
            if reason.trim().is_empty() {
                "This account cannot use SwiftTunnel. Contact support if you think this is wrong.".to_string()
            } else {
                reason.clone()
            },
        ),
        Lockout::UpdateRequired(message) => (
            "Update required",
            if message.trim().is_empty() {
                "This build is too old to connect. Install the latest SwiftTunnel.".to_string()
            } else {
                message.clone()
            },
        ),
    };

    let mut items = vec![
        Item::Gap(16),
        Item::Status {
            headline: headline.to_string(),
            sub: String::new(),
            dot: theme::ERROR,
            sub_ink: theme::TEXT_MUTED,
            right: None,
        },
        Item::Note(detail),
        Item::Gap(8),
    ];

    if matches!(lockout, Lockout::Banned(_)) && state.signed_in {
        items.push(Item::Group(vec![
            Row::new("Sign out").action(Action::SignOut).danger_if(true),
        ]));
    }

    items
}

// ── Connect ─────────────────────────────────────────────────────────────────

fn connect(state: &State) -> Vec<Item> {
    let t = &state.tunnel;
    let connected = t.status == Status::Connected;

    let headline = if connected {
        state
            .connected_region()
            .map(|r| r.name.clone())
            .or_else(|| t.region.clone())
            .unwrap_or_else(|| "Connected".to_string())
    } else if t.status == Status::Working {
        t.detail.clone()
    } else if state.auto_routing {
        "Automatic".to_string()
    } else {
        state
            .selected()
            .map(|r| r.name.clone())
            .unwrap_or_else(|| "No region".to_string())
    };

    let sub = if connected {
        "Roblox traffic is tunneled".to_string()
    } else if t.detail.is_empty() {
        "Ready to connect".to_string()
    } else {
        t.detail.clone()
    };

    let mut items = vec![Item::Status {
        headline,
        sub,
        dot: match t.status {
            Status::Connected => theme::CONNECTED,
            Status::Working => theme::WARNING,
            Status::Error => theme::ERROR,
            Status::Disconnected => theme::INACTIVE,
        },
        sub_ink: if t.status == Status::Error {
            theme::ERROR_TEXT
        } else {
            theme::TEXT_MUTED
        },
        right: connected.then(|| elapsed(t.elapsed)),
    }];

    items.push(Item::Gap(8));
    items.push(Item::Button {
        label: primary_label(state),
        action: Action::Primary,
        variant: if connected {
            Variant::Outline
        } else {
            Variant::Solid
        },
        disabled: t.status == Status::Working,
    });
    items.push(Item::Gap(12));

    if connected {
        items.push(Item::Stats([
            (
                "Ping".into(),
                t.ping_ms.map_or("--".into(), |v| format!("{v}ms")),
            ),
            ("Down".into(), bytes(t.bytes_down)),
            ("Up".into(), bytes(t.bytes_up)),
        ]));
        items.push(Item::Gap(12));
    }

    items.push(caption("Tunnel"));
    items.push(Item::Group(vec![
        Row::new("Region")
            .right(Right::TextChevron(region_label(state)))
            .action(Action::OpenRegions),
        Row::new("Adapter")
            .right(Right::TextChevron(adapter_label(state)))
            .action(Action::OpenAdapters),
        Row::new("Route Assist")
            .sub("Join servers in the tunneled region")
            .right(Right::Switch(state.route_assist))
            .action(Action::Toggle(Flag::RouteAssist)),
        Row::new("Bypass country ban")
            .sub("Use when Roblox is blocked entirely")
            .right(Right::Switch(state.country_ban))
            .action(Action::Toggle(Flag::CountryBan)),
    ]));

    items
}

/// What the one button on Connect currently does.
fn primary_label(state: &State) -> String {
    match state.tunnel.status {
        Status::Connected => "Disconnect".into(),
        Status::Working => {
            if state.tunnel.detail.is_empty() {
                "Working".into()
            } else {
                state.tunnel.detail.clone()
            }
        }
        _ => "Connect".into(),
    }
}

fn region_label(state: &State) -> String {
    if state.auto_routing {
        return "Automatic".into();
    }
    match state.selected() {
        Some(r) => r.name.clone(),
        None if state.selected_region.is_empty() => "Choose".into(),
        None => state.selected_region.clone(),
    }
}

// ── Region picker ───────────────────────────────────────────────────────────

fn regions(state: &State) -> Vec<Item> {
    let mut rows = vec![
        Row::new("Automatic")
            .sub("Pick the fastest relay at connect time")
            .right(Right::Tick(state.auto_routing))
            .action(Action::PickAutoRegion),
    ];

    for region in &state.regions {
        let selected = !state.auto_routing && state.selected_region == region.id;
        rows.push(
            Row::new(format!("{}  {}", region.country, region.name))
                .right(if selected {
                    Right::Tick(true)
                } else {
                    Right::Latency(region.ping_ms)
                })
                .action(Action::PickRegion(region.id.clone())),
        );
    }

    if state.regions.is_empty() {
        rows.push(Row::new("Fetching relays...").disabled(true));
    }

    vec![Item::Back("Region".into()), Item::Group(rows)]
}

// ── Roblox ──────────────────────────────────────────────────────────────────

/// The Roblox screen.
///
/// Nothing here writes anything. Every control edits a draft, and Apply is
/// the only thing that touches Roblox's files. The previous version wrote on
/// every click, from a thread per click, with a busy flag swallowing anything
/// pressed while a write was in flight; changing three settings raced three
/// writes against three re-reads and dropped clicks on the floor.
///
/// What is shown when there is no draft is what is actually applied to the
/// client, not what SwiftTunnel last asked for. Core reconciles the two, so a
/// cap the player changed in Roblox itself, or FFlags a Roblox update wiped,
/// show up here as gone.
fn roblox(state: &State) -> Vec<Item> {
    let r: &Roblox = &state.roblox;

    if !r.installed {
        return vec![
            Item::Gap(40),
            caption("Roblox"),
            Item::Group(vec![
                Row::new("Roblox is not installed")
                    .sub("Install it and reopen SwiftTunnel Lite")
                    .disabled(true),
            ]),
        ];
    }

    let draft = state.roblox_view();
    let dirty = state.roblox_dirty();

    let mut items = vec![
        caption("Frame rate"),
        Item::Group(vec![
            Row::new("Unlock frame rate")
                .sub("Removes Roblox's 60 FPS cap")
                .right(Right::Switch(draft.unlock_fps))
                .action(Action::Toggle(Flag::UnlockFps)),
            Row::new("Cap")
                .sub(fps_hint(&draft))
                .right(Right::Field {
                    text: draft.fps_text.clone(),
                    focused: state.focus == Some(FieldId::FpsCap),
                    id: FieldId::FpsCap,
                    valid: draft.fps().is_some(),
                })
                .disabled(!draft.unlock_fps),
        ]),
        Item::Gap(12),
        caption("Game"),
        Item::Group(vec![
            Row::new("Graphics").right(Right::Choice(vec![
                Chip {
                    label: "Auto".into(),
                    selected: draft.quality == 0,
                    action: Action::SetQuality(0),
                },
                Chip {
                    label: "Low".into(),
                    selected: draft.quality == 1,
                    action: Action::SetQuality(1),
                },
                Chip {
                    label: "Max".into(),
                    selected: draft.quality == 10,
                    action: Action::SetQuality(10),
                },
            ])),
            Row::new("Launch fullscreen")
                .right(Right::Switch(draft.fullscreen))
                .action(Action::Toggle(Flag::Fullscreen)),
        ]),
        Item::Gap(12),
        caption("FFlags"),
        Item::Group(vec![
            Row::new("Ultraboost")
                .sub("SwiftTunnel's own performance flags")
                .right(Right::Switch(draft.ultraboost))
                .action(Action::Toggle(Flag::Ultraboost)),
            Row::new("Custom FFlags")
                .sub(custom_hint(&draft))
                .right(Right::Switch(draft.custom_fflags))
                .action(Action::Toggle(Flag::CustomFflags)),
            Row::new("Paste from clipboard")
                .right(Right::Chevron)
                .action(Action::PasteFflags)
                .disabled(!draft.custom_fflags),
        ]),
        Item::Gap(10),
    ];

    if let Some(note) = &draft.fflag_note {
        items.push(Item::Note(note.clone()));
    }
    if let Some(error) = &r.error {
        items.push(Item::Note(error.clone()));
    }

    let _ = dirty;
    items
}

/// The control pinned to the bottom of a screen, outside the scroll.
///
/// Roblox has more settings than fit, and the one button that writes them must
/// not be the thing that scrolls off. It sits below the list instead, always
/// reachable, which also makes it obvious that nothing above it has been
/// applied yet.
pub fn footer(state: &State) -> Option<Item> {
    if state.push != Push::None || state.lockout.is_some() {
        return None;
    }
    if state.screen != Screen::Roblox || !state.roblox.installed {
        return None;
    }

    let draft = state.roblox_view();
    let dirty = state.roblox_dirty();

    // Roblox reads its settings once at launch, so applying while it is open
    // does nothing until it restarts. The label says which is about to happen.
    Some(Item::Button {
        label: if !dirty {
            "No changes to apply".into()
        } else if state.roblox.running {
            "Restart Roblox to apply".into()
        } else {
            "Apply".into()
        },
        action: Action::ApplyRoblox,
        variant: if dirty { Variant::Solid } else { Variant::Outline },
        disabled: !dirty || !draft.ready(),
    })
}

/// What the cap field is doing, said in the row's second line.
fn fps_hint(draft: &RobloxDraft) -> String {
    if !draft.unlock_fps {
        return "Roblox's default 60".into();
    }
    match draft.fps() {
        Some(_) => "Frames per second".into(),
        None => "Enter a number between 30 and 1000".into(),
    }
}

/// Whether a custom payload is loaded, and how big it is.
fn custom_hint(draft: &RobloxDraft) -> String {
    if draft.ultraboost {
        return "Turn Ultraboost off to use your own".into();
    }
    if !draft.custom_fflags {
        return "Import your own allowlisted flags".into();
    }
    if draft.custom_json.trim().is_empty() {
        return "Nothing pasted yet".into();
    }
    "Your own flags".into()
}

// ── Settings ────────────────────────────────────────────────────────────────

/// Settings, and it has to fit.
///
/// An earlier version laid out well past the viewport and scrolled, which
/// sliced the last row in half against the window edge and looked like a
/// rendering fault rather than a list. Every sub-label that was restating its
/// own row is gone, the version sits in the caption rather than costing a row,
/// and the adapter moved to Connect, where the thing it affects is.
fn settings(state: &State) -> Vec<Item> {
    vec![
        caption("General"),
        Item::Group(vec![
            Row::new("Start with Windows")
                .right(Right::Switch(state.run_on_startup))
                .action(Action::Toggle(Flag::RunOnStartup)),
            Row::new("Close to tray")
                .right(Right::Switch(state.close_to_tray))
                .action(Action::Toggle(Flag::CloseToTray)),
            Row::new("Reconnect automatically")
                .right(Right::Switch(state.auto_reconnect))
                .action(Action::Toggle(Flag::AutoReconnect)),
            Row::new("Discord Rich Presence")
                .sub("Show the region you are tunneled to")
                .right(Right::Switch(state.discord_rpc))
                .action(Action::Toggle(Flag::DiscordRpc)),
        ]),
        Item::Gap(12),
        caption("Driver"),
        Item::Group(vec![
            Row::new("Split tunnel driver")
                .sub(state.driver.status.clone())
                .right(Right::Text(if state.driver.ready {
                    "Ready".into()
                } else {
                    "Not ready".into()
                })),
            Row::new(if state.driver.repairing {
                "Reinstalling..."
            } else {
                "Reinstall driver"
            })
            .sub("Use if the tunnel will not start")
            .right(Right::Chevron)
            .action(Action::RepairDriver)
            .disabled(state.driver.repairing),
        ]),
        Item::Gap(12),
        // No update check. Lite ships inside the same installer as the full app
        // and is replaced when it is, so a button offering to look for one
        // would be a button that does nothing.
        Item::Caption {
            text: "Account".into(),
            trailing: Some(format!("v{}", env!("CARGO_PKG_VERSION"))),
        },
        Item::Group(vec![
            Row::new(state.email.clone().unwrap_or_else(|| "Signed out".into())),
            Row::new(if state.signed_in { "Sign out" } else { "Sign in" })
                .action(if state.signed_in {
                    Action::SignOut
                } else {
                    Action::SignIn
                })
                .danger_if(state.signed_in),
        ]),
    ]
}

/// A plain uppercase caption, which is almost all of them.
fn caption(text: &str) -> Item {
    Item::Caption {
        text: text.into(),
        trailing: None,
    }
}

fn adapter_label(state: &State) -> String {
    match &state.adapter_guid {
        None => "Automatic".into(),
        Some(guid) => state
            .adapters
            .iter()
            .find(|a| &a.guid == guid)
            .map(|a| a.name.clone())
            .unwrap_or_else(|| "Manual".into()),
    }
}

// ── Adapter picker ──────────────────────────────────────────────────────────

fn adapters(state: &State) -> Vec<Item> {
    let mut rows = vec![
        Row::new("Automatic")
            .sub("Let SwiftTunnel pick the adapter carrying your traffic")
            .right(Right::Tick(state.adapter_guid.is_none()))
            .action(Action::PickAdapter(None)),
    ];

    for adapter in &state.adapters {
        rows.push(
            Row::new(adapter.name.clone())
                .sub(adapter.detail.clone())
                .right(Right::Tick(
                    state.adapter_guid.as_deref() == Some(adapter.guid.as_str()),
                ))
                .action(Action::PickAdapter(Some(adapter.guid.clone()))),
        );
    }

    vec![Item::Back("Network adapter".into()), Item::Group(rows)]
}

// ── Formatting ──────────────────────────────────────────────────────────────

/// `1:04:21` once past an hour, `04:21` before it.
fn elapsed(seconds: u64) -> String {
    let h = seconds / 3600;
    let m = (seconds % 3600) / 60;
    let s = seconds % 60;
    if h > 0 {
        format!("{h}:{m:02}:{s:02}")
    } else {
        format!("{m:02}:{s:02}")
    }
}

/// Decimal units, matching the app's own readout.
fn bytes(value: u64) -> String {
    const KB: f64 = 1024.0;
    let v = value as f64;
    if v < KB {
        format!("{value}B")
    } else if v < KB * KB {
        format!("{:.0}K", v / KB)
    } else if v < KB * KB * KB {
        format!("{:.1}M", v / (KB * KB))
    } else {
        format!("{:.2}G", v / (KB * KB * KB))
    }
}

impl Row {
    /// Red only when the action is destructive, so one row can serve both
    /// "Sign out" and "Sign in".
    fn danger_if(mut self, yes: bool) -> Self {
        if yes {
            self.tone = Tone::Danger;
        }
        self
    }
}
