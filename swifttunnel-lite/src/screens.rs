//! Each screen, as a list of items.
//!
//! This is the whole interface. Everything about how it is measured, drawn and
//! clicked lives in `view`, so what is left here is what the screen actually
//! says, which is the part worth being able to read and change quickly.

use crate::state::{Push, Roblox, State, Status};
use crate::theme;
use crate::view::{Action, Chip, Flag, Item, Right, Row, Screen, Tone, Variant};

/// Caps worth offering as buttons. Anything between them is a rounding error.
const FPS_PRESETS: [u32; 5] = [60, 120, 144, 165, 240];

/// Build the current screen, or whatever is pushed over it.
pub fn build(state: &State) -> Vec<Item> {
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

    let mut items = vec![
        caption("Frame rate"),
        Item::Group(vec![
            Row::new("Unlock frame rate")
                .sub("Removes Roblox's 60 FPS cap")
                .right(Right::Switch(r.unlock_fps))
                .action(Action::Toggle(Flag::UnlockFps)),
            Row::new("Cap")
                .right(Right::Choice(
                    FPS_PRESETS
                        .iter()
                        .map(|fps| Chip {
                            label: fps.to_string(),
                            selected: r.target_fps == *fps,
                            action: Action::SetFps(*fps),
                        })
                        .collect(),
                ))
                .disabled(!r.unlock_fps),
        ]),
        Item::Gap(12),
        caption("Game"),
        Item::Group(vec![
            Row::new("Graphics").right(Right::Choice(vec![
                Chip {
                    label: "Auto".into(),
                    selected: r.quality == 0,
                    action: Action::SetQuality(0),
                },
                Chip {
                    label: "Low".into(),
                    selected: r.quality == 1,
                    action: Action::SetQuality(1),
                },
                Chip {
                    label: "Max".into(),
                    selected: r.quality == 10,
                    action: Action::SetQuality(10),
                },
            ])),
            Row::new("Ultraboost")
                .sub("Strips post-processing for the most frames")
                .right(Right::Switch(r.ultraboost))
                .action(Action::Toggle(Flag::Ultraboost)),
            Row::new("Launch fullscreen")
                .right(Right::Switch(r.fullscreen))
                .action(Action::Toggle(Flag::Fullscreen)),
        ]),
        Item::Gap(12),
    ];

    if let Some(error) = &r.error {
        items.push(Item::Note(error.clone()));
    }

    // No explanatory note under this. It said that Roblox reads its settings
    // at launch, which is exactly what the button already says, and it cost
    // 34px in a 344px window.
    items.push(Item::Button {
        label: if r.running {
            "Restart Roblox to apply".into()
        } else {
            "Roblox is not running".into()
        },
        action: Action::RestartRoblox,
        variant: Variant::Outline,
        disabled: !r.running,
    });

    items
}

// ── Settings ────────────────────────────────────────────────────────────────

/// Settings, and it has to fit.
///
/// The viewport is 280px. The first version of this screen laid out to 378 and
/// scrolled, which sliced the last row in half against the window edge and
/// looked like a rendering fault rather than a list. Every sub-label that was
/// restating its own row is gone, and the version moved into the caption,
/// which brings it to 276.
fn settings(state: &State) -> Vec<Item> {
    vec![
        caption("Startup"),
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
        ]),
        Item::Gap(12),
        caption("Network"),
        Item::Group(vec![
            Row::new("Adapter")
                .right(Right::TextChevron(adapter_label(state)))
                .action(Action::OpenAdapters),
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
