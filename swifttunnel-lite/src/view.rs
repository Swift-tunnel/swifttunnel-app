//! One description of a screen, used for layout, painting and hit testing.
//!
//! # Why not hand-placed rectangles
//!
//! The previous version of this window computed a `Layout` struct of named
//! `RECT`s, then painted shapes from it, then painted text from it, then
//! hit-tested against it. Four places to touch for one row, and it came to 1651
//! lines for three screens that between them show about twenty controls. Every
//! change was expensive, which is a large part of why the design stayed wrong.
//!
//! Here a screen is a `Vec<Item>` and everything else is derived. [`layout`]
//! walks the items once and emits shapes, text runs and clickable zones
//! together, so a row cannot be drawn in one place and clicked in another, and
//! adding one is a single line in `screens.rs`.
//!
//! Shapes go through [`crate::canvas`], which rasterises them antialiased in
//! software, and text is drawn by GDI on top, whose rasteriser is good and
//! already has the embedded Geist faces registered. Nothing here uses the GPU,
//! which is the entire point of this client.

use windows::Win32::Foundation::{COLORREF, RECT};
use windows::Win32::Graphics::Gdi::{
    DRAW_TEXT_FORMAT, DT_CENTER, DT_END_ELLIPSIS, DT_LEFT, DT_NOPREFIX, DT_RIGHT, DT_SINGLELINE,
    DT_VCENTER, DT_WORDBREAK, HDC,
};

use crate::canvas::{Canvas, Rgba, RoundRect};
use crate::gdi::{self, Font};
use crate::theme;
use windows::Win32::Graphics::Gdi::{
    CreateSolidBrush, DeleteObject, FillRect, IntersectClipRect, RestoreDC, SaveDC,
};

// ── What a screen is made of ────────────────────────────────────────────────

/// Something the user can do. Interpreted by the app, never by the view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Tab(Screen),
    Minimise,
    Close,
    /// Connect, disconnect, or whatever the driver state says instead.
    Primary,
    OpenRegions,
    Back,
    PickRegion(String),
    PickAutoRegion,
    OpenAdapters,
    PickAdapter(Option<String>),
    Toggle(Flag),
    /// Put the caret in a field. Clicking anywhere else takes it out again.
    Focus(FieldId),
    SetQuality(u32),
    /// Write the pending Roblox edits, and restart the game if it is running.
    ApplyRoblox,
    /// Read a custom FFlag payload out of the clipboard and check it.
    ImportFflags,
    SignOut,
    /// Sign in with whatever is in the email and password fields.
    SubmitLogin,
    SignIn,
    /// Reinstall the split tunnel driver.
    RepairDriver,
    /// Show the log file in Explorer.
    OpenLogs,
}

/// A value the user can type into.
///
/// One so far. It is an enum rather than a bare bool so focus can move to a
/// second field later without every match arm having to be found again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldId {
    FpsCap,
    Email,
    Password,
}

/// A boolean setting a row can flip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flag {
    RouteAssist,
    CountryBan,
    UnlockFps,
    Ultraboost,
    CustomFflags,
    Fullscreen,
    RunOnStartup,
    CloseToTray,
    AutoReconnect,
    DiscordRpc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Connect,
    Roblox,
    Settings,
}

/// The right-hand side of a row.
#[derive(Debug, Clone)]
pub enum Right {
    None,
    /// A plain value with no control beside it.
    Text(String),
    /// Value text in the latency scale's ink.
    Latency(Option<u32>),
    Switch(bool),
    /// Inline chips, one of which is selected.
    Choice(Vec<Chip>),
    /// Selected marker in a picker list.
    Tick(bool),
    /// A row that does something rather than showing a value.
    Chevron,
    /// Text then a chevron, for a row that opens another view.
    TextChevron(String),
    /// An editable value.
    Field {
        text: String,
        focused: bool,
        id: FieldId,
        /// Drawn in the warning ink when what is typed is not usable yet.
        valid: bool,
    },
}

#[derive(Debug, Clone)]
pub struct Chip {
    pub label: String,
    pub selected: bool,
    pub action: Action,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    Normal,
    Danger,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Variant {
    Solid,
    Outline,
}

#[derive(Debug, Clone)]
pub struct Row {
    pub label: String,
    pub sub: Option<String>,
    pub right: Right,
    pub action: Option<Action>,
    pub disabled: bool,
    pub tone: Tone,
}

impl Row {
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            sub: None,
            right: Right::None,
            action: None,
            disabled: false,
            tone: Tone::Normal,
        }
    }
    pub fn sub(mut self, value: impl Into<String>) -> Self {
        self.sub = Some(value.into());
        self
    }
    pub fn right(mut self, value: Right) -> Self {
        self.right = value;
        self
    }
    pub fn action(mut self, value: Action) -> Self {
        self.action = Some(value);
        self
    }
    pub fn disabled(mut self, value: bool) -> Self {
        self.disabled = value;
        self
    }
}

#[derive(Debug, Clone)]
pub enum Item {
    /// Uppercase label over a group, optionally with a value on the right.
    ///
    /// The trailing slot exists so a fact that needs saying once (the version)
    /// does not have to cost a whole 34px row in a 280px viewport.
    Caption {
        text: String,
        trailing: Option<String>,
    },
    /// A block of rows behind one rounded outline.
    Group(Vec<Row>),
    /// The status block: dot, headline, one line under it, optional right text.
    Status {
        headline: String,
        sub: String,
        /// None on a screen that is not reporting tunnel state, so the block
        /// can be used as a plain heading without a status light next to it.
        dot: Option<Rgba>,
        sub_ink: COLORREF,
        right: Option<String>,
    },
    /// Ping / down / up, while connected.
    Stats([(String, String); 3]),
    Button {
        label: String,
        action: Action,
        variant: Variant,
        disabled: bool,
    },
    /// The backdrop the sign-in screen sits on: grid, glow, floor shadow.
    ///
    /// Takes no vertical space and is emitted first, so everything after it
    /// draws on top.
    Atmosphere,
    /// The centred brand block: logo, tagline, name, one line under it.
    ///
    /// Only the sign-in screen uses it, and it deliberately mirrors the full
    /// app's login screen rather than inventing a second look for the same
    /// moment.
    Brand,
    /// A back control at the top of a pushed view.
    Back(String),
    /// Small print under a control.
    Note(String),
    /// The same, centred, for a screen that is centred.
    Fine(String),
    /// A full-width text box, as the sign-in form needs.
    Input {
        id: FieldId,
        placeholder: String,
        value: String,
        /// Caret position in characters.
        caret: usize,
        /// Selected range in characters, ordered.
        selection: (usize, usize),
        /// Draw the value as bullets.
        masked: bool,
        focused: bool,
    },
    /// A hairline with a word set into it.
    Divider(String),
    Gap(i32),
}

// ── What layout produces ────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub enum Shape {
    Round {
        rect: RECT,
        radius: i32,
        fill: Option<Rgba>,
        stroke: Option<Rgba>,
    },
    Circle {
        cx: f32,
        cy: f32,
        r: f32,
        fill: Rgba,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Face {
    Title,
    Headline,
    Body,
    Sub,
    Caption,
    /// Numbers: the round trip, the throughput, the session timer. Monospaced
    /// so a readout that changes does not shuffle the digits beside it.
    Value,
    /// Words that happen to sit where a value goes: a region name, an email,
    /// a version. Monospacing these was wrong and looked it, a proportional
    /// face set in mono reads as a terminal, not as the product.
    ValueText,
    Button,
    Tab,
    Chip,
    Icon,
}

#[derive(Debug, Clone)]
pub struct TextRun {
    pub rect: RECT,
    pub text: String,
    pub face: Face,
    pub ink: COLORREF,
    pub format: DRAW_TEXT_FORMAT,
}

/// One editable line, waiting to be measured and drawn.
#[derive(Debug, Clone)]
pub struct InputRun {
    pub rect: RECT,
    /// Already masked if the field is a password: the paint stage draws what
    /// it is given and never sees the real characters.
    pub text: String,
    pub caret: usize,
    pub selection: (usize, usize),
    pub focused: bool,
}

/// The character a masked field shows instead of the real one.
pub const BULLET: &str = "•";

/// Everything one screen needs, produced in a single walk.
#[derive(Debug, Default)]
pub struct Frame {
    pub shapes: Vec<Shape>,
    pub texts: Vec<TextRun>,
    /// Editable text, drawn at paint time so it can be measured.
    pub inputs: Vec<InputRun>,
    /// The app icon, drawn straight onto the device context like the text is.
    /// The canvas only knows rectangles and circles, and the logo is neither.
    pub icons: Vec<RECT>,
    pub hots: Vec<(RECT, Action)>,
    /// Full height of the laid-out content, before scrolling.
    pub content_height: i32,
}

impl Frame {
    fn round(&mut self, rect: RECT, radius: i32, fill: Option<Rgba>, stroke: Option<Rgba>) {
        self.shapes.push(Shape::Round {
            rect,
            radius,
            fill,
            stroke,
        });
    }

    fn text(&mut self, rect: RECT, text: &str, face: Face, ink: COLORREF, format: DRAW_TEXT_FORMAT) {
        if text.is_empty() {
            return;
        }
        self.texts.push(TextRun {
            rect,
            text: text.to_string(),
            face,
            ink,
            format,
        });
    }

    fn hot(&mut self, rect: RECT, action: Action) {
        self.hots.push((rect, action));
    }
}

/// Logical-to-device scaling, resolved once per DPI.
#[derive(Debug, Clone, Copy)]
pub struct Metrics {
    pub scale: f32,
}

impl Metrics {
    pub fn new(dpi: i32) -> Self {
        Self {
            scale: dpi as f32 / 96.0,
        }
    }
    /// Scale one logical value.
    #[inline]
    pub fn s(&self, value: i32) -> i32 {
        ((value as f32) * self.scale).round() as i32
    }
}

fn rect(left: i32, top: i32, right: i32, bottom: i32) -> RECT {
    RECT {
        left,
        top,
        right,
        bottom,
    }
}

pub fn contains(r: RECT, x: i32, y: i32) -> bool {
    x >= r.left && x < r.right && y >= r.top && y < r.bottom
}

const LEFT: DRAW_TEXT_FORMAT = DRAW_TEXT_FORMAT(
    DT_SINGLELINE.0 | DT_VCENTER.0 | DT_LEFT.0 | DT_NOPREFIX.0 | DT_END_ELLIPSIS.0,
);
const RIGHT: DRAW_TEXT_FORMAT =
    DRAW_TEXT_FORMAT(DT_SINGLELINE.0 | DT_VCENTER.0 | DT_RIGHT.0 | DT_NOPREFIX.0);
const CENTRE: DRAW_TEXT_FORMAT =
    DRAW_TEXT_FORMAT(DT_SINGLELINE.0 | DT_VCENTER.0 | DT_CENTER.0 | DT_NOPREFIX.0);
const WRAP: DRAW_TEXT_FORMAT = DRAW_TEXT_FORMAT(DT_LEFT.0 | DT_NOPREFIX.0 | DT_WORDBREAK.0);
const CENTRE_WRAP: DRAW_TEXT_FORMAT =
    DRAW_TEXT_FORMAT(DT_CENTER.0 | DT_NOPREFIX.0 | DT_WORDBREAK.0);

// ── The walk ────────────────────────────────────────────────────────────────

/// How tall a wrapped note needs to be.
///
/// Estimated from the character count rather than measured: layout has no
/// device context. Deliberately pessimistic about how much fits on a line, so
/// the error is a little wasted space rather than a sentence cut in half,
/// which is what a flat two-line reservation gave the longer lockout copy.
fn note_height(text: &str, width: i32, m: &Metrics) -> i32 {
    let per_line = m.s(14);
    let columns = (width / m.s(6)).max(16) as usize;
    let lines = text.chars().count().div_ceil(columns).clamp(1, 8);
    per_line * lines as i32 + m.s(6)
}

/// Lay a screen out inside `area`, offset upward by `scroll`.
///
/// `hot` is the action currently under the pointer, so the row it belongs to
/// can be drawn highlighted without the caller having to find it again.
pub fn layout(
    items: &[Item],
    area: RECT,
    m: &Metrics,
    scroll: i32,
    hot: Option<&Action>,
) -> Frame {
    let mut f = Frame::default();
    let left = area.left;
    let right = area.right;
    let mut y = area.top - scroll;
    let start = y;

    for item in items {
        match item {
            Item::Gap(size) => y += m.s(*size),

            Item::Caption { text, trailing } => {
                let h = m.s(theme::CAPTION_H);
                f.text(
                    rect(left + m.s(3), y, right, y + h),
                    &text.to_uppercase(),
                    Face::Caption,
                    theme::TEXT_DIMMED,
                    LEFT,
                );
                if let Some(value) = trailing {
                    f.text(
                        rect(left, y, right - m.s(3), y + h),
                        value,
                        // Not the caption face, which is tracked out: GDI adds
                        // that extra advance after the final glyph too, and
                        // DT_RIGHT then pushed it past the edge and clipped
                        // the last character off the version.
                        Face::Sub,
                        theme::TEXT_DIMMED,
                        RIGHT,
                    );
                }
                y += h;
            }

            Item::Note(text) => {
                let h = note_height(text, right - left - m.s(6), m);
                f.text(
                    rect(left + m.s(3), y, right - m.s(3), y + h),
                    text,
                    Face::Sub,
                    theme::TEXT_DIMMED,
                    WRAP,
                );
                y += h;
            }

            Item::Input {
                id,
                placeholder,
                value,
                caret,
                selection,
                masked,
                focused,
            } => {
                let h = m.s(34);
                let box_rect = rect(left, y, right, y + h);
                f.round(
                    box_rect,
                    m.s(theme::RADIUS_BTN),
                    Some(theme::BG),
                    Some(if *focused {
                        theme::BORDER_FOCUS
                    } else {
                        theme::BORDER_STRONG
                    }),
                );

                let pad_x = m.s(10);
                let shown = if *masked {
                    BULLET.repeat(value.chars().count())
                } else {
                    value.clone()
                };
                if shown.is_empty() && !*focused {
                    f.text(
                        rect(box_rect.left + pad_x, box_rect.top, box_rect.right - pad_x, box_rect.bottom),
                        placeholder,
                        Face::Body,
                        theme::TEXT_DIMMED,
                        LEFT,
                    );
                } else {
                    // Handed to the paint stage rather than drawn here: placing
                    // a caret and a selection needs the real width of the text
                    // before them, and layout has no device context to measure
                    // with. It was estimating seven pixels a character, which
                    // drifted badly on anything proportional.
                    f.inputs.push(InputRun {
                        rect: rect(
                            box_rect.left + pad_x,
                            box_rect.top,
                            box_rect.right - pad_x,
                            box_rect.bottom,
                        ),
                        text: shown,
                        caret: *caret,
                        selection: *selection,
                        focused: *focused,
                    });
                }

                f.hot(box_rect, Action::Focus(*id));
                y += h + m.s(8);
            }

            Item::Divider(word) => {
                let h = m.s(18);
                let mid = y + h / 2;
                let cx = left + (right - left) / 2;
                let gap = m.s(18);
                f.round(rect(left, mid, cx - gap, mid + 1), 0, Some(theme::BORDER), None);
                f.round(rect(cx + gap, mid, right, mid + 1), 0, Some(theme::BORDER), None);
                f.text(
                    rect(cx - gap, y, cx + gap, y + h),
                    word,
                    Face::Caption,
                    theme::TEXT_DIMMED,
                    CENTRE,
                );
                y += h + m.s(4);
            }

            Item::Fine(text) => {
                let h = note_height(text, right - left - m.s(16), m);
                f.text(
                    rect(left + m.s(8), y, right - m.s(8), y + h),
                    text,
                    Face::Sub,
                    theme::TEXT_DIMMED,
                    CENTRE_WRAP,
                );
                y += h;
            }

            Item::Atmosphere => {
                // The full app's login screen is a masked two-pitch grid with a
                // glow behind the logo and a shadow along the floor. Lite had a
                // flat black rectangle, which is most of why the two screens did
                // not feel like the same product.
                let w = right - left;
                let h = area.bottom - area.top;
                if w <= 0 || h <= 0 {
                    continue;
                }
                let cx = left + w / 2;
                // The mask in the full app is centred at 45% down, not halfway.
                let focus_y = area.top + h * 45 / 100;
                let half_w = (w as f32) * 0.5;
                let half_h = (h as f32) * 0.5;

                // Drawn in segments rather than as whole lines so the fade is
                // radial, the way a mask-image is, instead of only horizontal.
                let mut grid = |pitch: i32, peak: f32| {
                    let step = m.s(pitch);
                    if step <= 0 {
                        return;
                    }
                    let seg = step;
                    let fade = |x: i32, y: i32| -> f32 {
                        let dx = (x - cx) as f32 / (half_w * 0.95);
                        let dy = (y - focus_y) as f32 / (half_h * 1.05);
                        let d = (dx * dx + dy * dy).sqrt();
                        // Solid to 40% out, gone by the edge, as the radial
                        // gradient in the web version does.
                        peak * (1.0 - ((d - 0.4) / 0.6).clamp(0.0, 1.0))
                    };

                    let mut x = left;
                    while x < right {
                        let mut y = area.top;
                        while y < area.bottom {
                            let a = fade(x, y + seg / 2);
                            if a > 0.004 {
                                f.round(
                                    rect(x, y, x + 1, (y + seg).min(area.bottom)),
                                    0,
                                    Some(Rgba::hexa(0xFFFFFF, a)),
                                    None,
                                );
                            }
                            y += seg;
                        }
                        x += step;
                    }

                    let mut y = area.top;
                    while y < area.bottom {
                        let mut x = left;
                        while x < right {
                            let a = fade(x + seg / 2, y);
                            if a > 0.004 {
                                f.round(
                                    rect(x, y, (x + seg).min(right), y + 1),
                                    0,
                                    Some(Rgba::hexa(0xFFFFFF, a)),
                                    None,
                                );
                            }
                            x += seg;
                        }
                        y += step;
                    }
                };
                grid(24, 0.055);
                grid(96, 0.05);

                // Glow behind the logo: concentric discs, each barely there, so
                // they stack into a soft falloff without a gradient primitive.
                let glow_y = area.top + h * 30 / 100;
                let rings = 16;
                for i in (1..=rings).rev() {
                    let r = half_w * 0.85 * (i as f32 / rings as f32);
                    f.shapes.push(Shape::Circle {
                        cx: cx as f32,
                        cy: glow_y as f32,
                        r,
                        fill: Rgba::hexa(0xFFFFFF, 0.007),
                    });
                }

                // And a shadow along the floor, so the block sits on something.
                let floor = h / 3;
                let bands = 18;
                for i in 0..bands {
                    let top = area.bottom - floor + floor * i / bands;
                    let bottom = area.bottom - floor + floor * (i + 1) / bands;
                    let a = 0.5 * (i as f32 / bands as f32).powi(2);
                    f.round(
                        rect(left, top, right, bottom),
                        0,
                        Some(Rgba::hexa(0x000000, a)),
                        None,
                    );
                }
            }

            Item::Brand => {
                let logo = m.s(96);
                let cx = left + (right - left) / 2;
                f.icons.push(rect(cx - logo / 2, y, cx + logo / 2, y + logo));
                y += logo + m.s(10);

                // A dot the colour of a live tunnel, then the tagline, on one
                // line. Measured so the pair sits centred as a unit.
                let tag = "GAMING · RELAY · 14 SERVERS";
                let tag_w = m.s(178);
                let dot_x = cx - tag_w / 2;
                f.shapes.push(Shape::Circle {
                    cx: dot_x as f32,
                    cy: (y + m.s(5)) as f32,
                    r: m.s(2) as f32,
                    fill: theme::CONNECTED,
                });
                f.text(
                    rect(dot_x + m.s(6), y, cx + tag_w / 2, y + m.s(12)),
                    tag,
                    Face::Caption,
                    theme::TEXT_MUTED,
                    LEFT,
                );
                y += m.s(14);

                f.text(
                    rect(left, y, right, y + m.s(24)),
                    "SwiftTunnel",
                    Face::Title,
                    theme::TEXT,
                    CENTRE,
                );
                y += m.s(24);
                f.text(
                    rect(left, y, right, y + m.s(16)),
                    "Sign in to deploy the tunnel",
                    Face::Sub,
                    theme::TEXT_MUTED,
                    CENTRE,
                );
                y += m.s(16);
            }

            Item::Back(label) => {
                let h = m.s(22);
                // Full row width, for the label and the target both. A fixed
                // 90 here left the label 77px to live in, which fitted
                // "Regions" and turned "Network adapter" into "Network ad...".
                // Nothing else sits on this line to collide with.
                let r = rect(left, y, right, y + h);
                // The chevron is drawn as text from the icon face so it sits on
                // the same baseline as the label without a second measurement.
                f.text(
                    rect(r.left, y, r.left + m.s(12), y + h),
                    "\u{2039}",
                    Face::Icon,
                    theme::TEXT_MUTED,
                    CENTRE,
                );
                f.text(
                    rect(r.left + m.s(13), y, r.right, y + h),
                    label,
                    Face::Tab,
                    theme::TEXT_MUTED,
                    LEFT,
                );
                f.hot(r, Action::Back);
                y += h + m.s(6);
            }

            Item::Status {
                headline,
                sub,
                dot,
                sub_ink,
                right: trailing,
            } => {
                let h = m.s(theme::STATUS_H);
                // Without a dot the text starts at the margin instead of
                // leaving a hole where the light would have been.
                let text_left = match dot {
                    Some(fill) => {
                        f.shapes.push(Shape::Circle {
                            cx: (left + m.s(4)) as f32,
                            cy: (y + m.s(9)) as f32,
                            r: m.s(4) as f32,
                            fill: *fill,
                        });
                        left + m.s(15)
                    }
                    None => left,
                };
                let text_right = if trailing.is_some() {
                    right - m.s(48)
                } else {
                    right
                };
                f.text(
                    rect(text_left, y, text_right, y + m.s(20)),
                    headline,
                    Face::Headline,
                    theme::TEXT,
                    LEFT,
                );
                f.text(
                    rect(text_left, y + m.s(20), text_right, y + h),
                    sub,
                    Face::Sub,
                    *sub_ink,
                    LEFT,
                );
                if let Some(value) = trailing {
                    f.text(
                        rect(text_right, y, right, y + m.s(20)),
                        value,
                        Face::Value,
                        theme::TEXT_DIMMED,
                        RIGHT,
                    );
                }
                y += h;
            }

            Item::Stats(cells) => {
                let h = m.s(theme::STATS_H);
                let box_rect = rect(left, y, right, y + h);
                f.round(box_rect, m.s(theme::RADIUS), Some(theme::CARD), Some(theme::BORDER));
                let width = (right - left) / 3;
                for (i, (label, value)) in cells.iter().enumerate() {
                    let x = left + width * i as i32;
                    if i > 0 {
                        f.round(
                            rect(x, y + m.s(6), x + 1, y + h - m.s(6)),
                            0,
                            Some(theme::BORDER),
                            None,
                        );
                    }
                    f.text(
                        rect(x + m.s(8), y + m.s(5), x + width, y + m.s(15)),
                        &label.to_uppercase(),
                        Face::Caption,
                        theme::TEXT_DIMMED,
                        LEFT,
                    );
                    f.text(
                        rect(x + m.s(8), y + m.s(17), x + width - m.s(4), y + h - m.s(4)),
                        value,
                        Face::Value,
                        theme::TEXT,
                        LEFT,
                    );
                }
                y += h;
            }

            Item::Button {
                label,
                action,
                variant,
                disabled,
            } => {
                let h = m.s(theme::BUTTON_H);
                let r = rect(left, y, right, y + h);
                let hovered = !*disabled && hot == Some(action);
                let (fill, stroke, ink) = button_paint(*variant, *disabled, hovered);
                f.round(r, m.s(theme::RADIUS_BTN), fill, stroke);
                f.text(r, label, Face::Button, ink, CENTRE);
                if !*disabled {
                    f.hot(r, action.clone());
                }
                y += h;
            }

            Item::Group(rows) => {
                let heights: Vec<i32> = rows
                    .iter()
                    .map(|row| {
                        m.s(if row.sub.is_some() {
                            theme::ROW_H_SUB
                        } else {
                            theme::ROW_H
                        })
                    })
                    .collect();
                let total: i32 = heights.iter().sum();
                let group = rect(left, y, right, y + total);
                f.round(
                    group,
                    m.s(theme::RADIUS),
                    Some(theme::CARD),
                    Some(theme::BORDER),
                );

                let mut ry = y;
                let last = rows.len().saturating_sub(1);
                for (i, (row, h)) in rows.iter().zip(&heights).enumerate() {
                    let r = rect(left, ry, right, ry + h);
                    let hovered = row.action.is_some()
                        && !row.disabled
                        && hot.is_some()
                        && hot == row.action.as_ref();
                    if hovered {
                        // The card is rounded, so a square hover fill on the
                        // first or last row paints over its corners and the
                        // whole card reads as clipped while the pointer is on
                        // it. Round the corners that sit on the card edge and
                        // square off the inner side, which is safe to overdraw
                        // because HOVER is opaque.
                        let radius = m.s(theme::RADIUS);
                        let first = i == 0;
                        let bottom = i == last;
                        if first || bottom {
                            f.round(r, radius, Some(theme::HOVER), None);
                            if !first {
                                let cap = rect(left, r.top, right, r.top + radius);
                                f.round(cap, 0, Some(theme::HOVER), None);
                            }
                            if !bottom {
                                let cap = rect(left, r.bottom - radius, right, r.bottom);
                                f.round(cap, 0, Some(theme::HOVER), None);
                            }
                        } else {
                            f.round(r, 0, Some(theme::HOVER), None);
                        }
                    }
                    if ry > y {
                        f.round(
                            rect(left, ry, right, ry + 1),
                            0,
                            Some(theme::BORDER),
                            None,
                        );
                    }
                    layout_row(&mut f, row, r, m);
                    if let Some(action) = &row.action
                        && !row.disabled
                    {
                        f.hot(r, action.clone());
                    }
                    ry += h;
                }
                y += total;
            }
        }
    }

    f.content_height = y - start;
    f
}

/// Ink and fill for a button in each of its states.
fn button_paint(
    variant: Variant,
    disabled: bool,
    hovered: bool,
) -> (Option<Rgba>, Option<Rgba>, COLORREF) {
    match variant {
        Variant::Solid => {
            let mut fill = theme::ACCENT;
            if disabled {
                fill.a = 0.35;
            } else if hovered {
                // Lifting the fill is wrong on a near-white button, so the hover
                // is a slight dimming instead.
                fill.a = 0.88;
            }
            (Some(fill), None, theme::ON_ACCENT)
        }
        Variant::Outline => {
            let stroke = if hovered {
                theme::BORDER_STRONG
            } else {
                theme::BORDER
            };
            let ink = if disabled {
                theme::TEXT_DIMMED
            } else {
                theme::TEXT
            };
            let fill = hovered.then_some(theme::HOVER);
            (fill, Some(stroke), ink)
        }
    }
}

/// Place one row's label, sub-label and right-hand control.
fn layout_row(f: &mut Frame, row: &Row, r: RECT, m: &Metrics) {
    let pad = m.s(9);
    let label_ink = match (row.disabled, row.tone) {
        (true, _) => theme::TEXT_DIMMED,
        (false, Tone::Danger) => theme::ERROR_TEXT,
        (false, Tone::Normal) => theme::TEXT,
    };

    // Where the label has to stop.
    //
    // Text values are not measured, they are right-aligned inside a generous
    // rect: layout runs with no device context (the preview harness lays out
    // and paints in one pass), so any width computed here would be a guess,
    // and a guess that comes out short clips the value. Splitting the row and
    // letting DT_RIGHT place the text cannot clip anything that fits at all.
    let width = r.right - r.left;
    let reserved = match &row.right {
        Right::None => 0,
        Right::Switch(_) => m.s(theme::SWITCH_W + 6),
        Right::Tick(_) | Right::Chevron => m.s(18),
        Right::Field { .. } => m.s(64),
        Right::Choice(chips) => chip_strip_width(chips, m),
        Right::Latency(_) => m.s(46),
        // Three fifths of the row, which at 340 wide is enough for any value
        // these rows carry and still leaves the label more room than it needs.
        Right::Text(_) | Right::TextChevron(_) => width * 3 / 5,
    };
    let text_right = (r.right - pad - reserved).max(r.left + pad + m.s(40));

    match &row.sub {
        None => f.text(
            rect(r.left + pad, r.top, text_right, r.bottom),
            &row.label,
            Face::Body,
            label_ink,
            LEFT,
        ),
        Some(sub) => {
            let mid = r.top + (r.bottom - r.top) / 2;
            f.text(
                rect(r.left + pad, r.top + m.s(5), text_right, mid + m.s(1)),
                &row.label,
                Face::Body,
                label_ink,
                LEFT,
            );
            // The sub-label gets more room than the label does. A text value
            // is vertically centred, so it sits across both lines, but it is
            // one short run at the far right and holding the second line to
            // the same stop truncated copy that had room to spare.
            let sub_right = match &row.right {
                Right::Text(_) | Right::TextChevron(_) => {
                    text_right.max(r.right - pad - m.s(58))
                }
                _ => text_right,
            };
            f.text(
                rect(r.left + pad, mid, sub_right, r.bottom - m.s(5)),
                sub,
                Face::Sub,
                theme::TEXT_DIMMED,
                LEFT,
            );
        }
    }

    let cy = r.top + (r.bottom - r.top) / 2;
    let edge = r.right - pad;

    match &row.right {
        Right::None => {}

        Right::Text(value) => f.text(
            rect(text_right + m.s(6), r.top, edge, r.bottom),
            value,
            Face::ValueText,
            theme::TEXT_SECONDARY,
            RIGHT,
        ),

        Right::Latency(ms) => {
            let label = match ms {
                Some(v) => format!("{v} ms"),
                None => "--".to_string(),
            };
            f.text(
                rect(edge - m.s(44), r.top, edge, r.bottom),
                &label,
                Face::Value,
                theme::latency_ink(*ms),
                RIGHT,
            );
        }

        Right::TextChevron(value) => {
            let chevron = edge - m.s(10);
            f.text(
                rect(text_right + m.s(6), r.top, chevron - m.s(4), r.bottom),
                value,
                Face::ValueText,
                theme::TEXT_SECONDARY,
                RIGHT,
            );
            f.text(
                rect(chevron, r.top, edge, r.bottom),
                "\u{203A}",
                Face::Icon,
                theme::TEXT_DIMMED,
                CENTRE,
            );
        }


        Right::Field {
            text,
            focused,
            id,
            valid,
        } => {
            let w = m.s(56);
            let h = m.s(22);
            let box_rect = rect(edge - w, cy - h / 2, edge, cy + h / 2);
            let border = if *focused {
                theme::BORDER_FOCUS
            } else if *valid {
                theme::BORDER_STRONG
            } else {
                theme::ERROR
            };
            f.round(
                box_rect,
                m.s(theme::RADIUS_CHIP),
                Some(theme::BG),
                Some(border),
            );

            // The caret is a rule after the text rather than a real one: the
            // field takes digits appended and removed, never a cursor moved
            // into the middle, so there is nowhere else for it to be.
            let pad_x = m.s(7);
            let caret = if *focused { m.s(5) } else { 0 };
            f.text(
                rect(box_rect.left + pad_x, box_rect.top, box_rect.right - pad_x - caret, box_rect.bottom),
                text,
                Face::Value,
                if *valid { theme::TEXT } else { theme::ERROR_TEXT },
                RIGHT,
            );
            if *focused {
                f.round(
                    rect(
                        box_rect.right - pad_x - m.s(3),
                        box_rect.top + m.s(5),
                        box_rect.right - pad_x - m.s(2),
                        box_rect.bottom - m.s(5),
                    ),
                    0,
                    Some(theme::ACCENT),
                    None,
                );
            }
            if !row.disabled {
                f.hot(box_rect, Action::Focus(*id));
            }
        }

        Right::Chevron => f.text(
            rect(edge - m.s(10), r.top, edge, r.bottom),
            "\u{203A}",
            Face::Icon,
            theme::TEXT_DIMMED,
            CENTRE,
        ),

        Right::Tick(on) => {
            if *on {
                f.text(
                    rect(edge - m.s(14), r.top, edge, r.bottom),
                    "\u{2713}",
                    Face::Icon,
                    theme::CONNECTED_TEXT,
                    CENTRE,
                );
            }
        }

        Right::Switch(on) => {
            let w = m.s(theme::SWITCH_W);
            let h = m.s(theme::SWITCH_H);
            let track = rect(edge - w, cy - h / 2, edge, cy + h / 2);
            let fill = if row.disabled {
                Rgba {
                    a: 0.4,
                    ..if *on { theme::CONNECTED } else { theme::ACTIVE }
                }
            } else if *on {
                theme::CONNECTED
            } else {
                theme::ACTIVE
            };
            f.round(track, h / 2, Some(fill), None);

            let knob_r = (h as f32 - m.s(4) as f32) / 2.0;
            let inset = m.s(2) as f32 + knob_r;
            let cx = if *on {
                track.right as f32 - inset
            } else {
                track.left as f32 + inset
            };
            let knob = if *on {
                Rgba::hex(0x0A0A0A)
            } else {
                Rgba::hex(0xC4C4C4)
            };
            f.shapes.push(Shape::Circle {
                cx,
                cy: cy as f32,
                r: knob_r,
                fill: knob,
            });
        }

        Right::Choice(chips) => {
            let width = chip_strip_width(chips, m);
            let strip = rect(edge - width, cy - m.s(11), edge, cy + m.s(11));
            f.round(strip, m.s(theme::RADIUS_CHIP + 1), Some(theme::BG), None);

            let mut x = strip.left + m.s(1);
            for chip in chips {
                let w = chip_width(&chip.label, m);
                let r = rect(x, strip.top + m.s(1), x + w, strip.bottom - m.s(1));
                if chip.selected {
                    f.round(r, m.s(theme::RADIUS_CHIP), Some(theme::HOVER), None);
                }
                let ink = if row.disabled {
                    theme::TEXT_DIMMED
                } else if chip.selected {
                    theme::TEXT
                } else {
                    theme::TEXT_MUTED
                };
                f.text(r, &chip.label, Face::Chip, ink, CENTRE);
                if !row.disabled {
                    f.hot(r, chip.action.clone());
                }
                x += w;
            }
        }
    }
}

/// Rough advance width, used only to size the choice chips.
///
/// Their labels are two to four characters and every chip in a strip gets the
/// same treatment, so being a pixel out is invisible. Nothing that could clip
/// is positioned by measurement: values are right-aligned against a known edge
/// instead.
fn estimate_width(text: &str, m: &Metrics, per_char: f32) -> i32 {
    ((text.chars().count() as f32) * per_char * m.scale).round() as i32
}

fn chip_width(label: &str, m: &Metrics) -> i32 {
    // Chips carry short labels ("60", "Auto"), so a floor plus per-character
    // padding is enough and keeps every chip in a strip the same shape.
    m.s(10) + estimate_width(label, m, 6.0).max(m.s(8))
}

fn chip_strip_width(chips: &[Chip], m: &Metrics) -> i32 {
    chips.iter().map(|c| chip_width(&c.label, m)).sum::<i32>() + m.s(2)
}

// ── Painting ────────────────────────────────────────────────────────────────

pub fn paint_shapes(canvas: &mut Canvas, frame: &Frame) {
    for shape in &frame.shapes {
        match *shape {
            Shape::Round {
                rect: r,
                radius,
                fill,
                stroke,
            } => {
                let w = r.right - r.left;
                let h = r.bottom - r.top;
                if w <= 0 || h <= 0 {
                    continue;
                }
                let shape = RoundRect::new(r.left, r.top, w, h, radius);
                if let Some(colour) = fill {
                    canvas.fill_round_rect(shape, colour);
                }
                if let Some(colour) = stroke {
                    // Inset by half a pixel so the hairline lands inside the
                    // fill rather than straddling its edge, which at one pixel
                    // wide is the difference between crisp and grey.
                    canvas.stroke_round_rect(shape.inset(0.5), colour, 1.0);
                }
            }
            Shape::Circle { cx, cy, r, fill } => canvas.fill_circle(cx, cy, r, fill),
        }
    }
}

/// The GDI fonts one screen needs, built once per DPI.
pub struct Fonts {
    pub title: Font,
    pub headline: Font,
    pub body: Font,
    pub sub: Font,
    pub caption: Font,
    pub value: Font,
    pub value_text: Font,
    pub button: Font,
    pub tab: Font,
    pub chip: Font,
    pub icon: Font,
}

impl Fonts {
    pub fn new(m: &Metrics) -> Self {
        let ui = |px: i32, weight: i32| {
            let (family, gdi_weight) = theme::ui_face(weight);
            gdi::font(family, theme::FACE_UI_FALLBACK, m.s(px), gdi_weight, 0)
        };
        let mono = |px: i32, weight: i32| {
            let (family, gdi_weight) = theme::mono_face(weight);
            gdi::font(family, theme::FACE_MONO_FALLBACK, m.s(px), gdi_weight, 0)
        };
        Self {
            title: ui(12, 600),
            headline: ui(15, 600),
            body: ui(12, 500),
            sub: ui(10, 400),
            caption: ui(9, 600),
            // Numbers in the mono face, so a changing readout does not shuffle
            // the digits beside it.
            value: mono(11, 500),
            value_text: ui(12, 400),
            button: ui(13, 600),
            tab: ui(12, 500),
            chip: ui(11, 500),
            // The chevrons and the tick. Segoe UI Symbol carries them at every
            // size; Geist does not.
            icon: gdi::font("Segoe UI Symbol", "Segoe UI", m.s(13), 400, 0),
        }
    }

    fn pick(&self, face: Face) -> (&Font, i32) {
        match face {
            Face::Title => (&self.title, 0),
            Face::Headline => (&self.headline, 0),
            Face::Body => (&self.body, 0),
            Face::Sub => (&self.sub, 0),
            // The captions are structure, and tracking them out is what makes
            // them read as a label rather than as small text.
            Face::Caption => (&self.caption, 1),
            Face::Value => (&self.value, 0),
            Face::ValueText => (&self.value_text, 0),
            Face::Button => (&self.button, 0),
            Face::Tab => (&self.tab, 0),
            Face::Chip => (&self.chip, 0),
            Face::Icon => (&self.icon, 0),
        }
    }
}

/// Draw the runs, optionally only those touching `damage`.
///
/// GDI would clip them anyway, but every call still selects a font and lays
/// the string out first. Skipping the ones that cannot show saves that work,
/// which is most of it when a hover has damaged two rows out of fifteen.
/// Draw the editable fields: selection, text, caret.
///
/// Done here rather than in layout because every part of it needs the real
/// width of a substring, which needs the font and a device context.
pub fn paint_inputs(dc: HDC, fonts: &Fonts, frame: &Frame, damage: Option<RECT>) {
    for run in &frame.inputs {
        if let Some(d) = damage
            && (run.rect.bottom <= d.top || run.rect.top >= d.bottom)
        {
            continue;
        }
        let (font, tracking) = fonts.pick(Face::Body);
        let upto = |n: usize| {
            let prefix: String = run.text.chars().take(n).collect();
            gdi::text_width(dc, &prefix, font, tracking)
        };

        let width = run.rect.right - run.rect.left;
        let caret_x = upto(run.caret);
        let full = upto(run.text.chars().count());

        // Scroll so the caret stays inside the box. Without this, typing past
        // the right edge carried on invisibly.
        let mut offset = 0;
        if full > width {
            if caret_x > width {
                offset = caret_x - width + 2;
            }
            offset = offset.min(full - width + 2);
        }

        // SAFETY: drawing into a device context the caller owns, with every
        // object restored before returning.
        unsafe {
            let saved = SaveDC(dc);
            let _ = IntersectClipRect(
                dc,
                run.rect.left,
                run.rect.top,
                run.rect.right,
                run.rect.bottom,
            );

            let (sel_start, sel_end) = run.selection;
            if run.focused && sel_start != sel_end {
                let a = run.rect.left + upto(sel_start) - offset;
                let b = run.rect.left + upto(sel_end) - offset;
                let brush = CreateSolidBrush(theme::SELECTION);
                let band = RECT {
                    left: a,
                    top: run.rect.top + 6,
                    right: b,
                    bottom: run.rect.bottom - 6,
                };
                let _ = FillRect(dc, &band, brush);
                let _ = DeleteObject(brush.into());
            }

            gdi::text(
                dc,
                &run.text,
                RECT {
                    left: run.rect.left - offset,
                    ..run.rect
                },
                font,
                theme::TEXT,
                LEFT,
                tracking,
            );

            if run.focused && sel_start == sel_end {
                let x = run.rect.left + caret_x - offset;
                let brush = CreateSolidBrush(theme::TEXT);
                let bar = RECT {
                    left: x,
                    top: run.rect.top + 7,
                    right: x + 1,
                    bottom: run.rect.bottom - 7,
                };
                let _ = FillRect(dc, &bar, brush);
                let _ = DeleteObject(brush.into());
            }

            let _ = RestoreDC(dc, saved);
        }
    }
}

/// Draw the app icon into any slots this frame asked for.
pub fn paint_icons(dc: HDC, frame: &Frame, damage: Option<RECT>) {
    for r in &frame.icons {
        if let Some(d) = damage
            && (r.bottom <= d.top || r.top >= d.bottom)
        {
            continue;
        }
        let size = r.right - r.left;
        let mut icon = crate::tray::app_icon(size, size);
        if icon.is_invalid() {
            icon = crate::tray::app_icon(0, 0);
        }
        if icon.is_invalid() {
            log::warn!("no app icon available to draw on the sign-in screen");
            continue;
        }
        // SAFETY: the icon was just created and is destroyed straight after.
        unsafe {
            let _ = windows::Win32::UI::WindowsAndMessaging::DrawIconEx(
                dc,
                r.left,
                r.top,
                icon,
                size,
                size,
                0,
                None,
                windows::Win32::UI::WindowsAndMessaging::DI_NORMAL,
            );
            let _ = windows::Win32::UI::WindowsAndMessaging::DestroyIcon(icon);
        }
    }
}

pub fn paint_text_in(dc: HDC, fonts: &Fonts, frame: &Frame, damage: Option<RECT>) {
    for run in &frame.texts {
        if let Some(d) = damage
            && (run.rect.bottom <= d.top || run.rect.top >= d.bottom)
        {
            continue;
        }
        let (font, tracking) = fonts.pick(run.face);
        gdi::text(dc, &run.text, run.rect, font, run.ink, run.format, tracking);
    }
}

/// The action under the pointer, if any.
///
/// Walked back to front so a chip inside a row wins over the row itself, which
/// is the order they were emitted in.
pub fn hit(frame: &Frame, x: i32, y: i32) -> Option<Action> {
    frame
        .hots
        .iter()
        .rev()
        .find(|(r, _)| contains(*r, x, y))
        .map(|(_, a)| a.clone())
}
