#[path = "artwork.rs"]
mod artwork;
#[path = "drawing.rs"]
mod drawing;
#[path = "fonts.rs"]
mod fonts;

use crate::backend::Event;
use crate::model::{
    action_allowed, result_message, Action, Command, Installed, Package, LITE_FAMILY,
};
use std::cell::RefCell;
use std::sync::mpsc::{Receiver, Sender};
use std::time::{Duration, Instant};
use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::*;
use windows::Win32::Graphics::Dwm::{
    DwmSetWindowAttribute, DWMWA_USE_IMMERSIVE_DARK_MODE, DWMWA_WINDOW_CORNER_PREFERENCE,
    DWMWCP_ROUND,
};
use windows::Win32::Graphics::Gdi::*;
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Controls::{DRAWITEMSTRUCT, ODS_DISABLED, ODS_FOCUS, ODS_SELECTED};
use windows::Win32::UI::HiDpi::{
    GetDpiForWindow, SetProcessDpiAwarenessContext, DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2,
};
use windows::Win32::UI::Input::KeyboardAndMouse::EnableWindow;
use windows::Win32::UI::WindowsAndMessaging::*;

const ACTIONS: [Action; 4] = [
    Action::Install,
    Action::Repair,
    Action::Reinstall,
    Action::Uninstall,
];
const LABELS: [&str; 4] = ["Install", "Repair", "Reinstall", "Uninstall"];
// The website's petals at night: the artwork deep and out of focus, white
// copy on it, controls in glass and the main action solid white. COLORREF is
// BGR; the u32 values are GDI+ ARGB.
/// Behind the artwork, and all there is if it cannot be decoded.
const BG: COLORREF = COLORREF(0x2e0b07);
/// Text on a white control.
const INK: COLORREF = COLORREF(0x140b0a);
const WHITE: COLORREF = COLORREF(0xffffff);
/// Secondary copy: white with the night showing through.
const WHITE_SOFT: COLORREF = COLORREF(0xf7d6cd);
/// The headline's last line, the petal's own light.
const GLOW: COLORREF = COLORREF(0xffc0ab);
/// Rules and outlines, and the glass they sit on.
const HAIRLINE: u32 = 0x2effffff;
const GLASS: u32 = 0x1cffffff;
const WIDTH: i32 = 720;
const HEIGHT: i32 = 432;
/// The window's corner radius, the one Windows 11 gives its own windows.
const CORNER: i32 = 8;
/// Height over width: the artwork is cropped to this.
pub(crate) const ASPECT: f32 = HEIGHT as f32 / WIDTH as f32;
const BUTTON_TOP: i32 = 366;
const BUTTON_HEIGHT: i32 = 40;
const BUTTON_WIDTH: i32 = 100;
const MINIMIZE_ID: usize = 200;
const CLOSE_ID: usize = 201;
const DETAILS_ID: usize = 202;
/// The app chooser's two halves: the full app, bundled, and Lite, downloaded.
const PRODUCT_ID: usize = 203;
const LITE_ID: usize = 204;
/// The worker's events are read on this timer; the chooser animates on the other.
const EVENT_TIMER: usize = 1;
const SLIDE_TIMER: usize = 2;
/// How long the chooser's pill takes to slide to the other half.
const SLIDE: Duration = Duration::from_millis(220);
// The window never paints over its controls, so each control can repaint alone.
const WINDOW_STYLE_SETUP: WINDOW_STYLE =
    WINDOW_STYLE(WS_POPUP.0 | WS_SYSMENU.0 | WS_MINIMIZEBOX.0 | WS_CLIPCHILDREN.0);

pub struct State {
    package: Option<Package>,
    installed: Vec<Installed>,
    heading: String,
    detail: String,
    busy: bool,
    installing: bool,
    reboot_required: bool,
    exit_code: i32,
    buttons: Vec<HWND>,
    window_buttons: Vec<HWND>,
    details_button: Option<HWND>,
    /// The chooser's halves, the full app then Lite. Empty in Lite's own Setup.
    product_buttons: Vec<HWND>,
    /// The half just picked (true for Lite) while that switch is running.
    switching_to_lite: Option<bool>,
    /// Where the chooser's pill last started sliding from, and when.
    slide: Option<(f32, Instant)>,
    /// The animation clock. Both halves of the chooser paint as of this
    /// moment, so the pill they share always lines up.
    frame: Instant,
    worker_closed: bool,
    commands: Sender<Command>,
    events: Receiver<Event>,
}

impl State {
    pub fn new(commands: Sender<Command>, events: Receiver<Event>) -> Self {
        Self {
            package: None,
            installed: vec![],
            heading: "Preparing your installer".into(),
            detail: "Verifying the bundled app and checking your installation.".into(),
            busy: true,
            installing: false,
            reboot_required: false,
            exit_code: 0,
            buttons: vec![],
            window_buttons: vec![],
            details_button: None,
            product_buttons: vec![],
            switching_to_lite: None,
            slide: None,
            frame: Instant::now(),
            worker_closed: false,
            commands,
            events,
        }
    }

    fn ready(&mut self, package: Package, installed: Vec<Installed>) {
        self.exit_code = 0;
        self.heading = match installed.as_slice() {
            [] => format!("{} is ready to install", package.name),
            [_] => format!("{} is installed", package.name),
            _ => "Multiple installations found".into(),
        };
        self.detail = match installed.as_slice() {
            [] => "Install SwiftTunnel on this PC. Close SwiftTunnel before continuing.".into(),
            [current] if current.product_code.eq_ignore_ascii_case(&package.product_code) =>
                format!("Version {}. Repair fixes missing files. Reinstall replaces app files and keeps your preferences.", current.version),
            [current] if current.version == package.version && action_allowed(&package, &installed, Action::Install) =>
                format!("Version {} is installed from another package. Replace it with this build using Update. Your preferences are kept.", current.version),
            [current] if action_allowed(&package, &installed, Action::Install) =>
                format!("Version {} is installed. Update to {} with this package.", current.version, package.version),
            [_] => "This Setup is for a different version. To repair, download Setup for the installed version or a newer release.".into(),
            _ => "Open Windows Settings > Apps to choose a copy. Setup will not guess which one to change.".into(),
        };
        self.package = Some(package);
        self.installed = installed;
        self.busy = false;
        self.installing = false;
        self.switching_to_lite = None;
    }

    fn lite_selected(&self) -> bool {
        self.package
            .as_ref()
            .is_some_and(|p| p.upgrade_code.eq_ignore_ascii_case(LITE_FAMILY))
    }

    /// The app the window shows: the one just picked while the switch runs.
    fn shows_lite(&self) -> bool {
        self.switching_to_lite
            .unwrap_or_else(|| self.lite_selected())
    }

    /// The chooser's pill as of the current frame: 0 under the full app, 1
    /// under Lite, between the two while it slides, easing out as it arrives.
    fn pill_position(&self) -> f32 {
        let target = if self.shows_lite() { 1.0 } else { 0.0 };
        match self.slide {
            Some((from, start)) => {
                let elapsed = self.frame.saturating_duration_since(start);
                let t = (elapsed.as_secs_f32() / SLIDE.as_secs_f32()).min(1.0);
                from + (target - from) * (1.0 - (1.0 - t).powi(3))
            }
            None => target,
        }
    }

    /// Whether the pill has further to go as of the current frame.
    fn sliding(&self) -> bool {
        self.slide
            .is_some_and(|(_, start)| self.frame.saturating_duration_since(start) < SLIDE)
    }

    /// Applies a change, sliding the pill from where it is now if the change
    /// moves it to the other half.
    fn shift(&mut self, change: impl FnOnce(&mut Self)) {
        let (position, shown) = (self.pill_position(), self.shows_lite());
        change(self);
        if self.shows_lite() != shown {
            self.slide = Some((position, Instant::now()));
        }
    }

    /// The chooser can switch only between transactions and downloads.
    fn can_choose(&self) -> bool {
        !self.busy && !self.reboot_required && !self.worker_closed
    }

    fn worker_stopped(&mut self) -> bool {
        if self.worker_closed {
            return false;
        }
        self.worker_closed = true;
        self.package = None;
        self.switching_to_lite = None;
        if self.busy {
            self.busy = false;
            self.installing = false;
            self.exit_code = 1;
            self.heading = "Setup lost contact with its worker".into();
            self.detail = "Windows Installer may still be running. Wait for it to finish, then reopen Setup to check the installation. No success was confirmed.".into();
        }
        true
    }
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(Some(0)).collect()
}
fn scaled(value: i32, dpi: u32) -> i32 {
    (value * dpi as i32 + 48) / 96
}

unsafe fn text(
    dc: HDC,
    value: &str,
    rect: RECT,
    size: i32,
    weight: i32,
    color: COLORREF,
    flags: DRAW_TEXT_FORMAT,
) {
    let face = if weight >= 800 {
        w!("Figtree ExtraBold")
    } else if weight >= 600 {
        w!("Figtree SemiBold")
    } else {
        w!("Figtree")
    };
    text_face(dc, value, rect, size, color, flags, face, 0, false);
}

unsafe fn text_face(
    dc: HDC,
    value: &str,
    rect: RECT,
    size: i32,
    color: COLORREF,
    flags: DRAW_TEXT_FORMAT,
    face: PCWSTR,
    tracking: i32,
    outline: bool,
) {
    let font = CreateFontW(
        -size,
        0,
        0,
        0,
        400,
        0,
        0,
        0,
        DEFAULT_CHARSET,
        OUT_DEFAULT_PRECIS,
        CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY,
        DEFAULT_PITCH.0 as u32,
        face,
    );
    let old = SelectObject(dc, font.into());
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, color);
    let mut bounds = rect;
    let mut value: Vec<u16> = value.encode_utf16().collect();
    let previous_spacing = SetTextCharacterExtra(dc, tracking);
    if outline {
        let _ = BeginPath(dc);
    }
    DrawTextW(dc, &mut value, &mut bounds, flags | DT_NOPREFIX);
    if outline {
        let _ = EndPath(dc);
        let pen = CreatePen(PS_SOLID, (size / 40).max(1), color);
        let previous_pen = SelectObject(dc, pen.into());
        let _ = StrokePath(dc);
        SelectObject(dc, previous_pen);
        let _ = DeleteObject(pen.into());
    }
    SetTextCharacterExtra(dc, previous_spacing);
    SelectObject(dc, old);
    let _ = DeleteObject(font.into());
}

/// The website's mono labels: Azeret Mono capitals.
unsafe fn mono(
    dc: HDC,
    value: &str,
    rect: RECT,
    size: i32,
    color: COLORREF,
    flags: DRAW_TEXT_FORMAT,
) {
    text_face(
        dc,
        value,
        rect,
        size,
        color,
        flags,
        w!("Azeret Mono"),
        0,
        false,
    );
}

/// Width of a single line of text in the given face.
unsafe fn measure(dc: HDC, value: &str, size: i32, face: PCWSTR) -> i32 {
    let font = CreateFontW(
        -size,
        0,
        0,
        0,
        400,
        0,
        0,
        0,
        DEFAULT_CHARSET,
        OUT_DEFAULT_PRECIS,
        CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY,
        DEFAULT_PITCH.0 as u32,
        face,
    );
    let old = SelectObject(dc, font.into());
    let mut bounds = RECT::default();
    let mut value: Vec<u16> = value.encode_utf16().collect();
    DrawTextW(
        dc,
        &mut value,
        &mut bounds,
        DT_CALCRECT | DT_SINGLELINE | DT_NOPREFIX,
    );
    SelectObject(dc, old);
    let _ = DeleteObject(font.into());
    bounds.right - bounds.left
}

unsafe fn fill(dc: HDC, rect: &RECT, color: COLORREF) {
    let brush = CreateSolidBrush(color);
    FillRect(dc, rect, brush);
    let _ = DeleteObject(brush.into());
}

/// The product the window is about: the bundled full app or downloaded Lite.
fn product_name(state: &State) -> &'static str {
    if state.shows_lite() {
        "SwiftTunnel Lite"
    } else {
        "SwiftTunnel"
    }
}

unsafe fn paint(dc: HDC, bounds: RECT, dpi: u32, state: &State) {
    let s = |value: i32| scaled(value, dpi);
    fonts::install();
    fill(dc, &bounds, BG);
    artwork::paint(dc, bounds);

    // Top bar, the website's navbar: mark, wordmark, a rule and the page name.
    drawing::logo(
        dc,
        RECT {
            left: s(28),
            top: s(18),
            right: s(54),
            bottom: s(44),
        },
    );
    text(
        dc,
        "SwiftTunnel",
        RECT {
            left: s(64),
            top: s(18),
            right: s(260),
            bottom: s(44),
        },
        s(17),
        800,
        WHITE,
        DT_LEFT | DT_SINGLELINE | DT_VCENTER,
    );
    let rule = s(64) + measure(dc, "SwiftTunnel", s(17), w!("Figtree ExtraBold")) + s(14);
    drawing::line(dc, rule, s(24), rule, s(38), HAIRLINE, s(1) as f32);
    mono(
        dc,
        "SETUP",
        RECT {
            left: rule + s(14),
            top: s(18),
            right: s(400),
            bottom: s(44),
        },
        s(10),
        WHITE_SOFT,
        DT_LEFT | DT_SINGLELINE | DT_VCENTER,
    );

    // The homepage's index row: a hairline, the product, the version.
    drawing::line(
        dc,
        s(28),
        s(60),
        s(WIDTH - 28),
        s(60),
        HAIRLINE,
        s(1) as f32,
    );
    mono(
        dc,
        if state.shows_lite() {
            "00 · SWIFTTUNNEL LITE FOR WINDOWS"
        } else {
            "00 · SWIFTTUNNEL FOR WINDOWS"
        },
        RECT {
            left: s(28),
            top: s(66),
            right: s(470),
            bottom: s(82),
        },
        s(10),
        WHITE_SOFT,
        DT_LEFT | DT_SINGLELINE | DT_VCENTER,
    );
    // While a switch runs, the package on hand is not the one shown.
    let verified = state
        .package
        .as_ref()
        .filter(|_| state.switching_to_lite.is_none());
    let version = match verified {
        Some(package) => format!("V{}", package.version),
        None => "CHECKING".into(),
    };
    mono(
        dc,
        &version,
        RECT {
            left: s(470),
            top: s(66),
            right: s(WIDTH - 42),
            bottom: s(82),
        },
        s(10),
        WHITE,
        DT_RIGHT | DT_SINGLELINE | DT_VCENTER,
    );
    drawing::rounded(
        dc,
        RECT {
            left: s(WIDTH - 36),
            top: s(71),
            right: s(WIDTH - 29),
            bottom: s(78),
        },
        s(4) as f32,
        if verified.is_some() {
            0xff22c55e
        } else {
            0xff9aa3c7
        },
    );

    // The headline, white with the last line in the petal's light.
    for (index, (line, color)) in [
        ("One tap away", WHITE),
        ("from dominating", WHITE),
        ("every match.", GLOW),
    ]
    .into_iter()
    .enumerate()
    {
        let top = 84 + index as i32 * 44;
        text(
            dc,
            line,
            RECT {
                left: s(26),
                top: s(top),
                right: s(470),
                bottom: s(top + 52),
            },
            s(40),
            800,
            color,
            DT_LEFT | DT_SINGLELINE,
        );
    }

    // What the chooser is for, and what the chosen app includes. The chooser
    // itself is its two halves' buttons.
    if crate::MSI_NAME == "SwiftTunnel-Installer.msi" {
        mono(
            dc,
            "CHOOSE YOUR APP",
            RECT {
                left: s(28),
                top: s(234),
                right: s(330),
                bottom: s(248),
            },
            s(10),
            WHITE_SOFT,
            DT_LEFT | DT_SINGLELINE | DT_VCENTER,
        );
        text(
            dc,
            if state.shows_lite() {
                "Just the tunnel, the FPS unlock and an FPS counter. Light on your PC."
            } else {
                "Everything: routing, PC boosts and the in-game overlay."
            },
            RECT {
                left: s(28),
                top: s(300),
                right: s(460),
                bottom: s(318),
            },
            s(12),
            400,
            WHITE_SOFT,
            DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS,
        );
    }

    // The homepage hero's card: the mark on glass in a hairline square, a
    // crosshair through it and mono labels in the corners.
    let card = RECT {
        left: s(484),
        top: s(92),
        right: s(WIDTH - 28),
        bottom: s(300),
    };
    let hairline = s(1);
    drawing::rect(dc, card, GLASS);
    let (cx, cy) = ((card.left + card.right) / 2, (card.top + card.bottom) / 2);
    drawing::frame(dc, card, HAIRLINE, hairline);
    let (left, top) = (card.left + hairline, card.top + hairline);
    let (right, bottom) = (card.right - hairline, card.bottom - hairline);
    drawing::rect(
        dc,
        RECT {
            left,
            top: cy,
            right,
            bottom: cy + hairline,
        },
        HAIRLINE,
    );
    drawing::rect(
        dc,
        RECT {
            left: cx,
            top,
            right: cx + hairline,
            bottom: cy,
        },
        HAIRLINE,
    );
    drawing::rect(
        dc,
        RECT {
            left: cx,
            top: cy + hairline,
            right: cx + hairline,
            bottom,
        },
        HAIRLINE,
    );
    let rune = |value: &str, left: bool, top: bool| {
        let row = RECT {
            left: card.left + s(12),
            right: card.right - s(12),
            top: if top {
                card.top + s(12)
            } else {
                card.bottom - s(26)
            },
            bottom: if top {
                card.top + s(26)
            } else {
                card.bottom - s(12)
            },
        };
        let align = if left { DT_LEFT } else { DT_RIGHT };
        mono(
            dc,
            value,
            row,
            s(9),
            WHITE_SOFT,
            align | DT_SINGLELINE | DT_VCENTER,
        );
    };
    rune("ID-001", true, true);
    rune(
        if state.shows_lite() {
            "LITE"
        } else {
            "FULL APP"
        },
        false,
        true,
    );
    rune("WINDOWS 10/11", true, false);
    rune(
        if verified.is_some() {
            "VERIFIED"
        } else {
            "CHECKING"
        },
        false,
        false,
    );
    drawing::logo(
        dc,
        RECT {
            left: card.left + s(64),
            top: card.top + s(64),
            right: card.right - s(64),
            bottom: card.bottom - s(64),
        },
    );

    // Status, white on the cobalt: a dot, the heading and one line under it.
    let status_color = if state.exit_code != 0 {
        0xfffbbf24
    } else if state.busy {
        0xffc7d0ff
    } else {
        0xff4ade80
    };
    drawing::rounded(
        dc,
        RECT {
            left: s(28),
            top: s(378),
            right: s(37),
            bottom: s(387),
        },
        s(5) as f32,
        status_color,
    );
    // The text stops short of the first action button.
    let visible = visible_actions(state);
    let text_right = visible.first().map_or(s(WIDTH - 28), |&i| {
        action_rect(i, &visible, dpi).left - s(16)
    });
    text(
        dc,
        &state.heading,
        RECT {
            left: s(48),
            top: s(366),
            right: text_right,
            bottom: s(389),
        },
        s(16),
        600,
        WHITE,
        DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS,
    );
    let subtitle = if state.exit_code != 0 {
        "View details to continue".to_string()
    } else if state.installing {
        "Please wait. Your PC will not restart.".into()
    } else if state.busy && state.package.is_some() {
        "Downloading and checking. Close Setup to cancel.".into()
    } else if state.busy {
        "Checking your installation".into()
    } else if state.installed.is_empty() {
        format!("{} is not on this PC yet", product_name(state))
    } else {
        match state.installed.as_slice() {
            [installed] => format!("Version {} on this PC", installed.version),
            _ => "Choose an action".into(),
        }
    };
    text(
        dc,
        &subtitle,
        RECT {
            left: s(48),
            top: s(389),
            right: text_right,
            bottom: s(409),
        },
        s(12),
        400,
        WHITE_SOFT,
        DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS,
    );

    // The window's edge catches the light, all the way round.
    drawing::rounded_outline(dc, bounds, s(CORNER) as f32, 0x3dffffff, s(1) as f32);
}

/// The chooser's glass track, in window coordinates.
fn chooser_rect(dpi: u32) -> RECT {
    RECT {
        left: scaled(28, dpi),
        top: scaled(254, dpi),
        right: scaled(348, dpi),
        bottom: scaled(292, dpi),
    }
}

/// The part of the track each half's button covers: the full app (0) or Lite (1).
fn half_rect(index: usize, dpi: u32) -> RECT {
    let track = chooser_rect(dpi);
    let middle = segment_rect(1, dpi).left;
    if index == 0 {
        RECT {
            right: middle,
            ..track
        }
    } else {
        RECT {
            left: middle,
            ..track
        }
    }
}

/// Where the pill sits under one half's label.
fn segment_rect(index: usize, dpi: u32) -> RECT {
    let track = chooser_rect(dpi);
    let inset = scaled(4, dpi);
    let half = (track.right - track.left - inset * 2) / 2;
    let left = track.left + inset + half * index as i32;
    RECT {
        left,
        top: track.top + inset,
        right: left + half,
        bottom: track.bottom - inset,
    }
}

/// The pill at `position`: 0 under the full app, 1 under Lite.
fn pill_rect(position: f32, dpi: u32) -> RECT {
    let (first, second) = (segment_rect(0, dpi), segment_rect(1, dpi));
    let offset = ((second.left - first.left) as f32 * position).round() as i32;
    RECT {
        left: first.left + offset,
        right: first.right + offset,
        ..first
    }
}

/// The whole chooser, in window coordinates: the glass track, both labels and
/// the white pill. Each half's button paints its own slice of it, so the pill
/// slides across both, and a label turns to ink wherever the pill is under it.
unsafe fn paint_chooser(dc: HDC, dpi: u32, state: &State, focus: Option<usize>) {
    let track = chooser_rect(dpi);
    let radius = (track.bottom - track.top) as f32 / 2.0;
    drawing::rounded(dc, track, radius, GLASS);
    drawing::rounded_outline(dc, track, radius, HAIRLINE, scaled(1, dpi) as f32);
    let pill = pill_rect(state.pill_position(), dpi);
    let locked = !state.can_choose();
    let labels = |color: COLORREF| {
        for (index, label) in ["SwiftTunnel", "SwiftTunnel Lite"].iter().enumerate() {
            text(
                dc,
                label,
                segment_rect(index, dpi),
                scaled(13, dpi),
                600,
                color,
                DT_CENTER | DT_VCENTER | DT_SINGLELINE,
            );
        }
    };
    let saved = SaveDC(dc);
    let _ = ExcludeClipRect(dc, pill.left, pill.top, pill.right, pill.bottom);
    labels(if locked { COLORREF(0xc9a59b) } else { WHITE });
    let _ = RestoreDC(dc, saved);
    // A switch that is running keeps its pill solid; anything else that locks
    // the chooser dims it.
    let pill_color = if locked && state.switching_to_lite.is_none() {
        0x8cffffff
    } else {
        0xffffffff
    };
    let pill_radius = (pill.bottom - pill.top) as f32 / 2.0;
    drawing::rounded(dc, pill, pill_radius, pill_color);
    let saved = SaveDC(dc);
    let _ = IntersectClipRect(dc, pill.left, pill.top, pill.right, pill.bottom);
    labels(INK);
    let _ = RestoreDC(dc, saved);
    if let Some(index) = focus {
        let segment = segment_rect(index, dpi);
        drawing::rounded_outline(
            dc,
            segment,
            (segment.bottom - segment.top) as f32 / 2.0,
            0xffabc0ff,
            scaled(2, dpi) as f32,
        );
    }
}

/// Where a control sits in the window.
fn control_rect(id: usize, dpi: u32, state: &State) -> RECT {
    match id {
        MINIMIZE_ID | CLOSE_ID => window_button_rect(id - MINIMIZE_ID, dpi),
        PRODUCT_ID | LITE_ID => half_rect(id - PRODUCT_ID, dpi),
        DETAILS_ID => details_rect(dpi),
        _ => action_rect(id.wrapping_sub(100), &visible_actions(state), dpi),
    }
}

/// The text on an action or the Details button.
fn item_label(id: usize, state: &State) -> &'static str {
    match id {
        DETAILS_ID => "Details",
        100 if !state.installed.is_empty() => "Update",
        _ => LABELS.get(id.wrapping_sub(100)).copied().unwrap_or(""),
    }
}

/// Paints into an off-screen copy of `rect`, then copies it to `dc` in one
/// step, so nothing half-drawn reaches the screen.
unsafe fn buffered(dc: HDC, rect: RECT, draw: impl FnOnce(HDC, RECT)) {
    let (w, h) = (rect.right - rect.left, rect.bottom - rect.top);
    if w <= 0 || h <= 0 {
        return;
    }
    let surface = CreateCompatibleDC(Some(dc));
    let bitmap = CreateCompatibleBitmap(dc, w, h);
    let previous = SelectObject(surface, bitmap.into());
    draw(
        surface,
        RECT {
            left: 0,
            top: 0,
            right: w,
            bottom: h,
        },
    );
    let _ = BitBlt(dc, rect.left, rect.top, w, h, Some(surface), 0, 0, SRCCOPY);
    SelectObject(surface, previous);
    let _ = DeleteObject(bitmap.into());
    let _ = DeleteDC(surface);
}

/// One owner-drawn control, in its own coordinates. Its background is the
/// window's artwork under it, and the chooser's halves add their slice of the
/// chooser, so rounded corners have no box behind them.
unsafe fn paint_item(
    dc: HDC,
    bounds: RECT,
    dpi: u32,
    state: &State,
    id: usize,
    disabled: bool,
    pressed: bool,
    focused: bool,
) {
    let place = control_rect(id, dpi, state);
    let saved = SaveDC(dc);
    let _ = SetViewportOrgEx(dc, -place.left, -place.top, None);
    artwork::paint(
        dc,
        RECT {
            left: 0,
            top: 0,
            right: scaled(WIDTH, dpi),
            bottom: scaled(HEIGHT, dpi),
        },
    );
    if id == PRODUCT_ID || id == LITE_ID {
        paint_chooser(dc, dpi, state, focused.then_some(id - PRODUCT_ID));
    }
    let _ = RestoreDC(dc, saved);
    match id {
        PRODUCT_ID | LITE_ID => {}
        MINIMIZE_ID | CLOSE_ID => {
            paint_window_button(dc, bounds, dpi, id == CLOSE_ID, pressed, focused)
        }
        _ => paint_button(
            dc,
            bounds,
            dpi,
            item_label(id, state),
            disabled,
            false,
            pressed,
            focused,
        ),
    }
}

fn visible_actions(state: &State) -> Vec<usize> {
    if state.reboot_required || state.package.is_none() {
        return vec![];
    }
    let package = state.package.as_ref().unwrap();
    (0..ACTIONS.len())
        .filter(|&i| action_allowed(package, &state.installed, ACTIONS[i]))
        .collect()
}
fn action_rect(index: usize, visible: &[usize], dpi: u32) -> RECT {
    let total: i32 = visible.iter().map(|_| BUTTON_WIDTH).sum::<i32>()
        + (visible.len().saturating_sub(1) as i32) * 10;
    let mut left = WIDTH - 28 - total;
    for &i in visible {
        let width = BUTTON_WIDTH;
        if i == index {
            return RECT {
                left: scaled(left, dpi),
                right: scaled(left + width, dpi),
                top: scaled(BUTTON_TOP, dpi),
                bottom: scaled(BUTTON_TOP + BUTTON_HEIGHT, dpi),
            };
        }
        left += width + 10;
    }
    RECT::default()
}

/// Pills on the night: the main action solid white with ink text, the others
/// glass with a hairline.
unsafe fn paint_button(
    dc: HDC,
    bounds: RECT,
    dpi: u32,
    label: &str,
    disabled: bool,
    primary: bool,
    pressed: bool,
    focused: bool,
) {
    let primary = primary || matches!(label, "Install" | "Update" | "Repair");
    let radius = (bounds.bottom - bounds.top) as f32 / 2.0;
    if primary {
        let background = if disabled {
            0x73ffffff
        } else if pressed {
            0xffdde2fb
        } else {
            0xffffffff
        };
        drawing::rounded(dc, bounds, radius, background);
    } else {
        drawing::rounded(dc, bounds, radius, if pressed { 0x3dffffff } else { GLASS });
        drawing::rounded_outline(
            dc,
            bounds,
            radius,
            if disabled { 0x29ffffff } else { 0x52ffffff },
            scaled(1, dpi) as f32,
        );
    }
    text(
        dc,
        label,
        bounds,
        scaled(13, dpi),
        600,
        if primary {
            if disabled {
                COLORREF(0x6a5a55)
            } else {
                INK
            }
        } else if disabled {
            COLORREF(0xc9a59b)
        } else {
            WHITE
        },
        DT_CENTER | DT_VCENTER | DT_SINGLELINE,
    );
    if focused {
        // A child control is clipped to its own bounds, so the ring sits inside.
        let inset = scaled(3, dpi);
        let ring = RECT {
            left: bounds.left + inset,
            top: bounds.top + inset,
            right: bounds.right - inset,
            bottom: bounds.bottom - inset,
        };
        drawing::rounded_outline(
            dc,
            ring,
            (radius - inset as f32).max(2.0),
            if primary { 0xff2747e6 } else { 0xffffffff },
            scaled(2, dpi) as f32,
        );
    }
}

/// Minimise and close, drawn in white over the night.
unsafe fn paint_window_button(
    dc: HDC,
    bounds: RECT,
    dpi: u32,
    close: bool,
    pressed: bool,
    focused: bool,
) {
    if pressed {
        drawing::rounded(dc, bounds, scaled(6, dpi) as f32, 0x29ffffff);
    }
    let cx = (bounds.left + bounds.right) / 2;
    let cy = (bounds.top + bounds.bottom) / 2;
    let r = scaled(5, dpi);
    let width = scaled(1, dpi).max(1) as f32 * 1.25;
    if close {
        drawing::line(dc, cx - r, cy - r, cx + r, cy + r, 0xe6ffffff, width);
        drawing::line(dc, cx - r, cy + r, cx + r, cy - r, 0xe6ffffff, width);
    } else {
        drawing::line(dc, cx - r, cy, cx + r, cy, 0xe6ffffff, width);
    }
    if focused {
        drawing::rounded_outline(
            dc,
            bounds,
            scaled(6, dpi) as f32,
            0xffabc0ff,
            scaled(2, dpi) as f32,
        );
    }
}

fn window_button_rect(index: usize, dpi: u32) -> RECT {
    RECT {
        left: scaled(WIDTH - 104 + index as i32 * 40, dpi),
        top: scaled(12, dpi),
        right: scaled(WIDTH - 68 + index as i32 * 40, dpi),
        bottom: scaled(40, dpi),
    }
}

/// "Details" appears above the actions when something needs reading.
fn details_rect(dpi: u32) -> RECT {
    RECT {
        left: scaled(WIDTH - 28 - BUTTON_WIDTH, dpi),
        top: scaled(BUTTON_TOP - 40, dpi),
        right: scaled(WIDTH - 28, dpi),
        bottom: scaled(BUTTON_TOP - 10, dpi),
    }
}

// Uses the production paint functions without running an installer transaction.
#[cfg(debug_assertions)]
#[allow(dead_code)]
pub unsafe fn paint_preview(dc: HDC, bounds: RECT, dpi: u32, existing: bool) {
    let (commands, _) = std::sync::mpsc::channel();
    let (_, events) = std::sync::mpsc::channel();
    let mut state = State::new(commands, events);
    let package = Package {
        name: "SwiftTunnel".into(),
        version: "3.1.6".into(),
        product_code: "preview".into(),
        upgrade_code: "preview".into(),
    };
    let installed = if existing {
        vec![Installed {
            product_code: package.product_code.clone(),
            version: package.version.clone(),
        }]
    } else {
        vec![]
    };
    state.ready(package, installed);
    paint_composed(dc, bounds, dpi, &state, None);
}

/// Everything the window shows for a state, composed as the window composes
/// it: its own paint, then each visible control painted the way WM_DRAWITEM
/// paints it. `focus` is the control with keyboard focus, if any.
#[cfg(any(test, debug_assertions))]
#[allow(dead_code)]
unsafe fn paint_composed(dc: HDC, bounds: RECT, dpi: u32, state: &State, focus: Option<usize>) {
    paint(dc, bounds, dpi, state);
    let mut controls: Vec<(usize, bool)> = visible_actions(state)
        .into_iter()
        .map(|i| (100 + i, state.busy))
        .collect();
    controls.extend([(MINIMIZE_ID, false), (CLOSE_ID, false)]);
    if state.exit_code != 0 {
        controls.push((DETAILS_ID, false));
    }
    if crate::MSI_NAME == "SwiftTunnel-Installer.msi" {
        controls.extend([(PRODUCT_ID, false), (LITE_ID, false)]);
    }
    for (id, disabled) in controls {
        let rect = control_rect(id, dpi, state);
        let rect = RECT {
            left: rect.left + bounds.left,
            top: rect.top + bounds.top,
            right: rect.right + bounds.left,
            bottom: rect.bottom + bounds.top,
        };
        buffered(dc, rect, |surface, local| {
            paint_item(
                surface,
                local,
                dpi,
                state,
                id,
                disabled,
                false,
                focus == Some(id),
            )
        });
    }
}

unsafe fn update_buttons(hwnd: HWND, state: &State) {
    for (index, button) in state.buttons.iter().enumerate() {
        let allowed = !state.busy
            && !state.reboot_required
            && state
                .package
                .as_ref()
                .is_some_and(|p| action_allowed(p, &state.installed, ACTIONS[index]));
        let _ = EnableWindow(*button, allowed);
        let _ = ShowWindow(
            *button,
            if visible_actions(state).contains(&index) {
                SW_SHOW
            } else {
                SW_HIDE
            },
        );
        if index == 0 {
            // Setting the same text still repaints the button, so only change it.
            let label = item_label(100, state);
            let mut current = [0u16; 16];
            let length = GetWindowTextW(*button, &mut current).max(0) as usize;
            if String::from_utf16_lossy(&current[..length]) != label {
                let _ = SetWindowTextW(*button, PCWSTR(wide(label).as_ptr()));
            }
        }
    }
    if let Some(button) = state.details_button {
        let _ = ShowWindow(
            button,
            if state.exit_code != 0 {
                SW_SHOW
            } else {
                SW_HIDE
            },
        );
    }
    for button in &state.product_buttons {
        let _ = EnableWindow(*button, state.can_choose());
        // Owner-drawn: the pill follows the choice, so repaint both halves.
        let _ = InvalidateRect(Some(*button), None, false);
    }
    layout(hwnd, state);
    let _ = InvalidateRect(Some(hwnd), None, false);
}

/// Moves a control only when it is not already in place: moving repaints it.
unsafe fn place(parent: HWND, control: HWND, rect: RECT) {
    let mut current = RECT::default();
    let _ = GetWindowRect(control, &mut current);
    let mut origin = POINT {
        x: current.left,
        y: current.top,
    };
    let _ = ScreenToClient(parent, &mut origin);
    let (width, height) = (rect.right - rect.left, rect.bottom - rect.top);
    if origin.x != rect.left
        || origin.y != rect.top
        || current.right - current.left != width
        || current.bottom - current.top != height
    {
        let _ = MoveWindow(control, rect.left, rect.top, width, height, true);
    }
}

unsafe fn layout(hwnd: HWND, state: &State) {
    let dpi = GetDpiForWindow(hwnd).max(96);
    let visible = visible_actions(state);
    for (i, button) in state.product_buttons.iter().enumerate() {
        place(hwnd, *button, half_rect(i, dpi));
    }
    for (i, button) in state.buttons.iter().enumerate() {
        place(hwnd, *button, action_rect(i, &visible, dpi));
    }
    for (i, button) in state.window_buttons.iter().enumerate() {
        place(hwnd, *button, window_button_rect(i, dpi));
    }
    if let Some(button) = state.details_button {
        place(hwnd, button, details_rect(dpi));
    }
}

/// Asks Windows to round the window itself, which Windows 11 does with smooth
/// corners and a shadow. False on Windows 10, which has no such thing.
unsafe fn rounded_by_windows(hwnd: HWND) -> bool {
    let round = DWMWCP_ROUND;
    DwmSetWindowAttribute(
        hwnd,
        DWMWA_WINDOW_CORNER_PREFERENCE,
        (&round as *const _ as *const core::ffi::c_void).cast(),
        std::mem::size_of_val(&round) as u32,
    )
    .is_ok()
}

/// The window's rounded outline. Set when the window's size is, not on every
/// refresh, since setting it redraws the whole window.
unsafe fn shape(hwnd: HWND) {
    // A region cuts jagged corners and loses the shadow, so it is only for
    // Windows 10.
    if rounded_by_windows(hwnd) {
        let _ = SetWindowRgn(hwnd, None, true);
        return;
    }
    let dpi = GetDpiForWindow(hwnd).max(96);
    let region = CreateRoundRectRgn(
        0,
        0,
        scaled(WIDTH, dpi) + 1,
        scaled(HEIGHT, dpi) + 1,
        scaled(CORNER * 2, dpi),
        scaled(CORNER * 2, dpi),
    );
    if SetWindowRgn(hwnd, Some(region), true) == 0 {
        let _ = DeleteObject(region.into());
    }
}

/// Brings the controls in line with State after a change. Callers release
/// their mutable borrow first: this takes a shared one, so a control that
/// repaints at once can still read State.
unsafe fn refresh(hwnd: HWND, cell: &RefCell<State>) {
    if let Ok(state) = cell.try_borrow() {
        update_buttons(hwnd, &state);
        if state.sliding() {
            SetTimer(Some(hwnd), SLIDE_TIMER, 10, None);
        }
    }
}

unsafe extern "system" fn window_proc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    if msg == WM_NCCREATE {
        let create = &*(lp.0 as *const CREATESTRUCTW);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, create.lpCreateParams as isize);
    }
    let ptr = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut RefCell<State>;
    if ptr.is_null() {
        return DefWindowProcW(hwnd, msg, wp, lp);
    }
    if msg == WM_NCHITTEST {
        let mut point = POINT {
            x: (lp.0 as u16 as i16) as i32,
            y: ((lp.0 >> 16) as u16 as i16) as i32,
        };
        let _ = ScreenToClient(hwnd, &mut point);
        let dpi = GetDpiForWindow(hwnd).max(96);
        if point.x >= 0
            && point.x < scaled(WIDTH - 108, dpi)
            && point.y >= 0
            && point.y < scaled(48, dpi)
        {
            return LRESULT(HTCAPTION as isize);
        }
    }
    if msg == WM_COMMAND {
        match wp.0 & 0xffff {
            DETAILS_ID => {
                let details = (*ptr)
                    .try_borrow()
                    .ok()
                    .map(|s| (wide(&s.detail), wide(&s.heading)));
                if let Some((message, title)) = details {
                    MessageBoxW(
                        Some(hwnd),
                        PCWSTR(message.as_ptr()),
                        PCWSTR(title.as_ptr()),
                        MB_OK | MB_ICONINFORMATION,
                    );
                }
                return LRESULT(0);
            }
            MINIMIZE_ID => {
                let _ = ShowWindow(hwnd, SW_MINIMIZE);
                return LRESULT(0);
            }
            CLOSE_ID => {
                let _ = PostMessageW(Some(hwnd), WM_CLOSE, WPARAM(0), LPARAM(0));
                return LRESULT(0);
            }
            _ => {}
        }
    }
    // Windows can synchronously reenter this procedure during child creation,
    // layout and dialogs. Never create overlapping mutable State references.
    if msg == WM_DESTROY {
        let _ = KillTimer(Some(hwnd), EVENT_TIMER);
        let _ = KillTimer(Some(hwnd), SLIDE_TIMER);
        PostQuitMessage(0);
        return LRESULT(0);
    }
    if msg == WM_CLOSE {
        let installing = (*ptr).try_borrow().map(|s| s.installing).unwrap_or(true);
        if installing {
            MessageBoxW(Some(hwnd), w!("Windows Installer is still working. Wait for it to finish before closing Setup."), w!("Installation in progress"), MB_OK | MB_ICONINFORMATION);
        } else {
            let _ = DestroyWindow(hwnd);
        }
        return LRESULT(0);
    }
    if msg == WM_COMMAND && wp.0 & 0xffff == 103 {
        let can_remove = (*ptr).try_borrow().is_ok_and(|s| {
            !s.busy
                && !s.reboot_required
                && s.package
                    .as_ref()
                    .is_some_and(|p| action_allowed(p, &s.installed, Action::Uninstall))
        });
        if !can_remove || MessageBoxW(Some(hwnd), w!("Remove this SwiftTunnel product from your PC? Close SwiftTunnel before continuing."), w!("Uninstall SwiftTunnel"), MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2) != IDYES {
            return LRESULT(0);
        }
    }
    // Painting only reads State, through a shared borrow, so a control that
    // repaints in the middle of a refresh can still read it.
    match msg {
        WM_PAINT | WM_DRAWITEM => {
            let Ok(state) = (*ptr).try_borrow() else {
                return DefWindowProcW(hwnd, msg, wp, lp);
            };
            let dpi = GetDpiForWindow(hwnd).max(96);
            if msg == WM_PAINT {
                let mut ps = PAINTSTRUCT::default();
                let dc = BeginPaint(hwnd, &mut ps);
                let mut bounds = RECT::default();
                let _ = GetClientRect(hwnd, &mut bounds);
                buffered(dc, bounds, |dc, bounds| paint(dc, bounds, dpi, &state));
                let _ = EndPaint(hwnd, &ps);
                return LRESULT(0);
            }
            let item = &*(lp.0 as *const DRAWITEMSTRUCT);
            let flag = |value: u32| item.itemState.0 & value != 0;
            buffered(item.hDC, item.rcItem, |dc, bounds| {
                paint_item(
                    dc,
                    bounds,
                    dpi,
                    &state,
                    item.CtlID as usize,
                    flag(ODS_DISABLED.0),
                    flag(ODS_SELECTED.0),
                    flag(ODS_FOCUS.0),
                )
            });
            return LRESULT(1);
        }
        // Owner-drawn buttons paint their own background; nothing erases it first.
        WM_CTLCOLORBTN => return LRESULT(GetStockObject(NULL_BRUSH).0 as isize),
        WM_ERASEBKGND => return LRESULT(1),
        WM_DPICHANGED => {
            let rect = &*(lp.0 as *const RECT);
            let _ = SetWindowPos(
                hwnd,
                None,
                rect.left,
                rect.top,
                rect.right - rect.left,
                rect.bottom - rect.top,
                SWP_NOZORDER | SWP_NOACTIVATE,
            );
            shape(hwnd);
            refresh(hwnd, &*ptr);
            return LRESULT(0);
        }
        WM_TIMER if wp.0 == SLIDE_TIMER => {
            // Move the clock on, then repaint both halves as of it.
            let sliding = match (*ptr).try_borrow_mut() {
                Ok(mut state) => {
                    state.frame = Instant::now();
                    state.sliding()
                }
                Err(_) => true,
            };
            if let Ok(state) = (*ptr).try_borrow() {
                for button in &state.product_buttons {
                    let _ = InvalidateRect(Some(*button), None, false);
                }
            }
            if !sliding {
                let _ = KillTimer(Some(hwnd), SLIDE_TIMER);
            }
            return LRESULT(0);
        }
        WM_CREATE | WM_TIMER | WM_COMMAND => {}
        _ => return DefWindowProcW(hwnd, msg, wp, lp),
    }
    // These change State. The mutable borrow ends before the controls are
    // refreshed, since refreshing can repaint them on the spot.
    let Ok(mut guard) = (*ptr).try_borrow_mut() else {
        return DefWindowProcW(hwnd, msg, wp, lp);
    };
    let state = &mut *guard;
    let result = match msg {
        WM_CREATE => {
            let dark = 1i32;
            let _ = DwmSetWindowAttribute(
                hwnd,
                DWMWA_USE_IMMERSIVE_DARK_MODE,
                &dark as *const _ as _,
                4,
            );
            for (i, label) in LABELS.iter().enumerate() {
                if let Ok(button) = CreateWindowExW(
                    WINDOW_EX_STYLE::default(),
                    w!("BUTTON"),
                    PCWSTR(wide(label).as_ptr()),
                    WS_CHILD | WS_VISIBLE | WS_TABSTOP | WINDOW_STYLE(BS_OWNERDRAW as u32),
                    0,
                    0,
                    0,
                    0,
                    Some(hwnd),
                    Some(HMENU((100 + i) as *mut _)),
                    None,
                    None,
                ) {
                    state.buttons.push(button);
                } else {
                    return LRESULT(-1);
                }
            }
            for (i, label) in ["Minimize", "Close"].iter().enumerate() {
                match CreateWindowExW(
                    WINDOW_EX_STYLE::default(),
                    w!("BUTTON"),
                    PCWSTR(wide(label).as_ptr()),
                    WS_CHILD | WS_VISIBLE | WS_TABSTOP | WINDOW_STYLE(BS_OWNERDRAW as u32),
                    0,
                    0,
                    0,
                    0,
                    Some(hwnd),
                    Some(HMENU((MINIMIZE_ID + i) as *mut _)),
                    None,
                    None,
                ) {
                    Ok(button) => state.window_buttons.push(button),
                    Err(_) => return LRESULT(-1),
                }
            }
            state.details_button = CreateWindowExW(
                WINDOW_EX_STYLE::default(),
                w!("BUTTON"),
                w!("Details"),
                WS_CHILD | WS_TABSTOP | WINDOW_STYLE(BS_OWNERDRAW as u32),
                0,
                0,
                0,
                0,
                Some(hwnd),
                Some(HMENU(DETAILS_ID as *mut _)),
                None,
                None,
            )
            .ok();
            if state.details_button.is_none() {
                return LRESULT(-1);
            }
            // The full app's Setup offers Lite as the other half of a chooser.
            // Lite's own Setup has nothing to switch to.
            if crate::MSI_NAME == "SwiftTunnel-Installer.msi" {
                for (id, label) in [
                    (PRODUCT_ID, w!("SwiftTunnel")),
                    (LITE_ID, w!("SwiftTunnel Lite")),
                ] {
                    match CreateWindowExW(
                        WINDOW_EX_STYLE::default(),
                        w!("BUTTON"),
                        label,
                        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WINDOW_STYLE(BS_OWNERDRAW as u32),
                        0,
                        0,
                        0,
                        0,
                        Some(hwnd),
                        Some(HMENU(id as *mut _)),
                        None,
                        None,
                    ) {
                        Ok(button) => state.product_buttons.push(button),
                        Err(_) => return LRESULT(-1),
                    }
                }
            }
            SetTimer(Some(hwnd), EVENT_TIMER, 150, None);
            LRESULT(0)
        }
        WM_TIMER => {
            loop {
                let event = match state.events.try_recv() {
                    Ok(event) => event,
                    Err(std::sync::mpsc::TryRecvError::Empty) => break,
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        state.shift(|s| {
                            s.worker_stopped();
                        });
                        break;
                    }
                };
                match event {
                    Event::Progress(status) => {
                        state.heading = status;
                    }
                    Event::Ready(package, installed) => {
                        state.shift(|s| s.ready(package, installed));
                    }
                    Event::Finished(action, code, installed) => {
                        state.installed = installed;
                        state.busy = false;
                        state.installing = false;
                        state.exit_code = code;
                        state.reboot_required = matches!(code, 3010 | 1641);
                        let (ok, message) = result_message(action, code);
                        state.heading = if ok { "All done" } else { "Could not complete" }.into();
                        state.detail = message;
                    }
                    Event::Failed(error) => {
                        state.shift(|s| {
                            s.exit_code = 1;
                            s.busy = false;
                            s.installing = false;
                            s.switching_to_lite = None;
                        });
                        state.heading = "Setup needs attention".into();
                        state.detail = error;
                    }
                }
            }
            LRESULT(0)
        }
        WM_COMMAND => {
            let id = (wp.0 & 0xffff) as usize;
            // Each half of the chooser selects its own app; the half already
            // chosen does nothing.
            let wants_lite = match id {
                PRODUCT_ID => Some(false),
                LITE_ID => Some(true),
                _ => None,
            };
            if let Some(wants_lite) = wants_lite {
                if !state.product_buttons.is_empty()
                    && state.can_choose()
                    && wants_lite != state.lite_selected()
                {
                    let command = if wants_lite {
                        Command::DownloadLite
                    } else {
                        Command::UseBundled
                    };
                    if state.commands.send(command).is_ok() {
                        state.shift(|s| {
                            s.busy = true;
                            s.exit_code = 0;
                            s.switching_to_lite = Some(wants_lite);
                        });
                        state.heading = if wants_lite {
                            "Getting SwiftTunnel Lite"
                        } else {
                            "Switching to SwiftTunnel"
                        }
                        .into();
                    } else {
                        state.exit_code = 1;
                        state.heading = "Please reopen Setup".into();
                        state.detail = "The installer worker is unavailable.".into();
                    }
                }
            } else if (100..104).contains(&id) && !state.busy && !state.reboot_required {
                let action = ACTIONS[id - 100];
                if state
                    .package
                    .as_ref()
                    .is_some_and(|p| action_allowed(p, &state.installed, action))
                {
                    if state.commands.send(Command::Execute(action)).is_ok() {
                        state.exit_code = 0;
                        state.busy = true;
                        state.installing = true;
                        state.heading = format!("{} in progress", LABELS[id - 100]);
                        state.detail = "Applying changes. Some steps take a few minutes. Your PC will not restart automatically.".into();
                    } else {
                        state.exit_code = 1;
                        state.heading = "Please reopen Setup".into();
                        state.detail =
                            "The installer worker is unavailable. Close this window and try again."
                                .into();
                    }
                }
            }
            LRESULT(0)
        }
        _ => DefWindowProcW(hwnd, msg, wp, lp),
    };
    drop(guard);
    if msg == WM_CREATE {
        if result.0 == -1 {
            return result;
        }
        shape(hwnd);
    }
    refresh(hwnd, &*ptr);
    result
}

pub fn run(state: Box<State>) -> Result<i32, String> {
    fonts::install();
    let state = Box::new(RefCell::new(*state));
    unsafe {
        let _ = SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
        let instance = GetModuleHandleW(None).map_err(|e| e.to_string())?;
        let class = WNDCLASSW {
            lpfnWndProc: Some(window_proc),
            hInstance: instance.into(),
            hIcon: LoadIconW(Some(instance.into()), PCWSTR(1usize as *const u16))
                .map_err(|e| format!("Could not load the setup icon: {e}"))?,
            lpszClassName: w!("SwiftTunnelOfflineSetup"),
            hCursor: LoadCursorW(None, IDC_ARROW).map_err(|e| e.to_string())?,
            ..Default::default()
        };
        if RegisterClassW(&class) == 0 {
            return Err("Could not create the Setup window class.".into());
        }
        let style = WINDOW_STYLE_SETUP;
        let dpi = windows::Win32::UI::HiDpi::GetDpiForSystem();
        let mut bounds = RECT {
            left: 0,
            top: 0,
            right: scaled(WIDTH, dpi),
            bottom: scaled(HEIGHT, dpi),
        };
        let _ = windows::Win32::UI::HiDpi::AdjustWindowRectExForDpi(
            &mut bounds,
            style,
            false,
            WINDOW_EX_STYLE::default(),
            dpi,
        );
        let hwnd = CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            class.lpszClassName,
            w!("SwiftTunnel Setup"),
            style,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            bounds.right - bounds.left,
            bounds.bottom - bounds.top,
            None,
            None,
            Some(instance.into()),
            Some((state.as_ref() as *const RefCell<State>).cast()),
        )
        .map_err(|e| format!("Could not open Setup: {e}"))?;
        let small_icon = LoadImageW(
            Some(instance.into()),
            PCWSTR(1usize as *const u16),
            IMAGE_ICON,
            scaled(16, dpi),
            scaled(16, dpi),
            LR_SHARED,
        )
        .map_err(|e| format!("Could not load the small setup icon: {e}"))?;
        SendMessageW(
            hwnd,
            WM_SETICON,
            Some(WPARAM(ICON_SMALL as usize)),
            Some(LPARAM(small_icon.0 as isize)),
        );
        SendMessageW(
            hwnd,
            WM_SETICON,
            Some(WPARAM(ICON_BIG as usize)),
            Some(LPARAM(class.hIcon.0 as isize)),
        );
        let _ = ShowWindow(hwnd, SW_SHOW);
        let mut message = MSG::default();
        loop {
            let status = GetMessageW(&mut message, None, 0, 0).0;
            if status == 0 {
                break;
            }
            if status == -1 {
                let _ = DestroyWindow(hwnd);
                return Err("Setup's window message loop failed.".into());
            }
            if !IsDialogMessageW(hwnd, &message).as_bool() {
                let _ = TranslateMessage(&message);
                DispatchMessageW(&message);
            }
        }
    }
    let code = state.borrow().exit_code;
    Ok(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe fn render_png(state: &State, dpi: u32, focus: Option<usize>, path: &std::path::Path) {
        let (w, h) = (scaled(WIDTH, dpi), scaled(HEIGHT, dpi));
        let screen = GetDC(None);
        let dc = CreateCompatibleDC(Some(screen));
        let info = BITMAPINFO {
            bmiHeader: BITMAPINFOHEADER {
                biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                biWidth: w,
                biHeight: -h,
                biPlanes: 1,
                biBitCount: 32,
                biCompression: BI_RGB.0,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut bits = std::ptr::null_mut();
        let bitmap = CreateDIBSection(Some(dc), &info, DIB_RGB_COLORS, &mut bits, None, 0).unwrap();
        let previous = SelectObject(dc, bitmap.into());
        paint_composed(
            dc,
            RECT {
                left: 0,
                top: 0,
                right: w,
                bottom: h,
            },
            dpi,
            state,
            focus,
        );
        let _ = GdiFlush();
        write_png(path, w, h, bits);
        SelectObject(dc, previous);
        let _ = DeleteObject(bitmap.into());
        let _ = DeleteDC(dc);
        ReleaseDC(None, screen);
    }

    /// Saves top-down 32-bit BGRA pixels as a PNG.
    unsafe fn write_png(path: &std::path::Path, w: i32, h: i32, bits: *const std::ffi::c_void) {
        let pixels = std::slice::from_raw_parts(bits as *const u8, (w * h * 4) as usize);
        let rgba: Vec<u8> = pixels
            .chunks_exact(4)
            .flat_map(|p| [p[2], p[1], p[0], 255])
            .collect();
        let file = std::fs::File::create(path).unwrap();
        let mut encoder = png::Encoder::new(std::io::BufWriter::new(file), w as u32, h as u32);
        encoder.set_color(png::ColorType::Rgba);
        encoder.set_depth(png::BitDepth::Eight);
        encoder
            .write_header()
            .unwrap()
            .write_image_data(&rgba)
            .unwrap();
    }

    /// Copies what a live window currently shows, children included.
    unsafe fn capture_window(hwnd: HWND, path: &std::path::Path) {
        let mut client = RECT::default();
        let _ = GetClientRect(hwnd, &mut client);
        let (w, h) = (client.right, client.bottom);
        let window = GetDC(Some(hwnd));
        let dc = CreateCompatibleDC(Some(window));
        let info = BITMAPINFO {
            bmiHeader: BITMAPINFOHEADER {
                biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                biWidth: w,
                biHeight: -h,
                biPlanes: 1,
                biBitCount: 32,
                biCompression: BI_RGB.0,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut bits = std::ptr::null_mut();
        let bitmap = CreateDIBSection(Some(dc), &info, DIB_RGB_COLORS, &mut bits, None, 0).unwrap();
        let previous = SelectObject(dc, bitmap.into());
        let _ = BitBlt(dc, 0, 0, w, h, Some(window), 0, 0, SRCCOPY);
        let _ = GdiFlush();
        write_png(path, w, h, bits);
        SelectObject(dc, previous);
        let _ = DeleteObject(bitmap.into());
        let _ = DeleteDC(dc);
        ReleaseDC(Some(hwnd), window);
    }

    /// Design review: drives the real window through a switch to Lite and back
    /// and saves what it shows along the way.
    /// SETUP_PREVIEW_DIR=<dir> cargo test -p swifttunnel-setup live_switch -- --ignored
    #[test]
    #[ignore]
    fn live_switch() {
        let Ok(dir) = std::env::var("SETUP_PREVIEW_DIR") else {
            return;
        };
        let dir = std::path::PathBuf::from(dir);
        let package = |lite: bool| Package {
            name: if lite {
                "SwiftTunnel Lite"
            } else {
                "SwiftTunnel"
            }
            .into(),
            version: "3.1.6".into(),
            product_code: if lite { "lite" } else { "full" }.into(),
            upgrade_code: if lite {
                LITE_FAMILY.into()
            } else {
                crate::model::DESKTOP_FAMILY.into()
            },
        };
        unsafe {
            let _ = SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
            fonts::install();
            let instance = GetModuleHandleW(None).unwrap();
            let class = WNDCLASSW {
                lpfnWndProc: Some(window_proc),
                hInstance: instance.into(),
                lpszClassName: w!("SwiftTunnelSetupLiveTest"),
                hCursor: LoadCursorW(None, IDC_ARROW).unwrap(),
                ..Default::default()
            };
            assert_ne!(RegisterClassW(&class), 0);
            let (commands, actions) = std::sync::mpsc::channel();
            let (events, updates) = std::sync::mpsc::channel();
            let state = Box::new(RefCell::new(State::new(commands, updates)));
            let dpi = windows::Win32::UI::HiDpi::GetDpiForSystem();
            let hwnd = CreateWindowExW(
                WINDOW_EX_STYLE::default(),
                class.lpszClassName,
                w!("Setup live test"),
                WINDOW_STYLE_SETUP,
                40,
                40,
                scaled(WIDTH, dpi),
                scaled(HEIGHT, dpi),
                None,
                None,
                Some(instance.into()),
                Some((state.as_ref() as *const RefCell<State>).cast()),
            )
            .unwrap();
            // On screen so it paints, but behind every other window.
            let _ = ShowWindow(hwnd, SW_SHOWNOACTIVATE);
            let _ = SetWindowPos(
                hwnd,
                Some(HWND_BOTTOM),
                0,
                0,
                0,
                0,
                SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE,
            );
            let pump = |ms: u64| {
                let end = std::time::Instant::now() + std::time::Duration::from_millis(ms);
                let mut message = MSG::default();
                while std::time::Instant::now() < end {
                    while PeekMessageW(&mut message, None, 0, 0, PM_REMOVE).as_bool() {
                        let _ = TranslateMessage(&message);
                        DispatchMessageW(&message);
                    }
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
            };
            let frames = |name: &str, count: usize, every: u64| {
                for i in 0..count {
                    pump(every);
                    capture_window(hwnd, &dir.join(format!("live-{name}-{i}.png")));
                }
            };
            events.send(Event::Ready(package(false), vec![])).unwrap();
            pump(600);
            capture_window(hwnd, &dir.join("live-a-full.png"));
            SendMessageW(hwnd, WM_COMMAND, Some(WPARAM(LITE_ID)), Some(LPARAM(0)));
            assert_eq!(actions.try_recv().unwrap(), Command::DownloadLite);
            frames("b-click", 8, 30);
            events.send(Event::Ready(package(true), vec![])).unwrap();
            frames("c-ready", 8, 30);
            SendMessageW(hwnd, WM_COMMAND, Some(WPARAM(PRODUCT_ID)), Some(LPARAM(0)));
            assert_eq!(actions.try_recv().unwrap(), Command::UseBundled);
            events.send(Event::Ready(package(false), vec![])).unwrap();
            frames("d-back", 8, 30);
            // What one repaint of everything, and of one chooser half, costs.
            let timed = |window: HWND, flags: REDRAW_WINDOW_FLAGS| {
                let start = std::time::Instant::now();
                for _ in 0..20 {
                    let _ = RedrawWindow(Some(window), None, None, flags);
                }
                start.elapsed() / 20
            };
            let everything = RDW_INVALIDATE | RDW_UPDATENOW | RDW_ALLCHILDREN;
            let half = state.borrow().product_buttons[1];
            let objects = || {
                windows::Win32::System::Threading::GetGuiResources(
                    windows::Win32::System::Threading::GetCurrentProcess(),
                    windows::Win32::System::Threading::GR_GDIOBJECTS,
                )
            };
            let before = objects();
            println!(
                "full repaint {:?}, window alone {:?}, chooser half {:?}",
                timed(hwnd, everything),
                timed(hwnd, RDW_INVALIDATE | RDW_UPDATENOW),
                timed(half, RDW_INVALIDATE | RDW_UPDATENOW)
            );
            // Forty repaints later, no GDI objects have been left behind.
            assert!(
                objects() <= before,
                "{} GDI objects, was {before}",
                objects()
            );
            let _ = DestroyWindow(hwnd);
            pump(50);
        }
    }

    /// Design review: shows the real window on screen for a moment and saves
    /// the screen around it, with the corners and shadow Windows gives it.
    /// SETUP_PREVIEW_DIR=<dir> cargo test -p swifttunnel-setup on_screen -- --ignored
    #[test]
    #[ignore]
    fn on_screen() {
        let Ok(dir) = std::env::var("SETUP_PREVIEW_DIR") else {
            return;
        };
        let dir = std::path::PathBuf::from(dir);
        unsafe {
            let _ = SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
            fonts::install();
            let instance = GetModuleHandleW(None).unwrap();
            let class = WNDCLASSW {
                lpfnWndProc: Some(window_proc),
                hInstance: instance.into(),
                lpszClassName: w!("SwiftTunnelSetupOnScreenTest"),
                hCursor: LoadCursorW(None, IDC_ARROW).unwrap(),
                ..Default::default()
            };
            assert_ne!(RegisterClassW(&class), 0);
            let (commands, _actions) = std::sync::mpsc::channel();
            let (events, updates) = std::sync::mpsc::channel();
            let state = Box::new(RefCell::new(State::new(commands, updates)));
            let dpi = windows::Win32::UI::HiDpi::GetDpiForSystem();
            let (margin, w, h) = (scaled(48, dpi), scaled(WIDTH, dpi), scaled(HEIGHT, dpi));
            let hwnd = CreateWindowExW(
                WINDOW_EX_STYLE::default(),
                class.lpszClassName,
                w!("Setup on screen test"),
                WINDOW_STYLE_SETUP,
                margin * 2,
                margin * 2,
                w,
                h,
                None,
                None,
                Some(instance.into()),
                Some((state.as_ref() as *const RefCell<State>).cast()),
            )
            .unwrap();
            let _ = ShowWindow(hwnd, SW_SHOWNOACTIVATE);
            let _ = SetWindowPos(
                hwnd,
                Some(HWND_TOPMOST),
                0,
                0,
                0,
                0,
                SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE,
            );
            events
                .send(Event::Ready(
                    Package {
                        name: "SwiftTunnel".into(),
                        version: "3.9.0".into(),
                        product_code: "full".into(),
                        upgrade_code: crate::model::DESKTOP_FAMILY.into(),
                    },
                    vec![],
                ))
                .unwrap();
            let end = std::time::Instant::now() + std::time::Duration::from_millis(900);
            let mut message = MSG::default();
            while std::time::Instant::now() < end {
                while PeekMessageW(&mut message, None, 0, 0, PM_REMOVE).as_bool() {
                    let _ = TranslateMessage(&message);
                    DispatchMessageW(&message);
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            let (cw, ch) = (w + margin * 2, h + margin * 2);
            let screen = GetDC(None);
            let dc = CreateCompatibleDC(Some(screen));
            let info = BITMAPINFO {
                bmiHeader: BITMAPINFOHEADER {
                    biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                    biWidth: cw,
                    biHeight: -ch,
                    biPlanes: 1,
                    biBitCount: 32,
                    biCompression: BI_RGB.0,
                    ..Default::default()
                },
                ..Default::default()
            };
            let mut bits = std::ptr::null_mut();
            let bitmap =
                CreateDIBSection(Some(dc), &info, DIB_RGB_COLORS, &mut bits, None, 0).unwrap();
            let previous = SelectObject(dc, bitmap.into());
            let _ = BitBlt(dc, 0, 0, cw, ch, Some(screen), margin, margin, SRCCOPY);
            let _ = GdiFlush();
            write_png(&dir.join("on-screen.png"), cw, ch, bits);
            SelectObject(dc, previous);
            let _ = DeleteObject(bitmap.into());
            let _ = DeleteDC(dc);
            ReleaseDC(None, screen);
            let _ = DestroyWindow(hwnd);
        }
    }

    /// Design review: renders every screen to PNG.
    /// SETUP_PREVIEW_DIR=<dir> cargo test -p swifttunnel-setup preview_screens -- --ignored
    #[test]
    #[ignore]
    fn preview_screens() {
        let Ok(dir) = std::env::var("SETUP_PREVIEW_DIR") else {
            return;
        };
        let package = |lite: bool| Package {
            name: if lite {
                "SwiftTunnel Lite"
            } else {
                "SwiftTunnel"
            }
            .into(),
            version: "3.1.6".into(),
            product_code: "preview".into(),
            upgrade_code: if lite {
                LITE_FAMILY.into()
            } else {
                "preview".into()
            },
        };
        let installed = |version: &str, code: &str| {
            vec![Installed {
                product_code: code.into(),
                version: version.into(),
            }]
        };
        let screens: Vec<(&str, Option<usize>, Box<dyn Fn(&mut State)>)> = vec![
            (
                "1-fresh",
                None,
                Box::new(move |s: &mut State| s.ready(package(false), vec![])),
            ),
            (
                "2-update",
                None,
                Box::new(move |s: &mut State| s.ready(package(false), installed("3.1.5", "older"))),
            ),
            (
                "3-installed",
                None,
                Box::new(move |s: &mut State| {
                    s.ready(package(false), installed("3.1.6", "preview"))
                }),
            ),
            (
                "4-lite",
                None,
                Box::new(move |s: &mut State| s.ready(package(true), vec![])),
            ),
            (
                "5-busy",
                None,
                Box::new(move |s: &mut State| {
                    s.ready(package(false), vec![]);
                    s.busy = true;
                    s.installing = true;
                    s.heading = "Install in progress".into();
                }),
            ),
            (
                "6-error",
                None,
                Box::new(move |s: &mut State| {
                    s.ready(package(false), vec![]);
                    s.exit_code = 1603;
                    s.heading = "Could not complete".into();
                }),
            ),
            (
                "7-getting-lite",
                None,
                Box::new(move |s: &mut State| {
                    s.ready(package(false), vec![]);
                    s.busy = true;
                    s.switching_to_lite = Some(true);
                    s.heading = "Getting SwiftTunnel Lite".into();
                }),
            ),
            (
                "8-focus-install",
                Some(100),
                Box::new(move |s: &mut State| s.ready(package(false), vec![])),
            ),
            (
                "9-focus-lite",
                Some(LITE_ID),
                Box::new(move |s: &mut State| {
                    s.ready(package(false), installed("3.1.6", "preview"));
                }),
            ),
            (
                "10-sliding",
                None,
                Box::new(move |s: &mut State| {
                    s.ready(package(false), vec![]);
                    s.shift(|s| {
                        s.busy = true;
                        s.switching_to_lite = Some(true);
                    });
                    s.heading = "Getting SwiftTunnel Lite".into();
                    // A third of the way through the slide.
                    s.slide = Some((0.0, Instant::now() - SLIDE / 3));
                    s.frame = Instant::now();
                }),
            ),
        ];
        fonts::install();
        for dpi in [96u32, 144] {
            for (name, focus, setup) in &screens {
                let (commands, _) = std::sync::mpsc::channel();
                let (_, events) = std::sync::mpsc::channel();
                let mut state = State::new(commands, events);
                setup(&mut state);
                let path = std::path::Path::new(&dir).join(format!("{name}-{dpi}.png"));
                unsafe { render_png(&state, dpi, *focus, &path) };
            }
        }
    }

    #[test]
    fn chooser_pill_slides_from_where_it_is_to_the_chosen_half() {
        let (commands, _) = std::sync::mpsc::channel();
        let (_, events) = std::sync::mpsc::channel();
        let mut state = State::new(commands, events);
        state.ready(
            Package {
                name: "SwiftTunnel".into(),
                version: "3.1.6".into(),
                product_code: "full".into(),
                upgrade_code: crate::model::DESKTOP_FAMILY.into(),
            },
            vec![],
        );
        assert_eq!(state.pill_position(), 0.0);
        state.shift(|s| s.switching_to_lite = Some(true));
        // Until the animation clock moves on, the pill stays where it was.
        assert_eq!(state.pill_position(), 0.0);
        assert!(state.sliding());
        // Halfway through, it has covered most of the way and is slowing down.
        state.slide = Some((0.0, Instant::now() - SLIDE / 2));
        state.frame = Instant::now();
        let halfway = state.pill_position();
        assert!(halfway > 0.8 && halfway < 0.95, "{halfway}");
        // Turning back mid-slide starts from where the pill is, not a half.
        state.shift(|s| s.switching_to_lite = None);
        assert_eq!(state.pill_position(), halfway);
        state.frame = Instant::now() + SLIDE;
        assert_eq!(state.pill_position(), 0.0);
        assert!(!state.sliding());
        // A change that keeps the same half does not start a slide.
        state.slide = None;
        state.shift(|s| s.heading = "Checking".into());
        assert!(state.slide.is_none());
    }

    #[test]
    fn missing_worker_cannot_leave_setup_busy_or_claim_success() {
        let (commands, _) = std::sync::mpsc::channel();
        let (_, events) = std::sync::mpsc::channel();
        let mut state = State::new(commands, events);
        state.installing = true;
        assert!(state.worker_stopped());
        assert!(!state.busy && !state.installing);
        assert_eq!(state.exit_code, 1);
        assert!(state.package.is_none());
        assert!(!state.worker_stopped());
        assert!(state.detail.contains("may still be running"));
    }

    #[test]
    fn compact_controls_fit_at_common_display_scales() {
        for dpi in [96, 120, 144, 192] {
            for visible in [vec![0], vec![0, 3], vec![1, 2, 3]] {
                let mut previous = scaled(365, dpi);
                for &i in &visible {
                    let rect = action_rect(i, &visible, dpi);
                    assert!(rect.left >= previous && rect.right <= scaled(WIDTH - 27, dpi));
                    previous = rect.right;
                }
            }
            assert!(scaled(BUTTON_TOP + BUTTON_HEIGHT, dpi) < scaled(HEIGHT, dpi));
            for index in 0..2 {
                let rect = window_button_rect(index, dpi);
                assert!(rect.left >= 0 && rect.right < scaled(WIDTH, dpi));
                assert!(rect.bottom < scaled(48, dpi));
            }
        }
    }

    #[test]
    fn hidden_native_window_dispatches_actions_and_waits_for_worker_completion() {
        unsafe {
            let instance = GetModuleHandleW(None).unwrap();
            let class = WNDCLASSW {
                lpfnWndProc: Some(window_proc),
                hInstance: instance.into(),
                lpszClassName: w!("SwiftTunnelSetupWindowTest"),
                ..Default::default()
            };
            assert_ne!(RegisterClassW(&class), 0);
            let (commands, actions) = std::sync::mpsc::channel();
            let (events, updates) = std::sync::mpsc::channel();
            let state = Box::new(RefCell::new(State::new(commands, updates)));
            let hwnd = CreateWindowExW(
                WINDOW_EX_STYLE::default(),
                class.lpszClassName,
                w!("Hidden installer test"),
                WINDOW_STYLE_SETUP,
                0,
                0,
                WIDTH,
                HEIGHT,
                None,
                None,
                Some(instance.into()),
                Some((state.as_ref() as *const RefCell<State>).cast()),
            )
            .unwrap();
            // No visible window, backend worker, msiexec, or installation is started.
            assert_eq!(state.borrow().buttons.len(), 4);
            assert_eq!(state.borrow().window_buttons.len(), 2);
            assert!(state.borrow().details_button.is_some());
            assert_eq!(GetWindowLongW(hwnd, GWL_STYLE) as u32 & WS_CAPTION.0, 0);
            let region = CreateRectRgn(0, 0, 0, 0);
            if rounded_by_windows(hwnd) {
                // Windows 11 rounds the window itself, so it carries no region.
                assert_eq!(GetWindowRgn(hwnd, region), GDI_REGION_TYPE(0));
            } else {
                assert_ne!(GetWindowRgn(hwnd, region), GDI_REGION_TYPE(0));
                assert!(!PtInRegion(region, 0, 0).as_bool());
                assert!(PtInRegion(region, 30, 30).as_bool());
            }
            let _ = DeleteObject(region.into());
            let mut title_point = POINT { x: 100, y: 35 };
            let _ = ClientToScreen(hwnd, &mut title_point);
            let hit_point = LPARAM(
                ((title_point.y as u16 as u32) << 16 | title_point.x as u16 as u32) as isize,
            );
            assert_eq!(
                SendMessageW(hwnd, WM_NCHITTEST, Some(WPARAM(0)), Some(hit_point)).0,
                HTCAPTION as isize
            );
            assert!(state.borrow().busy);
            events
                .send(Event::Ready(
                    Package {
                        name: "SwiftTunnel".into(),
                        version: "3.1.6".into(),
                        product_code: "test".into(),
                        upgrade_code: "test".into(),
                    },
                    vec![],
                ))
                .unwrap();
            SendMessageW(hwnd, WM_TIMER, Some(WPARAM(1)), Some(LPARAM(0)));
            assert!(!state.borrow().busy);
            if crate::MSI_NAME == "SwiftTunnel-Installer.msi" {
                // The half already chosen does nothing.
                SendMessageW(hwnd, WM_COMMAND, Some(WPARAM(PRODUCT_ID)), Some(LPARAM(0)));
                assert!(actions.try_recv().is_err() && !state.borrow().busy);
                // Switching products is asynchronous and cannot queue transactions
                // or another download until the worker returns a verified package.
                SendMessageW(hwnd, WM_COMMAND, Some(WPARAM(LITE_ID)), Some(LPARAM(0)));
                assert_eq!(actions.try_recv().unwrap(), Command::DownloadLite);
                assert!(state.borrow().busy && !state.borrow().installing);
                // The chooser shows the pick at once; the package changes only
                // when the worker returns.
                assert!(state.borrow().shows_lite() && !state.borrow().lite_selected());
                SendMessageW(hwnd, WM_COMMAND, Some(WPARAM(100)), Some(LPARAM(0)));
                SendMessageW(hwnd, WM_COMMAND, Some(WPARAM(LITE_ID)), Some(LPARAM(0)));
                assert!(actions.try_recv().is_err());
                events
                    .send(Event::Failed("Download interrupted".into()))
                    .unwrap();
                SendMessageW(hwnd, WM_TIMER, Some(WPARAM(1)), Some(LPARAM(0)));
                assert!(!state.borrow().busy && !state.borrow().shows_lite());
                assert_eq!(
                    state.borrow().package.as_ref().unwrap().product_code,
                    "test"
                );
                SendMessageW(hwnd, WM_COMMAND, Some(WPARAM(LITE_ID)), Some(LPARAM(0)));
                assert_eq!(actions.try_recv().unwrap(), Command::DownloadLite);
                events
                    .send(Event::Ready(
                        Package {
                            name: "SwiftTunnel Lite".into(),
                            version: "3.1.6".into(),
                            product_code: "lite".into(),
                            upgrade_code: LITE_FAMILY.into(),
                        },
                        vec![],
                    ))
                    .unwrap();
                SendMessageW(hwnd, WM_TIMER, Some(WPARAM(1)), Some(LPARAM(0)));
                assert!(state.borrow().lite_selected());
                assert_eq!(state.borrow().exit_code, 0);
                SendMessageW(hwnd, WM_COMMAND, Some(WPARAM(PRODUCT_ID)), Some(LPARAM(0)));
                assert_eq!(actions.try_recv().unwrap(), Command::UseBundled);
                events
                    .send(Event::Ready(
                        Package {
                            name: "SwiftTunnel".into(),
                            version: "3.1.6".into(),
                            product_code: "test".into(),
                            upgrade_code: crate::model::DESKTOP_FAMILY.into(),
                        },
                        vec![],
                    ))
                    .unwrap();
                SendMessageW(hwnd, WM_TIMER, Some(WPARAM(1)), Some(LPARAM(0)));
                assert!(!state.borrow().lite_selected());
            }
            SendMessageW(hwnd, WM_COMMAND, Some(WPARAM(100)), Some(LPARAM(0)));
            assert_eq!(
                actions.try_recv().unwrap(),
                Command::Execute(Action::Install)
            );
            assert!(state.borrow().installing);
            // A repeated click cannot queue a second transaction.
            SendMessageW(hwnd, WM_COMMAND, Some(WPARAM(100)), Some(LPARAM(0)));
            assert!(actions.try_recv().is_err());
            events
                .send(Event::Finished(
                    Action::Install,
                    3010,
                    vec![Installed {
                        product_code: "test".into(),
                        version: "3.1.6".into(),
                    }],
                ))
                .unwrap();
            SendMessageW(hwnd, WM_TIMER, Some(WPARAM(1)), Some(LPARAM(0)));
            assert!(!state.borrow().installing);
            assert!(state.borrow().reboot_required);
            assert_eq!(state.borrow().exit_code, 3010);
            SendMessageW(hwnd, WM_COMMAND, Some(WPARAM(101)), Some(LPARAM(0)));
            assert!(actions.try_recv().is_err());
            events
                .send(Event::Failed(
                    "A detailed error that must remain available in Details.".repeat(20),
                ))
                .unwrap();
            SendMessageW(hwnd, WM_TIMER, Some(WPARAM(1)), Some(LPARAM(0)));
            assert_eq!(state.borrow().exit_code, 1);
            let detail_control = state.borrow().details_button.unwrap();
            assert_ne!(
                GetWindowLongW(detail_control, GWL_STYLE) as u32 & WS_VISIBLE.0,
                0
            );
            let error_text = state.borrow().detail.clone();
            drop(events);
            SendMessageW(hwnd, WM_TIMER, Some(WPARAM(1)), Some(LPARAM(0)));
            assert!(state.borrow().package.is_none());
            assert_eq!(state.borrow().detail, error_text);
            SendMessageW(hwnd, WM_COMMAND, Some(WPARAM(CLOSE_ID)), Some(LPARAM(0)));
            let mut close = MSG::default();
            assert!(PeekMessageW(&mut close, Some(hwnd), WM_CLOSE, WM_CLOSE, PM_REMOVE).as_bool());
            DispatchMessageW(&close);
            assert!(!IsWindow(Some(hwnd)).as_bool());
            let mut message = MSG::default();
            assert!(PeekMessageW(&mut message, None, WM_QUIT, WM_QUIT, PM_REMOVE).as_bool());
            let _ = UnregisterClassW(class.lpszClassName, Some(instance.into()));
        }
    }
}
