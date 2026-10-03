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
use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::*;
use windows::Win32::Graphics::Dwm::{DwmSetWindowAttribute, DWMWA_USE_IMMERSIVE_DARK_MODE};
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
// The website's petal theme: the hero's petals in their own colours, ink copy
// on the pale band, white controls on the cobalt below. COLORREF is BGR; the
// u32 values are GDI+ ARGB.
const BG: COLORREF = COLORREF(0xe64727);
const INK: COLORREF = COLORREF(0x140b0a);
/// The site's muted copy: ink at 86% over the pale petals.
const INK_SOFT: COLORREF = COLORREF(0x352928);
const WHITE: COLORREF = COLORREF(0xffffff);
const WHITE_SOFT: COLORREF = COLORREF(0xfbd6d2);
const INK_ARGB: u32 = 0xff0a0b14;
const INK_HAIRLINE: u32 = 0x240a0b14;
const WIDTH: i32 = 720;
const HEIGHT: i32 = 432;
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
const WINDOW_STYLE_SETUP: WINDOW_STYLE = WINDOW_STYLE(WS_POPUP.0 | WS_SYSMENU.0 | WS_MINIMIZEBOX.0);

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
        INK,
        DT_LEFT | DT_SINGLELINE | DT_VCENTER,
    );
    let rule = s(64) + measure(dc, "SwiftTunnel", s(17), w!("Figtree ExtraBold")) + s(14);
    drawing::line(dc, rule, s(24), rule, s(38), INK_HAIRLINE, s(1) as f32);
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
        INK_SOFT,
        DT_LEFT | DT_SINGLELINE | DT_VCENTER,
    );

    // The homepage's index row: a hairline, the product, the version.
    drawing::line(
        dc,
        s(28),
        s(60),
        s(WIDTH - 28),
        s(60),
        INK_HAIRLINE,
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
        INK_SOFT,
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
        INK,
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

    // The headline, set like the homepage's: the second line in outline.
    text(
        dc,
        "Less setup.",
        RECT {
            left: s(26),
            top: s(96),
            right: s(470),
            bottom: s(152),
        },
        s(50),
        800,
        INK,
        DT_LEFT | DT_SINGLELINE,
    );
    text_face(
        dc,
        "More play.",
        RECT {
            left: s(26),
            top: s(148),
            right: s(470),
            bottom: s(204),
        },
        s(50),
        INK,
        DT_LEFT | DT_SINGLELINE,
        w!("Figtree ExtraBold"),
        0,
        true,
    );

    // The app chooser's track and the line that says what the choice means.
    // Its two halves are owner-drawn buttons painted over the track.
    if crate::MSI_NAME == "SwiftTunnel-Installer.msi" {
        mono(
            dc,
            "CHOOSE YOUR APP",
            RECT {
                left: s(28),
                top: s(222),
                right: s(330),
                bottom: s(236),
            },
            s(10),
            INK_SOFT,
            DT_LEFT | DT_SINGLELINE | DT_VCENTER,
        );
        paint_chooser_frame(dc, dpi);
        text(
            dc,
            if state.shows_lite() {
                "Just the tunnel, the FPS unlock and an FPS counter. Light on your PC."
            } else {
                "Everything: routing, PC boosts and the in-game overlay."
            },
            RECT {
                left: s(28),
                top: s(290),
                right: s(460),
                bottom: s(310),
            },
            s(12),
            400,
            INK_SOFT,
            DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS,
        );
    }

    // The homepage hero's card: the mark on frosted glass in a hairline
    // square, a crosshair through it and mono labels in the corners.
    let card = RECT {
        left: s(484),
        top: s(92),
        right: s(WIDTH - 28),
        bottom: s(300),
    };
    let hairline = s(1);
    drawing::rect(dc, card, 0x66ffffff);
    let (cx, cy) = ((card.left + card.right) / 2, (card.top + card.bottom) / 2);
    drawing::frame(dc, card, INK_HAIRLINE, hairline);
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
        INK_HAIRLINE,
    );
    drawing::rect(
        dc,
        RECT {
            left: cx,
            top,
            right: cx + hairline,
            bottom: cy,
        },
        INK_HAIRLINE,
    );
    drawing::rect(
        dc,
        RECT {
            left: cx,
            top: cy + hairline,
            right: cx + hairline,
            bottom,
        },
        INK_HAIRLINE,
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
            INK_SOFT,
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
}

/// The chooser's glass track, in window coordinates.
fn chooser_rect(dpi: u32) -> RECT {
    RECT {
        left: scaled(28, dpi),
        top: scaled(242, dpi),
        right: scaled(348, dpi),
        bottom: scaled(282, dpi),
    }
}

/// One half of the chooser: the full app (0) or Lite (1).
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

unsafe fn paint_chooser_frame(dc: HDC, dpi: u32) {
    let track = chooser_rect(dpi);
    drawing::rounded(dc, track, scaled(9, dpi) as f32, 0xa6ffffff);
    drawing::rounded_outline(
        dc,
        track,
        scaled(9, dpi) as f32,
        INK_HAIRLINE,
        scaled(1, dpi) as f32,
    );
}

// Paint the corresponding background under owner-drawn buttons, so rounded
// corners have no rectangular card or contrasting box behind them.
unsafe fn paint_control_background(dc: HDC, dpi: u32, left: i32, top: i32) {
    let saved = SaveDC(dc);
    let _ = SetViewportOrgEx(dc, -left, -top, None);
    artwork::paint(
        dc,
        RECT {
            left: 0,
            top: 0,
            right: scaled(WIDTH, dpi),
            bottom: scaled(HEIGHT, dpi),
        },
    );
    let _ = RestoreDC(dc, saved);
}

/// A chooser half sits on the glass track, so its background is the artwork
/// with that slice of the track painted over it.
unsafe fn paint_segment_background(dc: HDC, dpi: u32, left: i32, top: i32) {
    paint_control_background(dc, dpi, left, top);
    let saved = SaveDC(dc);
    let _ = SetViewportOrgEx(dc, -left, -top, None);
    paint_chooser_frame(dc, dpi);
    let _ = RestoreDC(dc, saved);
}

unsafe fn paint_segment(
    dc: HDC,
    bounds: RECT,
    dpi: u32,
    label: &str,
    active: bool,
    disabled: bool,
    focused: bool,
) {
    if active {
        drawing::rounded(
            dc,
            bounds,
            scaled(6, dpi) as f32,
            if disabled { 0x990a0b14 } else { INK_ARGB },
        );
    }
    text(
        dc,
        label,
        bounds,
        scaled(13, dpi),
        600,
        if active {
            WHITE
        } else if disabled {
            COLORREF(0x9a8f8a)
        } else {
            INK
        },
        DT_CENTER | DT_VCENTER | DT_SINGLELINE,
    );
    if focused {
        drawing::rounded_outline(
            dc,
            bounds,
            scaled(6, dpi) as f32,
            0xff2747e6,
            scaled(2, dpi) as f32,
        );
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

/// Buttons on the cobalt, like the homepage hero's: the main action solid
/// white with ink text, the others white outlines.
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
    let radius = scaled(6, dpi) as f32;
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
        if pressed {
            drawing::rounded(dc, bounds, radius, 0x29ffffff);
        }
        drawing::rounded_outline(
            dc,
            bounds,
            radius,
            if disabled { 0x59ffffff } else { 0xccffffff },
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
            COLORREF(0xd9b3ad)
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

/// Minimise and close, drawn in ink over the pale petals.
unsafe fn paint_window_button(
    dc: HDC,
    bounds: RECT,
    dpi: u32,
    close: bool,
    pressed: bool,
    focused: bool,
) {
    if pressed {
        drawing::rounded(dc, bounds, scaled(6, dpi) as f32, 0x240a0b14);
    }
    let cx = (bounds.left + bounds.right) / 2;
    let cy = (bounds.top + bounds.bottom) / 2;
    let r = scaled(5, dpi);
    let width = scaled(1, dpi).max(1) as f32 * 1.25;
    if close {
        drawing::line(dc, cx - r, cy - r, cx + r, cy + r, INK_ARGB, width);
        drawing::line(dc, cx - r, cy + r, cx + r, cy - r, INK_ARGB, width);
    } else {
        drawing::line(dc, cx - r, cy, cx + r, cy, INK_ARGB, width);
    }
    if focused {
        drawing::rounded_outline(
            dc,
            bounds,
            scaled(6, dpi) as f32,
            0xff2747e6,
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
    paint(dc, bounds, dpi, &state);
    let visible = visible_actions(&state);
    for &i in &visible {
        let rect = action_rect(i, &visible, dpi);
        paint_button(
            dc,
            rect,
            dpi,
            if i == 0 && existing {
                "Update"
            } else {
                LABELS[i]
            },
            false,
            false,
            false,
            false,
        );
    }
    for i in 0..2 {
        paint_window_button(dc, window_button_rect(i, dpi), dpi, i == 1, false, false);
    }
    if crate::MSI_NAME == "SwiftTunnel-Installer.msi" {
        for (i, label) in ["SwiftTunnel", "SwiftTunnel Lite"].iter().enumerate() {
            paint_segment(dc, segment_rect(i, dpi), dpi, label, i == 0, false, false);
        }
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
            let label = if state.installed.is_empty() {
                "Install"
            } else {
                "Update"
            };
            let _ = SetWindowTextW(*button, PCWSTR(wide(label).as_ptr()));
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
        // Owner-drawn: the active half follows the choice, so repaint both.
        let _ = InvalidateRect(Some(*button), None, false);
    }
    layout(hwnd, state);
    let _ = InvalidateRect(Some(hwnd), None, false);
}

unsafe fn layout(hwnd: HWND, state: &State) {
    let dpi = GetDpiForWindow(hwnd).max(96);
    let visible = visible_actions(state);
    for (i, button) in state.product_buttons.iter().enumerate() {
        let r = segment_rect(i, dpi);
        let _ = MoveWindow(
            *button,
            r.left,
            r.top,
            r.right - r.left,
            r.bottom - r.top,
            true,
        );
    }
    for (i, button) in state.buttons.iter().enumerate() {
        let r = action_rect(i, &visible, dpi);
        let _ = MoveWindow(
            *button,
            r.left,
            r.top,
            r.right - r.left,
            r.bottom - r.top,
            true,
        );
    }
    let region = CreateRoundRectRgn(
        0,
        0,
        scaled(WIDTH, dpi) + 1,
        scaled(HEIGHT, dpi) + 1,
        scaled(14, dpi),
        scaled(14, dpi),
    );
    if SetWindowRgn(hwnd, Some(region), true) == 0 {
        let _ = DeleteObject(region.into());
    }
    for (i, button) in state.window_buttons.iter().enumerate() {
        let rect = window_button_rect(i, dpi);
        let _ = MoveWindow(
            *button,
            rect.left,
            rect.top,
            rect.right - rect.left,
            rect.bottom - rect.top,
            true,
        );
    }
    if let Some(button) = state.details_button {
        let r = details_rect(dpi);
        let _ = MoveWindow(
            button,
            r.left,
            r.top,
            r.right - r.left,
            r.bottom - r.top,
            true,
        );
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
        let _ = KillTimer(Some(hwnd), 1);
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
    let Ok(mut guard) = (*ptr).try_borrow_mut() else {
        return DefWindowProcW(hwnd, msg, wp, lp);
    };
    let state = &mut *guard;
    match msg {
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
            layout(hwnd, state);
            update_buttons(hwnd, state);
            SetTimer(Some(hwnd), 1, 150, None);
            LRESULT(0)
        }
        WM_TIMER => {
            loop {
                let event = match state.events.try_recv() {
                    Ok(event) => event,
                    Err(std::sync::mpsc::TryRecvError::Empty) => break,
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        if state.worker_stopped() {
                            update_buttons(hwnd, state);
                        }
                        break;
                    }
                };
                match event {
                    Event::Progress(status) => {
                        state.heading = status;
                    }
                    Event::Ready(package, installed) => state.ready(package, installed),
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
                        state.exit_code = 1;
                        state.busy = false;
                        state.installing = false;
                        state.switching_to_lite = None;
                        state.heading = "Setup needs attention".into();
                        state.detail = error;
                    }
                }
                update_buttons(hwnd, state);
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
                if state.product_buttons.is_empty()
                    || !state.can_choose()
                    || wants_lite == state.lite_selected()
                {
                    return LRESULT(0);
                }
                let command = if wants_lite {
                    Command::DownloadLite
                } else {
                    Command::UseBundled
                };
                if state.commands.send(command).is_ok() {
                    state.busy = true;
                    state.exit_code = 0;
                    state.switching_to_lite = Some(wants_lite);
                    state.heading = if command == Command::UseBundled {
                        "Switching to SwiftTunnel".into()
                    } else {
                        "Getting SwiftTunnel Lite".into()
                    };
                } else {
                    state.exit_code = 1;
                    state.heading = "Please reopen Setup".into();
                    state.detail = "The installer worker is unavailable.".into();
                }
                update_buttons(hwnd, state);
                return LRESULT(0);
            }
            if (100..104).contains(&id) && !state.busy && !state.reboot_required {
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
                    update_buttons(hwnd, state);
                }
            }
            LRESULT(0)
        }
        WM_DRAWITEM => {
            let item = &*(lp.0 as *const DRAWITEMSTRUCT);
            if item.CtlID as usize == MINIMIZE_ID || item.CtlID as usize == CLOSE_ID {
                let dpi = GetDpiForWindow(hwnd).max(96);
                let rect = window_button_rect(item.CtlID as usize - MINIMIZE_ID, dpi);
                paint_control_background(item.hDC, dpi, rect.left, rect.top);
                paint_window_button(
                    item.hDC,
                    item.rcItem,
                    GetDpiForWindow(hwnd).max(96),
                    item.CtlID as usize == CLOSE_ID,
                    (item.itemState.0 & ODS_SELECTED.0) != 0,
                    (item.itemState.0 & ODS_FOCUS.0) != 0,
                );
                return LRESULT(1);
            }
            let dpi = GetDpiForWindow(hwnd).max(96);
            let id = item.CtlID as usize;
            if id == PRODUCT_ID || id == LITE_ID {
                let index = id - PRODUCT_ID;
                let rect = segment_rect(index, dpi);
                paint_segment_background(item.hDC, dpi, rect.left, rect.top);
                paint_segment(
                    item.hDC,
                    item.rcItem,
                    dpi,
                    if index == 0 {
                        "SwiftTunnel"
                    } else {
                        "SwiftTunnel Lite"
                    },
                    (index == 1) == state.shows_lite(),
                    (item.itemState.0 & ODS_DISABLED.0) != 0,
                    (item.itemState.0 & ODS_FOCUS.0) != 0,
                );
                return LRESULT(1);
            }
            let pos = if id == DETAILS_ID {
                details_rect(dpi)
            } else {
                action_rect(
                    item.CtlID.saturating_sub(100) as usize,
                    &visible_actions(state),
                    dpi,
                )
            };
            paint_control_background(item.hDC, dpi, pos.left, pos.top);
            let disabled = (item.itemState.0 & ODS_DISABLED.0) != 0;
            let primary = false;
            let pressed = (item.itemState.0 & ODS_SELECTED.0) != 0;
            let mut label = [0u16; 64];
            let count = GetWindowTextW(item.hwndItem, &mut label);
            paint_button(
                item.hDC,
                item.rcItem,
                GetDpiForWindow(hwnd).max(96),
                &String::from_utf16_lossy(&label[..count.max(0) as usize]),
                disabled,
                primary,
                pressed,
                (item.itemState.0 & ODS_FOCUS.0) != 0,
            );
            LRESULT(1)
        }
        WM_PAINT => {
            let mut ps = PAINTSTRUCT::default();
            let dc = BeginPaint(hwnd, &mut ps);
            let mut bounds = RECT::default();
            let _ = GetClientRect(hwnd, &mut bounds);
            paint(dc, bounds, GetDpiForWindow(hwnd).max(96), state);
            let _ = EndPaint(hwnd, &ps);
            LRESULT(0)
        }
        WM_ERASEBKGND => LRESULT(1),
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
            layout(hwnd, state);
            LRESULT(0)
        }
        _ => DefWindowProcW(hwnd, msg, wp, lp),
    }
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

    /// Paints one owner-drawn control as WM_DRAWITEM does: on a surface of its
    /// own, in its own coordinates, then copied into place.
    unsafe fn paint_control(dc: HDC, rect: RECT, draw: &dyn Fn(HDC, RECT)) {
        let (w, h) = (rect.right - rect.left, rect.bottom - rect.top);
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

    /// Everything the window shows for a state, composed the way the window
    /// composes it: the painted background, then each visible control.
    unsafe fn paint_screen(dc: HDC, bounds: RECT, dpi: u32, state: &State, focus: Option<usize>) {
        paint(dc, bounds, dpi, state);
        let visible = visible_actions(state);
        let mut buttons: Vec<(usize, RECT, &str)> = visible
            .iter()
            .map(|&i| {
                let label = if i == 0 && !state.installed.is_empty() {
                    "Update"
                } else {
                    LABELS[i]
                };
                (100 + i, action_rect(i, &visible, dpi), label)
            })
            .collect();
        if state.exit_code != 0 {
            buttons.push((DETAILS_ID, details_rect(dpi), "Details"));
        }
        for (id, rect, label) in buttons {
            paint_control(dc, rect, &|surface, local| {
                paint_control_background(surface, dpi, rect.left, rect.top);
                let disabled = state.busy && id != DETAILS_ID;
                paint_button(
                    surface,
                    local,
                    dpi,
                    label,
                    disabled,
                    false,
                    false,
                    focus == Some(id),
                );
            });
        }
        for i in 0..2 {
            let rect = window_button_rect(i, dpi);
            paint_control(dc, rect, &|surface, local| {
                paint_control_background(surface, dpi, rect.left, rect.top);
                paint_window_button(
                    surface,
                    local,
                    dpi,
                    i == 1,
                    false,
                    focus == Some(MINIMIZE_ID + i),
                );
            });
        }
        if crate::MSI_NAME == "SwiftTunnel-Installer.msi" {
            for (i, label) in ["SwiftTunnel", "SwiftTunnel Lite"].iter().enumerate() {
                let rect = segment_rect(i, dpi);
                paint_control(dc, rect, &|surface, local| {
                    paint_segment_background(surface, dpi, rect.left, rect.top);
                    let active = (i == 1) == state.shows_lite();
                    paint_segment(
                        surface,
                        local,
                        dpi,
                        label,
                        active,
                        !state.can_choose(),
                        focus == Some(PRODUCT_ID + i),
                    );
                });
            }
        }
    }

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
        paint_screen(
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
        SelectObject(dc, previous);
        let _ = DeleteObject(bitmap.into());
        let _ = DeleteDC(dc);
        ReleaseDC(None, screen);
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
            assert_ne!(GetWindowRgn(hwnd, region), GDI_REGION_TYPE(0));
            assert!(!PtInRegion(region, 0, 0).as_bool());
            assert!(PtInRegion(region, 30, 30).as_bool());
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
