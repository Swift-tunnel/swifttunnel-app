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
// Native petal artwork and pale controls. COLORREF uses BGR.
const BG: COLORREF = COLORREF(0x1d0f0c);
const INK: COLORREF = COLORREF(0x140b0a);
const WIDTH: i32 = 720;
const HEIGHT: i32 = 432;
const BUTTON_TOP: i32 = 364;
const BUTTON_HEIGHT: i32 = 40;
const BUTTON_WIDTH: i32 = 96;
const MINIMIZE_ID: usize = 200;
const CLOSE_ID: usize = 201;
const DETAILS_ID: usize = 202;
const PRODUCT_ID: usize = 203;
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
    product_button: Option<HWND>,
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
            product_button: None,
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
    }

    fn lite_selected(&self) -> bool {
        self.package
            .as_ref()
            .is_some_and(|p| p.upgrade_code.eq_ignore_ascii_case(LITE_FAMILY))
    }

    fn product_label(&self) -> &'static str {
        if self.lite_selected() {
            "Back to Desktop"
        } else {
            "Get SwiftTunnel Lite"
        }
    }

    fn worker_stopped(&mut self) -> bool {
        if self.worker_closed {
            return false;
        }
        self.worker_closed = true;
        self.package = None;
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

unsafe fn fill(dc: HDC, rect: &RECT, color: COLORREF) {
    let brush = CreateSolidBrush(color);
    FillRect(dc, rect, brush);
    let _ = DeleteObject(brush.into());
}

unsafe fn paint(dc: HDC, bounds: RECT, dpi: u32, state: &State) {
    fonts::install();
    fill(dc, &bounds, BG);
    artwork::paint(dc, bounds);
    drawing::logo(
        dc,
        RECT {
            left: scaled(28, dpi),
            top: scaled(19, dpi),
            right: scaled(62, dpi),
            bottom: scaled(53, dpi),
        },
    );
    text(
        dc,
        "SwiftTunnel Setup",
        RECT {
            left: scaled(73, dpi),
            top: scaled(25, dpi),
            right: scaled(310, dpi),
            bottom: scaled(49, dpi),
        },
        scaled(15, dpi),
        600,
        COLORREF(0xffffff),
        DT_LEFT | DT_SINGLELINE,
    );
    text(
        dc,
        if state.lite_selected() {
            "SWIFTTUNNEL LITE / WINDOWS"
        } else {
            "SWIFTTUNNEL / WINDOWS"
        },
        RECT {
            left: scaled(32, dpi),
            top: scaled(143, dpi),
            right: scaled(440, dpi),
            bottom: scaled(165, dpi),
        },
        scaled(11, dpi),
        600,
        COLORREF(0xd8c4bd),
        DT_LEFT | DT_SINGLELINE,
    );
    text(
        dc,
        "Less setup.\nMore play.",
        RECT {
            left: scaled(30, dpi),
            top: scaled(172, dpi),
            right: scaled(475, dpi),
            bottom: scaled(289, dpi),
        },
        scaled(48, dpi),
        800,
        COLORREF(0xffffff),
        DT_LEFT,
    );
    drawing::logo(
        dc,
        RECT {
            left: scaled(505, dpi),
            top: scaled(166, dpi),
            right: scaled(659, dpi),
            bottom: scaled(300, dpi),
        },
    );
    if crate::MSI_NAME == "SwiftTunnel-Installer.msi" {
        text(
            dc,
            if state.lite_selected() {
                "Standalone Lite. No WebView2."
            } else {
                "Smaller native app. Internet required."
            },
            RECT {
                left: scaled(209, dpi),
                top: scaled(316, dpi),
                right: scaled(575, dpi),
                bottom: scaled(335, dpi),
            },
            scaled(11, dpi),
            400,
            COLORREF(0xd8c4bd),
            DT_LEFT | DT_SINGLELINE,
        );
    }
    let status_color = if state.exit_code != 0 {
        0xffefa45c
    } else if state.busy {
        0xffb8b3dc
    } else {
        0xff83d8bc
    };
    drawing::rounded(
        dc,
        RECT {
            left: scaled(28, dpi),
            top: scaled(371, dpi),
            right: scaled(36, dpi),
            bottom: scaled(379, dpi),
        },
        scaled(4, dpi) as f32,
        status_color,
    );
    text(
        dc,
        &state.heading,
        RECT {
            left: scaled(48, dpi),
            top: scaled(363, dpi),
            right: scaled(365, dpi),
            bottom: scaled(386, dpi),
        },
        scaled(16, dpi),
        600,
        COLORREF(0xffffff),
        DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS,
    );
    let subtitle = if state.exit_code != 0 {
        "View details to continue".to_string()
    } else if state.installing {
        "Please wait. Your PC will not restart.".into()
    } else if state.busy && state.package.is_some() {
        "Secure download. Close Setup to cancel.".into()
    } else if state.busy {
        "Checking your installation".into()
    } else if state.installed.is_empty() {
        "Ready when you are".into()
    } else {
        match state.installed.as_slice() {
            [installed] => format!("Version {}", installed.version),
            _ => "Choose an action".into(),
        }
    };
    text(
        dc,
        &subtitle,
        RECT {
            left: scaled(48, dpi),
            top: scaled(386, dpi),
            right: scaled(365, dpi),
            bottom: scaled(408, dpi),
        },
        scaled(11, dpi),
        400,
        COLORREF(0xc9b8b4),
        DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS,
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
    let mut left = WIDTH - 27 - total;
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
    let background = if disabled {
        0xff292637
    } else if pressed {
        if primary {
            0xffc3b9ee
        } else {
            0xff3c354f
        }
    } else if primary {
        0xffe5ddff
    } else {
        0xff302b40
    };
    drawing::rounded(dc, bounds, scaled(9, dpi) as f32, background);
    text(
        dc,
        label,
        bounds,
        scaled(13, dpi),
        600,
        if disabled {
            COLORREF(0x938b99)
        } else if primary {
            INK
        } else {
            COLORREF(0xf5eff3)
        },
        DT_CENTER | DT_VCENTER | DT_SINGLELINE,
    );
    if focused {
        let _ = DrawFocusRect(dc, &bounds);
    }
}

unsafe fn paint_window_button(
    dc: HDC,
    bounds: RECT,
    dpi: u32,
    close: bool,
    pressed: bool,
    focused: bool,
) {
    if pressed {
        fill(dc, &bounds, COLORREF(0x8b6551));
    }
    let cx = (bounds.left + bounds.right) / 2;
    let cy = (bounds.top + bounds.bottom) / 2;
    let r = scaled(5, dpi);
    let pen = CreatePen(PS_SOLID, scaled(1, dpi).max(1), COLORREF(0xd8c9c4));
    let old = SelectObject(dc, pen.into());
    if close {
        let _ = MoveToEx(dc, cx - r, cy - r, None);
        let _ = LineTo(dc, cx + r, cy + r);
        let _ = MoveToEx(dc, cx - r, cy + r, None);
        let _ = LineTo(dc, cx + r, cy - r);
    } else {
        let _ = MoveToEx(dc, cx - r, cy, None);
        let _ = LineTo(dc, cx + r, cy);
    }
    SelectObject(dc, old);
    let _ = DeleteObject(pen.into());
    if focused {
        let _ = DrawFocusRect(dc, &bounds);
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

fn product_button_rect(dpi: u32) -> RECT {
    RECT {
        left: scaled(32, dpi),
        top: scaled(307, dpi),
        right: scaled(196, dpi),
        bottom: scaled(341, dpi),
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
        paint_button(
            dc,
            product_button_rect(dpi),
            dpi,
            state.product_label(),
            false,
            false,
            false,
            false,
        );
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
    if let Some(button) = state.product_button {
        let _ = EnableWindow(
            button,
            !state.busy && !state.reboot_required && !state.worker_closed,
        );
        let _ = SetWindowTextW(button, PCWSTR(wide(state.product_label()).as_ptr()));
    }
    layout(hwnd, state);
    let _ = InvalidateRect(Some(hwnd), None, false);
}

unsafe fn layout(hwnd: HWND, state: &State) {
    let dpi = GetDpiForWindow(hwnd).max(96);
    let visible = visible_actions(state);
    if let Some(button) = state.product_button {
        let r = product_button_rect(dpi);
        let _ = MoveWindow(
            button,
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
        let _ = MoveWindow(
            button,
            scaled(WIDTH - 123, dpi),
            scaled(320, dpi),
            scaled(96, dpi),
            scaled(28, dpi),
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
            if crate::MSI_NAME == "SwiftTunnel-Installer.msi" {
                state.product_button = CreateWindowExW(
                    WINDOW_EX_STYLE::default(),
                    w!("BUTTON"),
                    w!("Get SwiftTunnel Lite"),
                    WS_CHILD | WS_VISIBLE | WS_TABSTOP | WINDOW_STYLE(BS_OWNERDRAW as u32),
                    0,
                    0,
                    0,
                    0,
                    Some(hwnd),
                    Some(HMENU(PRODUCT_ID as *mut _)),
                    None,
                    None,
                )
                .ok();
                if state.product_button.is_none() {
                    return LRESULT(-1);
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
            if id == PRODUCT_ID
                && state.product_button.is_some()
                && !state.busy
                && !state.reboot_required
                && !state.worker_closed
            {
                let command = if state.lite_selected() {
                    Command::UseBundled
                } else {
                    Command::DownloadLite
                };
                if state.commands.send(command).is_ok() {
                    state.busy = true;
                    state.exit_code = 0;
                    state.heading = if command == Command::UseBundled {
                        "Checking Desktop".into()
                    } else {
                        "Preparing Lite download".into()
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
            let pos = if item.CtlID as usize == PRODUCT_ID {
                product_button_rect(dpi)
            } else if item.CtlID as usize == DETAILS_ID {
                RECT {
                    left: scaled(WIDTH - 123, dpi),
                    top: scaled(320, dpi),
                    ..Default::default()
                }
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
                // Switching products is asynchronous and cannot queue transactions
                // or another download until the worker returns a verified package.
                SendMessageW(hwnd, WM_COMMAND, Some(WPARAM(PRODUCT_ID)), Some(LPARAM(0)));
                assert_eq!(actions.try_recv().unwrap(), Command::DownloadLite);
                assert!(state.borrow().busy && !state.borrow().installing);
                SendMessageW(hwnd, WM_COMMAND, Some(WPARAM(100)), Some(LPARAM(0)));
                SendMessageW(hwnd, WM_COMMAND, Some(WPARAM(PRODUCT_ID)), Some(LPARAM(0)));
                assert!(actions.try_recv().is_err());
                events
                    .send(Event::Failed("Download interrupted".into()))
                    .unwrap();
                SendMessageW(hwnd, WM_TIMER, Some(WPARAM(1)), Some(LPARAM(0)));
                assert!(!state.borrow().busy);
                assert_eq!(
                    state.borrow().package.as_ref().unwrap().product_code,
                    "test"
                );
                SendMessageW(hwnd, WM_COMMAND, Some(WPARAM(PRODUCT_ID)), Some(LPARAM(0)));
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
