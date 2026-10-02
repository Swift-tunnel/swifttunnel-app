#[path = "artwork.rs"]
mod artwork;
#[path = "fonts.rs"]
mod fonts;

use crate::backend::Event;
use crate::model::{action_allowed, result_message, Action, Installed, Package};
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
// Website design/new-theme, 2bccb79: light petal palette. COLORREF uses BGR.
const BG: COLORREF = COLORREF(0xfcf7f7);
const INK: COLORREF = COLORREF(0x140b0a);
const MUTED: COLORREF = COLORREF(0x765b56);
const BORDER: COLORREF = COLORREF(0xf2e4e1);
const CARD: COLORREF = COLORREF(0xfbf0ee);
const WIDTH: i32 = 780;
const HEIGHT: i32 = 450;
const BUTTON_TOP: i32 = 352;
const BUTTON_HEIGHT: i32 = 40;
const BUTTON_STEP: i32 = 179;
const BUTTON_WIDTH: i32 = 167;
const MINIMIZE_ID: usize = 200;
const CLOSE_ID: usize = 201;
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
    commands: Sender<Action>,
    events: Receiver<Event>,
}

impl State {
    pub fn new(commands: Sender<Action>, events: Receiver<Event>) -> Self {
        Self {
            package: None,
            installed: vec![],
            heading: "Preparing your installer".into(),
            detail:
                "Verifying the bundled package and checking your installation. No download needed."
                    .into(),
            busy: true,
            installing: false,
            reboot_required: false,
            exit_code: 0,
            buttons: vec![],
            window_buttons: vec![],
            commands,
            events,
        }
    }

    fn ready(&mut self, package: Package, installed: Vec<Installed>) {
        self.heading = match installed.as_slice() {
            [] => "Ready to install".into(),
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
                format!("Version {} is installed. Update to {} with this offline package.", current.version, package.version),
            [_] => "This Setup is for a different version. To repair, download Setup for the installed version or a newer release.".into(),
            _ => "Open Windows Settings > Apps to choose a copy. Setup will not guess which one to change.".into(),
        };
        self.package = Some(package);
        self.installed = installed;
        self.busy = false;
        self.installing = false;
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
    let panel = RECT {
        left: scaled(20, dpi),
        top: scaled(246, dpi),
        right: bounds.right - scaled(20, dpi),
        bottom: scaled(408, dpi),
    };
    let brush = CreateSolidBrush(CARD);
    let pen = CreatePen(PS_SOLID, scaled(1, dpi), COLORREF(0xf3d7cf));
    let previous_brush = SelectObject(dc, brush.into());
    let previous_pen = SelectObject(dc, pen.into());
    let _ = RoundRect(
        dc,
        panel.left,
        panel.top,
        panel.right,
        panel.bottom,
        scaled(24, dpi),
        scaled(24, dpi),
    );
    SelectObject(dc, previous_pen);
    SelectObject(dc, previous_brush);
    let _ = DeleteObject(pen.into());
    let _ = DeleteObject(brush.into());
    let x = scaled(36, dpi);
    let right = bounds.right - x;
    let area = |top, bottom| RECT {
        left: x,
        right,
        top: scaled(top, dpi),
        bottom: scaled(bottom, dpi),
    };
    text(
        dc,
        "SwiftTunnel",
        area(28, 55),
        scaled(21, dpi),
        600,
        INK,
        DT_LEFT,
    );
    text_face(
        dc,
        "WINDOWS / SETUP",
        RECT {
            right: right - scaled(104, dpi),
            ..area(35, 54)
        },
        scaled(10, dpi),
        MUTED,
        DT_RIGHT,
        w!("Azeret Mono"),
        0,
        false,
    );
    fill(dc, &area(66, 67), BORDER);
    text_face(
        dc,
        "01 / INSTALLATION",
        area(78, 97),
        scaled(10, dpi),
        MUTED,
        DT_LEFT,
        w!("Azeret Mono"),
        scaled(1, dpi),
        false,
    );
    text_face(
        dc,
        "Lower ping.",
        area(102, 159),
        scaled(48, dpi),
        INK,
        DT_LEFT,
        w!("Figtree ExtraBold"),
        -scaled(2, dpi),
        false,
    );
    text_face(
        dc,
        "Faster",
        area(155, 214),
        scaled(48, dpi),
        INK,
        DT_LEFT,
        w!("Figtree ExtraBold"),
        -scaled(2, dpi),
        false,
    );
    let signal = RECT {
        left: scaled(185, dpi),
        ..area(155, 214)
    };
    text_face(
        dc,
        "gameplay.",
        signal,
        scaled(48, dpi),
        INK,
        DT_LEFT,
        w!("Figtree ExtraBold"),
        -scaled(2, dpi),
        true,
    );
    let subtitle = state
        .package
        .as_ref()
        .map(|p| {
            format!(
                "{}  /  V{}  /  OFFLINE SETUP",
                p.name.to_uppercase(),
                p.version
            )
        })
        .unwrap_or_else(|| "BUNDLED PACKAGE  /  OFFLINE SETUP".into());
    text_face(
        dc,
        &subtitle,
        area(220, 241),
        scaled(10, dpi),
        MUTED,
        DT_LEFT,
        w!("Azeret Mono"),
        0,
        false,
    );

    text(
        dc,
        &state.heading,
        area(260, 291),
        scaled(22, dpi),
        600,
        INK,
        DT_LEFT,
    );
    text(
        dc,
        &state.detail,
        area(298, 344),
        scaled(14, dpi),
        400,
        MUTED,
        DT_LEFT | DT_WORDBREAK,
    );
    text(
        dc,
        if state.installing {
            "Windows Installer is working. Please keep this window open."
        } else if state.reboot_required {
            "Restart Windows to finish. Setup will never restart it automatically."
        } else {
            "Your installer stays protected for future updates and repairs."
        },
        area(420, 445),
        scaled(12, dpi),
        400,
        COLORREF(0xffffff),
        DT_LEFT | DT_WORDBREAK,
    );
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
    fill(dc, &bounds, CARD);
    let background = if primary {
        if pressed {
            COLORREF(0x352b2a)
        } else {
            INK
        }
    } else if pressed {
        COLORREF(0xf8e9e7)
    } else {
        CARD
    };
    let brush = CreateSolidBrush(background);
    let pen = CreatePen(
        PS_SOLID,
        scaled(1, dpi),
        if primary {
            background
        } else if disabled {
            BORDER
        } else {
            COLORREF(0xcfc6c3)
        },
    );
    let old_brush = SelectObject(dc, brush.into());
    let old_pen = SelectObject(dc, pen.into());
    let _ = RoundRect(
        dc,
        bounds.left,
        bounds.top,
        bounds.right,
        bounds.bottom,
        scaled(8, dpi),
        scaled(8, dpi),
    );
    SelectObject(dc, old_pen);
    SelectObject(dc, old_brush);
    let _ = DeleteObject(pen.into());
    let _ = DeleteObject(brush.into());
    text(
        dc,
        label,
        bounds,
        scaled(14, dpi),
        600,
        if disabled {
            COLORREF(0xb0a6a1)
        } else if primary {
            COLORREF(0xffffff)
        } else {
            INK
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
    fill(dc, &bounds, if pressed { BORDER } else { CARD });
    let cx = (bounds.left + bounds.right) / 2;
    let cy = (bounds.top + bounds.bottom) / 2;
    let r = scaled(5, dpi);
    let pen = CreatePen(PS_SOLID, scaled(1, dpi).max(1), INK);
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
        top: scaled(24, dpi),
        right: scaled(WIDTH - 68 + index as i32 * 40, dpi),
        bottom: scaled(56, dpi),
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
    for (i, label) in LABELS.iter().enumerate() {
        let enabled = action_allowed(
            state.package.as_ref().unwrap(),
            &state.installed,
            ACTIONS[i],
        );
        let left = scaled(36 + i as i32 * BUTTON_STEP, dpi);
        paint_button(
            dc,
            RECT {
                left,
                right: left + scaled(BUTTON_WIDTH, dpi),
                top: scaled(BUTTON_TOP, dpi),
                bottom: scaled(BUTTON_TOP + BUTTON_HEIGHT, dpi),
            },
            dpi,
            if i == 0 && existing { "Update" } else { label },
            !enabled,
            enabled && i == 0,
            false,
            false,
        );
    }
    for i in 0..2 {
        paint_window_button(dc, window_button_rect(i, dpi), dpi, i == 1, false, false);
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
        if index == 0 {
            let label = if state.installed.is_empty() {
                "Install"
            } else {
                "Update"
            };
            let _ = SetWindowTextW(*button, PCWSTR(wide(label).as_ptr()));
        }
    }
    let _ = InvalidateRect(Some(hwnd), None, false);
}

unsafe fn layout(hwnd: HWND, state: &State) {
    let dpi = GetDpiForWindow(hwnd).max(96);
    for (i, button) in state.buttons.iter().enumerate() {
        let _ = MoveWindow(
            *button,
            scaled(36 + i as i32 * BUTTON_STEP, dpi),
            scaled(BUTTON_TOP, dpi),
            scaled(BUTTON_WIDTH, dpi),
            scaled(BUTTON_HEIGHT, dpi),
            true,
        );
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
            && point.y < scaled(66, dpi)
        {
            return LRESULT(HTCAPTION as isize);
        }
    }
    if msg == WM_COMMAND {
        match wp.0 & 0xffff {
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
            let dark = 0i32;
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
            layout(hwnd, state);
            update_buttons(hwnd, state);
            SetTimer(Some(hwnd), 1, 150, None);
            LRESULT(0)
        }
        WM_TIMER => {
            while let Ok(event) = state.events.try_recv() {
                match event {
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
            if (100..104).contains(&id) && !state.busy && !state.reboot_required {
                let action = ACTIONS[id - 100];
                if state
                    .package
                    .as_ref()
                    .is_some_and(|p| action_allowed(p, &state.installed, action))
                {
                    if state.commands.send(action).is_ok() {
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
            let disabled = (item.itemState.0 & ODS_DISABLED.0) != 0;
            let primary = item.CtlID == 100 && !disabled;
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
            assert_eq!(GetWindowLongW(hwnd, GWL_STYLE) as u32 & WS_CAPTION.0, 0);
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
            SendMessageW(hwnd, WM_COMMAND, Some(WPARAM(100)), Some(LPARAM(0)));
            assert_eq!(actions.try_recv().unwrap(), Action::Install);
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
