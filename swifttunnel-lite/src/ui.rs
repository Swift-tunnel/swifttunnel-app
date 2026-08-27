//! The window.
//!
//! Everything is drawn in one `WM_PAINT`: shapes are composited by
//! [`crate::canvas`] into an offscreen buffer, blitted once, and the text is
//! drawn by GDI on top. Nothing animates and nothing is repainted on a timer
//! unless something actually changed, so an idle Lite costs no CPU and no GPU
//! at all. That is the whole reason this client is not a webview.
//!
//! The window is frameless because the app is: a 28px bar carrying the
//! wordmark, the free-tier budget and two buttons, then the tabs, then the
//! screen. `WM_NCHITTEST` gives the bar back to Windows as a caption so
//! dragging and snapping still work.

use std::ffi::c_void;

use windows::Win32::Foundation::{COLORREF, HWND, LPARAM, LRESULT, POINT, RECT, WPARAM};
use windows::Win32::Graphics::Dwm::{
    DWMWA_USE_IMMERSIVE_DARK_MODE, DWMWA_WINDOW_CORNER_PREFERENCE, DwmSetWindowAttribute,
};
use windows::Win32::Graphics::Gdi::{
    ScreenToClient,
    BeginPaint, DT_CENTER, DT_LEFT, DT_NOPREFIX, DT_RIGHT, DT_SINGLELINE, DT_VCENTER, EndPaint,
    ExcludeClipRect, GetMonitorInfoW, HDC, InvalidateRect, MONITOR_DEFAULTTONEAREST,
    MONITOR_DEFAULTTOPRIMARY, MONITORINFO, MonitorFromPoint, MonitorFromWindow, PAINTSTRUCT,
    SelectClipRgn,
};
use windows::Win32::UI::Input::KeyboardAndMouse::{
    TME_LEAVE, TRACKMOUSEEVENT, TrackMouseEvent,
};
use windows::Win32::UI::HiDpi::{
    DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2, GetDpiForMonitor, GetDpiForWindow,
    MDT_EFFECTIVE_DPI, SetProcessDpiAwarenessContext,
};
use windows::Win32::UI::WindowsAndMessaging::*;
use windows::core::w;

use crate::canvas::{Canvas, Rgba};
use crate::engine::Engine;
use crate::state::{Push, State, Status};
use crate::theme;
use crate::view::{
    self, Action, Face, Fonts, Frame, Metrics, Screen, Shape, TextRun, contains,
};

/// Repaint cadence while something is moving.
///
/// Only armed when the tunnel is up or mid-connect: a session timer that does
/// not tick looks broken, but a window sitting on Settings has nothing to
/// redraw and should cost nothing.
/// Not exported by the windows crate, so it is named here rather than left
/// as a bare identifier in the match below. An unresolved name there is a
/// binding pattern that matches every value, which silently swallowed every
/// message after it: no clicks, no repaints, no close.
const MOUSE_LEAVE: u32 = 0x02A3;

const TICK_TIMER: usize = 1;
const TICK_MS: u32 = 1000;

pub struct App {
    engine: Engine,
    pub state: State,
    m: Metrics,
    fonts: Fonts,
    chrome: Frame,
    content: Frame,
    scroll: i32,
    max_scroll: i32,
    hot: Option<Action>,
    dpi: i32,
    ticking: bool,
}

impl App {
    /// Rebuild the laid-out frames from the current state.
    ///
    /// Called after anything that changes what should be on screen. Layout is
    /// cheap (a walk over about twenty items) and doing it in one place means
    /// the painted pixels and the clickable rectangles can never disagree.
    fn rebuild(&mut self, client: RECT) {
        self.chrome = chrome(&self.state, &self.m, client, self.hot.as_ref());

        let area = content_area(&self.m, client);
        let items = crate::screens::build(&self.state);

        // Laid out once at the top to find its height, so the scroll can be
        // clamped before the frame that gets painted is built.
        let probe = view::layout(&items, area, &self.m, 0, None);
        let viewport = area.bottom - area.top;
        self.max_scroll = (probe.content_height - viewport).max(0);
        self.scroll = self.scroll.clamp(0, self.max_scroll);

        self.content = view::layout(&items, area, &self.m, self.scroll, self.hot.as_ref());

        if self.max_scroll > 0 {
            add_scrollbar(&mut self.content, area, &self.m, self.scroll, self.max_scroll);
        }
    }

    /// Whether the window needs a heartbeat right now.
    fn wants_tick(&self) -> bool {
        matches!(self.state.tunnel.status, Status::Connected | Status::Working)
    }

    fn action_at(&self, x: i32, y: i32) -> Option<Action> {
        view::hit(&self.chrome, x, y).or_else(|| view::hit(&self.content, x, y))
    }
}

/// Where the screen is drawn, below the chrome and inside the margin.
fn content_area(m: &Metrics, client: RECT) -> RECT {
    RECT {
        left: client.left + m.s(theme::PAD),
        top: client.top + m.s(theme::TITLE_H + theme::TAB_H) + m.s(theme::PAD),
        right: client.right - m.s(theme::PAD),
        bottom: client.bottom - m.s(theme::PAD),
    }
}

// ── Chrome ──────────────────────────────────────────────────────────────────

const TABS: [(Screen, &str); 3] = [
    (Screen::Connect, "Connect"),
    (Screen::Roblox, "Roblox"),
    (Screen::Settings, "Settings"),
];

const LEFT_MID: windows::Win32::Graphics::Gdi::DRAW_TEXT_FORMAT =
    windows::Win32::Graphics::Gdi::DRAW_TEXT_FORMAT(
        DT_SINGLELINE.0 | DT_VCENTER.0 | DT_LEFT.0 | DT_NOPREFIX.0,
    );
const RIGHT_MID: windows::Win32::Graphics::Gdi::DRAW_TEXT_FORMAT =
    windows::Win32::Graphics::Gdi::DRAW_TEXT_FORMAT(
        DT_SINGLELINE.0 | DT_VCENTER.0 | DT_RIGHT.0 | DT_NOPREFIX.0,
    );
const CENTRE_MID: windows::Win32::Graphics::Gdi::DRAW_TEXT_FORMAT =
    windows::Win32::Graphics::Gdi::DRAW_TEXT_FORMAT(
        DT_SINGLELINE.0 | DT_VCENTER.0 | DT_CENTER.0 | DT_NOPREFIX.0,
    );

fn rect(left: i32, top: i32, right: i32, bottom: i32) -> RECT {
    RECT {
        left,
        top,
        right,
        bottom,
    }
}

fn push_round(f: &mut Frame, r: RECT, radius: i32, fill: Option<Rgba>) {
    f.shapes.push(Shape::Round {
        rect: r,
        radius,
        fill,
        stroke: None,
    });
}

fn push_text(
    f: &mut Frame,
    r: RECT,
    text: &str,
    face: Face,
    ink: COLORREF,
    format: windows::Win32::Graphics::Gdi::DRAW_TEXT_FORMAT,
) {
    if text.is_empty() {
        return;
    }
    f.texts.push(TextRun {
        rect: r,
        text: text.to_string(),
        face,
        ink,
        format,
    });
}

/// The title bar and the tab strip.
fn chrome(state: &State, m: &Metrics, client: RECT, hot: Option<&Action>) -> Frame {
    let mut f = Frame::default();
    let title_h = m.s(theme::TITLE_H);
    let tab_h = m.s(theme::TAB_H);
    let width = client.right - client.left;

    // One plate behind both strips, so the tab underline sits on the same
    // surface as the wordmark rather than on a seam.
    push_round(
        &mut f,
        rect(0, 0, width, title_h + tab_h),
        0,
        Some(theme::CHROME),
    );
    push_round(
        &mut f,
        rect(0, title_h + tab_h - 1, width, title_h + tab_h),
        0,
        Some(theme::BORDER),
    );

    // ── Title bar ──
    let pad = m.s(10);
    // 78, not 70: at 12px semibold the wordmark is 74 wide and the shorter
    // rect was clipping it to "SwiftTunne".
    let wordmark_w = m.s(78);
    push_text(
        &mut f,
        rect(pad, 0, pad + wordmark_w, title_h),
        "SwiftTunnel",
        Face::Title,
        theme::TEXT_SECONDARY,
        LEFT_MID,
    );
    let pill = rect(
        pad + wordmark_w + m.s(5),
        title_h / 2 - m.s(7),
        pad + wordmark_w + m.s(5) + m.s(26),
        title_h / 2 + m.s(7),
    );
    push_round(&mut f, pill, m.s(3), Some(theme::ACTIVE));
    push_text(
        &mut f,
        pill,
        "LITE",
        Face::Caption,
        theme::TEXT_MUTED,
        CENTRE_MID,
    );

    // Window buttons, right to left.
    let button_w = m.s(32);
    let close = rect(width - button_w, 0, width, title_h);
    let minimise = rect(close.left - button_w, 0, close.left, title_h);

    if hot == Some(&Action::Close) {
        push_round(&mut f, close, 0, Some(Rgba::hex(0xE5484D)));
    } else if hot == Some(&Action::Minimise) {
        push_round(&mut f, minimise, 0, Some(theme::HOVER));
    }

    // A rule rather than a glyph: at this size a hyphen in any face sits off
    // centre and looks like a typo.
    let bar_w = m.s(9);
    push_round(
        &mut f,
        rect(
            minimise.left + (button_w - bar_w) / 2,
            title_h / 2,
            minimise.left + (button_w + bar_w) / 2,
            title_h / 2 + 1,
        ),
        0,
        Some(Rgba::hex(0x8A8A8A)),
    );
    push_text(
        &mut f,
        close,
        "\u{2715}",
        Face::Icon,
        if hot == Some(&Action::Close) {
            theme::TEXT
        } else {
            theme::TEXT_MUTED
        },
        CENTRE_MID,
    );
    f.hots.push((minimise, Action::Minimise));
    f.hots.push((close, Action::Close));

    // The free-tier budget, when the server is enforcing one.
    if let Some(secs) = state.free_tier_secs {
        push_text(
            &mut f,
            rect(minimise.left - m.s(50), 0, minimise.left - m.s(4), title_h),
            &free_tier(secs),
            Face::Value,
            free_tier_ink(secs),
            RIGHT_MID,
        );
    }

    // ── Tabs ──
    let tab_w = width / 3;
    for (i, (screen, label)) in TABS.iter().enumerate() {
        let x = i as i32 * tab_w;
        let r = rect(
            x,
            title_h,
            if i == 2 { width } else { x + tab_w },
            title_h + tab_h,
        );
        // Lit even while a picker is pushed over it: the region list is
        // part of Connect, and dropping the underline made the window
        // look like it had lost its place.
        let selected = state.screen == *screen;
        let hovered = hot == Some(&Action::Tab(*screen));
        push_text(
            &mut f,
            r,
            label,
            Face::Tab,
            if selected {
                theme::TEXT
            } else if hovered {
                theme::TEXT_SECONDARY
            } else {
                theme::TEXT_DIMMED
            },
            CENTRE_MID,
        );
        if selected {
            let inset = m.s(12);
            push_round(
                &mut f,
                rect(r.left + inset, r.bottom - m.s(2), r.right - inset, r.bottom),
                0,
                Some(theme::ACCENT),
            );
        }
        f.hots.push((r, Action::Tab(*screen)));
    }

    f
}

/// A hairline thumb beside a list that overflows.
fn add_scrollbar(f: &mut Frame, area: RECT, m: &Metrics, scroll: i32, max_scroll: i32) {
    let track = area.bottom - area.top;
    let total = track + max_scroll;
    let thumb = ((track as f32 / total as f32) * track as f32).max(m.s(24) as f32) as i32;
    let travel = track - thumb;
    let y = area.top + (scroll as f32 / max_scroll as f32 * travel as f32) as i32;
    let w = m.s(theme::SCROLLBAR_W);
    push_round(
        f,
        rect(area.right - w, y, area.right, y + thumb),
        w / 2,
        Some(Rgba::hexa(0x8A8A8A, 0.45)),
    );
}

fn free_tier(seconds: u32) -> String {
    if seconds < 60 {
        return "<1m".into();
    }
    let h = seconds / 3600;
    let m = (seconds % 3600) / 60;
    if h > 0 {
        format!("{h}h {m}m")
    } else {
        format!("{m}m")
    }
}

fn free_tier_ink(seconds: u32) -> COLORREF {
    if seconds <= 600 {
        theme::ERROR_TEXT
    } else if seconds <= 1800 {
        theme::LATENCY_FAIR
    } else {
        theme::TEXT_DIMMED
    }
}

// ── Painting ────────────────────────────────────────────────────────────────

/// Draw one whole frame.
///
/// Shared by the window and the preview harness so there is only ever one
/// rendering path, and a change cannot look right in the preview and wrong on
/// screen.
pub fn paint(dc: HDC, client: RECT, app: &App) {
    let width = client.right - client.left;
    let height = client.bottom - client.top;
    if width <= 0 || height <= 0 {
        return;
    }

    let mut canvas = Canvas::new(width, height, theme::BG);

    let area = content_area(&app.m, client);
    view::paint_shapes(&mut canvas, &app.chrome);

    // The content scrolls under the chrome, so it is confined to its own band.
    let previous = canvas.clip_rows(area.top - app.m.s(theme::PAD) + 1, client.bottom);
    view::paint_shapes(&mut canvas, &app.content);
    canvas.restore_clip(previous);

    crate::surface::blit(dc, &canvas);

    // Text is drawn straight onto the device context afterwards, because GDI's
    // rasteriser is genuinely good and already has the embedded Geist faces.
    view::paint_text(dc, &app.fonts, &app.chrome);

    unsafe {
        // Same band as the shapes, expressed as a clip: everything above the
        // content area is excluded so a scrolled row cannot print over the tabs.
        let _ = ExcludeClipRect(
            dc,
            0,
            0,
            width,
            area.top - app.m.s(theme::PAD) + 1,
        );
        view::paint_text(dc, &app.fonts, &app.content);
        let _ = SelectClipRgn(dc, None);
    }
}

// ── Window ──────────────────────────────────────────────────────────────────

pub fn run(engine: Engine) -> windows::core::Result<()> {
    unsafe {
        // Set explicitly rather than relying on the embedded manifest, which
        // declares PerMonitorV2 but still left GetDpiForWindow answering 96 on
        // a 125% display, so the window came out a fifth too small and was
        // then bitmap-stretched by the compositor.
        let _ = SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);

        let instance = windows::Win32::System::LibraryLoader::GetModuleHandleW(None)?;
        let class = w!("SwiftTunnelLiteWindow");
        let wc = WNDCLASSW {
            hCursor: LoadCursorW(None, IDC_ARROW)?,
            hInstance: instance.into(),
            lpszClassName: class,
            style: CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: Some(wndproc),
            // The whole client area is painted every time, so letting Windows
            // erase it first would only flash the wrong colour.
            hbrBackground: windows::Win32::Graphics::Gdi::HBRUSH(std::ptr::null_mut()),
            ..Default::default()
        };
        RegisterClassW(&wc);

        // Resolved before the window exists. Creating at 96 and resizing
        // afterwards does not work: Windows sends WM_DPICHANGED once shown and
        // its own sizing wins over a SetWindowPos from the handler.
        let dpi = {
            let monitor = MonitorFromPoint(POINT { x: 0, y: 0 }, MONITOR_DEFAULTTOPRIMARY);
            let mut x = 0u32;
            let mut y = 0u32;
            match GetDpiForMonitor(monitor, MDT_EFFECTIVE_DPI, &mut x, &mut y) {
                Ok(()) => (x as i32).max(96),
                Err(_) => 96,
            }
        };

        let app = new_app(engine, dpi);
        let m = Metrics::new(dpi);

        let hwnd = CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            class,
            w!("SwiftTunnel Lite"),
            // Frameless. The bar at the top is the app's own, and
            // WM_NCHITTEST hands it back as a caption so dragging still works.
            WS_POPUP | WS_MINIMIZEBOX | WS_SYSMENU,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            m.s(theme::WINDOW_W),
            m.s(theme::WINDOW_H),
            None,
            None,
            Some(instance.into()),
            Some(Box::into_raw(app) as *const c_void),
        )?;

        let dark: i32 = 1;
        let _ = DwmSetWindowAttribute(
            hwnd,
            DWMWA_USE_IMMERSIVE_DARK_MODE,
            &dark as *const _ as *const c_void,
            size_of::<i32>() as u32,
        );
        // DWMWCP_ROUND. The app's own window is rounded, and a hard-cornered
        // popup on Windows 11 reads as a dialog from another decade.
        let round: i32 = 2;
        let _ = DwmSetWindowAttribute(
            hwnd,
            DWMWA_WINDOW_CORNER_PREFERENCE,
            &round as *const _ as *const c_void,
            size_of::<i32>() as u32,
        );

        centre(hwnd);
        let _ = ShowWindow(hwnd, SW_SHOW);

        // Published now rather than in WM_CREATE: the engine's threads
        // are already running and a ping that lands before this point
        // would update the snapshot with nothing to tell about it.
        if let Some(app) = app_of(hwnd) {
            app.engine.attach(hwnd.0 as isize);
        }

        let mut message = MSG::default();
        while GetMessageW(&mut message, None, 0, 0).into() {
            let _ = TranslateMessage(&message);
            DispatchMessageW(&message);
        }
        Ok(())
    }
}

/// CW_USEDEFAULT places a popup at the top-left rather than cascading it.
fn centre(hwnd: HWND) {
    unsafe {
        let mut r = RECT::default();
        if GetWindowRect(hwnd, &mut r).is_err() {
            return;
        }
        let w = r.right - r.left;
        let h = r.bottom - r.top;
        let monitor = MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST);
        let mut info = MONITORINFO {
            cbSize: size_of::<MONITORINFO>() as u32,
            ..Default::default()
        };
        if !GetMonitorInfoW(monitor, &mut info).as_bool() {
            return;
        }
        let work = info.rcWork;
        let _ = SetWindowPos(
            hwnd,
            None,
            work.left + (work.right - work.left - w) / 2,
            work.top + (work.bottom - work.top - h) / 2,
            0,
            0,
            SWP_NOSIZE | SWP_NOZORDER,
        );
    }
}

/// Build the application state. Shared by the window and the preview so there
/// is one definition of what a fresh Lite looks like.
pub fn new_app(engine: Engine, dpi: i32) -> Box<App> {
    let m = Metrics::new(dpi);
    let mut state = State::default();
    engine.fill(&mut state);

    let mut app = Box::new(App {
        engine,
        state,
        m,
        fonts: Fonts::new(&m),
        chrome: Frame::default(),
        content: Frame::default(),
        scroll: 0,
        max_scroll: 0,
        hot: None,
        dpi,
        ticking: false,
    });
    let client = rect(0, 0, m.s(theme::WINDOW_W), m.s(theme::WINDOW_H));
    app.rebuild(client);
    app
}

/// Paint one frame to a file instead of onto the screen.
///
/// Lite runs elevated, and Windows blocks a non-elevated process from raising
/// or capturing an elevated window, so this is the only way to see a visual
/// change without asking a person to look at their own screen. It drives the
/// same [`paint`] the window does, so the two cannot drift.
pub fn render_preview(
    engine: Engine,
    path: &str,
    screen: Screen,
    push: Push,
    connected: bool,
) -> std::io::Result<()> {
    // Give the background fetch a moment to land, or every preview of the
    // region list shows an empty one. Only the harness waits; the window
    // fills in as the data arrives.
    std::thread::sleep(std::time::Duration::from_millis(2500));

    let dpi = 96;
    let m = Metrics::new(dpi);
    let mut app = new_app(engine, dpi);
    app.state.screen = screen;
    app.state.push = push;
    if connected {
        app.state.tunnel.status = Status::Connected;
        app.state.tunnel.elapsed = 1_337;
        app.state.tunnel.ping_ms = Some(42);
        app.state.tunnel.bytes_down = 5_242_880;
        app.state.tunnel.bytes_up = 1_048_576;
        app.state.tunnel.region = app.state.regions.first().map(|r| r.id.clone());
    }

    let w = m.s(theme::WINDOW_W);
    let h = m.s(theme::WINDOW_H);
    let client = rect(0, 0, w, h);
    app.rebuild(client);

    crate::preview::render(path, w, h, |dc, r| paint(dc, r, &app))
}

// ── Message loop ────────────────────────────────────────────────────────────

fn app_of(hwnd: HWND) -> Option<&'static mut App> {
    // SAFETY: the pointer is stored in WM_CREATE and cleared in WM_DESTROY, so
    // it is either null or a live Box for the whole time messages arrive.
    unsafe {
        let ptr = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut App;
        ptr.as_mut()
    }
}

fn client_of(hwnd: HWND) -> RECT {
    let mut r = RECT::default();
    // SAFETY: hwnd is valid for the lifetime of every message handled here.
    unsafe {
        let _ = GetClientRect(hwnd, &mut r);
    }
    r
}

fn repaint(hwnd: HWND) {
    // SAFETY: invalidating a live window; the paint itself happens later.
    unsafe {
        let _ = InvalidateRect(Some(hwnd), None, false);
    }
}

/// Arm or disarm the heartbeat so an idle window costs nothing.
fn sync_timer(hwnd: HWND, app: &mut App) {
    let wanted = app.wants_tick();
    if wanted == app.ticking {
        return;
    }
    // SAFETY: setting and killing a timer on a live window.
    unsafe {
        if wanted {
            SetTimer(Some(hwnd), TICK_TIMER, TICK_MS, None);
        } else {
            let _ = KillTimer(Some(hwnd), TICK_TIMER);
        }
    }
    app.ticking = wanted;
}

extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    unsafe {
        match msg {
            WM_CREATE => {
                let cs = lparam.0 as *const CREATESTRUCTW;
                SetWindowLongPtrW(hwnd, GWLP_USERDATA, (*cs).lpCreateParams as isize);
                if let Some(app) = app_of(hwnd) {
                    app.dpi = GetDpiForWindow(hwnd).max(96) as i32;
                    app.m = Metrics::new(app.dpi);
                    app.fonts = Fonts::new(&app.m);
                    app.rebuild(client_of(hwnd));
                    sync_timer(hwnd, app);
                }
                LRESULT(0)
            }

            // The title bar is the app's own, so Windows is told it is the
            // caption. The buttons on it are excluded, or they would drag the
            // window instead of being clicked.
            WM_NCHITTEST => {
                let Some(app) = app_of(hwnd) else {
                    return DefWindowProcW(hwnd, msg, wparam, lparam);
                };
                let mut point = POINT {
                    x: (lparam.0 & 0xFFFF) as i16 as i32,
                    y: ((lparam.0 >> 16) & 0xFFFF) as i16 as i32,
                };
                let _ = ScreenToClient(hwnd, &mut point);
                let bar = rect(0, 0, client_of(hwnd).right, app.m.s(theme::TITLE_H));
                if contains(bar, point.x, point.y)
                    && app.action_at(point.x, point.y).is_none()
                {
                    return LRESULT(HTCAPTION as isize);
                }
                LRESULT(HTCLIENT as isize)
            }

            WM_PAINT => {
                if let Some(app) = app_of(hwnd) {
                    let mut ps = PAINTSTRUCT::default();
                    let dc = BeginPaint(hwnd, &mut ps);
                    paint(dc, client_of(hwnd), app);
                    let _ = EndPaint(hwnd, &ps);
                }
                LRESULT(0)
            }

            WM_MOUSEMOVE => {
                if let Some(app) = app_of(hwnd) {
                    let x = (lparam.0 & 0xFFFF) as i16 as i32;
                    let y = ((lparam.0 >> 16) & 0xFFFF) as i16 as i32;
                    // Windows sends WM_MOUSELEAVE only when asked, and only
                    // once per request, so it is re-armed on every move.
                    // Without it a highlighted row stays lit after the
                    // pointer has left the window.
                    let mut track = TRACKMOUSEEVENT {
                        cbSize: size_of::<TRACKMOUSEEVENT>() as u32,
                        dwFlags: TME_LEAVE,
                        hwndTrack: hwnd,
                        dwHoverTime: 0,
                    };
                    let _ = TrackMouseEvent(&mut track);

                    let next = app.action_at(x, y);
                    if next != app.hot {
                        app.hot = next;
                        app.rebuild(client_of(hwnd));
                        repaint(hwnd);
                    }
                }
                LRESULT(0)
            }

            MOUSE_LEAVE => {
                if let Some(app) = app_of(hwnd)
                    && app.hot.is_some()
                {
                    app.hot = None;
                    app.rebuild(client_of(hwnd));
                    repaint(hwnd);
                }
                LRESULT(0)
            }

            WM_MOUSEWHEEL => {
                if let Some(app) = app_of(hwnd)
                    && app.max_scroll > 0
                {
                    let delta = ((wparam.0 >> 16) & 0xFFFF) as i16 as i32;
                    let step = app.m.s(theme::ROW_H) * delta / WHEEL_DELTA as i32;
                    let next = (app.scroll - step).clamp(0, app.max_scroll);
                    if next != app.scroll {
                        app.scroll = next;
                        app.rebuild(client_of(hwnd));
                        repaint(hwnd);
                    }
                }
                LRESULT(0)
            }

            WM_LBUTTONDOWN => {
                if let Some(app) = app_of(hwnd) {
                    let x = (lparam.0 & 0xFFFF) as i16 as i32;
                    let y = ((lparam.0 >> 16) & 0xFFFF) as i16 as i32;
                    if let Some(action) = app.action_at(x, y) {
                        dispatch(hwnd, app, action);
                    }
                }
                LRESULT(0)
            }

            WM_TIMER => {
                if wparam.0 == TICK_TIMER
                    && let Some(app) = app_of(hwnd)
                {
                    app.engine.fill(&mut app.state);
                    app.rebuild(client_of(hwnd));
                    sync_timer(hwnd, app);
                    repaint(hwnd);
                }
                LRESULT(0)
            }

            // Posted by the engine when a background job lands, so a finished
            // connect or a fresh ping shows up without waiting for a tick.
            crate::engine::WM_ENGINE_UPDATE => {
                if let Some(app) = app_of(hwnd) {
                    app.engine.fill(&mut app.state);
                    app.rebuild(client_of(hwnd));
                    sync_timer(hwnd, app);
                    repaint(hwnd);
                }
                LRESULT(0)
            }

            WM_DPICHANGED => {
                if let Some(app) = app_of(hwnd) {
                    app.dpi = ((wparam.0 & 0xFFFF) as i32).max(96);
                    app.m = Metrics::new(app.dpi);
                    app.fonts = Fonts::new(&app.m);
                    let target = lparam.0 as *const RECT;
                    if !target.is_null() {
                        let r = *target;
                        let _ = SetWindowPos(
                            hwnd,
                            None,
                            r.left,
                            r.top,
                            r.right - r.left,
                            r.bottom - r.top,
                            SWP_NOZORDER | SWP_NOACTIVATE,
                        );
                    }
                    app.rebuild(client_of(hwnd));
                    repaint(hwnd);
                }
                LRESULT(0)
            }

            WM_SIZE => {
                if let Some(app) = app_of(hwnd) {
                    app.rebuild(client_of(hwnd));
                }
                LRESULT(0)
            }

            // Nothing to erase: the whole client area is painted every time.
            WM_ERASEBKGND => LRESULT(1),

            WM_DESTROY => {
                let ptr = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut App;
                if !ptr.is_null() {
                    SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
                    drop(Box::from_raw(ptr));
                }
                PostQuitMessage(0);
                LRESULT(0)
            }

            _ => DefWindowProcW(hwnd, msg, wparam, lparam),
        }
    }
}

/// Carry out one action.
///
/// Anything that could block goes to the engine, which owns the background
/// threads; the message loop never waits on the network or the driver.
fn dispatch(hwnd: HWND, app: &mut App, action: Action) {
    match action {
        Action::Minimise => {
            // SAFETY: a live window.
            unsafe {
                let _ = ShowWindow(hwnd, SW_MINIMIZE);
            }
            return;
        }
        Action::Close => {
            // SAFETY: a live window.
            unsafe {
                let _ = PostMessageW(Some(hwnd), WM_CLOSE, WPARAM(0), LPARAM(0));
            }
            return;
        }
        Action::Tab(screen) => {
            app.state.screen = screen;
            app.state.push = Push::None;
            app.scroll = 0;
        }
        Action::Back => {
            app.state.push = Push::None;
            app.scroll = 0;
        }
        Action::OpenRegions => {
            app.state.push = Push::Regions;
            app.scroll = 0;
            app.engine.refresh_regions();
        }
        Action::OpenAdapters => {
            app.state.push = Push::Adapters;
            app.scroll = 0;
            app.engine.refresh_adapters();
        }
        other => {
            app.engine.dispatch(other, &mut app.state);
            app.state.push = match app.state.push {
                // A pick closes the list it was made in.
                Push::Regions | Push::Adapters => Push::None,
                Push::None => Push::None,
            };
        }
    }

    app.engine.fill(&mut app.state);
    app.hot = None;
    app.rebuild(client_of(hwnd));
    sync_timer(hwnd, app);
    repaint(hwnd);
}
