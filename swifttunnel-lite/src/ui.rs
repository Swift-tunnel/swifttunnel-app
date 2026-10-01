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
    BeginPaint, DT_CENTER, DT_LEFT, DT_NOPREFIX, DT_RIGHT, DT_SINGLELINE, DT_VCENTER, EndPaint,
    GetMonitorInfoW, HDC, IntersectClipRect, InvalidateRect, MONITOR_DEFAULTTONEAREST,
    MONITOR_DEFAULTTOPRIMARY, MONITORINFO, MonitorFromPoint, MonitorFromWindow, PAINTSTRUCT,
    ScreenToClient, SelectClipRgn,
};
use windows::Win32::UI::HiDpi::{
    DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2, GetDpiForMonitor, GetDpiForWindow,
    MDT_EFFECTIVE_DPI, SetProcessDpiAwarenessContext,
};
use windows::Win32::UI::Input::KeyboardAndMouse::{
    GetKeyState, TME_LEAVE, TRACKMOUSEEVENT, TrackMouseEvent,
};
use windows::Win32::UI::WindowsAndMessaging::*;
use windows::core::w;

use crate::canvas::{Canvas, Rgba};
use crate::engine::Engine;
use crate::state::{Push, State, Status};
use crate::theme;
use crate::tray::{CMD_QUIT, CMD_SHOW, Tray, WM_TRAY, tray_event};
use crate::view::{
    self, Action, Face, FieldId, Fonts, Frame, Item, Metrics, Screen, Shape, TextRun, contains,
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
    /// The pinned control below the list, when the screen has one.
    footer: Frame,
    scroll: i32,
    max_scroll: i32,
    hot: Option<Action>,
    dpi: i32,
    ticking: bool,
    /// Where the list ended up, which the footer moves.
    content_area: RECT,
    /// Where the lit row is, so a hover change can repaint just the rows that
    /// gained and lost the highlight instead of the whole window.
    hot_rect: Option<RECT>,
    /// Where the focused text field is, for the same reason while typing.
    focus_rect: Option<RECT>,
    /// The current screen's item tree, kept between frames.
    ///
    /// Hovering cannot change it, so rebuilding it on every mouse move was
    /// allocating a String per row several dozen times a second.
    items: Vec<Item>,
    /// Reused across repaints rather than rebuilt, so a slow machine is not
    /// allocating and zeroing 1.5MB to redraw a hover.
    canvas: Canvas,
    /// Everything is drawn here first and presented in one operation, so the
    /// window never shows shapes without their text.
    buffer: crate::surface::Buffer,
    /// `None` until the window exists, since the icon needs its handle.
    tray: Option<Tray>,
    /// Set by the tray's Quit item, so WM_CLOSE stops hiding and closes.
    quitting: bool,
}

impl App {
    /// Rebuild the laid-out frames from the current state.
    ///
    /// Called after anything that changes what should be on screen. Layout is
    /// cheap (a walk over about twenty items) and doing it in one place means
    /// the painted pixels and the clickable rectangles can never disagree.
    fn rebuild(&mut self, client: RECT) {
        self.relayout(client, true);
    }

    /// Re-lay the frames for a hover change and nothing else.
    ///
    /// Hovering changes which row is filled. It cannot change what the rows
    /// are, how tall they are, or how far the list scrolls, so none of the
    /// work that answers those questions has to run again. Doing it anyway
    /// meant every mouse move ran screens::build plus a second full layout
    /// pass, and dragging the pointer down a list stuttered.
    fn rehover(&mut self, client: RECT) {
        self.relayout(client, false);
    }

    /// `rebuild_items` false reuses the cached item tree and scroll extent.
    fn relayout(&mut self, client: RECT, rebuild_items: bool) {
        self.chrome = chrome(&self.state, &self.m, client, self.hot.as_ref());

        // The footer is laid out first, because whether there is one changes
        // how much room the list above it gets.
        let footer_item = crate::screens::footer(&self.state);
        let mut area = content_area(&self.m, client, self.state.lockout.is_some());
        self.footer = match &footer_item {
            None => Frame::default(),
            Some(item) => {
                let height = self.m.s(theme::BUTTON_H);
                let strip = RECT {
                    top: area.bottom - height,
                    ..area
                };
                area.bottom = strip.top - self.m.s(10);
                view::layout(
                    std::slice::from_ref(item),
                    strip,
                    &self.m,
                    0,
                    self.hot.as_ref(),
                )
            }
        };

        if rebuild_items {
            self.items = crate::screens::build(&self.state);
        }

        // Laid out once, then corrected only if that scroll turned out to be
        // past the end. This used to run a throwaway pass first purely to learn
        // the content height, which doubled the cost of every rebuild and never
        // changed the answer on a screen that does not scroll. The height does
        // not depend on the offset, so the real pass can report it just as well.
        self.content = view::layout(&self.items, area, &self.m, self.scroll, self.hot.as_ref());

        if rebuild_items {
            let viewport = area.bottom - area.top;
            self.max_scroll = (self.content.content_height - viewport).max(0);
            let clamped = self.scroll.clamp(0, self.max_scroll);
            if clamped != self.scroll {
                self.scroll = clamped;
                self.content =
                    view::layout(&self.items, area, &self.m, self.scroll, self.hot.as_ref());
            }
        }

        if self.max_scroll > 0 {
            add_scrollbar(
                &mut self.content,
                area,
                &self.m,
                self.scroll,
                self.max_scroll,
            );
        }
        self.content_area = area;

        // Where the highlight ended up. Taken from the hot zones rather than
        // recomputed, so it cannot drift from what was actually drawn, and
        // unioned because the fill is applied to every row carrying the action,
        // not just the first one found.
        self.focus_rect = self.state.focus.and_then(|id| {
            let wanted = Action::Focus(id);
            self.content
                .hots
                .iter()
                .find(|(_, action)| *action == wanted)
                .map(|(r, _)| *r)
        });

        self.hot_rect = self.hot.as_ref().and_then(|wanted| {
            let zones = self
                .chrome
                .hots
                .iter()
                .chain(self.footer.hots.iter())
                .chain(self.content.hots.iter());
            zones.fold(None, |found: Option<RECT>, (r, action)| {
                if action != wanted {
                    return found;
                }
                Some(match found {
                    None => *r,
                    Some(f) => RECT {
                        left: f.left.min(r.left),
                        top: f.top.min(r.top),
                        right: f.right.max(r.right),
                        bottom: f.bottom.max(r.bottom),
                    },
                })
            })
        });
    }

    /// Whether the window needs a heartbeat right now.
    fn wants_tick(&self) -> bool {
        matches!(
            self.state.tunnel.status,
            Status::Connected | Status::Working
        )
    }

    fn action_at(&self, x: i32, y: i32) -> Option<Action> {
        view::hit(&self.chrome, x, y)
            .or_else(|| view::hit(&self.footer, x, y))
            .or_else(|| view::hit(&self.content, x, y))
    }
}

/// Where the screen is drawn, below the chrome and inside the margin.
fn content_area(m: &Metrics, client: RECT, locked: bool) -> RECT {
    let strips = if locked {
        theme::TITLE_H
    } else {
        theme::TITLE_H + theme::TAB_H
    };
    RECT {
        left: client.left + m.s(theme::PAD),
        top: client.top + m.s(strips) + m.s(theme::PAD),
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
    // A locked screen keeps the title bar, for the window buttons, but drops
    // the tabs: they would imply there is something useful behind them.
    let locked = state.lockout.is_some();
    let tab_h = if locked { 0 } else { m.s(theme::TAB_H) };
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
    if locked {
        return f;
    }
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
pub fn paint(dc: HDC, client: RECT, app: &mut App) {
    paint_in(dc, client, app, None);
}

/// `damage` limits the work to the rows that actually changed.
///
/// None means the whole window, which is what a first paint, a resize and
/// WM_PRINTCLIENT all need.
pub fn paint_in(target: HDC, client: RECT, app: &mut App, damage: Option<RECT>) {
    let width = client.right - client.left;
    let height = client.bottom - client.top;
    if width <= 0 || height <= 0 {
        return;
    }

    // Everything below draws into the offscreen surface, never the window.
    let Some(dc) = app.buffer.begin(target, width, height) else {
        return;
    };

    app.canvas.reset(width, height, theme::BG);
    let canvas = &mut app.canvas;

    let area = app.content_area;
    view::paint_shapes(canvas, &app.chrome);
    view::paint_shapes(canvas, &app.footer);

    // The content scrolls under the chrome, so it is confined to its own
    // band. The band stops at the bottom of the content area rather than the
    // bottom of the window: a list that overflows should run off against the
    // same margin it started from, not get sliced flush with the frame, which
    // read as the window being broken rather than as there being more below.
    let mut band_top = area.top - app.m.s(theme::PAD) + 1;
    let mut band_bottom = area.bottom + app.m.s(theme::PAD) - 1;
    if let Some(d) = damage {
        band_top = band_top.max(d.top);
        band_bottom = band_bottom.min(d.bottom);
    }
    let previous = canvas.clip_rows(band_top, band_bottom);
    view::paint_shapes(canvas, &app.content);
    canvas.restore_clip(previous);

    app.buffer.fill_from(&app.canvas);

    // Text is drawn straight onto the device context afterwards, because GDI's
    // rasteriser is genuinely good and already has the embedded Geist faces.
    view::paint_text_in(dc, &app.fonts, &app.chrome, damage);
    view::paint_text_in(dc, &app.fonts, &app.footer, damage);

    unsafe {
        // Same band as the shapes, expressed as a clip: everything above the
        // content area is excluded so a scrolled row cannot print over the tabs.
        let _ = IntersectClipRect(dc, 0, band_top, width, band_bottom);
        view::paint_text_in(dc, &app.fonts, &app.content, damage);
        view::paint_icons(dc, &app.content, damage);
        view::paint_inputs(dc, &app.fonts, &app.content, damage);
        let _ = SelectClipRgn(dc, None);
    }

    // The finished frame reaches the window in one operation. Windows clips it
    // to whatever was invalidated, so a partial repaint stays partial.
    app.buffer.present(target);
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
            // Left null, the taskbar and Alt+Tab fall back to a blank default
            // even though the tray had the real logo all along.
            hIcon: crate::tray::app_icon(0, 0),
            hInstance: instance.into(),
            lpszClassName: class,
            // CS_DBLCLKS or WM_LBUTTONDBLCLK never arrives and a double click
            // reads as two separate clicks.
            style: CS_HREDRAW | CS_VREDRAW | CS_DBLCLKS,
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

        // The class icon covers most shells, but the taskbar reads ICON_BIG and
        // the title bar ICON_SMALL, and asking for each at its real metric gets
        // the right image out of the .ico instead of a scaled one.
        let big = crate::tray::app_icon(GetSystemMetrics(SM_CXICON), GetSystemMetrics(SM_CYICON));
        let small =
            crate::tray::app_icon(GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON));
        SendMessageW(
            hwnd,
            WM_SETICON,
            Some(WPARAM(ICON_BIG as usize)),
            Some(LPARAM(big.0 as isize)),
        );
        SendMessageW(
            hwnd,
            WM_SETICON,
            Some(WPARAM(ICON_SMALL as usize)),
            Some(LPARAM(small.0 as isize)),
        );

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

        // Resize to the DPI the window actually got.
        //
        // The size above came from GetDpiForMonitor on the primary monitor,
        // resolved before the window existed. That is a guess, and on a 125%
        // display it came back 96 while GetDpiForWindow reports 120: the frame
        // was built at 340x384 while every control inside it was laid out at
        // 125%, so all three screens overflowed and clipped. WM_CREATE already
        // rebuilds the metrics and the fonts at the real DPI; this makes the
        // frame agree with them.
        centre(hwnd);
        let _ = ShowWindow(hwnd, SW_SHOW);

        // Correct the size now that the window is on a monitor.
        //
        // Two APIs were tried before this one and both answered 96 on a 125%
        // display: GetDpiForWindow reports the system DPI until the window has
        // been shown, and GetDpiForMonitor answered 96 as well because this
        // process ends up per-monitor v1 aware rather than v2. GetDpiForWindow
        // is correct the moment the window is visible, which is late enough to
        // cost one frame of resize and early enough that nobody sees it.
        sync_window_dpi(hwnd);

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

/// Make the window and its contents agree with the DPI it is actually at.
///
/// Everything inside is laid out from `App::m`, and the frame is whatever it
/// was created as. When those two disagree the contents overflow the frame,
/// which is what made every screen clip on a scaled display.
fn sync_window_dpi(hwnd: HWND) {
    // SAFETY: hwnd is live and shown by the time this runs.
    let real = unsafe { GetDpiForWindow(hwnd).max(96) as i32 };
    let Some(app) = app_of(hwnd) else {
        log::warn!("sync_window_dpi: no app");
        return;
    };
    {
        let c = client_of(hwnd);
        log::info!(
            "sync_window_dpi: GetDpiForWindow={real} app.dpi={} client={}x{} want={}x{}",
            app.dpi,
            c.right - c.left,
            c.bottom - c.top,
            app.m.s(theme::WINDOW_W),
            app.m.s(theme::WINDOW_H),
        );
    }

    if real != app.dpi {
        app.dpi = real;
        app.m = Metrics::new(real);
        app.fonts = Fonts::new(&app.m);
    }

    // Compare the frame against the layout, not one DPI against another.
    //
    // WM_CREATE had already picked up the right DPI, so the contents were
    // correct all along and a DPI-to-DPI check found nothing to do. The thing
    // that was wrong was the window, created from a guess made before it
    // existed. This asks the question that actually matters: is the frame the
    // size the contents were laid out for?
    let want_w = app.m.s(theme::WINDOW_W);
    let want_h = app.m.s(theme::WINDOW_H);
    let client = client_of(hwnd);
    if client.right - client.left == want_w && client.bottom - client.top == want_h {
        return;
    }

    log::info!(
        "window is {}x{} but laid out for {want_w}x{want_h} at {real} DPI; resizing",
        client.right - client.left,
        client.bottom - client.top,
    );

    // SAFETY: resizing a live window this process owns.
    unsafe {
        let _ = SetWindowPos(hwnd, None, 0, 0, want_w, want_h, SWP_NOMOVE | SWP_NOZORDER);
    }
    centre(hwnd);
    app.rebuild(client_of(hwnd));
    repaint(hwnd);
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
        footer: Frame::default(),
        scroll: 0,
        max_scroll: 0,
        hot: None,
        dpi,
        ticking: false,
        canvas: Canvas::new(m.s(theme::WINDOW_W), m.s(theme::WINDOW_H), theme::BG),
        buffer: crate::surface::Buffer::new(),
        tray: None,
        quitting: false,
        content_area: RECT::default(),
        hot_rect: None,
        focus_rect: None,
        items: Vec::new(),
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
    // Render one of the full-window lockout screens instead. Reaching these
    // for real means signing out, getting banned or spending the whole free
    // allowance, none of which is a feedback loop for laying them out.
    lockout: Option<crate::state::Lockout>,
    // Preload the sign-in email, focused, so the cost of a field with more text
    // than fits can be measured. Add "!" to select it all.
    login_text: Option<String>,
    // Repaint many times and report the per-frame cost, for checking that a
    // slow machine can still afford this window.
    bench: bool,
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
    if let Some(text) = login_text {
        let select_all = text.ends_with('!');
        let text = text.trim_end_matches('!').to_string();
        app.state.login.email.text = text;
        let end = app.state.login.email.len();
        app.state.login.email.caret = end;
        app.state.login.email.anchor = if select_all { 0 } else { end };
        app.state.focus = Some(FieldId::Email);
    }
    if let Some(lockout) = lockout {
        app.state.signed_in = !matches!(lockout, crate::state::Lockout::SignedOut);
        app.state.lockout = Some(lockout);
    }
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

    crate::preview::render(path, w, h, move |dc, r| {
        // --bench times the whole frame: clear the surface, rasterise every
        // shape, blit, then draw the text. "Cheap enough for a slow machine"
        // is a claim that needs a number, and this is where it comes from.
        let runs: u32 = if bench { 50 } else { 1 };
        let started = std::time::Instant::now();
        for _ in 0..runs {
            paint(dc, r, &mut app);
        }
        if bench {
            let each = started.elapsed() / runs;
            println!("paint: {:.2} ms/frame", each.as_secs_f64() * 1000.0);
        }
    })
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

/// Repaint from the focused field down, after a keystroke.
///
/// Typing changes the field, and below it the button's enabled state and
/// whether an error note is showing. Nothing above the field can move, which
/// on the sign-in screen is the logo and the whole atmosphere: several hundred
/// grid segments and sixteen large alpha-blended discs. Redrawing those for
/// every character is what made typing stutter.
fn repaint_from_focus(hwnd: HWND, app: &App) {
    match app.focus_rect {
        Some(field) => repaint_rect(
            hwnd,
            RECT {
                left: app.content_area.left,
                top: field.top - 2,
                right: app.content_area.right,
                bottom: app.content_area.bottom,
            },
        ),
        None => repaint(hwnd),
    }
}

/// Invalidate one band rather than the window.
fn repaint_rect(hwnd: HWND, r: RECT) {
    // SAFETY: invalidating a live window; the paint itself happens later.
    unsafe {
        let _ = InvalidateRect(Some(hwnd), Some(&r), false);
    }
}

/// The band covering both rects, grown a little so an antialiased edge on the
/// boundary is repainted rather than left half drawn.
fn union(a: Option<RECT>, b: Option<RECT>) -> Option<RECT> {
    let joined = match (a, b) {
        (Some(a), Some(b)) => RECT {
            left: a.left.min(b.left),
            top: a.top.min(b.top),
            right: a.right.max(b.right),
            bottom: a.bottom.max(b.bottom),
        },
        (Some(only), None) | (None, Some(only)) => only,
        (None, None) => return None,
    };
    Some(RECT {
        top: joined.top - 2,
        bottom: joined.bottom + 2,
        ..joined
    })
}

/// Which sign-in field the keys are going to.
fn login_field(app: &mut App, email: bool) -> &mut crate::state::TextField {
    if email {
        &mut app.state.login.email
    } else {
        &mut app.state.login.password
    }
}

/// Modifier state right now. Reading it per keystroke is cheaper than tracking
/// key-up and key-down and cannot drift out of sync with the real keyboard.
fn ctrl_held() -> bool {
    // SAFETY: reading keyboard state takes no handles and cannot fail.
    unsafe { GetKeyState(0x11) < 0 }
}

fn shift_held() -> bool {
    // SAFETY: as above.
    unsafe { GetKeyState(0x10) < 0 }
}

fn repaint(hwnd: HWND) {
    // SAFETY: invalidating a live window; the paint itself happens later.
    unsafe {
        let _ = InvalidateRect(Some(hwnd), None, false);
    }
}

/// Arm or disarm the heartbeat so an idle window costs nothing.
/// Whether the window is actually on screen.
///
/// Hidden to the tray or minimised both count as not: there is nothing to
/// redraw and nobody to see it.
fn on_screen(hwnd: HWND) -> bool {
    // SAFETY: querying a live window.
    unsafe { IsWindowVisible(hwnd).as_bool() && !IsIconic(hwnd).as_bool() }
}

/// `visible` is passed rather than queried because WM_SHOWWINDOW and WM_SIZE
/// arrive while the change is still happening, so the window would report its
/// old state.
fn sync_timer(hwnd: HWND, app: &mut App, visible: bool) {
    // The heartbeat exists to move a session timer on screen. With a game
    // fullscreen and Lite in the tray there is no screen to move it on, and
    // ticking anyway costs a rebuild every second for nothing. The tunnel runs
    // on the engine's own threads and does not go through here.
    let wanted = app.wants_tick() && visible;
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
                    sync_timer(hwnd, app, on_screen(hwnd));
                    app.tray = Some(Tray::new(hwnd));
                }
                LRESULT(0)
            }

            // Closing the window is not quitting.
            //
            // The tunnel lives in this process, so destroying the window drops
            // the engine and tears the tunnel down. Doing that because someone
            // clicked the X mid-game is the wrong answer, and Settings has
            // promised otherwise since the day that switch was added.
            WM_CLOSE => {
                if let Some(app) = app_of(hwnd)
                    && !app.quitting
                    && app.state.close_to_tray
                    && app.tray.as_ref().is_some_and(|t| t.present())
                {
                    let _ = ShowWindow(hwnd, SW_HIDE);
                    return LRESULT(0);
                }
                DefWindowProcW(hwnd, msg, wparam, lparam)
            }

            WM_TRAY => {
                if let Some(app) = app_of(hwnd) {
                    match tray_event(lparam) {
                        // Left click or double click: bring it back.
                        WM_LBUTTONUP | WM_LBUTTONDBLCLK => {
                            let _ = ShowWindow(hwnd, SW_SHOW);
                            let _ = SetForegroundWindow(hwnd);
                        }
                        WM_RBUTTONUP => match app.tray.as_ref().and_then(|t| t.menu()) {
                            Some(CMD_SHOW) => {
                                let _ = ShowWindow(hwnd, SW_SHOW);
                                let _ = SetForegroundWindow(hwnd);
                            }
                            Some(CMD_QUIT) => {
                                app.quitting = true;
                                let _ = PostMessageW(Some(hwnd), WM_CLOSE, WPARAM(0), LPARAM(0));
                            }
                            _ => {}
                        },
                        _ => {}
                    }
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
                if contains(bar, point.x, point.y) && app.action_at(point.x, point.y).is_none() {
                    return LRESULT(HTCAPTION as isize);
                }
                LRESULT(HTCLIENT as isize)
            }

            WM_PAINT => {
                if let Some(app) = app_of(hwnd) {
                    let mut ps = PAINTSTRUCT::default();
                    let dc = BeginPaint(hwnd, &mut ps);
                    paint_in(dc, client_of(hwnd), app, Some(ps.rcPaint));
                    let _ = EndPaint(hwnd, &ps);
                }
                LRESULT(0)
            }

            // Draw into a device context somebody else owns, when asked.
            //
            // Everything that captures a window without going through the
            // screen sends this: Task View, the Alt-Tab preview, the taskbar
            // thumbnail, and PrintWindow. A window that only answers WM_PAINT
            // hands all of them a blank white rectangle.
            WM_PRINTCLIENT => {
                if let Some(app) = app_of(hwnd) {
                    paint(HDC(wparam.0 as *mut c_void), client_of(hwnd), app);
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
                        let was = app.hot_rect;
                        app.hot = next;
                        app.rehover(client_of(hwnd));
                        // Only the row that lost the highlight and the one that
                        // gained it changed. Repainting the whole window for
                        // that is what made dragging the pointer down a list
                        // stutter on a slow machine.
                        match union(was, app.hot_rect) {
                            Some(damage) => repaint_rect(hwnd, damage),
                            None => repaint(hwnd),
                        }
                    }
                }
                LRESULT(0)
            }

            MOUSE_LEAVE => {
                if let Some(app) = app_of(hwnd)
                    && app.hot.is_some()
                {
                    let was = app.hot_rect;
                    app.hot = None;
                    app.rehover(client_of(hwnd));
                    match was {
                        Some(damage) => repaint_rect(hwnd, damage),
                        None => repaint(hwnd),
                    }
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

            // Typing into the frame cap.
            //
            // Digits and backspace only. The field takes a number, so there is
            // nothing a letter could mean, and refusing them here is simpler
            // than validating them out afterwards. What is typed is still
            // checked before it can be applied, since "999999" is all digits
            // and still not a frame rate.
            // Caret movement, selection and paste. None of this can be done in
            // WM_CHAR: the arrows never arrive there, and ctrl-A shows up as a
            // bare control code indistinguishable from anything else.
            WM_KEYDOWN => {
                if let Some(app) = app_of(hwnd)
                    && matches!(
                        app.state.focus,
                        Some(FieldId::Email) | Some(FieldId::Password)
                    )
                {
                    let email = app.state.focus == Some(FieldId::Email);
                    let ctrl = ctrl_held();
                    let shift = shift_held();
                    let key = wparam.0 as u32;
                    let mut changed = true;
                    let field = login_field(app, email);
                    match key {
                        // Left, right, home, end, delete.
                        0x25 => {
                            let to = if ctrl {
                                field.word_left()
                            } else if field.has_selection() && !shift {
                                field.selection().0
                            } else {
                                field.caret.saturating_sub(1)
                            };
                            field.move_to(to, shift);
                        }
                        0x27 => {
                            let to = if ctrl {
                                field.word_right()
                            } else if field.has_selection() && !shift {
                                field.selection().1
                            } else {
                                field.caret + 1
                            };
                            field.move_to(to, shift);
                        }
                        0x24 => field.move_to(0, shift),
                        0x23 => {
                            let end = field.len();
                            field.move_to(end, shift);
                        }
                        0x2E => field.delete(),
                        // Ctrl-A selects everything, ctrl-V pastes.
                        0x41 if ctrl => field.select_all(),
                        0x56 if ctrl => {
                            if let Some(text) = crate::clipboard::text(256) {
                                let line = text.lines().next().unwrap_or("").trim().to_string();
                                field.insert(&line, 128);
                            }
                        }
                        _ => changed = false,
                    }
                    if changed {
                        app.state.login.error = None;
                        app.rebuild(client_of(hwnd));
                        repaint_from_focus(hwnd, app);
                        return LRESULT(0);
                    }
                }
                DefWindowProcW(hwnd, msg, wparam, lparam)
            }

            // Double click selects the whole field, which is the only way to
            // replace what is in one without holding backspace down.
            WM_LBUTTONDBLCLK => {
                if let Some(app) = app_of(hwnd) {
                    let x = (lparam.0 & 0xFFFF) as i16 as i32;
                    let y = ((lparam.0 >> 16) & 0xFFFF) as i16 as i32;
                    if let Some(Action::Focus(id)) = app.action_at(x, y)
                        && matches!(id, FieldId::Email | FieldId::Password)
                    {
                        app.state.focus = Some(id);
                        login_field(app, id == FieldId::Email).select_all();
                        app.rebuild(client_of(hwnd));
                        repaint(hwnd);
                    }
                }
                LRESULT(0)
            }

            WM_CHAR => {
                // The sign-in form takes free text, so it is handled before the
                // FPS field's digits-only rules. Matched on the code rather
                // than a char literal so no escape has to survive the edit.
                if let Some(app) = app_of(hwnd)
                    && matches!(
                        app.state.focus,
                        Some(FieldId::Email) | Some(FieldId::Password)
                    )
                {
                    let email = app.state.focus == Some(FieldId::Email);
                    let ctrl = ctrl_held();
                    let mut changed = true;
                    match wparam.0 as u32 {
                        // Tab moves on, Enter submits, Escape gives up focus.
                        9 => {
                            app.state.focus = Some(if email {
                                FieldId::Password
                            } else {
                                FieldId::Email
                            });
                        }
                        13 => {
                            if email && app.state.login.password.text.is_empty() {
                                app.state.focus = Some(FieldId::Password);
                            } else {
                                app.state.focus = None;
                                app.engine.dispatch(Action::SubmitLogin, &mut app.state);
                            }
                        }
                        27 => app.state.focus = None,
                        8 => {
                            let field = login_field(app, email);
                            field.backspace(ctrl);
                        }
                        // Every other control code is a ctrl combination, and
                        // those are dealt with in WM_KEYDOWN where the key is
                        // still distinguishable.
                        c if c < 32 => changed = false,
                        c => match char::from_u32(c) {
                            Some(ch) => login_field(app, email).insert(&ch.to_string(), 128),
                            None => changed = false,
                        },
                    }
                    if changed {
                        // A keystroke clears the last failure: the message was
                        // about what was typed before, not what is there now.
                        app.state.login.error = None;
                        app.rebuild(client_of(hwnd));
                        repaint_from_focus(hwnd, app);
                    }
                    return LRESULT(0);
                }

                if let Some(app) = app_of(hwnd)
                    && app.state.focus == Some(FieldId::FpsCap)
                {
                    let ch = char::from_u32(wparam.0 as u32).unwrap_or('\0');
                    let mut changed = true;
                    match ch {
                        '0'..='9' => app.state.edit_roblox(|d| {
                            // Four digits is 9999, past any real refresh rate,
                            // and stops the field growing out of its box.
                            if d.fps_text.trim().len() < 4 {
                                if d.fps_text.trim().is_empty() {
                                    d.fps_text.clear();
                                }
                                d.fps_text.push(ch);
                            }
                        }),
                        '\u{8}' => app.state.edit_roblox(|d| {
                            d.fps_text.pop();
                        }),
                        // Enter and Escape both mean "done".
                        '\r' | '\u{1b}' => app.state.focus = None,
                        _ => changed = false,
                    }
                    if changed {
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
                    let action = app.action_at(x, y);
                    let keeps_focus = matches!(action, Some(Action::Focus(_)));
                    if !keeps_focus && app.state.focus.is_some() {
                        app.state.focus = None;
                        app.rebuild(client_of(hwnd));
                        repaint(hwnd);
                    }
                    if let Some(action) = action {
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
                    sync_timer(hwnd, app, on_screen(hwnd));
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
                    sync_timer(hwnd, app, on_screen(hwnd));
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
                    let visible = wparam.0 as u32 != SIZE_MINIMIZED;
                    if visible {
                        // Coming back from the taskbar: catch the session timer
                        // up before it is drawn, or it shows the value it had
                        // when the window went away.
                        app.engine.fill(&mut app.state);
                    }
                    app.rebuild(client_of(hwnd));
                    sync_timer(hwnd, app, visible);
                }
                LRESULT(0)
            }

            // Hiding to the tray and coming back out of it.
            WM_SHOWWINDOW => {
                if let Some(app) = app_of(hwnd) {
                    let visible = wparam.0 != 0;
                    if visible {
                        app.engine.fill(&mut app.state);
                        app.rebuild(client_of(hwnd));
                    }
                    sync_timer(hwnd, app, visible);
                }
                DefWindowProcW(hwnd, msg, wparam, lparam)
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
    sync_timer(hwnd, app, on_screen(hwnd));
    repaint(hwnd);
}
