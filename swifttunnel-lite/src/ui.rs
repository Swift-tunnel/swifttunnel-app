//! The single window, painted by hand.
//!
//! Layout is a vertical stack: a status card, the connect action, an FPS
//! readout card, one Roblox toggle and the signed-in account. Everything is
//! drawn in one `WM_PAINT` into a memory DC and blitted, so there is no flicker
//! and nothing repaints unless something actually changed.

use std::ffi::c_void;

use windows::Win32::Foundation::{COLORREF, HWND, LPARAM, LRESULT, POINT, RECT, WPARAM};
use windows::Win32::Graphics::Dwm::{DWMWA_USE_IMMERSIVE_DARK_MODE, DwmSetWindowAttribute};
use windows::Win32::Graphics::Gdi::*;
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::HiDpi::{
    DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2, GetDpiForMonitor, MDT_EFFECTIVE_DPI,
    SetProcessDpiAwarenessContext,
};
use windows::Win32::UI::WindowsAndMessaging::*;
use windows::core::w;

use swifttunnel_core::auth::AuthManager;

use crate::canvas::{Canvas, Rgba, RoundRect};
use crate::engine::Engine;
use crate::surface;

use crate::gdi::{self, Font};
use crate::theme;

/// What the pointer is currently over, so it can be drawn lit.
#[derive(PartialEq, Clone, Copy)]
enum Hot {
    None,
    Nav(u8),
    Connect,
    Unlock,
    Region(u8),
}

/// Which page is showing. Three, deliberately: the tunnel, the game, and
/// the account. Everything the full app has beyond that is what makes it
/// the full app.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Connect,
    Roblox,
    Settings,
}

impl Screen {
    const ALL: [Screen; 3] = [Screen::Connect, Screen::Roblox, Screen::Settings];

    fn label(self) -> &'static str {
        match self {
            Screen::Connect => "Connect",
            Screen::Roblox => "Roblox",
            Screen::Settings => "Settings",
        }
    }
}

/// Timer that refreshes the readings. Any non-zero id will do; this one
/// is only ever used with this window.
const REFRESH_TIMER: usize = 1;

/// How often the window re-reads the engine, in milliseconds.
///
/// Fast enough that the frame counter looks live, slow enough that the
/// window is asleep almost all of the time. This is the only repeating
/// work Lite does while idle, and it repaints only when a value actually
/// changed.
const REFRESH_INTERVAL_MS: u32 = 500;

/// Re-read Roblox's frame cap every this many refreshes.
///
/// The cap lives in a file on disk and only changes when somebody changes
/// it, so polling it twice a second would be pure IO for nothing. Every
/// five seconds is enough to notice the full app or the player editing it
/// behind our back.
const CAP_RECHECK_TICKS: u32 = 10;

pub struct App {
    auth: AuthManager,
    engine: Engine,
    /// Refresh count, used to space out the slower checks.
    tick: u32,
    dpi: i32,
    /// Client width over design width, as a fraction so the maths stays integer.
    scale_num: i32,
    scale_den: i32,

    screen: Screen,
    /// The atmosphere, already composited. Keyed by size and connection
    /// state, which is everything it depends on.
    backdrop: Option<(i32, i32, bool, Vec<[f32; 3]>)>,
    /// Snapshot of the fleet. Copied out of the engine on the timer so the
    /// paint path never waits on a lock.
    regions: Vec<crate::engine::RegionRow>,
    best_ping: Option<u32>,
    roblox_running: bool,
    frame_cap: u32,
    connected: bool,
    region: String,
    unlock_cap: bool,
    hot: Hot,

    ui_micro: Font,
    ui_body: Font,
    ui_title: Font,
    ui_button: Font,
    /// Reserved for the tunnel's latency readout. Nothing renders numbers
    /// since the frame counter was removed.
    #[allow(dead_code)]
    mono_big: Font,
    mono_small: Font,
    ui_semi: Font,
    ui_display: Font,
}

impl App {
    /// Scale a logical measurement to the window's actual size.
    ///
    /// Derived from the client rectangle rather than from the DPI. Windows and
    /// the DPI reported for a window do not reliably agree at startup on a
    /// multi-monitor setup with mixed scaling: the window here reported 120 DPI
    /// while its client stayed 400px wide, so a DPI-derived layout was drawn
    /// 25% too large and every card ran off the right edge. Measuring against
    /// the space that actually exists cannot disagree with itself.
    fn s(&self, value: i32) -> i32 {
        (value * self.scale_num) / self.scale_den.max(1)
    }

    fn account(&self) -> String {
        if !self.auth.is_logged_in() {
            return "Not signed in".to_string();
        }
        match self.auth.get_user() {
            Some(user) => user.email,
            None => "Signed in".to_string(),
        }
    }
}

/// Vertical layout, in logical pixels, resolved against the client width.
/// Where everything sits.
///
/// The full app's shell, reduced to three pages: a fixed sidebar carrying the
/// wordmark, sectioned navigation and a session card, a header strip naming
/// the page, and the content column beside them. An earlier pass used a
/// segmented tab bar, which is a perfectly good control and looks nothing
/// whatsoever like SwiftTunnel.
struct Layout {
    sidebar: RECT,
    logo_mark: RECT,
    logo_text: RECT,
    /// TUNNEL / PERFORMANCE / SYSTEM.
    sections: [RECT; 3],
    nav: [RECT; 3],
    side_status: RECT,
    side_account: RECT,

    header: RECT,
    title: RECT,
    subtitle: RECT,
    pill: RECT,

    kicker: RECT,
    badge: RECT,
    headline: RECT,
    sub: RECT,
    connect: RECT,
    stat_left: RECT,
    stat_right: RECT,
    list_label: RECT,

    card: RECT,
    rows: Vec<RECT>,
}

fn layout(app: &App, client: RECT, rows: usize) -> Layout {
    let y = |v: i32| client.top + app.s(v);
    let x = |v: i32| client.left + app.s(v);
    let right = client.right - app.s(24);
    let bottom = client.bottom;

    let side_w = app.s(theme::SIDEBAR_W);
    let content_left = client.left + side_w + app.s(24);

    // Sidebar rows: a section label, then its one page.
    let mut sections = [RECT::default(); 3];
    let mut nav = [RECT::default(); 3];
    for i in 0..3 {
        let top = y(84 + 68 * i as i32);
        sections[i] = RECT {
            left: x(20),
            top,
            right: side_w - app.s(12),
            bottom: top + app.s(12),
        };
        nav[i] = RECT {
            left: x(12),
            top: top + app.s(16),
            right: side_w - app.s(12),
            bottom: top + app.s(52),
        };
    }

    // Connect is two columns, the others one. The fleet needs its own column
    // or the page turns back into a single scrolling stack.
    let two_col = matches!(app.screen, Screen::Connect);
    let col_w = app.s(300);
    let content_right = if two_col { content_left + col_w } else { right };
    let card_left = if two_col {
        content_left + col_w + app.s(28)
    } else {
        content_left
    };
    let row_h = if two_col {
        app.s(theme::REGION_H)
    } else {
        app.s(theme::ROW_H)
    };
    let card_top = if two_col { y(124) } else { y(190) };

    Layout {
        sidebar: RECT {
            left: client.left,
            top: client.top,
            right: client.left + side_w,
            bottom,
        },
        logo_mark: RECT {
            left: x(20),
            top: y(24),
            right: x(48),
            bottom: y(52),
        },
        logo_text: RECT {
            left: x(58),
            top: y(26),
            right: side_w - app.s(12),
            bottom: y(50),
        },
        sections,
        nav,
        side_status: RECT {
            left: x(12),
            top: bottom - app.s(112),
            right: side_w - app.s(12),
            bottom: bottom - app.s(60),
        },
        side_account: RECT {
            left: x(12),
            top: bottom - app.s(50),
            right: side_w - app.s(12),
            bottom: bottom - app.s(18),
        },
        header: RECT {
            left: client.left + side_w,
            top: client.top,
            right: client.right,
            bottom: y(theme::HEADER_H),
        },
        title: RECT {
            left: content_left,
            top: y(18),
            right: right - app.s(170),
            bottom: y(46),
        },
        subtitle: RECT {
            left: content_left,
            top: y(47),
            right: right - app.s(170),
            bottom: y(64),
        },
        pill: RECT {
            left: right - app.s(158),
            top: y(26),
            right,
            bottom: y(56),
        },
        kicker: RECT {
            left: content_left,
            top: y(108),
            right: content_right,
            bottom: y(122),
        },
        badge: RECT {
            left: content_left,
            top: y(130),
            right: content_left + app.s(32),
            bottom: y(152),
        },
        headline: RECT {
            left: content_left + app.s(42),
            top: y(124),
            right: content_right,
            bottom: y(158),
        },
        sub: RECT {
            left: content_left + app.s(42),
            top: y(160),
            right: content_right,
            bottom: y(178),
        },
        connect: RECT {
            left: content_left,
            top: y(196),
            right: content_right,
            bottom: y(242),
        },
        stat_left: RECT {
            left: content_left,
            top: y(268),
            right: content_left + app.s(150),
            bottom: y(326),
        },
        stat_right: RECT {
            left: content_left + app.s(150),
            top: y(268),
            right: content_right,
            bottom: y(326),
        },
        list_label: RECT {
            left: card_left,
            top: y(108),
            right,
            bottom: y(122),
        },
        card: RECT {
            left: card_left,
            top: card_top,
            right,
            bottom: card_top + row_h * rows.max(1) as i32,
        },
        rows: (0..rows)
            .map(|i| RECT {
                left: card_left,
                top: card_top + row_h * i as i32,
                right,
                bottom: card_top + row_h * (i as i32 + 1),
            })
            .collect(),
    }
}

/// How many rows the current screen shows.
fn row_count(app: &App) -> usize {
    match app.screen {
        Screen::Connect => app.regions.len().max(1),
        // Unlock the frame cap, then the cap itself.
        Screen::Roblox => 2,
        // Version, then channel.
        Screen::Settings => 2,
    }
}

/// What is under the pointer.
///
/// One function for both hover and click so the two can never disagree about
/// what a pixel belongs to.
fn hit_test(app: &App, l: &Layout, x: i32, y: i32) -> Hot {
    for (i, rect) in l.nav.iter().enumerate() {
        if contains(*rect, x, y) {
            return Hot::Nav(i as u8);
        }
    }

    match app.screen {
        Screen::Connect => {
            if contains(l.connect, x, y) {
                return Hot::Connect;
            }
            for (i, row) in l.rows.iter().enumerate() {
                if i < app.regions.len() && contains(*row, x, y) {
                    return Hot::Region(i as u8);
                }
            }
        }
        Screen::Roblox => {
            if let Some(row) = l.rows.first()
                && contains(*row, x, y)
            {
                return Hot::Unlock;
            }
        }
        Screen::Settings => {}
    }

    Hot::None
}
fn contains(r: RECT, x: i32, y: i32) -> bool {
    x >= r.left && x < r.right && y >= r.top && y < r.bottom
}

pub fn run(auth: AuthManager) -> windows::core::Result<()> {
    unsafe {
        // Set explicitly rather than relying on the embedded manifest. The
        // manifest declares PerMonitorV2, but GetDpiForWindow was still
        // answering 96 on a 125% display, which left the window and the type a
        // fifth too small and bitmap-stretched by the compositor.
        let _ = SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);

        let instance = GetModuleHandleW(None)?;

        let class = w!("SwiftTunnelLiteWindow");
        let wc = WNDCLASSW {
            hCursor: LoadCursorW(None, IDC_ARROW)?,
            hInstance: instance.into(),
            lpszClassName: class,
            style: CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: Some(wndproc),
            // The whole client area is painted every time, so letting Windows
            // erase it first would only cause a flash of the wrong colour.
            hbrBackground: HBRUSH(std::ptr::null_mut()),
            ..Default::default()
        };
        RegisterClassW(&wc);

        // Resolve the DPI before the window exists.
        //
        // Creating at 96 and resizing afterwards does not work: the window is
        // shown, Windows sends WM_DPICHANGED, and its own sizing wins over a
        // SetWindowPos issued from the handler, leaving the layout scaled for
        // 125% inside a 100% frame. Sizing it correctly up front sidesteps the
        // whole exchange.
        let dpi = {
            let monitor = MonitorFromPoint(POINT { x: 0, y: 0 }, MONITOR_DEFAULTTOPRIMARY);
            let mut x = 0u32;
            let mut y = 0u32;
            match GetDpiForMonitor(monitor, MDT_EFFECTIVE_DPI, &mut x, &mut y) {
                Ok(()) => (x as i32).max(96),
                Err(_) => 96,
            }
        };
        let px = |logical: i32| logical * dpi / 96;

        let mut frame = RECT {
            left: 0,
            top: 0,
            right: px(theme::WINDOW_W),
            bottom: px(theme::WINDOW_H),
        };
        let style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX;
        let _ = AdjustWindowRectEx(&mut frame, style, false, WINDOW_EX_STYLE::default());

        let app = new_app(auth, dpi);

        let hwnd = CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            class,
            w!("SwiftTunnel Lite"),
            // No maximise or resize: the layout is fixed.
            style,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            frame.right - frame.left,
            frame.bottom - frame.top,
            None,
            None,
            Some(instance.into()),
            Some(Box::into_raw(app) as *const c_void),
        )?;

        // A dark window under a light title bar looks broken.
        let dark: i32 = 1;
        let _ = DwmSetWindowAttribute(
            hwnd,
            DWMWA_USE_IMMERSIVE_DARK_MODE,
            &dark as *const _ as *const c_void,
            size_of::<i32>() as u32,
        );

        let _ = ShowWindow(hwnd, SW_SHOW);

        let mut message = MSG::default();
        while GetMessageW(&mut message, None, 0, 0).into() {
            let _ = TranslateMessage(&message);
            DispatchMessageW(&message);
        }
        Ok(())
    }
}

/// Build the application state.
///
/// Shared by the real window and the offscreen preview so there is only one
/// definition of what a fresh Lite looks like.
fn new_app(auth: AuthManager, dpi: i32) -> Box<App> {
    // Built before the window so the first paint already shows the
    // real frame cap rather than flicking from off to on a moment later.
    let engine = Engine::new();
    let unlock_cap = engine.fps_unlocked();

    Box::new(App {
        auth,
        engine,
        tick: 0,
        dpi,
        scale_num: theme::WINDOW_W,
        scale_den: theme::WINDOW_W,
        screen: Screen::Connect,
        backdrop: None,
        regions: Vec::new(),
        best_ping: None,
        roblox_running: false,
        frame_cap: 60,
        connected: false,
        region: "Auto".to_string(),
        unlock_cap,
        hot: Hot::None,
        // Placeholders; rebuilt at the real DPI in WM_CREATE.
        ui_micro: Font(HFONT(std::ptr::null_mut())),
        ui_body: Font(HFONT(std::ptr::null_mut())),
        ui_title: Font(HFONT(std::ptr::null_mut())),
        ui_button: Font(HFONT(std::ptr::null_mut())),
        mono_big: Font(HFONT(std::ptr::null_mut())),
        mono_small: Font(HFONT(std::ptr::null_mut())),
        ui_semi: Font(HFONT(std::ptr::null_mut())),
        ui_display: Font(HFONT(std::ptr::null_mut())),
    })
}

/// Paint one frame into a file instead of onto the screen.
///
/// Lite runs elevated, and Windows blocks a non-elevated process from
/// raising or capturing an elevated window, so this is the only way to see a
/// visual change without asking a person to look at their own screen. It
/// drives the same `paint` the window does, so nothing can drift.
pub fn render_preview(
    auth: AuthManager,
    path: &str,
    connected: bool,
    screen: Screen,
) -> std::io::Result<()> {
    // 2x so the antialiasing and the type are legible when the image is
    // looked at rather than glanced past.
    let dpi = 192;
    let width = theme::WINDOW_W * dpi / 96;
    let height = theme::WINDOW_H * dpi / 96;

    let mut app = new_app(auth, dpi);
    app.connected = connected;
    app.screen = screen;

    // The relay list arrives on a background thread, so give it a moment.
    // A preview of an empty list would not show the thing being reviewed.
    for _ in 0..40 {
        app.regions = app.engine.regions();
        if !app.regions.is_empty() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    app.best_ping = app.engine.best_ping();
    app.roblox_running = app.engine.roblox_running();
    app.unlock_cap = app.engine.fps_unlocked();
    app.frame_cap = app.engine.frame_cap();
    if let Some(first) = app.regions.first() {
        app.region = first.id.clone();
    }
    app.scale_num = width;
    app.scale_den = theme::WINDOW_W;

    crate::preview::render(path, width, height, |dc, rect| {
        // SAFETY: the DC belongs to the offscreen bitmap the preview owns
        // for the duration of this call, which is what paint expects.
        unsafe {
            build_fonts(&mut app);
            paint(dc, rect, &mut app);
        }
    })
}

unsafe extern "system" fn wndproc(
    hwnd: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    unsafe {
        match message {
            WM_CREATE => {
                let cs = lparam.0 as *const CREATESTRUCTW;
                let app = (*cs).lpCreateParams as *mut App;
                SetWindowLongPtrW(hwnd, GWLP_USERDATA, app as isize);

                // `dpi` was resolved from the monitor before the window was
                // created, so the fonts can be built at the right size on the
                // first pass and the window never needs resizing.
                build_fonts(&mut *app);

                // Nothing else drives a repaint: there is no animation and
                // no compositor here, so without a timer the frame counter
                // would only update when the mouse moved.
                SetTimer(Some(hwnd), REFRESH_TIMER, REFRESH_INTERVAL_MS, None);
                LRESULT(0)
            }

            WM_SIZE => {
                if let Some(app) = app_from(hwnd) {
                    let width = (lparam.0 & 0xFFFF) as i32;
                    if width > 0 {
                        app.scale_num = width;
                        app.scale_den = theme::WINDOW_W;
                        build_fonts(app);
                        let _ = InvalidateRect(Some(hwnd), None, false);
                    }
                }
                LRESULT(0)
            }

            WM_PAINT => {
                let app = app_from(hwnd);
                if let Some(app) = app {
                    let mut ps = PAINTSTRUCT::default();
                    let dc = BeginPaint(hwnd, &mut ps);
                    paint_buffered(hwnd, dc, app);
                    let _ = EndPaint(hwnd, &ps);
                }
                LRESULT(0)
            }

            WM_MOUSEMOVE => {
                if let Some(app) = app_from(hwnd) {
                    let x = (lparam.0 & 0xFFFF) as i16 as i32;
                    let y = ((lparam.0 >> 16) & 0xFFFF) as i16 as i32;
                    let mut client = RECT::default();
                    let _ = GetClientRect(hwnd, &mut client);
                    let l = layout(app, client, row_count(app));
                    let hot = hit_test(app, &l, x, y);

                    if hot != app.hot {
                        app.hot = hot;
                        let _ = InvalidateRect(Some(hwnd), None, false);
                    }
                }
                LRESULT(0)
            }

            WM_LBUTTONDOWN => {
                if let Some(app) = app_from(hwnd) {
                    let x = (lparam.0 & 0xFFFF) as i16 as i32;
                    let y = ((lparam.0 >> 16) & 0xFFFF) as i16 as i32;
                    let mut client = RECT::default();
                    let _ = GetClientRect(hwnd, &mut client);
                    let l = layout(app, client, row_count(app));

                    match hit_test(app, &l, x, y) {
                        Hot::Nav(i) => {
                            if let Some(screen) = Screen::ALL.get(i as usize) {
                                app.screen = *screen;
                                app.hot = Hot::None;
                                let _ = InvalidateRect(Some(hwnd), None, false);
                            }
                        }
                        Hot::Connect => {
                            // Still visual only: the tunnel itself is the
                            // remaining piece, and faking it convincingly is
                            // exactly the kind of lie that shipped a
                            // hardcoded frame rate last time.
                            app.connected = !app.connected;
                            let _ = InvalidateRect(Some(hwnd), None, false);
                        }
                        Hot::Region(i) => {
                            if let Some(region) = app.regions.get(i as usize) {
                                app.region = region.id.clone();
                                let _ = InvalidateRect(Some(hwnd), None, false);
                            }
                        }
                        Hot::Unlock => {
                            let wanted = !app.unlock_cap;
                            match app.engine.set_fps_unlocked(wanted) {
                                // Only move the switch once the cap actually
                                // changed, so what is on screen is what is
                                // on disk.
                                Ok(()) => {
                                    app.unlock_cap = wanted;
                                    app.frame_cap = app.engine.frame_cap();
                                }
                                Err(reason) => {
                                    log::warn!("could not change the frame cap: {reason}")
                                }
                            }
                            let _ = InvalidateRect(Some(hwnd), None, false);
                        }
                        Hot::None => {}
                    }
                }
                LRESULT(0)
            }

            WM_DPICHANGED => {
                // Windows states the new DPI in the low word of wParam and a
                // suggested window rectangle in lParam. Taking that rectangle
                // is the documented contract; computing our own and calling
                // SetWindowPos from here is overridden, which is why earlier
                // attempts left a 125% layout inside a 100% frame.
                let dpi = (wparam.0 & 0xFFFF) as i32;
                if let Some(app) = app_from(hwnd) {
                    app.dpi = dpi.max(96);
                    build_fonts(app);
                }

                // Deliberately not resizing the window from here. Both
                // computing our own rectangle and adopting the suggested one
                // ended with a window collapsed to its title bar. The layout
                // scales to whatever client area exists, so leaving the frame
                // alone is safe: the content simply fits the window Windows
                // gives us.
                let _ = InvalidateRect(Some(hwnd), None, false);
                LRESULT(0)
            }

            WM_ERASEBKGND => LRESULT(1),

            WM_TIMER => {
                if let Some(app) = app_from(hwnd) {
                    app.tick = app.tick.wrapping_add(1);

                    // Only the frame cap needs watching now, and it lives in
                    // a file that changes when somebody changes it. Repaint
                    // only on a real change: invalidating on every tick would
                    // put this window back in the business of burning frames
                    // for nothing, which is the whole problem Lite avoids.
                    // The region list moves on its own as pings land, so it
                    // is copied every tick. The Roblox settings live in a
                    // file and only change when somebody changes them, so
                    // they are checked far less often.
                    let regions = app.engine.regions();
                    let best_ping = app.engine.best_ping();
                    let mut dirty = regions.len() != app.regions.len()
                        || best_ping != app.best_ping
                        || regions
                            .iter()
                            .zip(app.regions.iter())
                            .any(|(a, b)| a.ping_ms != b.ping_ms);
                    app.regions = regions;
                    app.best_ping = best_ping;

                    if app.tick % CAP_RECHECK_TICKS == 0 {
                        let unlock_cap = app.engine.fps_unlocked();
                        let frame_cap = app.engine.frame_cap();
                        let running = app.engine.roblox_running();
                        if unlock_cap != app.unlock_cap
                            || frame_cap != app.frame_cap
                            || running != app.roblox_running
                        {
                            app.unlock_cap = unlock_cap;
                            app.frame_cap = frame_cap;
                            app.roblox_running = running;
                            dirty = true;
                        }
                    }

                    // Repaint only on a real change. Invalidating every tick
                    // would put this window back in the business of burning
                    // frames for nothing, which is the whole problem Lite
                    // exists to avoid.
                    if dirty {
                        let _ = InvalidateRect(Some(hwnd), None, false);
                    }
                }
                LRESULT(0)
            }

            WM_DESTROY => {
                let _ = KillTimer(Some(hwnd), REFRESH_TIMER);
                // Dropping the App drops the Engine, which stops the game
                // watcher and closes the ETW trace.
                let ptr = SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0) as *mut App;
                if !ptr.is_null() {
                    drop(Box::from_raw(ptr));
                }
                PostQuitMessage(0);
                LRESULT(0)
            }

            _ => DefWindowProcW(hwnd, message, wparam, lparam),
        }
    }
}

/// Rebuild fonts and resize the window for the DPI it is actually on.
///
/// Type sizes come from the running app: micro-labels 10px/600 tracked
/// ~1.3px, body 13px, headline 19px/600, and the numeric readout 30px/600 in
/// mono with tight negative tracking.
unsafe fn build_fonts(app: &mut App) {
    let px = |logical: i32| (logical * app.scale_num) / app.scale_den.max(1);

    app.ui_micro = gdi::font(theme::FACE_UI, theme::FACE_UI_FALLBACK, px(10), 600, px(1));
    app.ui_body = gdi::font(theme::FACE_UI, theme::FACE_UI_FALLBACK, px(13), 400, 0);
    app.ui_title = gdi::font(theme::FACE_UI, theme::FACE_UI_FALLBACK, px(19), 600, 0);
    app.ui_button = gdi::font(theme::FACE_UI, theme::FACE_UI_FALLBACK, px(14), 600, 0);
    app.mono_big = gdi::font(theme::FACE_MONO, theme::FACE_MONO_FALLBACK, px(26), 600, -1);
    app.mono_small = gdi::font(theme::FACE_MONO, theme::FACE_MONO_FALLBACK, px(12), 500, 0);
    app.ui_semi = gdi::font(theme::FACE_UI, theme::FACE_UI_FALLBACK, px(13), 600, 0);
    app.ui_display = gdi::font(theme::FACE_UI, theme::FACE_UI_FALLBACK, px(25), 700, px(-1));
}

unsafe fn app_from<'a>(hwnd: HWND) -> Option<&'a mut App> {
    unsafe {
        let ptr = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut App;
        if ptr.is_null() { None } else { Some(&mut *ptr) }
    }
}

/// Paint into a memory DC, then blit once.
unsafe fn paint_buffered(hwnd: HWND, dc: HDC, app: &mut App) {
    unsafe {
        let mut client = RECT::default();
        let _ = GetClientRect(hwnd, &mut client);
        let w = client.right - client.left;
        let h = client.bottom - client.top;

        let mem = CreateCompatibleDC(Some(dc));
        let bmp = CreateCompatibleBitmap(dc, w, h);
        let old = SelectObject(mem, bmp.into());

        paint(mem, client, app);

        let _ = BitBlt(dc, 0, 0, w, h, Some(mem), 0, 0, SRCCOPY);

        SelectObject(mem, old);
        let _ = DeleteObject(bmp.into());
        let _ = DeleteDC(mem);
    }
}

unsafe fn paint(dc: HDC, client: RECT, app: &mut App) {
    // Nothing here is unsafe any more: shapes go through the canvas and the
    // blit and text helpers own their own unsafety. Kept as an unsafe fn so
    // the call sites, which hold raw device contexts, still read as such.
    {
        let w = client.right - client.left;
        let h = client.bottom - client.top;
        if w <= 0 || h <= 0 {
            return;
        }

        let l = layout(app, client, row_count(app));

        let mut canvas = Canvas::new(w, h, theme::BG);

        // The atmosphere is three radial gradients over every pixel, which is
        // square roots per pixel per paint. Recomputing it on every hover was
        // the stutter, so it is composited once per size and connection state
        // and copied back after that.
        let stale = match &app.backdrop {
            Some((cw, ch, live, pixels)) if *cw == w && *ch == h && *live == app.connected => {
                !canvas.restore(pixels)
            }
            _ => true,
        };
        if stale {
            surface::paint_atmosphere(&mut canvas, app.connected);
            app.backdrop = Some((w, h, app.connected, canvas.snapshot()));
        }

        draw_shapes(&mut canvas, app, &l);
        surface::blit(dc, &canvas);
        draw_text(dc, app, &l);
    }
}

fn rect_of(r: RECT, radius: i32) -> RoundRect {
    RoundRect::new(r.left, r.top, r.right - r.left, r.bottom - r.top, radius)
}

/// Colour for a round trip, on the app's own latency scale.
fn latency_paint(ms: Option<u32>) -> Rgba {
    match ms {
        None => theme::INACTIVE,
        Some(v) if v <= 60 => theme::CONNECTED,
        Some(v) if v <= 140 => theme::LATENCY_FAIR,
        Some(_) => theme::LATENCY_POOR,
    }
}

fn latency_ink(ms: Option<u32>) -> COLORREF {
    match ms {
        None => theme::TEXT_MUTED,
        Some(v) if v <= 60 => theme::CONNECTED_TEXT,
        Some(v) if v <= 140 => theme::LATENCY_FAIR_TEXT,
        Some(_) => theme::LATENCY_POOR_TEXT,
    }
}

/// Title and one line of explanation, per page, the way the header reads in
/// the full app.
fn page_heading(screen: Screen) -> (&'static str, &'static str) {
    match screen {
        Screen::Connect => ("Connect", "Route game traffic through the fastest relay"),
        Screen::Roblox => ("Roblox", "Frame cap and launch settings"),
        Screen::Settings => ("Settings", "Account, version and updates"),
    }
}

/// The sidebar's section headings, one page each.
const SECTIONS: [&str; 3] = ["tunnel", "performance", "system"];

// ---------------------------------------------------------------------------
// Shapes
// ---------------------------------------------------------------------------

fn draw_shapes(canvas: &mut Canvas, app: &App, l: &Layout) {
    draw_shell_shapes(canvas, app, l);

    match app.screen {
        Screen::Connect => draw_connect_shapes(canvas, app, l),
        Screen::Roblox => draw_roblox_shapes(canvas, app, l),
        Screen::Settings => draw_card(canvas, app, l),
    }
}

fn draw_shell_shapes(canvas: &mut Canvas, app: &App, l: &Layout) {
    // Sidebar plate, square rather than rounded: it runs the full height of
    // the window and a radius would read as a floating panel.
    canvas.fill_round_rect(rect_of(l.sidebar, 0), theme::SIDEBAR);
    canvas.fill_round_rect(
        RoundRect::new(l.sidebar.right - 1, l.sidebar.top, 1, l.sidebar.bottom, 0),
        theme::BORDER,
    );

    // Wordmark.
    canvas.fill_round_rect(rect_of(l.logo_mark, app.s(8)), theme::ACCENT);

    // The selected page.
    let index = Screen::ALL
        .iter()
        .position(|s| *s == app.screen)
        .unwrap_or(0);
    for (i, item) in l.nav.iter().enumerate() {
        let shape = rect_of(*item, app.s(9));
        if i == index {
            canvas.fill_round_rect(shape, theme::BG_HOVER);
        } else if app.hot == Hot::Nav(i as u8) {
            canvas.fill_round_rect(shape, theme::CARD);
        }
    }

    // Session card at the foot of the sidebar.
    let status = rect_of(l.side_status, app.s(10));
    canvas.fill_round_rect(status, theme::BG);
    canvas.stroke_round_rect(status.inset(0.5), theme::BORDER, 1.0);
    canvas.fill_circle(
        l.side_status.left as f32 + app.s(14) as f32,
        l.side_status.top as f32 + app.s(17) as f32,
        app.s(3) as f32,
        if app.connected {
            theme::CONNECTED
        } else {
            theme::INACTIVE
        },
    );

    // Avatar.
    canvas.fill_circle(
        l.side_account.left as f32 + app.s(13) as f32,
        (l.side_account.top + l.side_account.bottom) as f32 / 2.0,
        app.s(13) as f32,
        theme::CARD,
    );

    // Header hairline, so the content scrolls under something rather than
    // floating free.
    canvas.fill_round_rect(
        RoundRect::new(
            l.header.left,
            l.header.bottom - 1,
            l.header.right - l.header.left,
            1,
            0,
        ),
        theme::BORDER,
    );

    // Connection pill.
    let pill = rect_of(l.pill, (l.pill.bottom - l.pill.top) / 2);
    canvas.fill_round_rect(pill, theme::CARD);
    canvas.stroke_round_rect(pill.inset(0.5), theme::BORDER, 1.0);
    canvas.fill_circle(
        l.pill.left as f32 + app.s(16) as f32,
        (l.pill.top + l.pill.bottom) as f32 / 2.0,
        app.s(3) as f32,
        if app.connected {
            theme::CONNECTED
        } else {
            theme::INACTIVE
        },
    );
}

fn draw_card(canvas: &mut Canvas, app: &App, l: &Layout) {
    let card = rect_of(l.card, app.s(theme::RADIUS));
    canvas.fill_round_rect(card, theme::CARD);
    canvas.stroke_round_rect(card.inset(0.5), theme::BORDER, 1.0);

    let pad = app.s(16) as f32;
    for row in l.rows.iter().skip(1) {
        canvas.fill_round_rect(
            RoundRect {
                x: card.x + pad,
                y: row.top as f32,
                w: card.w - pad * 2.0,
                h: 1.0,
                radius: 0.0,
            },
            theme::BORDER,
        );
    }
}

fn draw_connect_shapes(canvas: &mut Canvas, app: &App, l: &Layout) {
    let badge = rect_of(l.badge, app.s(6));
    canvas.fill_round_rect(badge, theme::CARD);
    canvas.stroke_round_rect(badge.inset(0.5), theme::BORDER, 1.0);

    let button = rect_of(l.connect, app.s(theme::RADIUS_BTN));
    let hot = app.hot == Hot::Connect;
    if app.connected {
        canvas.fill_round_rect(button, theme::CARD);
        canvas.stroke_round_rect(
            button.inset(0.5),
            if hot {
                theme::BORDER_STRONG
            } else {
                theme::BORDER
            },
            1.0,
        );
    } else {
        canvas.drop_shadow(
            button,
            Rgba::hexa(0x000000, 0.55),
            app.s(18) as f32,
            app.s(6) as f32,
        );
        canvas.fill_round_rect(
            button,
            if hot {
                Rgba::hex(0xFFFFFF)
            } else {
                theme::ACCENT
            },
        );
    }

    draw_card(canvas, app, l);

    let card = rect_of(l.card, app.s(theme::RADIUS));
    for (i, row) in l.rows.iter().enumerate() {
        let Some(region) = app.regions.get(i) else {
            continue;
        };

        if app.hot == Hot::Region(i as u8) {
            let mut hover = rect_of(*row, app.s(8));
            hover.x += 4.0;
            hover.w -= 8.0;
            canvas.fill_round_rect(hover, theme::BG_HOVER);
        }

        // Selected page marker down the left edge, the way the app marks the
        // region you are pinned to.
        if region.id == app.region {
            canvas.fill_round_rect(
                RoundRect::new(
                    row.left + app.s(4),
                    row.top + app.s(10),
                    app.s(2),
                    row.bottom - row.top - app.s(20),
                    1,
                ),
                theme::ACCENT,
            );
        }

        let badge = RoundRect::new(
            row.left + app.s(16),
            (row.top + row.bottom) / 2 - app.s(10),
            app.s(26),
            app.s(20),
            app.s(5),
        );
        canvas.fill_round_rect(badge, theme::BG);
        canvas.stroke_round_rect(badge.inset(0.5), theme::BORDER_STRONG, 1.0);

        let bars = region.bars();
        let bar_w = app.s(3);
        let gap = app.s(2);
        let base = row.right - app.s(76);
        let foot = (row.top + row.bottom) / 2 + app.s(6);
        for b in 0..3u8 {
            let height = app.s(4 + 3 * b as i32);
            canvas.fill_round_rect(
                RoundRect::new(
                    base + (bar_w + gap) * b as i32,
                    foot - height,
                    bar_w,
                    height,
                    1,
                ),
                if b < bars {
                    latency_paint(region.ping_ms)
                } else {
                    theme::BORDER_STRONG
                },
            );
        }
    }
    let _ = card;
}

fn draw_roblox_shapes(canvas: &mut Canvas, app: &App, l: &Layout) {
    draw_card(canvas, app, l);

    let Some(row) = l.rows.first() else {
        return;
    };

    // Pill switch, in the app's idiom rather than a checkbox.
    let w = app.s(38);
    let h = app.s(22);
    let mid = (row.top + row.bottom) / 2;
    let track = RoundRect::new(row.right - app.s(16) - w, mid - h / 2, w, h, h / 2);

    canvas.fill_round_rect(
        track,
        if app.unlock_cap {
            theme::ACCENT
        } else {
            theme::BG
        },
    );
    if !app.unlock_cap {
        canvas.stroke_round_rect(
            track.inset(0.5),
            if app.hot == Hot::Unlock {
                theme::BORDER_STRONG
            } else {
                theme::BORDER
            },
            1.0,
        );
    }

    let knob_r = (h as f32 / 2.0) - app.s(3) as f32;
    let knob_x = if app.unlock_cap {
        track.x + track.w - knob_r - app.s(3) as f32
    } else {
        track.x + knob_r + app.s(3) as f32
    };
    canvas.fill_circle(
        knob_x,
        mid as f32,
        knob_r,
        if app.unlock_cap {
            Rgba::hex(0x0A0A0A)
        } else {
            theme::BORDER_STRONG
        },
    );
}

// ---------------------------------------------------------------------------
// Text
// ---------------------------------------------------------------------------

fn draw_text(dc: HDC, app: &App, l: &Layout) {
    draw_shell_text(dc, app, l);

    match app.screen {
        Screen::Connect => draw_connect_text(dc, app, l),
        Screen::Roblox => draw_roblox_text(dc, app, l),
        Screen::Settings => draw_settings_text(dc, app, l),
    }
}

fn draw_shell_text(dc: HDC, app: &App, l: &Layout) {
    gdi::text(
        dc,
        "SwiftTunnel",
        l.logo_text,
        &app.ui_semi,
        theme::TEXT,
        DT_SINGLELINE | DT_VCENTER | DT_NOPREFIX,
        0,
    );

    for (i, screen) in Screen::ALL.iter().enumerate() {
        kicker(dc, app, SECTIONS[i], l.sections[i]);

        let selected = *screen == app.screen;
        gdi::text(
            dc,
            screen.label(),
            RECT {
                left: l.nav[i].left + app.s(14),
                ..l.nav[i]
            },
            &app.ui_semi,
            if selected {
                theme::TEXT
            } else {
                theme::TEXT_SECONDARY
            },
            DT_SINGLELINE | DT_VCENTER | DT_NOPREFIX,
            0,
        );
    }

    kicker(
        dc,
        app,
        if app.connected {
            "connected"
        } else {
            "not connected"
        },
        RECT {
            left: l.side_status.left + app.s(24),
            top: l.side_status.top + app.s(11),
            right: l.side_status.right - app.s(8),
            bottom: l.side_status.top + app.s(25),
        },
    );
    gdi::text(
        dc,
        if app.connected {
            "Session live"
        } else {
            "No active session"
        },
        RECT {
            left: l.side_status.left + app.s(24),
            top: l.side_status.top + app.s(27),
            right: l.side_status.right - app.s(8),
            bottom: l.side_status.bottom - app.s(6),
        },
        &app.ui_body,
        theme::TEXT_MUTED,
        DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS,
        0,
    );

    gdi::text(
        dc,
        &app.account(),
        RECT {
            left: l.side_account.left + app.s(32),
            ..l.side_account
        },
        &app.ui_body,
        theme::TEXT_MUTED,
        DT_SINGLELINE | DT_VCENTER | DT_NOPREFIX | DT_END_ELLIPSIS,
        0,
    );

    let (title, subtitle) = page_heading(app.screen);
    gdi::text(
        dc,
        title,
        l.title,
        &app.ui_display,
        theme::TEXT,
        DT_SINGLELINE | DT_NOPREFIX,
        0,
    );
    gdi::text(
        dc,
        subtitle,
        l.subtitle,
        &app.ui_body,
        theme::TEXT_MUTED,
        DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS,
        0,
    );

    kicker(
        dc,
        app,
        if app.connected {
            "connected"
        } else {
            "disconnected"
        },
        RECT {
            left: l.pill.left + app.s(26),
            ..l.pill
        },
    );
}

/// The tracked uppercase label the app puts above every value.
fn kicker(dc: HDC, app: &App, text: &str, rect: RECT) {
    gdi::text(
        dc,
        &text.to_uppercase(),
        rect,
        &app.ui_micro,
        theme::TEXT_MUTED,
        DT_SINGLELINE | DT_VCENTER | DT_NOPREFIX,
        app.s(2),
    );
}

fn draw_connect_text(dc: HDC, app: &App, l: &Layout) {
    let selected = app.regions.iter().find(|r| r.id == app.region);

    kicker(
        dc,
        app,
        if app.connected {
            "tunnelled to"
        } else {
            "ready to tunnel"
        },
        l.kicker,
    );
    gdi::text(
        dc,
        selected.map(|r| r.country.as_str()).unwrap_or("ST"),
        l.badge,
        &app.ui_micro,
        theme::TEXT_MUTED,
        DT_SINGLELINE | DT_CENTER | DT_VCENTER | DT_NOPREFIX,
        app.s(1),
    );
    gdi::text(
        dc,
        selected.map(|r| r.name.as_str()).unwrap_or("Auto"),
        l.headline,
        &app.ui_display,
        theme::TEXT,
        DT_SINGLELINE | DT_NOPREFIX,
        0,
    );

    let relays = selected.map(|r| r.relays).unwrap_or(0);
    let sub = match relays {
        0 => "picks the fastest relay".to_string(),
        1 => "1 relay available".to_string(),
        n => format!("{n} relays available"),
    };
    gdi::text(
        dc,
        &sub,
        l.sub,
        &app.ui_body,
        theme::TEXT_MUTED,
        DT_SINGLELINE | DT_NOPREFIX,
        0,
    );

    gdi::text(
        dc,
        if app.connected {
            "Disconnect"
        } else {
            "Connect"
        },
        l.connect,
        &app.ui_button,
        if app.connected {
            theme::TEXT
        } else {
            theme::ON_ACCENT
        },
        DT_SINGLELINE | DT_CENTER | DT_VCENTER | DT_NOPREFIX,
        0,
    );

    let ping = selected.and_then(|r| r.ping_ms).or(app.best_ping);
    stat(
        dc,
        app,
        l.stat_left,
        "relay rtt",
        &ping
            .map(|v| format!("{v} ms"))
            .unwrap_or_else(|| "--".to_string()),
        latency_ink(ping),
    );
    stat(
        dc,
        app,
        l.stat_right,
        "session",
        if app.connected { "live" } else { "--" },
        if app.connected {
            theme::CONNECTED_TEXT
        } else {
            theme::TEXT_MUTED
        },
    );

    kicker(
        dc,
        app,
        &format!("regions  {}", app.regions.len()),
        l.list_label,
    );

    for (i, row) in l.rows.iter().enumerate() {
        let Some(region) = app.regions.get(i) else {
            gdi::text(
                dc,
                "Finding relays...",
                *row,
                &app.ui_body,
                theme::TEXT_MUTED,
                DT_SINGLELINE | DT_VCENTER | DT_CENTER | DT_NOPREFIX,
                0,
            );
            continue;
        };

        gdi::text(
            dc,
            &region.country,
            RECT {
                left: row.left + app.s(16),
                right: row.left + app.s(42),
                ..*row
            },
            &app.ui_micro,
            theme::TEXT_MUTED,
            DT_SINGLELINE | DT_CENTER | DT_VCENTER | DT_NOPREFIX,
            app.s(1),
        );
        gdi::text(
            dc,
            &region.name,
            RECT {
                left: row.left + app.s(52),
                right: row.right - app.s(84),
                ..*row
            },
            &app.ui_semi,
            if region.id == app.region {
                theme::TEXT
            } else {
                theme::TEXT_SECONDARY
            },
            DT_SINGLELINE | DT_VCENTER | DT_NOPREFIX | DT_END_ELLIPSIS,
            0,
        );
        gdi::text(
            dc,
            &region
                .ping_ms
                .map(|v| format!("{v} ms"))
                .unwrap_or_else(|| "--".to_string()),
            RECT {
                left: row.right - app.s(64),
                right: row.right - app.s(16),
                ..*row
            },
            &app.mono_small,
            latency_ink(region.ping_ms),
            DT_SINGLELINE | DT_VCENTER | DT_RIGHT | DT_NOPREFIX,
            0,
        );
    }
}

/// A tracked label with a mono value beneath it.
fn stat(dc: HDC, app: &App, rect: RECT, label: &str, value: &str, ink: COLORREF) {
    kicker(
        dc,
        app,
        label,
        RECT {
            bottom: rect.top + app.s(14),
            ..rect
        },
    );
    gdi::text(
        dc,
        value,
        RECT {
            top: rect.top + app.s(20),
            ..rect
        },
        &app.mono_big,
        ink,
        DT_SINGLELINE | DT_NOPREFIX,
        app.s(-1),
    );
}

fn draw_roblox_text(dc: HDC, app: &App, l: &Layout) {
    kicker(dc, app, "game", l.kicker);
    gdi::text(
        dc,
        if app.roblox_running {
            "Running"
        } else {
            "Not running"
        },
        RECT {
            left: l.kicker.left,
            ..l.headline
        },
        &app.ui_display,
        theme::TEXT,
        DT_SINGLELINE | DT_NOPREFIX,
        0,
    );
    gdi::text(
        dc,
        if app.roblox_running {
            "changes apply on the next launch"
        } else {
            "start Roblox to see it here"
        },
        RECT {
            left: l.kicker.left,
            ..l.sub
        },
        &app.ui_body,
        theme::TEXT_MUTED,
        DT_SINGLELINE | DT_NOPREFIX,
        0,
    );

    if let Some(row) = l.rows.first() {
        gdi::text(
            dc,
            "Unlock frame cap",
            RECT {
                left: row.left + app.s(16),
                top: row.top + app.s(12),
                right: row.right - app.s(70),
                bottom: row.top + app.s(32),
            },
            &app.ui_semi,
            theme::TEXT,
            DT_SINGLELINE | DT_NOPREFIX,
            0,
        );
        gdi::text(
            dc,
            "Removes Roblox's 60 FPS limit",
            RECT {
                left: row.left + app.s(16),
                top: row.top + app.s(34),
                right: row.right - app.s(70),
                bottom: row.bottom - app.s(8),
            },
            &app.ui_body,
            theme::TEXT_MUTED,
            DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS,
            0,
        );
    }

    if let Some(row) = l.rows.get(1) {
        row_label(dc, app, *row, app.s(16), "Frame cap");
        gdi::text(
            dc,
            &app.frame_cap.to_string(),
            RECT {
                right: row.right - app.s(16),
                ..*row
            },
            &app.mono_small,
            if app.unlock_cap {
                theme::CONNECTED_TEXT
            } else {
                theme::TEXT_MUTED
            },
            DT_SINGLELINE | DT_VCENTER | DT_RIGHT | DT_NOPREFIX,
            0,
        );
    }
}

fn draw_settings_text(dc: HDC, app: &App, l: &Layout) {
    kicker(dc, app, "signed in as", l.kicker);
    gdi::text(
        dc,
        &app.account(),
        RECT {
            left: l.kicker.left,
            ..l.headline
        },
        &app.ui_title,
        theme::TEXT,
        DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS,
        0,
    );
    gdi::text(
        dc,
        "the full app shares this session",
        RECT {
            left: l.kicker.left,
            ..l.sub
        },
        &app.ui_body,
        theme::TEXT_MUTED,
        DT_SINGLELINE | DT_NOPREFIX,
        0,
    );

    if let Some(row) = l.rows.first() {
        row_label(dc, app, *row, app.s(16), "Version");
        row_value(dc, app, *row, app.s(16), env!("CARGO_PKG_VERSION"));
    }
    if let Some(row) = l.rows.get(1) {
        row_label(dc, app, *row, app.s(16), "Channel");
        row_value(dc, app, *row, app.s(16), "Preview");
    }
}
/// Left-hand label of a list row.
fn row_label(dc: HDC, app: &App, row: RECT, pad: i32, value: &str) {
    gdi::text(
        dc,
        value,
        RECT {
            left: row.left + pad,
            top: row.top,
            right: row.right - pad,
            bottom: row.bottom,
        },
        &app.ui_body,
        theme::TEXT,
        DT_SINGLELINE | DT_VCENTER | DT_NOPREFIX,
        0,
    );
}

/// Right-aligned value of a list row.
fn row_value(dc: HDC, app: &App, row: RECT, pad: i32, value: &str) {
    gdi::text(
        dc,
        value,
        RECT {
            left: row.left + pad,
            top: row.top,
            right: row.right - pad,
            bottom: row.bottom,
        },
        &app.ui_body,
        theme::TEXT_SECONDARY,
        DT_SINGLELINE | DT_VCENTER | DT_RIGHT | DT_NOPREFIX,
        0,
    );
}
