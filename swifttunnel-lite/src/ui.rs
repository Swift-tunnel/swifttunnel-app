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

use crate::backdrop::Backdrop;
use crate::engine::Engine;

use crate::gdi::{self, Font};
use crate::theme;

/// What the pointer is currently over, so it can be drawn lit.
#[derive(PartialEq, Clone, Copy)]
enum Hot {
    None,
    Connect,
    Unlock,
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
    /// Cached atmosphere. Rebuilt only on a resize or a connection change.
    backdrop: Backdrop,
    /// Refresh count, used to space out the slower checks.
    tick: u32,
    dpi: i32,
    /// Client width over design width, as a fraction so the maths stays integer.
    scale_num: i32,
    scale_den: i32,

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
/// Deliberately not a miniature of the full app. The previous version stacked
/// three floating cards down a 400px window, which is a shape designed for a
/// 1200px one and reads as a bad copy at this size. This is what Windows does
/// for a small utility: a status line, one primary action, and the settings
/// gathered into a single list.
struct Layout {
    /// State dot, left of the headline.
    dot: RECT,
    headline: RECT,
    subtitle: RECT,
    connect: RECT,
    /// The list both rows share.
    list: RECT,
    region_row: RECT,
    unlock_row: RECT,
    account: RECT,
}

fn layout(app: &App, client: RECT) -> Layout {
    let pad = app.s(theme::PAD);
    let left = client.left + pad;
    let right = client.right - pad;
    let y = |v: i32| client.top + app.s(v);
    let row_h = app.s(theme::ROW_H);

    // Headline is indented past the dot so the two read as one line.
    let text_left = left + app.s(16);
    let list_top = y(150);

    Layout {
        dot: RECT {
            left,
            top: y(30),
            right: left + app.s(8),
            bottom: y(38),
        },
        headline: RECT {
            left: text_left,
            top: y(22),
            right,
            bottom: y(50),
        },
        subtitle: RECT {
            left: text_left,
            top: y(52),
            right,
            bottom: y(70),
        },
        connect: RECT {
            left,
            top: y(88),
            right,
            bottom: y(132),
        },
        list: RECT {
            left,
            top: list_top,
            right,
            bottom: list_top + row_h * 2,
        },
        region_row: RECT {
            left,
            top: list_top,
            right,
            bottom: list_top + row_h,
        },
        unlock_row: RECT {
            left,
            top: list_top + row_h,
            right,
            bottom: list_top + row_h * 2,
        },
        account: RECT {
            left,
            top: y(258),
            right,
            bottom: y(276),
        },
    }
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

        // Built before the window so the first paint already shows the
        // real frame cap rather than flicking from off to on a moment later.
        let engine = Engine::new();
        let unlock_cap = engine.fps_unlocked();

        let app = Box::new(App {
            auth,
            engine,
            backdrop: Backdrop::new(),
            tick: 0,
            dpi,
            scale_num: theme::WINDOW_W,
            scale_den: theme::WINDOW_W,
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
        });

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
                    let l = layout(app, client);

                    let hot = if contains(l.connect, x, y) {
                        Hot::Connect
                    } else if contains(l.unlock_row, x, y) {
                        Hot::Unlock
                    } else {
                        Hot::None
                    };

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
                    let l = layout(app, client);

                    if contains(l.connect, x, y) {
                        // Still visual only: the tunnel is the next piece.
                        // It no longer invents a frame rate to go with it,
                        // because the number on screen now comes from the
                        // game and inventing one was a lie waiting to ship.
                        app.connected = !app.connected;
                        let _ = InvalidateRect(Some(hwnd), None, false);
                    } else if contains(l.unlock_row, x, y) {
                        let wanted = !app.unlock_cap;
                        match app.engine.set_fps_unlocked(wanted) {
                            // Only move the switch once the cap actually
                            // changed, so what is on screen is what is on
                            // disk.
                            Ok(()) => app.unlock_cap = wanted,
                            Err(reason) => {
                                log::warn!("could not change the frame cap: {reason}")
                            }
                        }
                        let _ = InvalidateRect(Some(hwnd), None, false);
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
                    if app.tick % CAP_RECHECK_TICKS == 0 {
                        let unlock_cap = app.engine.fps_unlocked();
                        if unlock_cap != app.unlock_cap {
                            app.unlock_cap = unlock_cap;
                            let _ = InvalidateRect(Some(hwnd), None, false);
                        }
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
    app.mono_big = gdi::font(theme::FACE_MONO, theme::FACE_MONO_FALLBACK, px(30), 600, -1);
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
    unsafe {
        // Ground. The flat fill stays as a floor under the atmosphere so a
        // failed bitmap shows the right black rather than uninitialised memory.
        let bg = CreateSolidBrush(theme::BG);
        FillRect(dc, &client, bg);
        let _ = DeleteObject(bg.into());

        let width = client.right - client.left;
        let height = client.bottom - client.top;
        app.backdrop.draw(dc, width, height, app.connected);

        let l = layout(app, client);

        // ---- Status --------------------------------------------------------
        // A line, not a card. At this width a border around two strings is just
        // a border, and it was the thing making the window look like a dialog.
        gdi::dot(
            dc,
            l.dot.left + app.s(4),
            l.dot.top + app.s(4),
            app.s(4),
            if app.connected {
                theme::CONNECTED
            } else {
                theme::INACTIVE
            },
        );

        gdi::text(
            dc,
            if app.connected {
                app.region.as_str()
            } else {
                "Not connected"
            },
            l.headline,
            &app.ui_title,
            theme::TEXT,
            DT_SINGLELINE | DT_NOPREFIX,
            0,
        );

        gdi::text(
            dc,
            if app.connected {
                "Tunnel active"
            } else {
                "Tunnel is off"
            },
            l.subtitle,
            &app.ui_body,
            theme::TEXT_MUTED,
            DT_SINGLELINE | DT_NOPREFIX,
            0,
        );

        // ---- Connect -------------------------------------------------------
        let hot = app.hot == Hot::Connect;
        let (fill, ink, outline): (Option<COLORREF>, COLORREF, Option<COLORREF>) = if app.connected
        {
            // Secondary once connected: the primary action is done.
            (
                Some(theme::CARD),
                theme::TEXT,
                Some(if hot {
                    theme::BORDER_STRONG
                } else {
                    theme::BORDER
                }),
            )
        } else if hot {
            (Some(theme::TEXT), theme::ON_ACCENT, None)
        } else {
            (Some(theme::ACCENT), theme::ON_ACCENT, None)
        };

        gdi::round_rect(dc, l.connect, app.s(theme::RADIUS_BTN), fill, outline);
        gdi::text(
            dc,
            if app.connected {
                "Disconnect"
            } else {
                "Connect"
            },
            l.connect,
            &app.ui_button,
            ink,
            DT_SINGLELINE | DT_CENTER | DT_VCENTER | DT_NOPREFIX,
            0,
        );

        // ---- Settings list -------------------------------------------------
        gdi::round_rect(
            dc,
            l.list,
            app.s(theme::RADIUS),
            Some(theme::CARD),
            Some(theme::BORDER),
        );

        let row_pad = app.s(16);

        // Hairline between the rows, inset so it does not touch the corners.
        let line = RECT {
            left: l.list.left + row_pad,
            top: l.region_row.bottom,
            right: l.list.right - row_pad,
            bottom: l.region_row.bottom + app.s(1).max(1),
        };
        let hairline = CreateSolidBrush(theme::BORDER);
        FillRect(dc, &line, hairline);
        let _ = DeleteObject(hairline.into());

        row_label(dc, app, l.region_row, row_pad, "Region");
        row_value(dc, app, l.region_row, row_pad, app.region.as_str());

        row_label(dc, app, l.unlock_row, row_pad, "Unlock Roblox frame cap");

        // The switch sits at the right of its row, where Windows puts it.
        let knob = app.s(18);
        let mid = (l.unlock_row.top + l.unlock_row.bottom) / 2;
        let check = RECT {
            left: l.unlock_row.right - row_pad - knob,
            top: mid - knob / 2,
            right: l.unlock_row.right - row_pad,
            bottom: mid + knob / 2,
        };
        gdi::round_rect(
            dc,
            check,
            app.s(5),
            Some(if app.unlock_cap {
                theme::ACCENT
            } else {
                theme::BG
            }),
            Some(if app.unlock_cap {
                theme::ACCENT
            } else if app.hot == Hot::Unlock {
                theme::BORDER_STRONG
            } else {
                theme::BORDER
            }),
        );
        if app.unlock_cap {
            gdi::text(
                dc,
                "\u{2713}",
                check,
                &app.ui_body,
                theme::ON_ACCENT,
                DT_SINGLELINE | DT_CENTER | DT_VCENTER | DT_NOPREFIX,
                0,
            );
        }

        // ---- Account -------------------------------------------------------
        gdi::text(
            dc,
            &app.account(),
            l.account,
            &app.ui_body,
            theme::TEXT_MUTED,
            DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS,
            0,
        );
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
