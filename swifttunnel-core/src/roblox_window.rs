//! Window placement via public Win32 APIs. No hooks or process injection.
use serde::Serialize;
use windows::{
    Win32::{
        Foundation::{HWND, LPARAM, RECT},
        Graphics::Gdi::{
            EnumDisplayMonitors, GetMonitorInfoW, HDC, HMONITOR, MONITOR_DEFAULTTONEAREST,
            MONITORINFO, MONITORINFOEXW, MonitorFromWindow,
        },
        UI::WindowsAndMessaging::*,
    },
    core::BOOL,
};
#[derive(Clone, Serialize)]
pub struct Display {
    pub id: String,
    pub primary: bool,
    pub left: i32,
    pub top: i32,
    pub width: i32,
    pub height: i32,
}

#[derive(Clone, Serialize)]
pub struct GameMonitor {
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
    pub scale: f64,
}

pub fn monitor_for_player(pid: u32) -> Option<GameMonitor> {
    let mut search = FindWindow { pid, window: None };
    unsafe {
        let _ = EnumWindows(
            Some(window_callback),
            LPARAM((&mut search as *mut FindWindow) as isize),
        );
        let window = search.window?;
        let monitor = MonitorFromWindow(window, MONITOR_DEFAULTTONEAREST);
        let mut info = MONITORINFO {
            cbSize: std::mem::size_of::<MONITORINFO>() as u32,
            ..Default::default()
        };
        if !GetMonitorInfoW(monitor, &mut info).as_bool() {
            return None;
        }
        let r = info.rcMonitor;
        let dpi = windows::Win32::UI::HiDpi::GetDpiForWindow(window);
        Some(GameMonitor {
            x: r.left,
            y: r.top,
            w: r.right - r.left,
            h: r.bottom - r.top,
            scale: if dpi > 0 { f64::from(dpi) / 96.0 } else { 1.0 },
        })
    }
}
pub fn displays() -> Vec<Display> {
    let mut result = Vec::new();
    unsafe {
        let _ = EnumDisplayMonitors(
            None,
            None,
            Some(monitor_callback),
            LPARAM((&mut result as *mut Vec<Display>) as isize),
        );
    }
    result
}
unsafe extern "system" fn monitor_callback(
    monitor: HMONITOR,
    _: HDC,
    _: *mut RECT,
    data: LPARAM,
) -> BOOL {
    unsafe {
        let result = &mut *(data.0 as *mut Vec<Display>);
        if result.len() >= 16 {
            return false.into();
        }
        let mut info = MONITORINFOEXW::default();
        info.monitorInfo.cbSize = std::mem::size_of::<MONITORINFOEXW>() as u32;
        if GetMonitorInfoW(monitor, &mut info as *mut _ as *mut MONITORINFO).as_bool() {
            let end = info
                .szDevice
                .iter()
                .position(|v| *v == 0)
                .unwrap_or(info.szDevice.len());
            let r = info.monitorInfo.rcMonitor;
            result.push(Display {
                id: String::from_utf16_lossy(&info.szDevice[..end]),
                primary: info.monitorInfo.dwFlags & 1 != 0,
                left: r.left,
                top: r.top,
                width: r.right - r.left,
                height: r.bottom - r.top,
            });
        }
        true.into()
    }
}
struct FindWindow {
    pid: u32,
    window: Option<HWND>,
}
unsafe extern "system" fn window_callback(window: HWND, data: LPARAM) -> BOOL {
    unsafe {
        let search = &mut *(data.0 as *mut FindWindow);
        let mut pid = 0;
        GetWindowThreadProcessId(window, Some(&mut pid));
        if pid == search.pid
            && IsWindowVisible(window).as_bool()
            && GetWindow(window, GW_OWNER)
                .ok()
                .is_none_or(|owner| owner.0.is_null())
        {
            search.window = Some(window);
            return false.into();
        }
        true.into()
    }
}
pub fn place(pid: u32, borderless: bool, monitor: Option<&str>) -> Result<bool, String> {
    if !borderless && monitor.is_none() {
        return Ok(true);
    }
    let available = displays();
    let mut search = FindWindow { pid, window: None };
    unsafe {
        let _ = EnumWindows(
            Some(window_callback),
            LPARAM((&mut search as *mut FindWindow) as isize),
        );
    }
    let Some(window) = search.window else {
        return Ok(false);
    };
    unsafe {
        let mut current = RECT::default();
        GetWindowRect(window, &mut current).map_err(|e| e.to_string())?;
        let center = (
            (current.left + current.right) / 2,
            (current.top + current.bottom) / 2,
        );
        let selected = monitor
            .and_then(|id| available.iter().find(|d| d.id == id))
            .or_else(|| {
                if monitor.is_none() {
                    available.iter().find(|d| {
                        center.0 >= d.left
                            && center.0 < d.left + d.width
                            && center.1 >= d.top
                            && center.1 < d.top + d.height
                    })
                } else {
                    None
                }
            })
            .or_else(|| available.iter().find(|d| d.primary))
            .ok_or("No display is available.")?;
        if borderless {
            let style = GetWindowLongPtrW(window, GWL_STYLE);
            SetWindowLongPtrW(
                window,
                GWL_STYLE,
                style & !(WS_CAPTION.0 as isize | WS_THICKFRAME.0 as isize),
            );
        }
        let (width, height) = if borderless {
            (selected.width, selected.height)
        } else {
            (
                (current.right - current.left).min(selected.width),
                (current.bottom - current.top).min(selected.height),
            )
        };
        SetWindowPos(
            window,
            None,
            selected.left,
            selected.top,
            width,
            height,
            SWP_NOACTIVATE | SWP_NOZORDER | SWP_FRAMECHANGED,
        )
        .map_err(|e| e.to_string())?;
    }
    Ok(true)
}
