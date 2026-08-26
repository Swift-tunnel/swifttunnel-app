//! The product's own typefaces, carried inside the binary.
//!
//! **Geist** and **Geist Mono**, which is what `index.html` loads for the whole
//! app. An earlier pass used Figtree and Azeret Mono because the Connect tab's
//! own stylesheet imports them, but those are a local override on one screen;
//! the face anyone recognises as SwiftTunnel, in the sidebar and every heading,
//! is Geist. Getting that wrong is why the window kept reading as somebody
//! else's app even after the colours and the layout were right.
//!
//! Neither ships with Windows, and GDI substitutes a missing face rather than
//! failing, so asking for a font that is not registered silently gets you Segoe
//! UI and no warning.
//!
//! The files are embedded with `include_bytes!` and registered from memory, so:
//!
//! - Lite stays one self-contained exe, which is the whole point of it.
//! - Nothing is installed system-wide, so uninstalling leaves no trace and no
//!   elevation is needed to render text.
//! - There is no download at startup and no dependency on Google Fonts being
//!   reachable, which matters for users behind exactly the sort of censorship
//!   this product exists to get around.
//!
//! Both are SIL Open Font Licence, which permits embedding and redistribution.
//! `resources/fonts` carries their licences alongside them.
//!
//! # Variable fonts
//!
//! Upstream only publishes these as variable fonts, and GDI has no idea what a
//! weight axis is: it registers the default instance and fakes anything heavier
//! by smearing the outline. So the type scale leans on size and colour for
//! hierarchy rather than on weight, and asks for at most one step of emphasis.

use std::ffi::c_void;

use windows::Win32::Graphics::Gdi::AddFontMemResourceEx;

/// Geist, the UI face.
const GEIST: &[u8] = include_bytes!("../resources/fonts/Geist.ttf");

/// Geist Mono, for every measurement.
const GEIST_MONO: &[u8] = include_bytes!("../resources/fonts/GeistMono.ttf");

/// Register both faces for this process.
///
/// Call once, before any font is created. Failures are deliberately silent: a
/// face that does not register falls back to the stack in `theme`, which is
/// worse looking but perfectly usable, and a window that refuses to open
/// because a font did not load would be a far worse outcome.
pub fn install() {
    let loaded = register(GEIST) + register(GEIST_MONO);
    log::info!("registered {loaded} embedded font faces");
}

fn register(bytes: &'static [u8]) -> u32 {
    let mut faces: u32 = 0;

    // SAFETY: the buffer comes from `include_bytes!` and so lives for the whole
    // program, which is what AddFontMemResourceEx requires: it does not copy,
    // and the memory must outlive every font created from it.
    let handle = unsafe {
        AddFontMemResourceEx(
            bytes.as_ptr() as *const c_void,
            bytes.len() as u32,
            None,
            &mut faces,
        )
    };

    if handle.is_invalid() {
        log::warn!("an embedded font face failed to register");
        return 0;
    }

    // The handle is deliberately dropped. Removing the font is only useful at
    // shutdown, and the process exiting frees it anyway.
    faces
}
