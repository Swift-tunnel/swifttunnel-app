//! The product's own typefaces, carried inside the binary.
//!
//! **Geist** and **Geist Mono**, which is what `index.html` loads for the whole
//! app. An earlier pass used Figtree and Azeret Mono because the Connect tab's
//! own stylesheet imports them, but those are a local override on one screen;
//! the face anyone recognises as SwiftTunnel, in the sidebar and every heading,
//! is Geist.
//!
//! Neither ships with Windows, and GDI substitutes a missing face rather than
//! failing, so asking for a font that is not registered silently gets you Segoe
//! UI and no warning at all.
//!
//! # Real weights, not a variable font
//!
//! Google's font repository only publishes Geist as a variable font, and GDI
//! has no idea what a weight axis is: it registers the default instance and
//! fakes anything heavier by smearing the outline, which is why an earlier
//! attempt still looked wrong even with the right family. These are the static
//! per-weight files the Google Fonts CSS API serves to clients that cannot take
//! woff2, so 500, 600 and 700 are genuinely drawn rather than emboldened.
//!
//! Embedded with `include_bytes!` and registered from memory, so Lite stays one
//! self-contained exe, needs no elevation to draw text, installs nothing, leaves
//! nothing behind, and does not depend on Google Fonts being reachable, which
//! matters for users behind exactly the censorship this product exists to beat.
//!
//! Both are SIL Open Font Licence, which permits embedding and redistribution.

use std::ffi::c_void;

use windows::Win32::Graphics::Gdi::AddFontMemResourceEx;

/// Geist at the four weights the interface actually uses: body, nav and labels,
/// emphasis, and the page headings.
const GEIST: &[&[u8]] = &[
    include_bytes!("../resources/fonts/Geist-400.ttf"),
    include_bytes!("../resources/fonts/Geist-500.ttf"),
    include_bytes!("../resources/fonts/Geist-600.ttf"),
    include_bytes!("../resources/fonts/Geist-700.ttf"),
];

/// Geist Mono, for every measurement. Two weights is all the numbers need.
const GEIST_MONO: &[&[u8]] = &[
    include_bytes!("../resources/fonts/GeistMono-400.ttf"),
    include_bytes!("../resources/fonts/GeistMono-500.ttf"),
];

/// Register every face for this process.
///
/// Call once, before any font is created. Failures are deliberately silent: a
/// face that does not register falls back to the stack in `theme`, which is
/// worse looking but perfectly usable, and a window that refuses to open
/// because a font did not load would be a far worse outcome.
pub fn install() {
    let mut loaded = 0;
    for bytes in GEIST.iter().chain(GEIST_MONO.iter()) {
        loaded += register(bytes);
    }

    // Loud, because the failure is silent everywhere else.
    //
    // These files shipped as EOT for a while (which is what the Google Fonts
    // CSS API hands a user agent old enough to ask for it), and
    // AddFontMemResourceEx rejects EOT. Every face failed, GDI substituted
    // Segoe UI without a word, and the only symptom was that the app looked
    // subtly wrong. A count of zero here is now the thing to look for.
    if loaded == 0 {
        log::error!(
            "no embedded font faces registered: the UI will fall back to Segoe UI. \
             Are resources/fonts/*.ttf actually TrueType?"
        );
    } else {
        log::info!("registered {loaded} embedded font faces");
    }
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
