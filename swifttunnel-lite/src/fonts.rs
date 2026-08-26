//! The product's own typefaces, carried inside the binary.
//!
//! The app's Connect screen is set in **Figtree**, with **Azeret Mono** for
//! anything numeric. Neither ships with Windows, and until now Lite asked for
//! them, did not get them, and silently rendered everything in Segoe UI,
//! because GDI substitutes a missing face rather than failing. That single
//! substitution was most of why Lite did not look like SwiftTunnel: the palette
//! matched all along, the letterforms never did.
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
//! Both faces are SIL Open Font Licence, which permits embedding and
//! redistribution. `resources/fonts` carries their licences alongside them.

use std::ffi::c_void;

use windows::Win32::Graphics::Gdi::AddFontMemResourceEx;

/// Figtree, the UI face. Static instances rather than the variable file:
/// GDI renders a variable font at its default instance and fakes the rest by
/// smearing the outline, so real weights are the difference between type that
/// looks drawn and type that looks stretched.
const FIGTREE: &[&[u8]] = &[
    include_bytes!("../resources/fonts/Figtree-Regular.ttf"),
    include_bytes!("../resources/fonts/Figtree-Medium.ttf"),
    include_bytes!("../resources/fonts/Figtree-SemiBold.ttf"),
    include_bytes!("../resources/fonts/Figtree-Bold.ttf"),
];

/// Azeret Mono, for numbers. Only the regular weight is used, so the variable
/// file's default instance is exactly what is wanted and there is no reason to
/// carry four copies of it.
const AZERET_MONO: &[u8] = include_bytes!("../resources/fonts/AzeretMono.ttf");

/// Register every embedded face for this process.
///
/// Call once, before any font is created. Failures are deliberately silent:
/// a face that does not register falls back to the stack in `theme`, which is
/// worse looking but perfectly usable, and a window that refuses to open
/// because a font did not load would be a far worse outcome.
pub fn install() {
    let mut loaded = 0;
    for bytes in FIGTREE {
        loaded += register(bytes);
    }
    loaded += register(AZERET_MONO);

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
