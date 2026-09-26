//! Website typography, registered privately from embedded static fonts.
//! No font files are installed on the machine and no network request is made.
use std::sync::OnceLock;
use windows::Win32::Graphics::Gdi::AddFontMemResourceEx;

pub fn install() {
    static READY: OnceLock<()> = OnceLock::new();
    READY.get_or_init(|| {
        // Keep both redistribution notices inside the self-contained executable.
        std::hint::black_box(concat!(
            include_str!("../resources/fonts/OFL-Figtree.txt"),
            "\n",
            include_str!("../resources/fonts/OFL-AzeretMono.txt")
        ));
        for bytes in [
            include_bytes!("../resources/fonts/Figtree-Regular.ttf").as_slice(),
            include_bytes!("../resources/fonts/Figtree-SemiBold.ttf").as_slice(),
            include_bytes!("../resources/fonts/Figtree-ExtraBold.ttf").as_slice(),
            include_bytes!("../resources/fonts/AzeretMono-Regular.ttf").as_slice(),
        ] {
            let mut count = 0;
            // The static byte buffers outlive every font handle. Windows releases
            // these process-private resources on exit. GDI can fall back if needed.
            unsafe {
                AddFontMemResourceEx(bytes.as_ptr().cast(), bytes.len() as u32, None, &mut count);
            }
        }
    });
}
