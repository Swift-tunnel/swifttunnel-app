//! A small software renderer for the parts GDI cannot draw.
//!
//! # Why this exists
//!
//! GDI is from 1995 and it shows. `RoundRect` has no antialiasing, so every
//! corner in the window came out with visible stair-steps; there are no
//! gradients beyond a straight linear ramp, and no shadows at all. A modern
//! looking window needs all three, and three attempts at getting close without
//! them all failed for the same reason.
//!
//! Direct2D would provide them, but getting the embedded fonts into DirectWrite
//! means implementing `IDWriteFontCollectionLoader` and friends, which is a
//! large amount of COM plumbing for a payoff available much more cheaply: the
//! shapes here are simple enough to rasterise directly.
//!
//! So the surface is composited in software into a 32-bit buffer and blitted
//! once, and **text is still drawn by GDI on top**, because GDI's text
//! rasteriser is genuinely good and already has the embedded faces registered.
//!
//! The cost is paid on state changes, not per frame. Nothing here animates.

/// Straight alpha, non-premultiplied, in 0..1. Kept as floats because the
/// compositing here is a handful of layers on a small surface, and the
//  arithmetic being obvious is worth more than the cycles.
#[derive(Debug, Clone, Copy)]
pub struct Rgba {
    pub r: f32,
    pub g: f32,
    pub b: f32,
    pub a: f32,
}

impl Rgba {
    pub const fn hex(value: u32) -> Self {
        Self {
            r: ((value >> 16) & 0xFF) as f32,
            g: ((value >> 8) & 0xFF) as f32,
            b: (value & 0xFF) as f32,
            a: 1.0,
        }
    }

    pub const fn hexa(value: u32, alpha: f32) -> Self {
        let mut c = Self::hex(value);
        c.a = alpha;
        c
    }
}

/// A 32-bit BGRX surface matching a top-down DIB, so it can be handed straight
/// to `CreateDIBSection` memory without a conversion pass.
pub struct Canvas {
    pub width: i32,
    pub height: i32,
    pixels: Vec<[f32; 3]>,
    /// Rows outside this band are discarded.
    ///
    /// A scrolling list is laid out at a negative offset, so its first row is
    /// partly above the viewport and would otherwise paint straight over the
    /// tab strip. Clipping in `blend` rather than per shape means every
    /// primitive gets it for free, including the ones added later.
    clip_top: i32,
    clip_bottom: i32,
}

impl Canvas {
    pub fn new(width: i32, height: i32, fill: Rgba) -> Self {
        let count = (width.max(0) * height.max(0)) as usize;
        Self {
            width,
            height,
            pixels: vec![[fill.r, fill.g, fill.b]; count],
            clip_top: 0,
            clip_bottom: height,
        }
    }

    /// Restrict painting to a horizontal band, and return the previous one so
    /// the caller can put it back.
    pub fn clip_rows(&mut self, top: i32, bottom: i32) -> (i32, i32) {
        let previous = (self.clip_top, self.clip_bottom);
        self.clip_top = top.max(0);
        self.clip_bottom = bottom.min(self.height);
        previous
    }

    /// Put a band returned by [`Canvas::clip_rows`] back.
    pub fn restore_clip(&mut self, previous: (i32, i32)) {
        self.clip_top = previous.0;
        self.clip_bottom = previous.1;
    }

    #[inline]
    fn blend(&mut self, x: i32, y: i32, colour: Rgba, coverage: f32) {
        if x < 0 || y < self.clip_top || x >= self.width || y >= self.clip_bottom {
            return;
        }
        let a = colour.a * coverage;
        if a <= 0.0 {
            return;
        }
        let a = a.min(1.0);
        let p = &mut self.pixels[(y * self.width + x) as usize];
        p[0] = colour.r * a + p[0] * (1.0 - a);
        p[1] = colour.g * a + p[1] * (1.0 - a);
        p[2] = colour.b * a + p[2] * (1.0 - a);
    }

    /// Write the surface out as BGRX, which is what a 32bpp `BI_RGB` DIB wants.
    pub fn write_bgrx(&self, out: &mut [u32]) {
        for (i, p) in self.pixels.iter().enumerate() {
            if i >= out.len() {
                break;
            }
            let r = p[0].clamp(0.0, 255.0) as u32;
            let g = p[1].clamp(0.0, 255.0) as u32;
            let b = p[2].clamp(0.0, 255.0) as u32;
            out[i] = (r << 16) | (g << 8) | b;
        }
    }
}

/// A rectangle with rounded corners, in pixels.
#[derive(Debug, Clone, Copy)]
pub struct RoundRect {
    pub x: f32,
    pub y: f32,
    pub w: f32,
    pub h: f32,
    pub radius: f32,
}

impl RoundRect {
    pub fn new(x: i32, y: i32, w: i32, h: i32, radius: i32) -> Self {
        Self {
            x: x as f32,
            y: y as f32,
            w: w as f32,
            h: h as f32,
            radius: radius as f32,
        }
    }

    pub fn inset(self, by: f32) -> Self {
        Self {
            x: self.x + by,
            y: self.y + by,
            w: (self.w - by * 2.0).max(0.0),
            h: (self.h - by * 2.0).max(0.0),
            radius: (self.radius - by).max(0.0),
        }
    }

    /// Signed distance to the shape's edge: negative inside, positive outside.
    ///
    /// A distance field rather than a scanline fill, because it gives
    /// antialiasing, strokes and shadows from one function. Coverage is the
    /// distance clamped across one pixel, strokes are the band between two
    /// distances, and a shadow is the same field pushed outward and softened.
    #[inline]
    fn distance(&self, px: f32, py: f32) -> f32 {
        let hw = self.w / 2.0;
        let hh = self.h / 2.0;
        let cx = self.x + hw;
        let cy = self.y + hh;
        let r = self.radius.min(hw).min(hh);

        let dx = (px - cx).abs() - (hw - r);
        let dy = (py - cy).abs() - (hh - r);

        let outside = (dx.max(0.0).powi(2) + dy.max(0.0).powi(2)).sqrt();
        outside + dx.max(dy).min(0.0) - r
    }
}

/// Antialiased coverage for one pixel, from a signed distance.
#[inline]
fn coverage(distance: f32) -> f32 {
    // One pixel of feathering centred on the edge. Wider looks blurry, narrower
    // brings the stair-steps back.
    (0.5 - distance).clamp(0.0, 1.0)
}

impl Canvas {
    /// Fill a rounded rectangle, antialiased.
    pub fn fill_round_rect(&mut self, shape: RoundRect, colour: Rgba) {
        let (x0, y0, x1, y1) = bounds(&shape, 1.0, self.width, self.height);
        for y in y0..y1 {
            for x in x0..x1 {
                let d = shape.distance(x as f32 + 0.5, y as f32 + 0.5);
                self.blend(x, y, colour, coverage(d));
            }
        }
    }

    /// Stroke a rounded rectangle, antialiased, centred on the path.
    pub fn stroke_round_rect(&mut self, shape: RoundRect, colour: Rgba, width: f32) {
        let half = width / 2.0;
        let (x0, y0, x1, y1) = bounds(&shape, width + 1.0, self.width, self.height);
        for y in y0..y1 {
            for x in x0..x1 {
                let d = shape.distance(x as f32 + 0.5, y as f32 + 0.5).abs() - half;
                self.blend(x, y, colour, coverage(d));
            }
        }
    }

    /// A filled circle, antialiased. Used for status dots and the gauge cap.
    pub fn fill_circle(&mut self, cx: f32, cy: f32, r: f32, colour: Rgba) {
        let x0 = ((cx - r - 1.0).floor() as i32).max(0);
        let x1 = ((cx + r + 1.0).ceil() as i32).min(self.width);
        let y0 = ((cy - r - 1.0).floor() as i32).max(0);
        let y1 = ((cy + r + 1.0).ceil() as i32).min(self.height);

        for y in y0..y1 {
            for x in x0..x1 {
                let dx = x as f32 + 0.5 - cx;
                let dy = y as f32 + 0.5 - cy;
                let d = (dx * dx + dy * dy).sqrt() - r;
                self.blend(x, y, colour, coverage(d));
            }
        }
    }

}

/// Pixel range a shape can touch, clamped to the surface.
///
/// `pad` widens it by however far the drawing bleeds past the path: one
/// pixel for a fill's feathering, the stroke width plus one for an outline.
fn bounds(shape: &RoundRect, pad: f32, width: i32, height: i32) -> (i32, i32, i32, i32) {
    let x0 = ((shape.x - pad).floor() as i32).max(0);
    let y0 = ((shape.y - pad).floor() as i32).max(0);
    let x1 = ((shape.x + shape.w + pad).ceil() as i32).min(width);
    let y1 = ((shape.y + shape.h + pad).ceil() as i32).min(height);
    (x0, y0, x1, y1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe(c: &Canvas, x: i32, y: i32) -> [f32; 3] {
        c.pixels[(y * c.width + x) as usize]
    }

    #[test]
    fn a_filled_shape_is_solid_in_the_middle() {
        let mut c = Canvas::new(40, 40, Rgba::hex(0x000000));
        c.fill_round_rect(RoundRect::new(5, 5, 30, 30, 8), Rgba::hex(0xFFFFFF));
        let centre = probe(&c, 20, 20);
        assert!(centre[0] > 250.0, "centre should be opaque white");
    }

    #[test]
    fn corners_are_antialiased_rather_than_stepped() {
        // The whole reason this module exists. A corner pixel should be a
        // partial blend, not fully on or fully off, which is exactly what GDI
        // could not do and what made every card look jagged.
        let mut c = Canvas::new(40, 40, Rgba::hex(0x000000));
        c.fill_round_rect(RoundRect::new(4, 4, 32, 32, 10), Rgba::hex(0xFFFFFF));

        let mut partial = 0;
        for y in 4..16 {
            for x in 4..16 {
                let v = probe(&c, x, y)[0];
                if v > 8.0 && v < 247.0 {
                    partial += 1;
                }
            }
        }
        assert!(
            partial > 6,
            "expected feathered corner pixels, found {partial}"
        );
    }

    #[test]
    fn nothing_is_drawn_outside_the_shape() {
        let mut c = Canvas::new(40, 40, Rgba::hex(0x000000));
        c.fill_round_rect(RoundRect::new(10, 10, 20, 20, 6), Rgba::hex(0xFFFFFF));
        assert_eq!(probe(&c, 1, 1)[0], 0.0);
        assert_eq!(probe(&c, 38, 38)[0], 0.0);
    }

    #[test]
    fn the_clip_band_keeps_a_scrolled_row_off_the_chrome() {
        // A list is laid out at a negative offset, so its first row starts
        // above the viewport. Without the clip it paints over the tab strip.
        let mut c = Canvas::new(40, 40, Rgba::hex(0x000000));
        let previous = c.clip_rows(20, 40);
        c.fill_round_rect(RoundRect::new(0, 0, 40, 40, 0), Rgba::hex(0xFFFFFF));
        assert_eq!(probe(&c, 20, 10)[0], 0.0, "above the band stays untouched");
        assert!(probe(&c, 20, 30)[0] > 250.0, "inside the band is painted");

        c.restore_clip(previous);
        c.fill_round_rect(RoundRect::new(0, 0, 40, 40, 0), Rgba::hex(0xFFFFFF));
        assert!(probe(&c, 20, 10)[0] > 250.0, "restoring lifts the band");
    }

    #[test]
    fn writing_out_produces_bgrx() {
        let mut c = Canvas::new(2, 1, Rgba::hex(0x112233));
        let mut out = vec![0u32; 2];
        c.write_bgrx(&mut out);
        assert_eq!(out[0], 0x112233);
        // And the buffer is untouched where nothing was drawn.
        c.fill_round_rect(RoundRect::new(0, 0, 2, 1, 0), Rgba::hex(0xFFFFFF));
        c.write_bgrx(&mut out);
        assert_eq!(out[0], 0xFFFFFF);
    }
}
