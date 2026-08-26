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

    pub const fn white(alpha: f32) -> Self {
        Self {
            r: 255.0,
            g: 255.0,
            b: 255.0,
            a: alpha,
        }
    }
}

/// A 32-bit BGRX surface matching a top-down DIB, so it can be handed straight
/// to `CreateDIBSection` memory without a conversion pass.
pub struct Canvas {
    pub width: i32,
    pub height: i32,
    pixels: Vec<[f32; 3]>,
}

impl Canvas {
    pub fn new(width: i32, height: i32, fill: Rgba) -> Self {
        let count = (width.max(0) * height.max(0)) as usize;
        Self {
            width,
            height,
            pixels: vec![[fill.r, fill.g, fill.b]; count],
        }
    }

    #[inline]
    fn blend(&mut self, x: i32, y: i32, colour: Rgba, coverage: f32) {
        if x < 0 || y < 0 || x >= self.width || y >= self.height {
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

    /// Blend a colour at one pixel. Public so other modules can composite
    /// their own fields without reimplementing the arithmetic.
    #[inline]
    pub fn blend_at(&mut self, x: i32, y: i32, colour: Rgba, cover: f32) {
        self.blend(x, y, colour, cover);
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

    /// A soft shadow cast by a shape.
    ///
    /// Approximated by fading the distance field over `blur` rather than
    /// convolving, which for a rounded rectangle is visually indistinguishable
    /// and enormously cheaper.
    pub fn drop_shadow(&mut self, shape: RoundRect, colour: Rgba, blur: f32, dy: f32) {
        if blur <= 0.0 {
            return;
        }
        let cast = RoundRect {
            y: shape.y + dy,
            ..shape
        };
        let (x0, y0, x1, y1) = bounds(&cast, blur + dy.abs() + 1.0, self.width, self.height);

        for y in y0..y1 {
            for x in x0..x1 {
                let d = cast.distance(x as f32 + 0.5, y as f32 + 0.5);
                if d <= 0.0 {
                    // Inside the caster: the shape itself paints here.
                    continue;
                }
                let t = (1.0 - (d / blur)).clamp(0.0, 1.0);
                // Squared falloff reads closer to a real gaussian tail than a
                // straight ramp, which looks like a halo.
                self.blend(x, y, colour, t * t);
            }
        }
    }

    /// Vertical linear gradient clipped to a rounded rectangle.
    ///
    /// Waiting on the region rows and the Roblox card, which is the next screen.
    #[allow(dead_code)]
    pub fn fill_round_rect_gradient(&mut self, shape: RoundRect, top: Rgba, bottom: Rgba) {
        let (x0, y0, x1, y1) = bounds(&shape, 1.0, self.width, self.height);
        for y in y0..y1 {
            let t = if shape.h > 0.0 {
                ((y as f32 + 0.5 - shape.y) / shape.h).clamp(0.0, 1.0)
            } else {
                0.0
            };
            let colour = Rgba {
                r: top.r + (bottom.r - top.r) * t,
                g: top.g + (bottom.g - top.g) * t,
                b: top.b + (bottom.b - top.b) * t,
                a: top.a + (bottom.a - top.a) * t,
            };
            for x in x0..x1 {
                let d = shape.distance(x as f32 + 0.5, y as f32 + 0.5);
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

    /// An arc of a ring. Angles in degrees, clockwise from twelve, which is how
    /// the design reads them. Unused until the connection ring lands.
    #[allow(dead_code)]
    /// An arc of a ring, for the boost gauge. Angles in degrees, clockwise from

    pub fn stroke_arc(
        &mut self,
        cx: f32,
        cy: f32,
        radius: f32,
        thickness: f32,
        start_deg: f32,
        sweep_deg: f32,
        colour: Rgba,
    ) {
        let outer = radius + thickness / 2.0 + 1.0;
        let x0 = ((cx - outer).floor() as i32).max(0);
        let x1 = ((cx + outer).ceil() as i32).min(self.width);
        let y0 = ((cy - outer).floor() as i32).max(0);
        let y1 = ((cy + outer).ceil() as i32).min(self.height);

        let start = start_deg.to_radians();
        let sweep = sweep_deg.to_radians();

        for y in y0..y1 {
            for x in x0..x1 {
                let dx = x as f32 + 0.5 - cx;
                let dy = y as f32 + 0.5 - cy;
                let dist = (dx * dx + dy * dy).sqrt();
                let band = (dist - radius).abs() - thickness / 2.0;
                let cover = coverage(band);
                if cover <= 0.0 {
                    continue;
                }

                // atan2 measured clockwise from straight up.
                let mut angle = dx.atan2(-dy);
                if angle < 0.0 {
                    angle += std::f32::consts::TAU;
                }
                let mut rel = angle - start;
                if rel < 0.0 {
                    rel += std::f32::consts::TAU;
                }
                if rel > sweep {
                    continue;
                }

                self.blend(x, y, colour, cover);
            }
        }
    }
}

/// Pixel bounds to visit for a shape, padded and clipped to the surface.
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
    fn a_shadow_falls_outside_its_caster_and_fades() {
        let mut c = Canvas::new(60, 60, Rgba::hex(0x000000));
        let shape = RoundRect::new(20, 20, 20, 20, 6);
        c.drop_shadow(shape, Rgba::white(1.0), 8.0, 0.0);

        let near = probe(&c, 20, 15)[0];
        let far = probe(&c, 20, 8)[0];
        assert!(near > far, "shadow should fade with distance");
        assert!(far < 60.0, "shadow should be gone by the outer edge");
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
