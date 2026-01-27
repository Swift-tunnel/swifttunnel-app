//! Animation system for smooth UI transitions

use eframe::egui;
use std::collections::HashMap;

// Animation timing constants
pub const TOGGLE_ANIMATION_DURATION: f32 = 0.15;   // 150ms for toggle switches
pub const PULSE_ANIMATION_DURATION: f32 = 2.0;      // 2s breathing cycle for connected pulse
pub const HOVER_ANIMATION_DURATION: f32 = 0.1;      // 100ms for hover effects
pub const SHIMMER_ANIMATION_DURATION: f32 = 1.5;    // 1.5s for skeleton shimmer
pub const CARD_TRANSITION_DURATION: f32 = 0.2;      // 200ms for card state changes
pub const BUTTON_PRESS_DURATION: f32 = 0.08;        // 80ms for button press feedback

/// Ease-out-cubic interpolation for smooth animations
pub fn ease_out_cubic(t: f32) -> f32 {
    let t = t.clamp(0.0, 1.0);
    1.0 - (1.0 - t).powi(3)
}

/// Ease-in-out for shimmer effects
pub fn ease_in_out_sine(t: f32) -> f32 {
    let t = t.clamp(0.0, 1.0);
    -(((t * std::f32::consts::PI).cos() - 1.0) / 2.0)
}

/// Interpolate between two colors
pub fn lerp_color(from: egui::Color32, to: egui::Color32, t: f32) -> egui::Color32 {
    let t = t.clamp(0.0, 1.0);
    egui::Color32::from_rgba_unmultiplied(
        (from.r() as f32 + (to.r() as f32 - from.r() as f32) * t) as u8,
        (from.g() as f32 + (to.g() as f32 - from.g() as f32) * t) as u8,
        (from.b() as f32 + (to.b() as f32 - from.b() as f32) * t) as u8,
        (from.a() as f32 + (to.a() as f32 - from.a() as f32) * t) as u8,
    )
}

/// Animation state for a single value
#[derive(Clone)]
pub struct Animation {
    start_time: std::time::Instant,
    duration: f32,
    from: f32,
    to: f32,
}

impl Animation {
    pub fn new(from: f32, to: f32, duration: f32) -> Self {
        Self {
            start_time: std::time::Instant::now(),
            duration,
            from,
            to,
        }
    }

    pub fn current_value(&self) -> f32 {
        let elapsed = self.start_time.elapsed().as_secs_f32();
        let t = (elapsed / self.duration).min(1.0);
        let eased = ease_out_cubic(t);
        self.from + (self.to - self.from) * eased
    }

    pub fn is_complete(&self) -> bool {
        self.start_time.elapsed().as_secs_f32() >= self.duration
    }
}

/// Animation manager for all UI animations
#[derive(Default)]
pub struct AnimationManager {
    /// Toggle switch animations (key = toggle ID)
    toggle_animations: HashMap<String, Animation>,
    /// Hover state animations for cards (key = card ID)
    hover_animations: HashMap<String, Animation>,
}

impl AnimationManager {
    pub fn animate_toggle(&mut self, id: &str, target: bool, current: f32) {
        let target_val = if target { 1.0 } else { 0.0 };
        // Only start a new animation if target changed
        if let Some(existing) = self.toggle_animations.get(id) {
            if (existing.to - target_val).abs() < 0.01 {
                return; // Already animating to this target
            }
        }
        self.toggle_animations.insert(
            id.to_string(),
            Animation::new(current, target_val, TOGGLE_ANIMATION_DURATION)
        );
    }

    pub fn get_toggle_value(&self, id: &str, fallback: bool) -> f32 {
        if let Some(anim) = self.toggle_animations.get(id) {
            anim.current_value()
        } else {
            if fallback { 1.0 } else { 0.0 }
        }
    }

    pub fn animate_hover(&mut self, id: &str, is_hovered: bool, current: f32) {
        let target_val = if is_hovered { 1.0 } else { 0.0 };
        if let Some(existing) = self.hover_animations.get(id) {
            if (existing.to - target_val).abs() < 0.01 {
                return;
            }
        }
        self.hover_animations.insert(
            id.to_string(),
            Animation::new(current, target_val, HOVER_ANIMATION_DURATION)
        );
    }

    pub fn get_hover_value(&self, id: &str) -> f32 {
        if let Some(anim) = self.hover_animations.get(id) {
            anim.current_value()
        } else {
            0.0
        }
    }

    pub fn has_active_animations(&self) -> bool {
        self.toggle_animations.values().any(|a| !a.is_complete()) ||
        self.hover_animations.values().any(|a| !a.is_complete())
    }

    pub fn cleanup_completed(&mut self) {
        // Only clean up toggle animations that have completed AND returned to "off" state
        self.toggle_animations.retain(|_, a| !a.is_complete() || a.to > 0.5);
        // Only clean up hover animations that have completed AND returned to "not hovered" state
        // This prevents flickering when continuously hovering (animation completes at 1.0)
        self.hover_animations.retain(|_, a| !a.is_complete() || a.to > 0.5);
    }
}

/// VPN connection progress step
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ConnectionStep {
    Idle,
    Fetching,
    Adapter,
    Tunnel,
    Routing,
    Connected,
}

impl ConnectionStep {
    pub fn from_state(state: &crate::vpn::ConnectionState) -> Self {
        use crate::vpn::ConnectionState;
        match state {
            ConnectionState::Disconnected => ConnectionStep::Idle,
            ConnectionState::FetchingConfig => ConnectionStep::Fetching,
            ConnectionState::CreatingAdapter => ConnectionStep::Adapter,
            ConnectionState::Connecting => ConnectionStep::Tunnel,
            ConnectionState::ConfiguringSplitTunnel => ConnectionStep::Routing,
            ConnectionState::ConfiguringRoutes => ConnectionStep::Routing,
            ConnectionState::Connected { .. } => ConnectionStep::Connected,
            ConnectionState::Disconnecting => ConnectionStep::Idle,
            ConnectionState::Error(_) => ConnectionStep::Idle,
        }
    }

    pub fn step_index(&self) -> usize {
        match self {
            ConnectionStep::Idle => 0,
            ConnectionStep::Fetching => 1,
            ConnectionStep::Adapter => 2,
            ConnectionStep::Tunnel => 3,
            ConnectionStep::Routing => 4,
            ConnectionStep::Connected => 5,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            ConnectionStep::Idle => "Ready",
            ConnectionStep::Fetching => "Fetching",
            ConnectionStep::Adapter => "Adapter",
            ConnectionStep::Tunnel => "Tunnel",
            ConnectionStep::Routing => "Routing",
            ConnectionStep::Connected => "Done",
        }
    }
}

/// Format bytes per second as human-readable string
pub fn format_bytes_per_sec(bytes_per_sec: f64) -> String {
    if bytes_per_sec < 1024.0 {
        format!("{:.0} B/s", bytes_per_sec)
    } else if bytes_per_sec < 1024.0 * 1024.0 {
        format!("{:.1} KB/s", bytes_per_sec / 1024.0)
    } else if bytes_per_sec < 1024.0 * 1024.0 * 1024.0 {
        format!("{:.1} MB/s", bytes_per_sec / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB/s", bytes_per_sec / (1024.0 * 1024.0 * 1024.0))
    }
}
