//! Animation system for smooth UI transitions
//!
//! Provides animation management for toggles, hovers, and other UI elements.

use std::collections::HashMap;
use crate::gui::theme::{TOGGLE_ANIMATION_DURATION, HOVER_ANIMATION_DURATION, ease_out_cubic};

/// Animation state for a single value
#[derive(Clone)]
pub struct Animation {
    start_time: std::time::Instant,
    duration: f32,
    from: f32,
    to: f32,
}

impl Animation {
    /// Create a new animation from `from` to `to` over `duration` seconds
    pub fn new(from: f32, to: f32, duration: f32) -> Self {
        Self {
            start_time: std::time::Instant::now(),
            duration,
            from,
            to,
        }
    }

    /// Get the current interpolated value
    pub fn current_value(&self) -> f32 {
        let elapsed = self.start_time.elapsed().as_secs_f32();
        let t = (elapsed / self.duration).min(1.0);
        let eased = ease_out_cubic(t);
        self.from + (self.to - self.from) * eased
    }

    /// Check if the animation has completed
    pub fn is_complete(&self) -> bool {
        self.start_time.elapsed().as_secs_f32() >= self.duration
    }

    /// Get the target value
    pub fn target(&self) -> f32 {
        self.to
    }
}

/// Animation manager for all UI animations
#[derive(Default)]
pub struct AnimationManager {
    /// Toggle switch animations (key = toggle ID)
    toggle_animations: HashMap<String, Animation>,
    /// Hover state animations for cards (key = card ID)
    hover_animations: HashMap<String, Animation>,
    /// Generic value animations (key = animation ID)
    value_animations: HashMap<String, Animation>,
}

impl AnimationManager {
    /// Start or update a toggle animation
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

    /// Get current toggle animation value (0.0 = off, 1.0 = on)
    pub fn get_toggle_value(&self, id: &str, fallback: bool) -> f32 {
        if let Some(anim) = self.toggle_animations.get(id) {
            anim.current_value()
        } else {
            if fallback { 1.0 } else { 0.0 }
        }
    }

    /// Start or update a hover animation
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

    /// Get current hover animation value (0.0 = not hovered, 1.0 = hovered)
    pub fn get_hover_value(&self, id: &str) -> f32 {
        if let Some(anim) = self.hover_animations.get(id) {
            anim.current_value()
        } else {
            0.0
        }
    }

    /// Start a generic value animation
    pub fn animate_value(&mut self, id: &str, from: f32, to: f32, duration: f32) {
        self.value_animations.insert(
            id.to_string(),
            Animation::new(from, to, duration)
        );
    }

    /// Get current value animation
    pub fn get_value(&self, id: &str, fallback: f32) -> f32 {
        if let Some(anim) = self.value_animations.get(id) {
            anim.current_value()
        } else {
            fallback
        }
    }

    /// Check if any animations are still running
    pub fn has_active_animations(&self) -> bool {
        self.toggle_animations.values().any(|a| !a.is_complete()) ||
        self.hover_animations.values().any(|a| !a.is_complete()) ||
        self.value_animations.values().any(|a| !a.is_complete())
    }

    /// Clean up completed animations to free memory
    pub fn cleanup_completed(&mut self) {
        self.toggle_animations.retain(|_, a| !a.is_complete());
        self.hover_animations.retain(|_, a| !a.is_complete());
        self.value_animations.retain(|_, a| !a.is_complete());
    }

    /// Get animation for direct access
    pub fn get_animation(&self, id: &str) -> Option<&Animation> {
        self.value_animations.get(id)
    }
}

/// VPN connection progress step
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ConnectionStep {
    Idle,
    Fetching,
    Adapter,
    Tunnel,
    Routing,
    Connected,
}

impl ConnectionStep {
    /// Get the step index for progress display (0-5)
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

    /// Get the label for this step
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
