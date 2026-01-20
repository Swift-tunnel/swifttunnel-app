//! Sidebar navigation component
//!
//! Icon-only sidebar with tooltips

use eframe::egui::{self, Color32, Ui, Sense, Vec2, Pos2, Rect};
use crate::gui::theme::*;
use crate::gui::animations::AnimationManager;
use crate::gui::Page;

/// Sidebar navigation item
struct NavItem {
    icon: &'static str,
    label: &'static str,
    page: Page,
}

const NAV_ITEMS: &[NavItem] = &[
    NavItem { icon: "🏠", label: "Home", page: Page::Home },
    NavItem { icon: "🎮", label: "Games", page: Page::Games },
    NavItem { icon: "⚡", label: "Boost", page: Page::Boost },
    NavItem { icon: "📊", label: "Network", page: Page::Network },
    NavItem { icon: "⚙", label: "Settings", page: Page::Settings },
];

/// Render the sidebar
/// Returns Some(Page) if a nav item was clicked
pub fn render_sidebar(
    ui: &mut Ui,
    current_page: Page,
    animations: &mut AnimationManager,
    user_avatar: Option<&str>,
    version: &str,
    app_start_time: std::time::Instant,
) -> Option<Page> {
    let mut clicked_page: Option<Page> = None;

    // Allocate the sidebar area
    let sidebar_rect = ui.available_rect_before_wrap();
    let sidebar_rect = Rect::from_min_size(
        sidebar_rect.min,
        Vec2::new(SIDEBAR_WIDTH, sidebar_rect.height()),
    );

    // Draw sidebar background
    ui.painter().rect_filled(sidebar_rect, 0.0, BG_SIDEBAR);

    // Draw right border
    let border_rect = Rect::from_min_size(
        Pos2::new(sidebar_rect.max.x - 1.0, sidebar_rect.min.y),
        Vec2::new(1.0, sidebar_rect.height()),
    );
    ui.painter().rect_filled(border_rect, 0.0, BG_ELEVATED);

    // Sidebar content
    ui.allocate_new_ui(egui::UiBuilder::new().max_rect(sidebar_rect), |ui| {
        ui.vertical(|ui| {
            ui.set_min_width(SIDEBAR_WIDTH);
            ui.set_max_width(SIDEBAR_WIDTH);

            ui.add_space(12.0);

            // Logo at top
            render_logo(ui, app_start_time);

            ui.add_space(20.0);

            // Navigation items
            for item in NAV_ITEMS {
                if render_nav_item(ui, item, current_page, animations) {
                    clicked_page = Some(item.page);
                }
            }

            // Flexible spacer
            ui.add_space(ui.available_height() - 80.0);

            // Bottom section: user avatar and version
            render_bottom_section(ui, user_avatar, version);
        });
    });

    clicked_page
}

/// Render the SwiftTunnel logo
fn render_logo(ui: &mut Ui, app_start_time: std::time::Instant) {
    let logo_size = 36.0;
    let _center_x = SIDEBAR_WIDTH / 2.0;

    ui.horizontal(|ui| {
        ui.add_space((SIDEBAR_WIDTH - logo_size) / 2.0);

        let (rect, _) = ui.allocate_exact_size(Vec2::new(logo_size, logo_size), Sense::hover());
        let center = rect.center();

        // Animated gradient ring
        let elapsed = app_start_time.elapsed().as_secs_f32();
        let rotation = elapsed * 0.5;

        // Ring color animation
        let ring_color_1 = lerp_color(ACCENT_PRIMARY, ACCENT_CYAN, ((rotation).sin() + 1.0) / 2.0);
        let ring_color_2 = lerp_color(ACCENT_CYAN, ACCENT_SECONDARY, ((rotation + 1.0).sin() + 1.0) / 2.0);

        // Background circle
        ui.painter().circle_filled(center, logo_size * 0.42, BG_ELEVATED);

        // Gradient-like arc segments
        for i in 0..8 {
            let angle_start = (i as f32 / 8.0) * std::f32::consts::TAU + rotation;
            let color = lerp_color(ring_color_1, ring_color_2, i as f32 / 8.0);
            let alpha = 0.6 + (((angle_start * 2.0).sin() + 1.0) / 2.0) * 0.4;

            for j in 0..3 {
                let angle = angle_start + j as f32 * 0.05;
                let x = center.x + angle.cos() * (logo_size * 0.35);
                let y = center.y + angle.sin() * (logo_size * 0.35);
                ui.painter().circle_filled(Pos2::new(x, y), 2.0, color.gamma_multiply(alpha));
            }
        }

        // Inner "S" wave
        let wave_color = ACCENT_CYAN;
        for i in 0..3 {
            let offset = (i as f32 - 1.0) * 4.0;
            let start = Pos2::new(center.x - 8.0, center.y + offset);
            let end = Pos2::new(center.x + 8.0, center.y + offset);
            let control1 = Pos2::new(center.x - 3.0, center.y + offset - 4.0);
            let control2 = Pos2::new(center.x + 3.0, center.y + offset + 4.0);

            let points = [start, control1, control2, end];
            let alpha = 0.6 + (i as f32 * 0.2);
            let stroke = egui::Stroke::new(2.0, wave_color.gamma_multiply(alpha));
            ui.painter().add(egui::Shape::CubicBezier(egui::epaint::CubicBezierShape::from_points_stroke(
                points,
                false,
                Color32::TRANSPARENT,
                stroke,
            )));
        }
    });
}

/// Render a navigation item
/// Returns true if clicked
fn render_nav_item(
    ui: &mut Ui,
    item: &NavItem,
    current_page: Page,
    animations: &mut AnimationManager,
) -> bool {
    let is_active = current_page == item.page;
    let item_id = format!("nav_{:?}", item.page);
    let hover_val = animations.get_hover_value(&item_id);

    let item_height = 48.0;
    let (rect, response) = ui.allocate_exact_size(Vec2::new(SIDEBAR_WIDTH, item_height), Sense::click());

    // Update hover animation
    animations.animate_hover(&item_id, response.hovered(), hover_val);

    if ui.is_rect_visible(rect) {
        // Background on hover/active
        let bg_color = if is_active {
            ACCENT_PRIMARY.gamma_multiply(0.15)
        } else {
            lerp_color(Color32::TRANSPARENT, BG_ELEVATED, hover_val)
        };

        if bg_color.a() > 0 {
            ui.painter().rect_filled(rect, 0.0, bg_color);
        }

        // Active indicator bar (left edge)
        if is_active {
            let bar_rect = Rect::from_min_size(
                rect.min,
                Vec2::new(NAV_ACCENT_WIDTH, item_height),
            );
            ui.painter().rect_filled(bar_rect, 0.0, ACCENT_CYAN);
        }

        // Icon
        let icon_color = if is_active {
            ACCENT_CYAN
        } else {
            lerp_color(TEXT_MUTED, TEXT_PRIMARY, hover_val)
        };

        let font = egui::FontId::proportional(SIDEBAR_ICON_SIZE);
        let galley = ui.painter().layout_no_wrap(item.icon.to_string(), font, icon_color);
        let icon_pos = Pos2::new(
            rect.center().x - galley.size().x / 2.0,
            rect.center().y - galley.size().y / 2.0,
        );
        ui.painter().galley(icon_pos, galley, icon_color);
    }

    // Tooltip
    if response.hovered() {
        egui::show_tooltip_at_pointer(ui.ctx(), ui.layer_id(), egui::Id::new(&item_id).with("tooltip"), |ui: &mut egui::Ui| {
            ui.label(egui::RichText::new(item.label)
                .size(12.0)
                .color(TEXT_PRIMARY));
        });
    }

    response.clicked()
}

/// Render bottom section with user avatar and version
fn render_bottom_section(ui: &mut Ui, _user_avatar: Option<&str>, version: &str) {
    ui.add_space(8.0);

    // Separator
    let sep_rect = Rect::from_min_size(
        Pos2::new(12.0, ui.cursor().min.y),
        Vec2::new(SIDEBAR_WIDTH - 24.0, 1.0),
    );
    ui.painter().rect_filled(sep_rect, 0.0, BG_ELEVATED);

    ui.add_space(12.0);

    // User avatar placeholder
    ui.horizontal(|ui| {
        ui.add_space((SIDEBAR_WIDTH - 32.0) / 2.0);

        let (rect, response) = ui.allocate_exact_size(Vec2::new(32.0, 32.0), Sense::click());
        ui.painter().circle_filled(rect.center(), 14.0, BG_ELEVATED);
        ui.painter().circle_stroke(rect.center(), 14.0, egui::Stroke::new(1.0, BG_HOVER));

        // User icon
        let font = egui::FontId::proportional(14.0);
        let galley = ui.painter().layout_no_wrap("👤".to_string(), font, TEXT_MUTED);
        let icon_pos = Pos2::new(
            rect.center().x - galley.size().x / 2.0,
            rect.center().y - galley.size().y / 2.0,
        );
        ui.painter().galley(icon_pos, galley, TEXT_MUTED);

        if response.hovered() {
            egui::show_tooltip_at_pointer(ui.ctx(), ui.layer_id(), egui::Id::new("user_tooltip"), |ui| {
                ui.label(egui::RichText::new("Account")
                    .size(12.0)
                    .color(TEXT_PRIMARY));
            });
        }
    });

    ui.add_space(8.0);

    // Version
    ui.horizontal(|ui| {
        let version_text = format!("v{}", version);
        let font = egui::FontId::proportional(10.0);
        let galley = ui.painter().layout_no_wrap(version_text.clone(), font.clone(), TEXT_DIMMED);
        let text_width = galley.size().x;

        ui.add_space((SIDEBAR_WIDTH - text_width) / 2.0);
        ui.label(egui::RichText::new(version_text)
            .size(10.0)
            .color(TEXT_DIMMED));
    });

    ui.add_space(12.0);
}
