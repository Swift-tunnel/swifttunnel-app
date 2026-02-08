//! Layout module - sidebar navigation and app structure

use super::*;
use super::theme::*;
use super::animations::*;

/// Navigation items for the sidebar
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NavItem {
    Connect,
    Boost,
    Network,
    Settings,
}

impl NavItem {
    /// Icon character for the nav item
    pub fn icon(&self) -> &'static str {
        match self {
            NavItem::Connect => "C",
            NavItem::Boost => "B",
            NavItem::Network => "N",
            NavItem::Settings => "S",
        }
    }

    /// Tooltip text
    pub fn tooltip(&self) -> &'static str {
        match self {
            NavItem::Connect => "VPN Connect",
            NavItem::Boost => "FPS Boost",
            NavItem::Network => "Network Analyzer",
            NavItem::Settings => "Settings",
        }
    }

    /// Keyboard shortcut hint
    pub fn shortcut(&self) -> &'static str {
        match self {
            NavItem::Connect => "Ctrl+1",
            NavItem::Boost => "Ctrl+2",
            NavItem::Network => "Ctrl+3",
            NavItem::Settings => "Ctrl+4",
        }
    }
}

impl BoosterApp {
    /// Render the complete app layout with sidebar
    pub fn render_app_layout(&mut self, ctx: &egui::Context) {
        let is_logged_in = matches!(self.auth_state, AuthState::LoggedIn(_));
        let is_logging_in = matches!(self.auth_state, AuthState::LoggingIn);
        let is_awaiting_oauth = matches!(self.auth_state, AuthState::AwaitingOAuthCallback(_));

        // Main container
        egui::CentralPanel::default()
            .frame(egui::Frame::NONE.fill(BG_BASE))
            .show(ctx, |ui| {
                let total_size = ui.available_size();

                // Layout: [Sidebar | Content Area]
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing = egui::vec2(0.0, 0.0);

                    // Left Sidebar
                    if is_logged_in {
                        self.render_sidebar(ui, total_size.y);
                    }

                    // Main content area
                    let content_width = total_size.x - if is_logged_in { SIDEBAR_WIDTH } else { 0.0 };

                    ui.vertical(|ui| {
                        ui.set_min_width(content_width);
                        ui.set_max_width(content_width);

                        // Top bar (always visible when logged in)
                        if is_logged_in {
                            self.render_top_bar(ui);
                        }

                        // Content area height
                        let content_height = total_size.y - if is_logged_in { TOP_BAR_HEIGHT } else { 0.0 };
                        // Account for scrollbar width (12px) and extra safety margin
                        let inner_content_width = content_width - CONTENT_PADDING * 2.0 - 16.0;

                        // Auth screens are rendered WITHOUT ScrollArea for proper centering
                        if !is_logged_in && !is_logging_in && !is_awaiting_oauth {
                            // Allocate fixed size area for login screen centering
                            ui.allocate_ui_with_layout(
                                egui::vec2(content_width, content_height),
                                egui::Layout::top_down(egui::Align::LEFT),
                                |ui| {
                                    self.render_full_login_screen(ui);
                                }
                            );
                        } else if is_logging_in {
                            ui.allocate_ui_with_layout(
                                egui::vec2(content_width, content_height),
                                egui::Layout::top_down(egui::Align::LEFT),
                                |ui| {
                                    self.render_login_pending(ui);
                                }
                            );
                        } else if is_awaiting_oauth {
                            ui.allocate_ui_with_layout(
                                egui::vec2(content_width, content_height),
                                egui::Layout::top_down(egui::Align::LEFT),
                                |ui| {
                                    self.render_awaiting_oauth_callback(ui);
                                }
                            );
                        } else {
                            // Logged in content with scroll
                            egui::ScrollArea::vertical()
                                .auto_shrink([false, false])
                                .max_height(content_height)
                                .show(ui, |ui| {
                                    // Constrain width to prevent overflow
                                    ui.set_max_width(content_width);

                                    // Content wrapper with consistent padding
                                    egui::Frame::NONE
                                        .inner_margin(egui::Margin {
                                            left: CONTENT_PADDING as i8,
                                            right: CONTENT_PADDING as i8,
                                            top: 0,
                                            bottom: SPACING_MD as i8,
                                        })
                                        .show(ui, |ui| {
                                            // Constrain content width to prevent overflow
                                            ui.set_min_width(inner_content_width);
                                            ui.set_max_width(inner_content_width);

                                            // Store content width for tabs to use
                                            self.content_area_width = inner_content_width;

                                            // Render decorative banner (inside padded area for alignment)
                                            self.render_header_banner(ui);

                                            ui.add_space(SPACING_MD);

                                            match self.current_tab {
                                                Tab::Connect => self.render_connect_tab(ui),
                                                Tab::Boost => self.render_boost_tab(ui),
                                                Tab::Network => self.render_network_tab(ui),
                                                Tab::Settings => self.render_settings_tab(ui),
                                            }
                                        });

                                    ui.add_space(SPACING_XL);
                                });
                        }
                    });
                });
            });

        // Overlay notifications
        self.render_process_notification(ctx);
    }

    /// Render the left sidebar with icon navigation
    fn render_sidebar(&mut self, ui: &mut egui::Ui, height: f32) {
        egui::Frame::NONE
            .fill(BG_SIDEBAR)
            .stroke(egui::Stroke::new(1.0, BORDER_SUBTLE))
            .show(ui, |ui| {
                ui.set_min_size(egui::vec2(SIDEBAR_WIDTH, height));
                ui.set_max_width(SIDEBAR_WIDTH);

                ui.vertical(|ui| {
                    ui.spacing_mut().item_spacing = egui::vec2(0.0, 0.0);

                    // Logo area at top
                    ui.add_space(SPACING_MD);
                    ui.vertical_centered(|ui| {
                        self.render_sidebar_logo(ui);
                    });

                    ui.add_space(SPACING_LG);

                    // Navigation items
                    let nav_items = [
                        (NavItem::Connect, Tab::Connect),
                        (NavItem::Boost, Tab::Boost),
                        (NavItem::Network, Tab::Network),
                        (NavItem::Settings, Tab::Settings),
                    ];

                    for (nav_item, tab) in nav_items {
                        self.render_nav_item(ui, nav_item, tab);
                    }

                    // Spacer to push version to bottom
                    ui.add_space(ui.available_height() - 60.0);

                    // Version at bottom
                    ui.vertical_centered(|ui| {
                        ui.add_space(SPACING_SM);
                        ui.label(egui::RichText::new(format!("v{}", env!("CARGO_PKG_VERSION")))
                            .size(10.0)
                            .color(TEXT_DIMMED));
                    });
                });
            });
    }

    /// Render the sidebar logo
    fn render_sidebar_logo(&mut self, ui: &mut egui::Ui) {
        let logo_size = 32.0;

        if let Some(texture) = &self.logo_texture {
            let image = egui::Image::new(texture)
                .fit_to_exact_size(egui::vec2(logo_size, logo_size))
                .rounding(egui::CornerRadius::same(8));
            ui.add(image);
        } else {
            // Fallback gradient circle
            let (rect, _) = ui.allocate_exact_size(egui::vec2(logo_size, logo_size), egui::Sense::hover());
            let painter = ui.painter();

            // Gradient effect (approximated with two circles)
            painter.circle_filled(rect.center(), logo_size * 0.48, ACCENT_PRIMARY.gamma_multiply(0.3));
            painter.circle_filled(rect.center(), logo_size * 0.4, ACCENT_PRIMARY);

            // S letter
            painter.text(
                rect.center(),
                egui::Align2::CENTER_CENTER,
                "S",
                egui::FontId::proportional(16.0),
                TEXT_PRIMARY
            );
        }
    }

    /// Render a single navigation item
    fn render_nav_item(&mut self, ui: &mut egui::Ui, nav_item: NavItem, tab: Tab) {
        let is_active = self.current_tab == tab;
        let item_id = format!("nav_{:?}", tab);
        let hover_val = self.animations.get_hover_value(&item_id);

        ui.vertical_centered(|ui| {
            // Active indicator bar on left
            let indicator_rect = ui.allocate_exact_size(egui::vec2(SIDEBAR_WIDTH, 44.0), egui::Sense::hover()).0;

            if is_active {
                // Active indicator line on left edge
                let line_rect = egui::Rect::from_min_size(
                    egui::pos2(indicator_rect.min.x, indicator_rect.min.y + 8.0),
                    egui::vec2(3.0, 28.0)
                );
                ui.painter().rect_filled(line_rect, 2.0, ACCENT_PRIMARY);
            }

            // Button area
            let button_rect = egui::Rect::from_center_size(
                indicator_rect.center(),
                egui::vec2(40.0, 40.0)
            );

            let response = ui.allocate_rect(button_rect, egui::Sense::click());
            let is_hovered = response.hovered();

            // Animate hover
            self.animations.animate_hover(&item_id, is_hovered, hover_val);

            // Background
            let bg_color = if is_active {
                ACCENT_PRIMARY.gamma_multiply(0.12)
            } else {
                lerp_color(egui::Color32::TRANSPARENT, BG_HOVER, hover_val)
            };

            ui.painter().rect_filled(button_rect, 10.0, bg_color);

            // Icon (drawn with painter)
            let icon_color = if is_active {
                ACCENT_PRIMARY
            } else {
                lerp_color(TEXT_MUTED, TEXT_PRIMARY, hover_val)
            };

            let icon_stroke = egui::Stroke::new(1.6, icon_color);
            let c = button_rect.center();
            let s = 8.0; // icon half-size

            match nav_item {
                NavItem::Connect => {
                    // Speedometer: arc + needle
                    let segments = 20;
                    let start_angle = std::f32::consts::PI * 0.8;
                    let end_angle = std::f32::consts::PI * 0.2;
                    let sweep = std::f32::consts::TAU - (start_angle - end_angle);
                    let r = s;
                    let points: Vec<egui::Pos2> = (0..=segments)
                        .map(|i| {
                            let t = i as f32 / segments as f32;
                            let angle = start_angle + sweep * t;
                            egui::pos2(c.x + r * angle.cos(), c.y - r * angle.sin())
                        })
                        .collect();
                    for w in points.windows(2) {
                        ui.painter().line_segment([w[0], w[1]], icon_stroke);
                    }
                    // Needle pointing upper-right
                    let needle_angle = std::f32::consts::PI * 0.65;
                    let needle_end = egui::pos2(c.x + (s - 2.0) * needle_angle.cos(), c.y - (s - 2.0) * needle_angle.sin());
                    ui.painter().line_segment([c, needle_end], egui::Stroke::new(2.0, icon_color));
                    ui.painter().circle_filled(c, 2.0, icon_color);
                }
                NavItem::Boost => {
                    // Lightning bolt
                    let pts = [
                        egui::pos2(c.x + 1.0, c.y - s),
                        egui::pos2(c.x - 3.0, c.y + 1.0),
                        egui::pos2(c.x + 1.0, c.y + 1.0),
                        egui::pos2(c.x - 1.0, c.y + s),
                        egui::pos2(c.x + 3.0, c.y - 1.0),
                        egui::pos2(c.x - 1.0, c.y - 1.0),
                        egui::pos2(c.x + 1.0, c.y - s),
                    ];
                    for w in pts.windows(2) {
                        ui.painter().line_segment([w[0], w[1]], egui::Stroke::new(1.8, icon_color));
                    }
                }
                NavItem::Network => {
                    // Wifi: 3 arcs + dot
                    ui.painter().circle_filled(egui::pos2(c.x, c.y + s - 2.0), 2.0, icon_color);
                    for (i, radius) in [4.5_f32, 7.5, 10.5].iter().enumerate() {
                        let segments = 12;
                        let arc_center = egui::pos2(c.x, c.y + s - 2.0);
                        let start = std::f32::consts::PI * 0.25;
                        let end = std::f32::consts::PI * 0.75;
                        let alpha = 1.0 - i as f32 * 0.15;
                        let arc_stroke = egui::Stroke::new(1.6, icon_color.gamma_multiply(alpha));
                        let points: Vec<egui::Pos2> = (0..=segments)
                            .map(|j| {
                                let t = j as f32 / segments as f32;
                                let angle = start + (end - start) * t;
                                egui::pos2(
                                    arc_center.x + radius * angle.cos(),
                                    arc_center.y - radius * angle.sin(),
                                )
                            })
                            .collect();
                        for w in points.windows(2) {
                            ui.painter().line_segment([w[0], w[1]], arc_stroke);
                        }
                    }
                }
                NavItem::Settings => {
                    // Gear: circle with notches
                    let r_outer = s;
                    let r_inner = s * 0.55;
                    ui.painter().circle_stroke(c, r_inner, icon_stroke);
                    let teeth = 6;
                    for i in 0..teeth {
                        let angle = (i as f32 / teeth as f32) * std::f32::consts::TAU;
                        let inner_pt = egui::pos2(c.x + r_inner * angle.cos(), c.y + r_inner * angle.sin());
                        let outer_pt = egui::pos2(c.x + r_outer * angle.cos(), c.y + r_outer * angle.sin());
                        ui.painter().line_segment([inner_pt, outer_pt], egui::Stroke::new(2.5, icon_color));
                    }
                }
            }

            // Tooltip on hover
            if is_hovered {
                egui::show_tooltip_at_pointer(
                    ui.ctx(),
                    egui::LayerId::new(egui::Order::Tooltip, ui.id().with(&item_id)),
                    ui.id().with(&item_id),
                    |ui| {
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new(nav_item.tooltip())
                                .size(12.0)
                                .color(TEXT_PRIMARY));
                            ui.add_space(8.0);
                            ui.label(egui::RichText::new(nav_item.shortcut())
                                .size(10.0)
                                .color(TEXT_MUTED));
                        });
                    }
                );
            }

            // Handle click
            if response.clicked() {
                self.current_tab = tab;
                self.mark_dirty();
            }
        });
    }

    /// Render the top bar with toggle and status
    fn render_top_bar(&mut self, ui: &mut egui::Ui) {
        egui::Frame::NONE
            .fill(BG_SIDEBAR)
            .stroke(egui::Stroke::new(1.0, BORDER_SUBTLE))
            .show(ui, |ui| {
                ui.set_min_height(TOP_BAR_HEIGHT);
                ui.set_max_height(TOP_BAR_HEIGHT);

                ui.horizontal(|ui| {
                    ui.add_space(SPACING_MD);

                    // Connection toggle
                    self.render_connection_toggle(ui);

                    ui.add_space(SPACING_SM);

                    // App name - compact
                    ui.vertical(|ui| {
                        ui.add_space(10.0);
                        ui.label(egui::RichText::new("SwiftTunnel")
                            .size(16.0)
                            .color(TEXT_PRIMARY)
                            .strong());
                        ui.label(egui::RichText::new("Game Booster")
                            .size(10.0)
                            .color(TEXT_DIMMED));
                    });

                    // Boost badge
                    if self.state.optimizations_active {
                        let active_count = self.count_active_boosts();
                        if active_count > 0 {
                            ui.add_space(SPACING_SM);
                            egui::Frame::NONE
                                .fill(ACCENT_PRIMARY.gamma_multiply(0.08))
                                .stroke(egui::Stroke::new(1.0, ACCENT_PRIMARY.gamma_multiply(0.15)))
                                .rounding(10.0)
                                .inner_margin(egui::Margin::symmetric(8, 3))
                                .show(ui, |ui| {
                                    ui.label(egui::RichText::new(format!("{} boosts", active_count))
                                        .size(10.0)
                                        .color(ACCENT_PRIMARY));
                                });
                        }
                    }

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.add_space(SPACING_MD);

                        // User info (if available)
                        if let Some(ref user) = self.user_info {
                            self.render_user_badge(ui, user);
                        }

                        // Status indicator
                        ui.add_space(SPACING_SM);
                        self.render_status_badge(ui);
                    });
                });
            });
    }

    /// Render the main connection toggle button
    fn render_connection_toggle(&mut self, ui: &mut egui::Ui) {
        let is_connected = self.vpn_state.is_connected();
        let is_connecting = self.vpn_state.is_connecting() || self.connecting_initiated.is_some();

        let toggle_size = egui::vec2(88.0, 36.0);
        let (rect, response) = ui.allocate_exact_size(toggle_size, egui::Sense::click());

        let is_hovered = response.hovered();

        // Determine state and colors
        let (label, bg_color) = if is_connected {
            ("ON", STATUS_CONNECTED)
        } else if is_connecting {
            ("...", STATUS_WARNING)
        } else {
            ("OFF", BG_ELEVATED)
        };

        let bg = if is_hovered && !is_connecting {
            lighten(bg_color, 0.08)
        } else {
            bg_color
        };

        // Subtle glow when connected
        if is_connected {
            ui.painter().rect_filled(
                rect.expand(2.0),
                10.0,
                STATUS_CONNECTED.gamma_multiply(0.1)
            );
        }

        // Main button
        ui.painter().rect_filled(rect, 8.0, bg);

        // Border
        let border_color = if is_connected {
            STATUS_CONNECTED.gamma_multiply(0.3)
        } else if is_connecting {
            STATUS_WARNING.gamma_multiply(0.3)
        } else if is_hovered {
            BORDER_HOVER
        } else {
            BORDER_SUBTLE
        };
        ui.painter().rect(rect, 8.0, egui::Color32::TRANSPARENT, egui::Stroke::new(1.0, border_color), egui::StrokeKind::Middle);

        // Label
        let text_color = if is_connected || is_connecting {
            egui::Color32::WHITE
        } else {
            TEXT_SECONDARY
        };

        ui.painter().text(
            rect.center(),
            egui::Align2::CENTER_CENTER,
            label,
            egui::FontId::proportional(14.0),
            text_color
        );

        // Handle click
        if response.clicked() && !is_connecting {
            if is_connected {
                self.disconnect_vpn();
            } else {
                self.connect_vpn();
            }
        }
    }

    /// Render user badge in top bar
    fn render_user_badge(&self, ui: &mut egui::Ui, user: &crate::auth::UserInfo) {
        egui::Frame::NONE
            .fill(BG_ELEVATED)
            .rounding(16.0)
            .inner_margin(egui::Margin::symmetric(8, 3))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 6.0;

                    // User icon
                    let (icon_rect, _) = ui.allocate_exact_size(egui::vec2(18.0, 18.0), egui::Sense::hover());
                    ui.painter().circle_filled(icon_rect.center(), 9.0, ACCENT_SECONDARY.gamma_multiply(0.2));
                    ui.painter().text(
                        icon_rect.center(),
                        egui::Align2::CENTER_CENTER,
                        user.email.chars().next().unwrap_or('U').to_uppercase().to_string(),
                        egui::FontId::proportional(9.0),
                        ACCENT_SECONDARY
                    );

                    // Email (truncated)
                    let display_email = if user.email.len() > 20 {
                        format!("{}...", &user.email[..17])
                    } else {
                        user.email.clone()
                    };
                    ui.label(egui::RichText::new(display_email)
                        .size(11.0)
                        .color(TEXT_SECONDARY));
                });
            });
    }

    /// Render status badge in top bar
    fn render_status_badge(&self, ui: &mut egui::Ui) {
        let is_connected = self.vpn_state.is_connected();
        let is_connecting = self.vpn_state.is_connecting();

        let (status_text, status_color) = if is_connected {
            ("PROTECTED", STATUS_CONNECTED)
        } else if is_connecting {
            ("CONNECTING", STATUS_WARNING)
        } else {
            ("OFFLINE", STATUS_INACTIVE)
        };

        egui::Frame::NONE
            .fill(status_color.gamma_multiply(0.08))
            .stroke(egui::Stroke::new(1.0, status_color.gamma_multiply(0.15)))
            .rounding(12.0)
            .inner_margin(egui::Margin::symmetric(10, 4))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 5.0;

                    // Status dot
                    let (dot_rect, _) = ui.allocate_exact_size(egui::vec2(6.0, 6.0), egui::Sense::hover());
                    ui.painter().circle_filled(dot_rect.center(), 3.0, status_color);

                    ui.label(egui::RichText::new(status_text)
                        .size(10.0)
                        .color(status_color)
                        .strong());
                });
            });
    }

    /// Render clean header banner with page title
    fn render_header_banner(&self, ui: &mut egui::Ui) {
        let banner_width = ui.available_width();
        let (banner_rect, _) = ui.allocate_exact_size(egui::vec2(banner_width, HEADER_BANNER_HEIGHT), egui::Sense::hover());

        let painter = ui.painter_at(banner_rect);

        // Subtle gradient background
        for y in 0..HEADER_BANNER_HEIGHT as i32 {
            let t = y as f32 / HEADER_BANNER_HEIGHT;
            let color = lerp_color(GRADIENT_BANNER_START, GRADIENT_BANNER_END, t);
            painter.hline(
                banner_rect.min.x..=banner_rect.max.x,
                banner_rect.min.y + y as f32,
                egui::Stroke::new(1.0, color)
            );
        }

        // Page title and subtitle
        let (title, subtitle) = match self.current_tab {
            Tab::Connect => ("Connect", "VPN tunnel"),
            Tab::Boost => ("FPS Boost", "System optimization"),
            Tab::Network => ("Network", "Connection analysis"),
            Tab::Settings => ("Settings", "Preferences"),
        };

        // Title
        painter.text(
            egui::pos2(banner_rect.min.x + 4.0, banner_rect.center().y - 6.0),
            egui::Align2::LEFT_CENTER,
            title,
            egui::FontId::proportional(22.0),
            TEXT_PRIMARY
        );

        // Subtitle
        painter.text(
            egui::pos2(banner_rect.min.x + 4.0, banner_rect.center().y + 14.0),
            egui::Align2::LEFT_CENTER,
            subtitle,
            egui::FontId::proportional(11.0),
            TEXT_DIMMED
        );

        // Accent underline bar
        let underline_rect = egui::Rect::from_min_size(
            egui::pos2(banner_rect.min.x, banner_rect.max.y - 2.0),
            egui::vec2(48.0, 2.0)
        );
        painter.rect_filled(underline_rect, 1.0, ACCENT_PRIMARY.gamma_multiply(0.5));
    }
}
