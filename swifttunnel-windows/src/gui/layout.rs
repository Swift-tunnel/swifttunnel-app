//! Layout module - ExitLag-style sidebar navigation and app structure

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
            NavItem::Connect => "\u{1F310}", // 🌐 Globe
            NavItem::Boost => "\u{26A1}",    // ⚡ Lightning
            NavItem::Network => "\u{1F4CA}", // 📊 Chart
            NavItem::Settings => "\u{2699}",  // ⚙ Gear
        }
    }

    /// Simple ASCII icon fallback
    pub fn icon_simple(&self) -> &'static str {
        match self {
            NavItem::Connect => "((o))",
            NavItem::Boost => ">",
            NavItem::Network => ":::",
            NavItem::Settings => "*",
        }
    }

    /// Tooltip text
    pub fn tooltip(&self) -> &'static str {
        match self {
            NavItem::Connect => "Connect",
            NavItem::Boost => "Boost",
            NavItem::Network => "Network",
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

                        // Content area with scroll
                        let content_height = total_size.y - if is_logged_in { TOP_BAR_HEIGHT } else { 0.0 };
                        // Account for scrollbar width (12px) and extra safety margin
                        let inner_content_width = content_width - CONTENT_PADDING * 2.0 - 16.0;

                        egui::ScrollArea::vertical()
                            .auto_shrink([false, false])
                            .max_height(content_height)
                            .show(ui, |ui| {
                                // Constrain width to prevent overflow
                                ui.set_max_width(content_width);

                                if !is_logged_in && !is_logging_in && !is_awaiting_oauth {
                                    self.render_full_login_screen(ui);
                                } else if is_logging_in {
                                    self.render_login_pending(ui);
                                } else if is_awaiting_oauth {
                                    self.render_awaiting_oauth_callback(ui);
                                } else {
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
                                }

                                ui.add_space(SPACING_XL);
                            });
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
                ACCENT_PRIMARY.gamma_multiply(0.15)
            } else {
                lerp_color(egui::Color32::TRANSPARENT, BG_HOVER, hover_val)
            };

            ui.painter().rect_filled(button_rect, 10.0, bg_color);

            // Icon
            let icon_color = if is_active {
                ACCENT_PRIMARY
            } else {
                lerp_color(TEXT_MUTED, TEXT_PRIMARY, hover_val)
            };

            ui.painter().text(
                button_rect.center(),
                egui::Align2::CENTER_CENTER,
                nav_item.icon_simple(),
                egui::FontId::proportional(if is_active { 18.0 } else { 16.0 }),
                icon_color
            );

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
                    ui.add_space(CONTENT_PADDING);

                    // Connection toggle (large ON/OFF button)
                    self.render_connection_toggle(ui);

                    // App name
                    ui.add_space(SPACING_MD);
                    ui.vertical(|ui| {
                        ui.add_space(8.0);
                        ui.label(egui::RichText::new("SwiftTunnel")
                            .size(18.0)
                            .color(TEXT_PRIMARY)
                            .strong());
                        ui.label(egui::RichText::new("Game Booster")
                            .size(11.0)
                            .color(TEXT_DIMMED));
                    });

                    // Boost badge
                    if self.state.optimizations_active {
                        let active_count = self.count_active_boosts();
                        if active_count > 0 {
                            ui.add_space(SPACING_MD);
                            egui::Frame::NONE
                                .fill(ACCENT_PRIMARY.gamma_multiply(0.12))
                                .stroke(egui::Stroke::new(1.0, ACCENT_PRIMARY.gamma_multiply(0.2)))
                                .rounding(12.0)
                                .inner_margin(egui::Margin::symmetric(10, 4))
                                .show(ui, |ui| {
                                    ui.horizontal(|ui| {
                                        ui.label(egui::RichText::new(">")
                                            .size(10.0)
                                            .color(ACCENT_PRIMARY));
                                        ui.add_space(2.0);
                                        ui.label(egui::RichText::new(format!("{} boosts", active_count))
                                            .size(11.0)
                                            .color(ACCENT_PRIMARY));
                                    });
                                });
                        }
                    }

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.add_space(CONTENT_PADDING);

                        // User info (if available)
                        if let Some(ref user) = self.user_info {
                            self.render_user_badge(ui, user);
                        }

                        // Status indicator
                        ui.add_space(SPACING_MD);
                        self.render_status_badge(ui);
                    });
                });
            });
    }

    /// Render the main connection toggle button
    fn render_connection_toggle(&mut self, ui: &mut egui::Ui) {
        let is_connected = self.vpn_state.is_connected();
        let is_connecting = self.vpn_state.is_connecting() || self.connecting_initiated.is_some();

        let toggle_size = egui::vec2(100.0, 40.0);
        let (rect, response) = ui.allocate_exact_size(toggle_size, egui::Sense::click());

        let is_hovered = response.hovered();

        // Determine state and colors
        let (label, bg_color, glow_color) = if is_connected {
            ("ON", STATUS_CONNECTED, STATUS_CONNECTED_GLOW)
        } else if is_connecting {
            ("...", STATUS_WARNING, STATUS_WARNING)
        } else {
            ("OFF", BG_ELEVATED, BG_HOVER)
        };

        let bg = if is_hovered && !is_connecting {
            lighten(bg_color, 0.1)
        } else {
            bg_color
        };

        // Draw glow effect when connected
        if is_connected {
            let elapsed = self.app_start_time.elapsed().as_secs_f32();
            let pulse = ((elapsed * std::f32::consts::PI / PULSE_ANIMATION_DURATION).sin() + 1.0) / 2.0;
            let glow_alpha = 0.15 + pulse * 0.1;

            // Outer glow
            ui.painter().rect_filled(
                rect.expand(3.0),
                14.0,
                glow_color.gamma_multiply(glow_alpha)
            );
        }

        // Main button
        ui.painter().rect_filled(rect, 12.0, bg);

        // Border
        let border_color = if is_connected {
            STATUS_CONNECTED.gamma_multiply(0.5)
        } else if is_connecting {
            STATUS_WARNING.gamma_multiply(0.5)
        } else if is_hovered {
            BORDER_HOVER
        } else {
            BORDER_SUBTLE
        };
        ui.painter().rect(rect, 12.0, egui::Color32::TRANSPARENT, egui::Stroke::new(1.0, border_color), egui::StrokeKind::Middle);

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
            egui::FontId::proportional(16.0),
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
            .rounding(20.0)
            .inner_margin(egui::Margin::symmetric(10, 4))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 6.0;

                    // User icon
                    let (icon_rect, _) = ui.allocate_exact_size(egui::vec2(20.0, 20.0), egui::Sense::hover());
                    ui.painter().circle_filled(icon_rect.center(), 10.0, ACCENT_SECONDARY.gamma_multiply(0.3));
                    ui.painter().text(
                        icon_rect.center(),
                        egui::Align2::CENTER_CENTER,
                        user.email.chars().next().unwrap_or('U').to_uppercase().to_string(),
                        egui::FontId::proportional(10.0),
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
            .fill(status_color.gamma_multiply(0.12))
            .stroke(egui::Stroke::new(1.0, status_color.gamma_multiply(0.25)))
            .rounding(14.0)
            .inner_margin(egui::Margin::symmetric(12, 6))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 6.0;

                    // Animated indicator dot
                    let (dot_rect, _) = ui.allocate_exact_size(egui::vec2(8.0, 8.0), egui::Sense::hover());

                    if is_connected {
                        // Pulse animation
                        let elapsed = self.app_start_time.elapsed().as_secs_f32();
                        let pulse = ((elapsed * std::f32::consts::PI / PULSE_ANIMATION_DURATION).sin() + 1.0) / 2.0;
                        let glow_radius = 3.0 + pulse * 2.0;
                        ui.painter().circle_filled(dot_rect.center(), glow_radius, status_color.gamma_multiply(0.4));
                    }

                    ui.painter().circle_filled(dot_rect.center(), 3.0, status_color);

                    ui.label(egui::RichText::new(status_text)
                        .size(11.0)
                        .color(status_color)
                        .strong());
                });
            });
    }

    /// Render decorative header banner (ExitLag-style)
    fn render_header_banner(&self, ui: &mut egui::Ui) {
        let banner_width = ui.available_width();
        let (banner_rect, _) = ui.allocate_exact_size(egui::vec2(banner_width, HEADER_BANNER_HEIGHT), egui::Sense::hover());

        let painter = ui.painter_at(banner_rect);

        // Gradient background
        for y in 0..HEADER_BANNER_HEIGHT as i32 {
            let t = y as f32 / HEADER_BANNER_HEIGHT;
            let color = lerp_color(GRADIENT_BANNER_START, GRADIENT_BANNER_END, t);
            painter.hline(
                banner_rect.min.x..=banner_rect.max.x,
                banner_rect.min.y + y as f32,
                egui::Stroke::new(1.0, color)
            );
        }

        // Decorative geometric shapes (like ExitLag's phone/device graphic)
        let elapsed = self.app_start_time.elapsed().as_secs_f32();

        // Animated gradient line at top
        let line_y = banner_rect.min.y + 2.0;
        let line_width = banner_width * 0.6;
        let line_offset = ((elapsed * 0.3).sin() + 1.0) / 2.0 * (banner_width - line_width);

        // Draw gradient accent line
        for x in 0..line_width as i32 {
            let t = x as f32 / line_width;
            let color = lerp_color(GRADIENT_ACCENT_START, GRADIENT_ACCENT_END, t);
            let alpha = if t < 0.1 || t > 0.9 {
                (t.min(1.0 - t) * 10.0).min(1.0) * 0.6
            } else {
                0.6
            };
            painter.vline(
                banner_rect.min.x + line_offset + x as f32,
                line_y..=line_y + 2.0,
                egui::Stroke::new(1.0, color.gamma_multiply(alpha))
            );
        }

        // Abstract tech pattern in top-right
        let pattern_x = banner_rect.max.x - 200.0;
        let pattern_y = banner_rect.min.y + 20.0;

        // Floating rectangles with glow
        for i in 0..5 {
            let offset = (elapsed * 0.5 + i as f32 * 0.7).sin() * 8.0;
            let rect = egui::Rect::from_min_size(
                egui::pos2(pattern_x + i as f32 * 35.0 + offset, pattern_y + (i as f32 * 15.0).sin() * 10.0),
                egui::vec2(25.0, 45.0 - i as f32 * 5.0)
            );

            let alpha = 0.05 + (i as f32 * 0.02);
            painter.rect_filled(rect, 4.0, ACCENT_PRIMARY.gamma_multiply(alpha));
            painter.rect(rect, 4.0, egui::Color32::TRANSPARENT, egui::Stroke::new(1.0, ACCENT_PRIMARY.gamma_multiply(alpha * 1.5)), egui::StrokeKind::Middle);
        }

        // Page title overlay
        let title = match self.current_tab {
            Tab::Connect => "Connect",
            Tab::Boost => "FPS Boost",
            Tab::Network => "Network",
            Tab::Settings => "Settings",
        };

        // Title - no extra padding since banner is inside padded frame
        painter.text(
            egui::pos2(banner_rect.min.x + 4.0, banner_rect.max.y - 30.0),
            egui::Align2::LEFT_CENTER,
            title,
            egui::FontId::proportional(28.0),
            TEXT_PRIMARY
        );
    }
}
