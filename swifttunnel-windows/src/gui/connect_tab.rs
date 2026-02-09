//! Connect tab rendering - VPN connection, region selection, game presets

use super::*;
use super::theme::*;
use super::animations::*;
use crate::auth::AuthState;
use crate::vpn::{ConnectionState, GamePreset};
use std::sync::atomic::Ordering;

impl BoosterApp {
    pub(crate) fn render_connect_tab(&mut self, ui: &mut egui::Ui) {
        // Show update banner if available (adds spacing after if shown)
        let had_banner = self.has_update_banner();
        self.render_update_banner(ui);
        if had_banner {
            ui.add_space(12.0);
        }

        // Show driver install banner if driver is missing
        self.render_driver_banner(ui);

        let is_logged_in = matches!(self.auth_state, AuthState::LoggedIn(_));

        if !is_logged_in {
            self.render_login_prompt(ui);
            return;
        }

        self.render_connection_status(ui);
        ui.add_space(16.0);
        self.render_game_preset_selector(ui);
        ui.add_space(16.0);
        self.render_region_selector(ui);
        // Only show Practice Mode if experimental mode is enabled
        if self.experimental_mode {
            ui.add_space(16.0);
            self.render_latency_slider(ui);
        }
        ui.add_space(16.0);
        self.render_quick_info(ui);
    }

    /// Render game preset selector cards (ExitLag-style)
    pub(crate) fn render_game_preset_selector(&mut self, ui: &mut egui::Ui) {
        egui::Frame::NONE
            .fill(BG_CARD)
            .stroke(egui::Stroke::new(1.0, BORDER_SUBTLE))
            .rounding(12.0)
            .inner_margin(16)
            .show(ui, |ui| {

                // Section header
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Game Selection").size(14.0).color(TEXT_PRIMARY).strong());
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let count = self.selected_game_presets.len();
                        if count > 0 {
                            egui::Frame::NONE
                                .fill(ACCENT_PRIMARY.gamma_multiply(0.12))
                                .rounding(8.0)
                                .inner_margin(egui::Margin::symmetric(8, 3))
                                .show(ui, |ui| {
                                    ui.label(egui::RichText::new(format!("{} selected", count))
                                        .size(10.0).color(ACCENT_PRIMARY).strong());
                                });
                        }
                    });
                });

                ui.add_space(12.0);

                // Game preset cards in responsive grid
                let available = ui.available_width();
                let card_spacing = 10.0;
                let presets = GamePreset::all();
                let is_connected = self.vpn_state.is_connected();

                // Responsive columns: 3 if enough space (>= 140px per card), else 2
                let cols = if (available - card_spacing * 2.0) / 3.0 >= 140.0 { 3 } else { 2 };
                let card_width = ((available - card_spacing * (cols as f32 - 1.0)) / cols as f32).floor();

                let mut preset_iter = presets.iter().peekable();
                while preset_iter.peek().is_some() {
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing = egui::vec2(card_spacing, 0.0);

                        for _ in 0..cols {
                            if let Some(preset) = preset_iter.next() {
                                let is_selected = self.selected_game_presets.contains(preset);

                                let card_bg = if is_selected {
                                    ACCENT_PRIMARY.gamma_multiply(0.12)
                                } else {
                                    BG_ELEVATED
                                };
                                let card_border = if is_selected {
                                    egui::Stroke::new(1.5, ACCENT_PRIMARY)
                                } else {
                                    egui::Stroke::new(1.0, BORDER_SUBTLE)
                                };

                                let response = egui::Frame::NONE
                                    .fill(card_bg)
                                    .stroke(card_border)
                                    .rounding(8.0)
                                    .inner_margin(egui::Margin::symmetric(8, 12))
                                    .show(ui, |ui| {
                                        ui.set_min_width(card_width);
                                        ui.set_max_width(card_width);

                                        ui.vertical_centered(|ui| {
                                            // Game name as primary element
                                            let name_color = if is_selected { TEXT_PRIMARY } else { TEXT_SECONDARY };
                                            ui.label(egui::RichText::new(preset.display_name())
                                                .size(13.0).color(name_color).strong());

                                            // Selection indicator
                                            if is_selected {
                                                ui.add_space(4.0);
                                                egui::Frame::NONE
                                                    .fill(ACCENT_PRIMARY.gamma_multiply(0.2))
                                                    .rounding(4.0)
                                                    .inner_margin(egui::Margin::symmetric(6, 2))
                                                    .show(ui, |ui| {
                                                        ui.label(egui::RichText::new("Selected")
                                                            .size(9.0).color(ACCENT_PRIMARY));
                                                    });
                                            }
                                        });
                                    })
                                    .response;

                                // Handle click (only when not connected)
                                if response.interact(egui::Sense::click()).clicked() && !is_connected {
                                    if is_selected {
                                        self.selected_game_presets.remove(preset);
                                    } else {
                                        self.selected_game_presets.insert(*preset);
                                    }
                                    self.mark_dirty();
                                }

                                // Change cursor on hover (only when not connected)
                                if !is_connected {
                                    response.on_hover_cursor(egui::CursorIcon::PointingHand);
                                }
                            }
                        }
                    });
                    if preset_iter.peek().is_some() {
                        ui.add_space(8.0);
                    }
                }

                // Warning if no game selected
                if self.selected_game_presets.is_empty() {
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("Select at least one game to enable split tunneling")
                            .size(11.0).color(STATUS_WARNING));
                    });
                }
            });
    }

    pub(crate) fn render_login_prompt(&mut self, ui: &mut egui::Ui) {
        let mut go_settings = false;

        egui::Frame::NONE
            .fill(BG_CARD).stroke(egui::Stroke::new(1.0, BORDER_SUBTLE))
            .rounding(12.0).inner_margin(20)
            .show(ui, |ui| {
                ui.vertical_centered(|ui| {
                    ui.add_space(32.0);
                    let (rect, _) = ui.allocate_exact_size(egui::vec2(64.0, 64.0), egui::Sense::hover());
                    ui.painter().circle_filled(rect.center(), 32.0, ACCENT_PRIMARY.gamma_multiply(0.2));
                    ui.painter().circle_stroke(rect.center(), 32.0, egui::Stroke::new(2.0, ACCENT_PRIMARY));

                    ui.add_space(20.0);
                    ui.label(egui::RichText::new("Sign In Required").size(20.0).color(TEXT_PRIMARY).strong());
                    ui.add_space(8.0);
                    ui.label(egui::RichText::new("Connect to gaming servers and reduce your ping").size(14.0).color(TEXT_SECONDARY));
                    ui.add_space(24.0);

                    if ui.add(
                        egui::Button::new(egui::RichText::new("Go to Account Settings").size(14.0).color(TEXT_PRIMARY))
                            .fill(ACCENT_PRIMARY).rounding(8.0).min_size(egui::vec2(200.0, 44.0))
                    ).clicked() {
                        go_settings = true;
                    }
                    ui.add_space(32.0);
                });
            });

        if go_settings {
            self.current_tab = Tab::Settings;
            self.settings_section = SettingsSection::Account;
        }
    }

    pub(crate) fn render_connection_status(&mut self, ui: &mut egui::Ui) {
        // Check if smart server selection is in progress
        if let Some(ref selection) = self.smart_selection {
            self.render_smart_selection_overlay(ui, selection.clone());
            return;
        }

        // Check if we should show instant connecting feedback
        // This gives immediate visual response when user clicks Connect
        let instant_connecting = self.connecting_initiated.is_some()
            && matches!(self.vpn_state, ConnectionState::Disconnected);

        let (status_text, _status_icon, status_color, detail_text, show_connected_info) = if instant_connecting {
            // Show connecting state immediately while VPN state catches up
            ("Connecting", "", STATUS_WARNING, "Initiating...".to_string(), false)
        } else {
            match &self.vpn_state {
                ConnectionState::Disconnected => ("Disconnected", "", STATUS_INACTIVE, "Ready to connect".to_string(), false),
                ConnectionState::FetchingConfig => ("Connecting", "", STATUS_WARNING, "Fetching config...".to_string(), false),
                ConnectionState::CreatingAdapter => ("Connecting", "", STATUS_WARNING, "Creating adapter...".to_string(), false),
                ConnectionState::Connecting => ("Connecting", "", STATUS_WARNING, "Establishing tunnel...".to_string(), false),
                ConnectionState::ConfiguringSplitTunnel => ("Connecting", "", STATUS_WARNING, "Configuring split tunnel...".to_string(), false),
                ConnectionState::ConfiguringRoutes => ("Connecting", "", STATUS_WARNING, "Setting up routes...".to_string(), false),
                ConnectionState::Connected { server_region, .. } => {
                    let name = if let Ok(list) = self.dynamic_server_list.lock() {
                        list.get_server(server_region)
                            .map(|s| s.name.clone())
                            .unwrap_or_else(|| server_region.clone())
                    } else {
                        server_region.clone()
                    };
                    ("Protected", "", STATUS_CONNECTED, name, true)
                }
                ConnectionState::Disconnecting => ("Disconnecting", "", STATUS_WARNING, "Please wait...".to_string(), false),
                ConnectionState::Error(msg) => {
                    // Format user-friendly VPN error messages
                    let user_friendly = if msg.contains("Administrator privileges required") {
                        "Admin access required. Restart as Administrator.".to_string()
                    } else if msg.contains("wintun.dll not found") {
                        "Driver not found. Please reinstall SwiftTunnel.".to_string()
                    } else if msg.contains("401") || msg.contains("Unauthorized") {
                        "Connection failed. Try again.".to_string()
                    } else if msg.contains("404") {
                        "Server unavailable. Try a different region.".to_string()
                    } else if msg.contains("timeout") || msg.contains("Timeout") {
                        "Connection timed out. Check your internet.".to_string()
                    } else if msg.contains("Network error") || msg.contains("network") {
                        "Network error. Check your connection.".to_string()
                    } else if msg.contains("handshake") || msg.contains("Handshake") {
                        "Secure connection failed. Try again.".to_string()
                    } else {
                        msg.clone()
                    };
                    ("Error", "", STATUS_ERROR, user_friendly, false)
                }
            }
        };

        let is_connected = self.vpn_state.is_connected();
        // Include instant_connecting for animation purposes
        let is_connecting = self.vpn_state.is_connecting() || instant_connecting;
        let is_error = matches!(&self.vpn_state, ConnectionState::Error(_));

        let (uptime_str, split_tunnel_active, tunneled_processes) = if let ConnectionState::Connected {
            since, split_tunnel_active, tunneled_processes, ..
        } = &self.vpn_state {
            let uptime = since.elapsed();
            let h = uptime.as_secs() / 3600;
            let m = (uptime.as_secs() % 3600) / 60;
            let s = uptime.as_secs() % 60;
            (format!("{:02}:{:02}:{:02}", h, m, s), *split_tunnel_active, tunneled_processes.clone())
        } else {
            (String::new(), false, Vec::new())
        };

        let mut do_connect = false;
        let mut do_disconnect = false;

        // Dynamic card styling based on state
        let (card_bg, card_border, border_width) = if is_connected {
            // Connected: subtle green tint with glow
            (lerp_color(BG_CARD, STATUS_CONNECTED, 0.05),
             STATUS_CONNECTED.gamma_multiply(0.4),
             1.5)
        } else if is_error {
            // Error: subtle red tint
            (lerp_color(BG_CARD, STATUS_ERROR, 0.03),
             STATUS_ERROR.gamma_multiply(0.3),
             1.0)
        } else {
            (BG_CARD, BORDER_SUBTLE, 1.0)
        };

        egui::Frame::NONE
            .fill(card_bg)
            .stroke(egui::Stroke::new(border_width, card_border))
            .rounding(16.0)
            .inner_margin(egui::Margin::symmetric(20, 18))
            .show(ui, |ui| {

                ui.horizontal(|ui| {
                    // Status indicator with animation
                    let indicator_size = 48.0;
                    let (indicator_rect, _) = ui.allocate_exact_size(egui::vec2(indicator_size, indicator_size), egui::Sense::hover());
                    let center = indicator_rect.center();

                    if is_connected {
                        // Animated breathing glow for connected state
                        let elapsed = self.app_start_time.elapsed().as_secs_f32();
                        let pulse = ((elapsed * std::f32::consts::PI / PULSE_ANIMATION_DURATION).sin() + 1.0) / 2.0;

                        // Outer glow rings
                        for i in 0..3 {
                            let ring_pulse = ((pulse + i as f32 * 0.2) % 1.0);
                            let radius = 18.0 + ring_pulse * 8.0;
                            let alpha = 0.15 * (1.0 - ring_pulse);
                            ui.painter().circle_filled(center, radius, STATUS_CONNECTED_GLOW.gamma_multiply(alpha));
                        }

                        // Main circle
                        ui.painter().circle_filled(center, 16.0, STATUS_CONNECTED);
                        // Inner highlight
                        ui.painter().circle_filled(center, 8.0, STATUS_CONNECTED_GLOW.gamma_multiply(0.5));
                    } else if is_connecting {
                        // Spinning animation for connecting
                        let elapsed = self.app_start_time.elapsed().as_secs_f32();

                        // Rotating dots
                        for i in 0..3 {
                            let angle = elapsed * 3.0 + (i as f32 * std::f32::consts::TAU / 3.0);
                            let radius = 14.0;
                            let dot_pos = egui::pos2(
                                center.x + angle.cos() * radius,
                                center.y + angle.sin() * radius
                            );
                            let dot_alpha = 0.3 + (1.0 - (i as f32 / 3.0)) * 0.7;
                            ui.painter().circle_filled(dot_pos, 4.0 - i as f32 * 0.5, STATUS_WARNING.gamma_multiply(dot_alpha));
                        }

                        // Center dot
                        ui.painter().circle_filled(center, 6.0, STATUS_WARNING.gamma_multiply(0.3));
                    } else if is_error {
                        // Error state
                        ui.painter().circle_filled(center, 16.0, STATUS_ERROR.gamma_multiply(0.2));
                        ui.painter().circle_stroke(center, 16.0, egui::Stroke::new(2.0, STATUS_ERROR));
                        ui.painter().text(center, egui::Align2::CENTER_CENTER,
                            "!", egui::FontId::proportional(18.0), STATUS_ERROR);
                    } else {
                        // Disconnected state
                        ui.painter().circle_filled(center, 16.0, BG_ELEVATED);
                        ui.painter().circle_stroke(center, 16.0, egui::Stroke::new(1.5, STATUS_INACTIVE));
                    }

                    ui.add_space(14.0);

                    ui.vertical(|ui| {
                        // Status text
                        ui.label(egui::RichText::new(status_text)
                            .size(20.0)
                            .color(status_color)
                            .strong());
                        ui.add_space(2.0);
                        ui.label(egui::RichText::new(&detail_text)
                            .size(13.0)
                            .color(TEXT_SECONDARY));
                    });

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let (btn_text, btn_color) = if is_connected {
                            ("Disconnect", STATUS_ERROR)
                        } else if is_connecting {
                            ("Cancel", STATUS_WARNING)
                        } else {
                            ("Connect", ACCENT_PRIMARY)
                        };

                        let btn_response = ui.add(
                            egui::Button::new(egui::RichText::new(btn_text)
                                .size(14.0)
                                .color(TEXT_PRIMARY)
                                .strong())
                                .fill(btn_color)
                                .rounding(10.0)
                                .min_size(egui::vec2(120.0, 44.0))
                        );

                        if btn_response.clicked() {
                            if is_connected || is_connecting {
                                do_disconnect = true;
                            } else {
                                do_connect = true;
                            }
                        }
                    });
                });

                // VPN Connection Progress Steps (shown during connecting states)
                if is_connecting {
                    ui.add_space(18.0);
                    self.render_connection_progress_steps(ui);
                }

                if show_connected_info {
                    ui.add_space(16.0);

                    // Subtle divider
                    let divider_rect = ui.allocate_exact_size(egui::vec2(ui.available_width(), 1.0), egui::Sense::hover()).0;
                    ui.painter().rect_filled(divider_rect, 0.0, BG_ELEVATED);

                    ui.add_space(14.0);

                    // Info badges in a row
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 12.0;

                        // Uptime badge
                        egui::Frame::NONE
                            .fill(BG_ELEVATED)
                            .rounding(8.0)
                            .inner_margin(egui::Margin::symmetric(12, 8))
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    ui.spacing_mut().item_spacing.x = 6.0;
                                    ui.vertical(|ui| {
                                        ui.spacing_mut().item_spacing.y = 1.0;
                                        ui.label(egui::RichText::new("Uptime").size(10.0).color(TEXT_MUTED));
                                        ui.label(egui::RichText::new(&uptime_str).size(12.0).color(TEXT_PRIMARY).strong());
                                    });
                                });
                            });

                        // Split tunnel badge (if active)
                        if split_tunnel_active {
                            let (tunnel_text, tunnel_color) = if tunneled_processes.is_empty() {
                                ("Waiting...", STATUS_WARNING)
                            } else {
                                (&tunneled_processes.join(", ") as &str, STATUS_CONNECTED)
                            };

                            egui::Frame::NONE
                                .fill(tunnel_color.gamma_multiply(0.1))
                                .stroke(egui::Stroke::new(1.0, tunnel_color.gamma_multiply(0.3)))
                                .rounding(8.0)
                                .inner_margin(egui::Margin::symmetric(12, 8))
                                .show(ui, |ui| {
                                    ui.horizontal(|ui| {
                                        ui.spacing_mut().item_spacing.x = 6.0;
                                        ui.vertical(|ui| {
                                            ui.spacing_mut().item_spacing.y = 1.0;
                                            ui.label(egui::RichText::new("Split Tunnel").size(10.0).color(TEXT_MUTED));
                                            ui.label(egui::RichText::new(tunnel_text).size(11.0).color(tunnel_color));
                                        });
                                    });
                                });
                        }

                        // Custom Relay badge (only when experimental mode + custom relay configured)
                        if self.experimental_mode
                            && !self.custom_relay_server.is_empty()
                        {
                            let relay_color = STATUS_WARNING;
                            egui::Frame::NONE
                                .fill(relay_color.gamma_multiply(0.1))
                                .stroke(egui::Stroke::new(1.0, relay_color.gamma_multiply(0.3)))
                                .rounding(8.0)
                                .inner_margin(egui::Margin::symmetric(12, 8))
                                .show(ui, |ui| {
                                    ui.horizontal(|ui| {
                                        ui.spacing_mut().item_spacing.x = 6.0;
                                        ui.vertical(|ui| {
                                            ui.spacing_mut().item_spacing.y = 1.0;
                                            ui.label(egui::RichText::new("Custom Relay").size(10.0).color(TEXT_MUTED));
                                            // Show shortened version of the relay server
                                            let display = if self.custom_relay_server.len() > 20 {
                                                format!("{}...", &self.custom_relay_server[..17])
                                            } else {
                                                self.custom_relay_server.clone()
                                            };
                                            ui.label(egui::RichText::new(display).size(11.0).color(relay_color));
                                        });
                                    });
                                });
                        }

                        // Auto Routing badge (only when experimental mode + auto routing enabled)
                        if self.experimental_mode && self.auto_routing_enabled {
                            let game_region_name = self.vpn_connection.try_lock().ok()
                                .and_then(|conn| conn.auto_router().and_then(|r| r.current_game_region()).map(|r| r.display_name().to_string()));

                            let (badge_text, badge_color) = if let Some(region) = game_region_name {
                                (format!("Game: {}", region), STATUS_CONNECTED)
                            } else {
                                ("Monitoring...".to_string(), TEXT_MUTED)
                            };

                            egui::Frame::NONE
                                .fill(badge_color.gamma_multiply(0.1))
                                .stroke(egui::Stroke::new(1.0, badge_color.gamma_multiply(0.3)))
                                .rounding(8.0)
                                .inner_margin(egui::Margin::symmetric(12, 8))
                                .show(ui, |ui| {
                                    ui.horizontal(|ui| {
                                        ui.spacing_mut().item_spacing.x = 6.0;
                                        ui.vertical(|ui| {
                                            ui.spacing_mut().item_spacing.y = 1.0;
                                            ui.label(egui::RichText::new("Auto Routing").size(10.0).color(TEXT_MUTED));
                                            ui.label(egui::RichText::new(&badge_text).size(11.0).color(badge_color));
                                        });
                                    });
                                });
                        }
                    });

                    // Throughput graph (new row)
                    ui.add_space(10.0);
                    self.render_throughput_graph(ui);
                }
            });

        if do_connect { self.connect_vpn(); }
        if do_disconnect { self.disconnect_vpn(); }
    }

    /// Render VPN connection progress steps
    pub(crate) fn render_connection_progress_steps(&self, ui: &mut egui::Ui) {
        let current_step = ConnectionStep::from_state(&self.vpn_state);
        let current_idx = current_step.step_index();

        // Steps: Fetching (1), Adapter (2), Tunnel (3), Routing (4)
        let steps = [
            (1, "Config"),
            (2, "Adapter"),
            (3, "Tunnel"),
            (4, "Route"),
        ];

        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 0.0;
            let available = ui.available_width();
            let step_width = available / (steps.len() as f32);

            for (idx, label) in steps {
                let is_complete = current_idx > idx;
                let is_current = current_idx == idx;

                ui.allocate_ui(egui::vec2(step_width, 32.0), |ui| {
                    ui.vertical_centered(|ui| {
                        // Draw step dot
                        let dot_size = 10.0;
                        let (rect, _) = ui.allocate_exact_size(egui::vec2(dot_size, dot_size), egui::Sense::hover());

                        let dot_color = if is_complete {
                            STATUS_CONNECTED
                        } else if is_current {
                            STATUS_WARNING
                        } else {
                            BG_ELEVATED
                        };

                        // Current step has a pulsing effect
                        if is_current {
                            let elapsed = self.app_start_time.elapsed().as_secs_f32();
                            let pulse = ((elapsed * std::f32::consts::PI * 2.0).sin() + 1.0) / 2.0;
                            let glow_radius = 5.0 + pulse * 2.0;
                            ui.painter().circle_filled(rect.center(), glow_radius, dot_color.gamma_multiply(0.3));
                        }
                        ui.painter().circle_filled(rect.center(), 4.0, dot_color);

                        // Step label
                        let label_color = if is_complete || is_current { TEXT_PRIMARY } else { TEXT_MUTED };
                        ui.label(egui::RichText::new(label).size(10.0).color(label_color));
                    });
                });
            }
        });
    }

    /// Update throughput history from current stats
    pub(crate) fn update_throughput_history(&mut self) {
        if !self.vpn_state.is_connected() {
            return;
        }

        let Some(stats) = &self.throughput_stats else { return };

        let now = std::time::Instant::now();
        let current_tx = stats.get_bytes_tx();
        let current_rx = stats.get_bytes_rx();

        // Calculate rate from last reading
        if let Some((last_tx, last_rx, last_time)) = self.last_throughput_bytes {
            let elapsed = now.duration_since(last_time).as_secs_f64();
            if elapsed >= 0.5 {
                // At least 500ms between samples for smoother graph
                let tx_rate = (current_tx.saturating_sub(last_tx)) as f64 / elapsed;
                let rx_rate = (current_rx.saturating_sub(last_rx)) as f64 / elapsed;

                self.throughput_history.push_back((now, tx_rate, rx_rate));

                // Keep last 60 samples (about 30 seconds at 2 samples/sec)
                while self.throughput_history.len() > 60 {
                    self.throughput_history.pop_front();
                }

                self.last_throughput_bytes = Some((current_tx, current_rx, now));
            }
        } else {
            // First reading
            self.last_throughput_bytes = Some((current_tx, current_rx, now));
        }
    }

    /// Render network throughput graph
    pub(crate) fn render_throughput_graph(&self, ui: &mut egui::Ui) {
        if self.throughput_history.is_empty() {
            // Show placeholder when no data yet
            egui::Frame::NONE
                .fill(BG_ELEVATED)
                .rounding(8.0)
                .inner_margin(egui::Margin::symmetric(12, 8))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 6.0;
                        ui.vertical(|ui| {
                            ui.spacing_mut().item_spacing.y = 1.0;
                            ui.label(egui::RichText::new("Throughput").size(10.0).color(TEXT_MUTED));
                            ui.label(egui::RichText::new("Collecting...").size(11.0).color(TEXT_SECONDARY));
                        });
                    });
                });
            return;
        }

        // Calculate max value for scaling
        let max_throughput = self.throughput_history.iter()
            .map(|(_, tx, rx)| tx.max(*rx))
            .fold(1.0f64, |a, b| a.max(b));

        // Get current rates
        let (current_tx, current_rx) = self.throughput_history.back()
            .map(|(_, tx, rx)| (*tx, *rx))
            .unwrap_or((0.0, 0.0));

        egui::Frame::NONE
            .fill(BG_ELEVATED)
            .rounding(8.0)
            .inner_margin(egui::Margin::symmetric(10, 8))
            .show(ui, |ui| {
                ui.vertical(|ui| {
                    // Header with current values
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("Tunnel Traffic").size(10.0).color(TEXT_MUTED));
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.label(egui::RichText::new(format!("DN {}", format_bytes_per_sec(current_rx)))
                                .size(10.0).color(STATUS_CONNECTED));
                            ui.label(egui::RichText::new(" / ").size(10.0).color(TEXT_MUTED));
                            ui.label(egui::RichText::new(format!("UP {}", format_bytes_per_sec(current_tx)))
                                .size(10.0).color(ACCENT_CYAN));
                        });
                    });

                    ui.add_space(4.0);

                    // Graph area
                    let graph_height = 40.0;
                    let graph_width = ui.available_width();
                    let (graph_rect, _) = ui.allocate_exact_size(egui::vec2(graph_width, graph_height), egui::Sense::hover());

                    let painter = ui.painter_at(graph_rect);

                    // Background
                    painter.rect_filled(graph_rect, 4.0, BG_CARD);

                    // Draw grid lines (2 horizontal)
                    for i in 1..3 {
                        let y = graph_rect.top() + (graph_height * i as f32 / 3.0);
                        painter.line_segment(
                            [egui::pos2(graph_rect.left(), y), egui::pos2(graph_rect.right(), y)],
                            egui::Stroke::new(0.5, BG_HOVER)
                        );
                    }

                    let num_points = self.throughput_history.len();
                    if num_points >= 2 {
                        let x_step = graph_width / (num_points - 1).max(1) as f32;

                        // Draw TX line (cyan)
                        let tx_points: Vec<egui::Pos2> = self.throughput_history.iter().enumerate()
                            .map(|(i, (_, tx, _))| {
                                let x = graph_rect.left() + x_step * i as f32;
                                let y = graph_rect.bottom() - ((*tx / max_throughput) as f32 * (graph_height - 4.0));
                                egui::pos2(x, y.max(graph_rect.top() + 2.0))
                            })
                            .collect();

                        // Draw RX line (green)
                        let rx_points: Vec<egui::Pos2> = self.throughput_history.iter().enumerate()
                            .map(|(i, (_, _, rx))| {
                                let x = graph_rect.left() + x_step * i as f32;
                                let y = graph_rect.bottom() - ((*rx / max_throughput) as f32 * (graph_height - 4.0));
                                egui::pos2(x, y.max(graph_rect.top() + 2.0))
                            })
                            .collect();

                        // Draw fill under lines (subtle)
                        for pair in tx_points.windows(2) {
                            let quad = [
                                pair[0],
                                pair[1],
                                egui::pos2(pair[1].x, graph_rect.bottom()),
                                egui::pos2(pair[0].x, graph_rect.bottom()),
                            ];
                            painter.add(egui::Shape::convex_polygon(
                                quad.to_vec(),
                                ACCENT_CYAN.gamma_multiply(0.1),
                                egui::Stroke::NONE,
                            ));
                        }

                        for pair in rx_points.windows(2) {
                            let quad = [
                                pair[0],
                                pair[1],
                                egui::pos2(pair[1].x, graph_rect.bottom()),
                                egui::pos2(pair[0].x, graph_rect.bottom()),
                            ];
                            painter.add(egui::Shape::convex_polygon(
                                quad.to_vec(),
                                STATUS_CONNECTED.gamma_multiply(0.1),
                                egui::Stroke::NONE,
                            ));
                        }

                        // Draw lines
                        for pair in tx_points.windows(2) {
                            painter.line_segment(
                                [pair[0], pair[1]],
                                egui::Stroke::new(1.5, ACCENT_CYAN.gamma_multiply(0.8))
                            );
                        }

                        for pair in rx_points.windows(2) {
                            painter.line_segment(
                                [pair[0], pair[1]],
                                egui::Stroke::new(1.5, STATUS_CONNECTED.gamma_multiply(0.8))
                            );
                        }
                    }
                });
            });
    }

    pub(crate) fn render_region_selector(&mut self, ui: &mut egui::Ui) {
        let mut clicked_region: Option<String> = None;
        // Use Cell for interior mutability - allows modification inside nested closures
        let gear_clicked = std::cell::Cell::new(false);
        let is_finding = self.finding_best_server.load(Ordering::Relaxed);

        // PERFORMANCE: Use cached values instead of locking mutexes every frame
        let regions = &self.cached_regions;
        let is_loading = self.servers_loading;
        let error_msg: Option<String> = if let Ok(list) = self.dynamic_server_list.try_lock() {
            list.error_message().map(|s| s.to_string())
        } else {
            None
        };
        let latencies = &self.cached_latencies;

        // Section header with enhanced styling
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("SELECT REGION").size(11.0).color(TEXT_SECONDARY).strong());

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if is_loading {
                    // Animated loading indicator
                    let elapsed = self.app_start_time.elapsed().as_secs_f32();
                    let pulse = ((elapsed * 3.0).sin() + 1.0) / 2.0;
                    let color = lerp_color(ACCENT_PRIMARY, ACCENT_CYAN, pulse);
                    let (dot_rect, _) = ui.allocate_exact_size(egui::vec2(6.0, 6.0), egui::Sense::hover());
                    ui.painter().circle_filled(dot_rect.center(), 3.0, color);
                    ui.add_space(4.0);
                    ui.label(egui::RichText::new("Loading...").size(11.0).color(ACCENT_PRIMARY));
                } else if is_finding {
                    let elapsed = self.app_start_time.elapsed().as_secs_f32();
                    let pulse = ((elapsed * 3.0).sin() + 1.0) / 2.0;
                    let color = lerp_color(ACCENT_CYAN, STATUS_CONNECTED, pulse);
                    let (dot_rect, _) = ui.allocate_exact_size(egui::vec2(6.0, 6.0), egui::Sense::hover());
                    ui.painter().circle_filled(dot_rect.center(), 3.0, color);
                    ui.add_space(4.0);
                    ui.label(egui::RichText::new("Measuring...").size(11.0).color(ACCENT_CYAN));
                } else {
                    // Server count badge
                    egui::Frame::NONE
                        .fill(BG_ELEVATED)
                        .rounding(8.0)
                        .inner_margin(egui::Margin::symmetric(8, 3))
                        .show(ui, |ui| {
                            ui.label(egui::RichText::new(format!("{} regions", regions.len()))
                                .size(10.0)
                                .color(TEXT_MUTED));
                        });
                }
            });
        });
        ui.add_space(14.0);

        // Show skeleton loading or error state if no regions
        if regions.is_empty() {
            if is_loading {
                // Skeleton loading cards with shimmer effect
                self.render_skeleton_region_cards(ui);
            } else if let Some(err) = &error_msg {
                // Error state with retry
                egui::Frame::NONE
                    .fill(STATUS_ERROR.gamma_multiply(0.08))
                    .stroke(egui::Stroke::new(1.0, STATUS_ERROR.gamma_multiply(0.3)))
                    .rounding(12.0)
                    .inner_margin(egui::Margin::symmetric(24, 20))
                    .show(ui, |ui| {
                                ui.vertical_centered(|ui| {
                            ui.add_space(8.0);
                            ui.label(egui::RichText::new("Failed to load servers")
                                .size(15.0)
                                .color(TEXT_PRIMARY)
                                .strong());
                            ui.add_space(6.0);
                            ui.label(egui::RichText::new(err)
                                .size(12.0)
                                .color(TEXT_SECONDARY));
                            ui.add_space(16.0);
                            if ui.add(
                                egui::Button::new(egui::RichText::new("Retry").size(13.0).color(TEXT_PRIMARY))
                                    .fill(ACCENT_PRIMARY)
                                    .rounding(8.0)
                                    .min_size(egui::vec2(100.0, 36.0))
                            ).clicked() {
                                self.retry_load_servers();
                            }
                        });
                    });
            } else {
                // Empty state
                egui::Frame::NONE
                    .fill(BG_CARD)
                    .rounding(12.0)
                    .inner_margin(egui::Margin::symmetric(24, 30))
                    .show(ui, |ui| {
                                ui.vertical_centered(|ui| {
                            ui.label(egui::RichText::new("No servers available")
                                .size(14.0)
                                .color(TEXT_MUTED));
                        });
                    });
            }
            return;
        }

        // Calculate grid dimensions - responsive columns
        let available_width = self.content_area_width.min(ui.available_width());
        let card_spacing = 10.0;
        // Use 2 columns if wide enough (>= 180px inner per card), else 1 column
        let region_cols = if (available_width - card_spacing) / 2.0 - 24.0 >= 180.0 { 2 } else { 1 };
        let card_width = ((available_width - card_spacing * (region_cols as f32 - 1.0).max(0.0)) / region_cols as f32).floor();
        let inner_width = (card_width - 24.0).max(120.0); // Account for inner_margin (12 * 2)

        // Create responsive-column grid with enhanced cards
        let mut region_iter = regions.iter().peekable();
        while region_iter.peek().is_some() {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = card_spacing;

                for _ in 0..region_cols {
                    if let Some(region) = region_iter.next() {
                        let is_selected = self.selected_region == region.id;
                        let latency = latencies.get(&region.id).map(|(_, l)| *l);
                        let card_id = format!("region_{}", region.id);

                        // Get hover animation value
                        let hover_val = self.animations.get_hover_value(&card_id);

                        // Calculate colors based on state
                        let (bg, border_color, border_width) = if is_selected {
                            (lerp_color(ACCENT_PRIMARY.gamma_multiply(0.12), ACCENT_PRIMARY.gamma_multiply(0.18), hover_val),
                             ACCENT_PRIMARY,
                             1.5)
                        } else {
                            let hover_bg = lerp_color(BG_CARD, BG_ELEVATED, hover_val * 0.5);
                            let hover_border = lerp_color(BORDER_SUBTLE, ACCENT_PRIMARY.gamma_multiply(0.4), hover_val);
                            (hover_bg, hover_border, 1.0 + hover_val * 0.5)
                        };

                        let response = egui::Frame::NONE
                            .fill(bg)
                            .stroke(egui::Stroke::new(border_width, border_color))
                            .rounding(12.0)
                            .inner_margin(egui::Margin::symmetric(12, 12))
                            .show(ui, |ui| {
                                // Constrain the card to exactly the calculated width
                                ui.set_min_width(inner_width);
                                ui.set_max_width(inner_width);
                                ui.set_min_height(80.0);

                                ui.vertical(|ui| {
                                    // Top row: Country code + latency
                                    ui.horizontal(|ui| {
                                        // Country code badge
                                        egui::Frame::NONE
                                            .fill(if is_selected { ACCENT_PRIMARY } else { BG_ELEVATED })
                                            .rounding(4.0)
                                            .inner_margin(egui::Margin::symmetric(6, 3))
                                            .show(ui, |ui| {
                                                ui.label(egui::RichText::new(&region.country_code)
                                                    .size(10.0)
                                                    .color(if is_selected { egui::Color32::WHITE } else { TEXT_SECONDARY })
                                                    .strong());
                                            });

                                        // "LAST" badge
                                        let is_last_used = self.last_connected_region.as_ref().map(|r| r == &region.id).unwrap_or(false);
                                        if is_last_used && !is_selected {
                                            ui.add_space(2.0);
                                            egui::Frame::NONE
                                                .fill(ACCENT_CYAN.gamma_multiply(0.12))
                                                .rounding(4.0)
                                                .inner_margin(egui::Margin::symmetric(4, 2))
                                                .show(ui, |ui| {
                                                    ui.label(egui::RichText::new("LAST")
                                                        .size(8.0)
                                                        .color(ACCENT_CYAN));
                                                });
                                        }

                                        // Push latency to the right using right-to-left layout
                                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                            // Latency display (compact) with pulsing dot for real-time indicator
                                            if let Some(ms) = latency {
                                                let lat_color = latency_color(ms);
                                                ui.label(egui::RichText::new(format!("{}ms", ms))
                                                    .size(11.0)
                                                    .color(lat_color)
                                                    .strong());
                                                // Pulsing dot shows latencies are live
                                                let elapsed = self.app_start_time.elapsed().as_secs_f32();
                                                let pulse = ((elapsed * 1.5).sin() + 1.0) / 2.0;
                                                let dot_alpha = 0.6 + pulse * 0.4;
                                                let (dot_rect, _) = ui.allocate_exact_size(egui::vec2(6.0, 6.0), egui::Sense::hover());
                                                ui.painter().circle_filled(dot_rect.center(), 3.0, lat_color.gamma_multiply(dot_alpha));
                                            } else if is_finding {
                                                let elapsed = self.app_start_time.elapsed().as_secs_f32();
                                                let dots = match ((elapsed * 2.0) as i32) % 4 {
                                                    0 => ".", 1 => "..", 2 => "...", _ => "",
                                                };
                                                ui.label(egui::RichText::new(format!("{}", dots))
                                                    .size(10.0)
                                                    .color(TEXT_DIMMED));
                                            } else {
                                                ui.label(egui::RichText::new("--")
                                                    .size(11.0)
                                                    .color(TEXT_DIMMED));
                                            }
                                        });
                                    });

                                    ui.add_space(6.0);

                                    // Region name with gear icon
                                    ui.horizontal(|ui| {
                                        ui.label(egui::RichText::new(&region.name)
                                            .size(14.0)
                                            .color(TEXT_PRIMARY)
                                            .strong());

                                        // Forced server indicator
                                        if self.forced_servers.contains_key(&region.id) {
                                            ui.add_space(2.0);
                                            ui.label(egui::RichText::new("Pinned").size(9.0).color(ACCENT_SECONDARY));
                                        }

                                        // Push gear button to right
                                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                            let gear_btn = ui.add(
                                                egui::Button::new(egui::RichText::new("\u{2699}").size(12.0).color(TEXT_MUTED))
                                                    .fill(BG_HOVER.gamma_multiply(0.5))
                                                    .rounding(4.0)
                                                    .min_size(egui::vec2(24.0, 24.0))
                                                    .sense(egui::Sense::click())
                                            );
                                            if gear_btn.clicked() {
                                                if self.server_selection_popup.as_ref() == Some(&region.id) {
                                                    self.server_selection_popup = None;
                                                } else {
                                                    self.server_selection_popup = Some(region.id.clone());
                                                }
                                                gear_clicked.set(true);
                                            }
                                            if gear_btn.hovered() {
                                                gear_clicked.set(true);
                                            }
                                        });
                                    });

                                    ui.add_space(2.0);

                                    // Description (truncated)
                                    ui.label(egui::RichText::new(&region.description)
                                        .size(10.0)
                                        .color(TEXT_MUTED));

                                    // Latency bar
                                    if let Some(ms) = latency {
                                        ui.add_space(6.0);
                                        let bar_height = 3.0;
                                        let bar_width = (inner_width - 4.0).max(50.0);
                                        let (bar_rect, _) = ui.allocate_exact_size(egui::vec2(bar_width, bar_height), egui::Sense::hover());
                                        ui.painter().rect_filled(bar_rect, 2.0, BG_ELEVATED);
                                        let fill_percent = latency_fill_percent(ms);
                                        let fill_rect = egui::Rect::from_min_size(
                                            bar_rect.min,
                                            egui::vec2(bar_width * fill_percent, bar_height)
                                        );
                                        ui.painter().rect_filled(fill_rect, 2.0, latency_color(ms));
                                    }
                                });
                            });

                        // Handle hover for animation
                        let is_hovered = response.response.hovered();
                        self.animations.animate_hover(&card_id, is_hovered, hover_val);

                        // Only select region if gear button wasn't clicked
                        // NOTE: Do NOT use response.response.interact(Sense::click()) here!
                        // In egui 0.26+, calling interact() on a Frame response makes it
                        // steal clicks from nested widgets (like our gear button).
                        // Instead, use manual click detection.
                        let frame_rect = response.response.rect;
                        if !gear_clicked.get() && response.response.hovered() {
                            if ui.input(|i| i.pointer.any_click()) {
                                if let Some(pos) = ui.input(|i| i.pointer.interact_pos()) {
                                    if frame_rect.contains(pos) {
                                        clicked_region = Some(region.id.clone());
                                    }
                                }
                            }
                        }
                    }
                }
            });
            ui.add_space(8.0);
        }

        // Handle click
        if let Some(region_id) = clicked_region {
            self.select_region(&region_id);
        }

        // Render server selection popup if open
        self.render_server_selection_popup(ui);
    }

    /// Render the server selection popup for a region
    pub(crate) fn render_server_selection_popup(&mut self, ui: &mut egui::Ui) {
        let popup_region_id = match &self.server_selection_popup {
            Some(id) => id.clone(),
            None => return,
        };

        // Get servers for this region
        let (servers_in_region, region_name): (Vec<(String, Option<u32>)>, String) = {
            let regions = &self.cached_regions;
            let latencies = &self.cached_latencies;

            if let Some(region) = regions.iter().find(|r| r.id == popup_region_id) {
                // For each server in the region, try to get individual latency
                // We only have region-level latency (best server), so show that for best
                let best_server_latency = latencies.get(&popup_region_id);

                let server_list: Vec<(String, Option<u32>)> = region.servers.iter()
                    .map(|server_id| {
                        // Check if this is the best server
                        let latency = if best_server_latency.map(|(best_id, _)| best_id == server_id).unwrap_or(false) {
                            best_server_latency.map(|(_, lat)| *lat)
                        } else {
                            None // We don't have individual server latencies
                        };
                        (server_id.clone(), latency)
                    })
                    .collect();
                (server_list, region.name.clone())
            } else {
                return;
            }
        };

        // Check if the current forced server is set for this region
        let current_forced = self.forced_servers.get(&popup_region_id).cloned();

        // Show popup window - use open() to track when X button is clicked
        let popup_id = egui::Id::new("server_selection_popup");
        let mut window_open = true;
        let close_popup = egui::Window::new(format!("Select Server - {}", region_name))
            .id(popup_id)
            .open(&mut window_open)  // Track window close via X button
            .collapsible(false)
            .resizable(false)
            .default_open(true)  // Ensure popup never starts collapsed
            .order(egui::Order::Foreground)  // Ensure popup appears above all content
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .frame(egui::Frame::popup(ui.style())
                .fill(BG_CARD)
                .stroke(egui::Stroke::new(1.0, BORDER_SUBTLE))
                .rounding(12.0)
                .inner_margin(16))
            .show(ui.ctx(), |ui| {
                let mut should_close = false;

                ui.set_min_width(280.0);

                // "Auto (Best Ping)" option
                let is_auto = current_forced.is_none();
                let auto_response = egui::Frame::NONE
                    .fill(if is_auto { ACCENT_PRIMARY.gamma_multiply(0.12) } else { BG_ELEVATED.gamma_multiply(0.5) })
                    .stroke(egui::Stroke::new(
                        if is_auto { 1.5 } else { 1.0 },
                        if is_auto { ACCENT_PRIMARY } else { BORDER_SUBTLE }
                    ))
                    .rounding(8.0)
                    .inner_margin(egui::Margin::symmetric(12, 10))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new("Auto (Best Ping)")
                                .size(13.0)
                                .color(if is_auto { TEXT_PRIMARY } else { TEXT_SECONDARY })
                                .strong());

                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                ui.label(egui::RichText::new("Recommended")
                                    .size(10.0)
                                    .color(ACCENT_CYAN));
                            });
                        });
                    });

                if auto_response.response.interact(egui::Sense::click()).clicked() {
                    // Remove forced server - use auto
                    self.forced_servers.remove(&popup_region_id);
                    self.mark_dirty();
                    should_close = true;
                }

                ui.add_space(8.0);

                // Divider
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Or select specific server:")
                        .size(11.0)
                        .color(TEXT_MUTED));
                });

                ui.add_space(6.0);

                // Server list
                for (server_id, latency) in &servers_in_region {
                    let is_selected = current_forced.as_ref() == Some(server_id);
                    let display_name = self.format_server_display_name(server_id);

                    let server_response = egui::Frame::NONE
                        .fill(if is_selected { ACCENT_SECONDARY.gamma_multiply(0.12) } else { egui::Color32::TRANSPARENT })
                        .stroke(egui::Stroke::new(
                            if is_selected { 1.5 } else { 1.0 },
                            if is_selected { ACCENT_SECONDARY } else { BORDER_SUBTLE.gamma_multiply(0.5) }
                        ))
                        .rounding(8.0)
                        .inner_margin(egui::Margin::symmetric(12, 8))
                        .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                ui.label(egui::RichText::new(&display_name)
                                    .size(12.0)
                                    .color(if is_selected { TEXT_PRIMARY } else { TEXT_SECONDARY }));

                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                    if let Some(ms) = latency {
                                        let lat_color = latency_color(*ms);
                                        ui.label(egui::RichText::new(format!("{}ms", ms))
                                            .size(11.0)
                                            .color(lat_color));
                                        // Small dot for best server indicator
                                        let (dot_rect, _) = ui.allocate_exact_size(egui::vec2(6.0, 6.0), egui::Sense::hover());
                                        ui.painter().circle_filled(dot_rect.center(), 3.0, STATUS_CONNECTED);
                                    }
                                });
                            });
                        });

                    if server_response.response.interact(egui::Sense::click()).clicked() {
                        // Force this server
                        self.forced_servers.insert(popup_region_id.clone(), server_id.clone());
                        self.mark_dirty();
                        should_close = true;
                    }

                    ui.add_space(4.0);
                }

                ui.add_space(8.0);

                // Close button
                ui.horizontal(|ui| {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.add(
                            egui::Button::new(egui::RichText::new("Close").size(12.0))
                                .fill(BG_ELEVATED)
                                .rounding(6.0)
                        ).clicked() {
                            should_close = true;
                        }
                    });
                });

                should_close
            });

        // Close popup if requested (via Close button, server selection, or X button)
        if !window_open {
            // User clicked X button on window
            self.server_selection_popup = None;
        } else if let Some(inner) = close_popup {
            if let Some(true) = inner.inner {
                // User clicked Close button or selected a server
                self.server_selection_popup = None;
            }
        }
    }

    /// Format server ID for display (e.g., "singapore-02" -> "Singapore 02")
    pub(crate) fn format_server_display_name(&self, server_id: &str) -> String {
        // Split on dash, capitalize first letter of each part
        server_id.split('-')
            .map(|part| {
                let mut chars = part.chars();
                match chars.next() {
                    Some(c) => c.to_uppercase().chain(chars).collect::<String>(),
                    None => String::new(),
                }
            })
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Render skeleton loading cards with shimmer effect
    pub(crate) fn render_skeleton_region_cards(&self, ui: &mut egui::Ui) {
        let available_width = self.content_area_width.min(ui.available_width());
        let card_spacing = 10.0;
        let skeleton_cols = if (available_width - card_spacing) / 2.0 - 24.0 >= 180.0 { 2 } else { 1 };
        let card_width = ((available_width - card_spacing * (skeleton_cols as f32 - 1.0).max(0.0)) / skeleton_cols as f32).floor();
        let inner_width = (card_width - 24.0).max(120.0);

        // Shimmer animation progress
        let elapsed = self.app_start_time.elapsed().as_secs_f32();
        let shimmer_progress = (elapsed / SHIMMER_ANIMATION_DURATION).fract();

        // Render 4 skeleton cards
        let skeleton_rows = (4 + skeleton_cols - 1) / skeleton_cols;
        for row in 0..skeleton_rows {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = card_spacing;

                for col in 0..skeleton_cols {
                    let card_offset = (row * skeleton_cols + col) as f32 * 0.1;
                    let local_shimmer = (shimmer_progress + card_offset) % 1.0;

                    egui::Frame::NONE
                        .fill(BG_CARD)
                        .stroke(egui::Stroke::new(1.0, BORDER_SUBTLE))
                        .rounding(12.0)
                        .inner_margin(egui::Margin::symmetric(12, 12))
                        .show(ui, |ui| {
                            ui.set_min_width(inner_width);
                            ui.set_max_width(inner_width);
                            ui.set_min_height(80.0);

                            ui.vertical(|ui| {
                                // Skeleton badge
                                let badge_rect = ui.allocate_exact_size(egui::vec2(50.0, 18.0), egui::Sense::hover()).0;
                                self.render_skeleton_rect(ui.painter(), badge_rect, 4.0, local_shimmer);

                                ui.add_space(6.0);

                                // Skeleton title
                                let title_rect = ui.allocate_exact_size(egui::vec2(inner_width * 0.6, 14.0), egui::Sense::hover()).0;
                                self.render_skeleton_rect(ui.painter(), title_rect, 4.0, local_shimmer + 0.05);

                                ui.add_space(4.0);

                                // Skeleton description
                                let desc_rect = ui.allocate_exact_size(egui::vec2(inner_width * 0.8, 10.0), egui::Sense::hover()).0;
                                self.render_skeleton_rect(ui.painter(), desc_rect, 4.0, local_shimmer + 0.1);

                                ui.add_space(6.0);

                                // Skeleton latency bar
                                let bar_rect = ui.allocate_exact_size(egui::vec2((inner_width - 4.0).max(50.0), 3.0), egui::Sense::hover()).0;
                                self.render_skeleton_rect(ui.painter(), bar_rect, 2.0, local_shimmer + 0.15);
                            });
                        });
                }
            });
            ui.add_space(8.0);
        }
    }

    /// Render a single skeleton rectangle with shimmer effect
    pub(crate) fn render_skeleton_rect(&self, painter: &egui::Painter, rect: egui::Rect, rounding: f32, shimmer_offset: f32) {
        // Base skeleton color
        let base_color = BG_ELEVATED;

        // Shimmer highlight that moves across
        let shimmer_width = rect.width() * 0.4;
        let shimmer_x = rect.left() - shimmer_width + (rect.width() + shimmer_width * 2.0) * ease_in_out_sine(shimmer_offset % 1.0);

        // Draw base
        painter.rect_filled(rect, rounding, base_color);

        // Draw shimmer highlight (clipped to rect)
        let shimmer_rect = egui::Rect::from_min_max(
            egui::pos2(shimmer_x.max(rect.left()), rect.top()),
            egui::pos2((shimmer_x + shimmer_width).min(rect.right()), rect.bottom())
        );

        if shimmer_rect.width() > 0.0 {
            // Gradient-like effect using multiple rectangles
            let highlight_color = BG_HOVER;
            painter.rect_filled(shimmer_rect, rounding, highlight_color);
        }
    }

    /// Select a region - no longer pings, just selects the first server
    pub(crate) fn select_region(&mut self, region_id: &str) {
        self.selected_region = region_id.to_string();

        // Get first server from the region
        if let Ok(list) = self.dynamic_server_list.lock() {
            if let Some(region) = list.get_region(region_id) {
                if let Some(first_server) = region.servers.first() {
                    self.selected_server = first_server.clone();
                }
            }
        }

        self.mark_dirty();
    }

    /// Render the artificial latency slider (practice mode)
    pub(crate) fn render_latency_slider(&mut self, ui: &mut egui::Ui) {
        const LATENCY_MAX_MS: u32 = 100;
        const LATENCY_STEP_MS: u32 = 5;
        const DEBOUNCE_SECS: u64 = 5; // Anti-abuse: 5 second delay before applying

        // Calculate time remaining for pending change
        let pending_secs_remaining = self.pending_latency.map(|(_, time)| {
            let elapsed = time.elapsed().as_secs();
            if elapsed >= DEBOUNCE_SECS { 0 } else { DEBOUNCE_SECS - elapsed }
        });

        egui::Frame::NONE
            .fill(BG_CARD)
            .stroke(egui::Stroke::new(1.0, BORDER_SUBTLE))
            .rounding(12.0)
            .inner_margin(16)
            .show(ui, |ui| {

                // Section header with value badge
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Practice Mode").size(14.0).color(TEXT_PRIMARY).strong());

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        // Show pending countdown if waiting
                        if let Some(secs) = pending_secs_remaining {
                            if secs > 0 {
                                ui.label(egui::RichText::new(format!("{}s", secs))
                                    .size(11.0).color(TEXT_MUTED));
                            }
                        }

                        let badge_text = if self.artificial_latency_ms == 0 {
                            "Off".to_string()
                        } else {
                            format!("+{}ms", self.artificial_latency_ms)
                        };
                        let badge_color = if self.artificial_latency_ms == 0 {
                            TEXT_MUTED
                        } else {
                            STATUS_WARNING
                        };

                        egui::Frame::NONE
                            .fill(if self.artificial_latency_ms == 0 { BG_ELEVATED } else { STATUS_WARNING.gamma_multiply(0.15) })
                            .rounding(4.0)
                            .inner_margin(egui::Margin::symmetric(8, 2))
                            .show(ui, |ui| {
                                ui.label(egui::RichText::new(badge_text).size(11.0).color(badge_color).strong());
                            });

                        if self.updating_latency {
                            ui.spinner();
                        }
                    });
                });

                ui.add_space(12.0);

                // Slider
                let mut latency_f32 = self.artificial_latency_ms as f32;
                let slider = egui::Slider::new(&mut latency_f32, 0.0..=LATENCY_MAX_MS as f32)
                    .step_by(LATENCY_STEP_MS as f64)
                    .show_value(false)
                    .trailing_fill(true);

                let response = ui.add(slider);

                // Update value if changed
                let new_latency = latency_f32 as u32;
                if new_latency != self.artificial_latency_ms {
                    self.artificial_latency_ms = new_latency;
                    self.mark_dirty();
                }

                // Queue latency update when slider is released (5s debounce for anti-abuse)
                if response.drag_stopped() && self.vpn_state.is_connected() {
                    if new_latency != self.last_applied_latency {
                        log::info!("Latency change queued: {}ms -> {}ms (applying in {}s)",
                            self.last_applied_latency, new_latency, DEBOUNCE_SECS);
                        self.pending_latency = Some((new_latency, std::time::Instant::now()));
                    }
                }

                // Min/max labels
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("0ms").size(10.0).color(TEXT_MUTED));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(egui::RichText::new(format!("{}ms", LATENCY_MAX_MS)).size(10.0).color(TEXT_MUTED));
                    });
                });

                ui.add_space(4.0);

                // Description with anti-abuse note
                ui.label(egui::RichText::new("Add artificial latency for high-ping practice (5s delay)")
                    .size(11.0).color(TEXT_MUTED));
            });
    }

    pub(crate) fn render_quick_info(&self, ui: &mut egui::Ui) {
        // Show diagnostics when connected, otherwise show info
        if self.vpn_state.is_connected() {
            self.render_tunnel_diagnostics(ui);
        } else {
            egui::Frame::NONE
                .fill(BG_CARD).stroke(egui::Stroke::new(1.0, BORDER_SUBTLE))
                .rounding(12.0).inner_margin(20)
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.add_space(8.0);
                        ui.vertical(|ui| {
                            ui.spacing_mut().item_spacing.y = 4.0;
                            ui.label(egui::RichText::new("How Split Tunneling Works").size(13.0).color(TEXT_PRIMARY).strong());
                            ui.label(egui::RichText::new("Only selected games use the VPN. Other apps connect normally, reducing overhead and lag.")
                                .size(11.0).color(TEXT_SECONDARY));
                        });
                    });
                });
        }
    }

    /// Render tunnel diagnostics panel (shown when connected)
    fn render_tunnel_diagnostics(&self, ui: &mut egui::Ui) {
        // Try to get diagnostics from VPN connection
        let diagnostics = self.vpn_connection.try_lock().ok().and_then(|v| {
            v.get_split_tunnel_diagnostics()
        });

        egui::Frame::NONE
            .fill(BG_CARD).stroke(egui::Stroke::new(1.0, BORDER_SUBTLE))
            .rounding(12.0).inner_margin(16)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Tunnel Status").size(13.0).color(TEXT_PRIMARY).strong());
                });

                ui.add_space(12.0);

                if let Some((adapter_name, has_default_route, tunneled, bypassed)) = diagnostics {
                    // Network adapter row
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("Network:").size(11.0).color(TEXT_MUTED));
                        ui.add_space(4.0);
                        let adapter = adapter_name.as_deref().unwrap_or("Unknown");
                        ui.label(egui::RichText::new(adapter).size(11.0).color(TEXT_SECONDARY));

                        // Default route indicator
                        if has_default_route {
                            egui::Frame::NONE
                                .fill(STATUS_CONNECTED.gamma_multiply(0.12))
                                .rounding(4.0)
                                .inner_margin(egui::Margin::symmetric(4, 1))
                                .show(ui, |ui| {
                                    ui.label(egui::RichText::new("OK").size(9.0).color(STATUS_CONNECTED));
                                });
                        } else {
                            egui::Frame::NONE
                                .fill(STATUS_WARNING.gamma_multiply(0.12))
                                .rounding(4.0)
                                .inner_margin(egui::Margin::symmetric(4, 1))
                                .show(ui, |ui| {
                                    ui.label(egui::RichText::new("No Route").size(9.0).color(STATUS_WARNING));
                                })
                                .response
                                .on_hover_text("Adapter may not have default route - check network settings");
                        }
                    });

                    ui.add_space(8.0);

                    // Traffic stats row
                    ui.horizontal(|ui| {
                        // Tunneled packets
                        ui.label(egui::RichText::new("Tunneled:").size(11.0).color(TEXT_MUTED));
                        ui.add_space(4.0);
                        let tunneled_color = if tunneled > 0 { STATUS_CONNECTED } else { TEXT_MUTED };
                        ui.label(egui::RichText::new(format_packet_count(tunneled)).size(11.0).color(tunneled_color));

                        ui.add_space(16.0);

                        // Bypassed packets
                        ui.label(egui::RichText::new("Bypassed:").size(11.0).color(TEXT_MUTED));
                        ui.add_space(4.0);
                        ui.label(egui::RichText::new(format_packet_count(bypassed)).size(11.0).color(TEXT_SECONDARY));
                    });

                    ui.add_space(8.0);

                    // Status indicator
                    let (status_text, status_color) = if tunneled > 0 {
                        ("Active - Game traffic is being tunneled", STATUS_CONNECTED)
                    } else if bypassed > 0 {
                        ("Waiting - No game traffic detected yet", STATUS_WARNING)
                    } else {
                        ("Initializing...", TEXT_MUTED)
                    };
                    ui.label(egui::RichText::new(status_text).size(10.0).color(status_color));

                } else {
                    ui.label(egui::RichText::new("Connecting...").size(11.0).color(TEXT_MUTED));
                }
            });
    }

    /// Render the smart server selection overlay
    /// Shows an animated card while testing servers to find the best one
    pub(crate) fn render_smart_selection_overlay(&mut self, ui: &mut egui::Ui, selection: super::SmartServerSelection) {
        let elapsed = selection.started_at.elapsed();
        let progress = (selection.current_index as f32 / selection.servers.len().max(1) as f32).min(1.0);
        let elapsed_secs = elapsed.as_secs_f32();

        // Get region name
        let region_name = if let Ok(list) = self.dynamic_server_list.try_lock() {
            list.get_region(&selection.region_id)
                .map(|r| r.name.clone())
                .unwrap_or_else(|| selection.region_id.clone())
        } else {
            selection.region_id.clone()
        };

        egui::Frame::NONE
            .fill(lerp_color(BG_CARD, ACCENT_PRIMARY, 0.03))
            .stroke(egui::Stroke::new(1.5, ACCENT_PRIMARY.gamma_multiply(0.4)))
            .rounding(16.0)
            .inner_margin(egui::Margin::symmetric(24, 24))
            .show(ui, |ui| {
                ui.vertical_centered(|ui| {
                    // Animated radar/scanner visualization
                    let indicator_size = 80.0;
                    let (indicator_rect, _) = ui.allocate_exact_size(egui::vec2(indicator_size, indicator_size), egui::Sense::hover());
                    let center = indicator_rect.center();

                    // Outer ring
                    ui.painter().circle_stroke(center, 36.0, egui::Stroke::new(2.0, ACCENT_PRIMARY.gamma_multiply(0.2)));
                    ui.painter().circle_stroke(center, 28.0, egui::Stroke::new(1.5, ACCENT_PRIMARY.gamma_multiply(0.15)));
                    ui.painter().circle_stroke(center, 20.0, egui::Stroke::new(1.0, ACCENT_PRIMARY.gamma_multiply(0.1)));

                    // Rotating sweep effect (like a radar)
                    let sweep_angle = elapsed_secs * 3.0;
                    let sweep_length = 35.0;
                    for i in 0..8 {
                        let angle = sweep_angle + (i as f32 * 0.1);
                        let alpha = 0.6 - (i as f32 * 0.07);
                        let end = egui::pos2(
                            center.x + angle.cos() * sweep_length,
                            center.y + angle.sin() * sweep_length
                        );
                        ui.painter().line_segment(
                            [center, end],
                            egui::Stroke::new(2.0, ACCENT_PRIMARY.gamma_multiply(alpha.max(0.0)))
                        );
                    }

                    // Server dots around the circle (one per server)
                    let num_servers = selection.servers.len();
                    for (i, server_id) in selection.servers.iter().enumerate() {
                        let angle = (i as f32 / num_servers.max(1) as f32) * std::f32::consts::TAU - std::f32::consts::FRAC_PI_2;
                        let dot_pos = egui::pos2(
                            center.x + angle.cos() * 30.0,
                            center.y + angle.sin() * 30.0
                        );

                        let dot_color = if let Some(Some(ms)) = selection.results.get(server_id) {
                            // Tested - show latency color
                            latency_color(*ms)
                        } else if i < selection.current_index {
                            // Testing failed
                            STATUS_ERROR.gamma_multiply(0.5)
                        } else if i == selection.current_index {
                            // Currently testing - pulse
                            let pulse = ((elapsed_secs * 4.0).sin() + 1.0) / 2.0;
                            ACCENT_PRIMARY.gamma_multiply(0.5 + pulse * 0.5)
                        } else {
                            // Not yet tested
                            TEXT_DIMMED.gamma_multiply(0.5)
                        };

                        let dot_size = if i == selection.current_index { 5.0 } else { 4.0 };
                        ui.painter().circle_filled(dot_pos, dot_size, dot_color);
                    }

                    // Center dot with pulse
                    let pulse = ((elapsed_secs * 2.0).sin() + 1.0) / 2.0;
                    ui.painter().circle_filled(center, 8.0 + pulse * 2.0, ACCENT_PRIMARY.gamma_multiply(0.3));
                    ui.painter().circle_filled(center, 6.0, ACCENT_PRIMARY);

                    ui.add_space(16.0);

                    // Title
                    ui.label(egui::RichText::new("Finding Best Server")
                        .size(16.0)
                        .color(TEXT_PRIMARY)
                        .strong());

                    ui.add_space(4.0);

                    // Region name
                    ui.label(egui::RichText::new(format!("Testing servers in {}", region_name))
                        .size(12.0)
                        .color(TEXT_SECONDARY));

                    ui.add_space(12.0);

                    // Progress bar
                    let bar_width = 200.0;
                    let bar_height = 4.0;
                    let (bar_rect, _) = ui.allocate_exact_size(egui::vec2(bar_width, bar_height), egui::Sense::hover());

                    // Background
                    ui.painter().rect_filled(bar_rect, 2.0, BG_ELEVATED);

                    // Progress fill with animated shimmer
                    let fill_width = bar_width * progress;
                    if fill_width > 0.0 {
                        let fill_rect = egui::Rect::from_min_size(
                            bar_rect.left_top(),
                            egui::vec2(fill_width, bar_height)
                        );
                        ui.painter().rect_filled(fill_rect, 2.0, ACCENT_PRIMARY);

                        // Shimmer effect
                        let shimmer_x = bar_rect.left() + (elapsed_secs * 50.0) % (bar_width + 30.0) - 15.0;
                        let shimmer_rect = egui::Rect::from_min_size(
                            egui::pos2(shimmer_x.max(bar_rect.left()).min(fill_rect.right() - 10.0), bar_rect.top()),
                            egui::vec2(15.0, bar_height)
                        );
                        if shimmer_rect.left() < fill_rect.right() {
                            ui.painter().rect_filled(shimmer_rect, 2.0, ACCENT_PRIMARY.gamma_multiply(1.3));
                        }
                    }

                    ui.add_space(8.0);

                    // Server count
                    ui.label(egui::RichText::new(format!("{} / {} servers tested", selection.current_index, selection.servers.len()))
                        .size(11.0)
                        .color(TEXT_MUTED));

                    // Show best so far if found
                    if let Some((best_id, best_ms)) = &selection.best_server {
                        ui.add_space(8.0);
                        let best_name = self.format_server_display_name(best_id);
                        ui.horizontal(|ui| {
                            ui.add_space((ui.available_width() - 150.0) / 2.0);
                            ui.label(egui::RichText::new("Best so far:")
                                .size(10.0)
                                .color(TEXT_MUTED));
                            ui.label(egui::RichText::new(format!("{} ({}ms)", best_name, best_ms))
                                .size(10.0)
                                .color(STATUS_CONNECTED));
                        });
                    }
                });
            });
    }
}

/// Format packet count for display (e.g., 1234 -> "1.2K", 1234567 -> "1.2M")
fn format_packet_count(count: u64) -> String {
    if count >= 1_000_000 {
        format!("{:.1}M", count as f64 / 1_000_000.0)
    } else if count >= 1_000 {
        format!("{:.1}K", count as f64 / 1_000.0)
    } else {
        count.to_string()
    }
}
