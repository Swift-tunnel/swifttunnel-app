//! Settings tab rendering - general settings, performance summary, account management

use super::*;
use super::theme::*;
use crate::auth::AuthState;
use crate::geolocation::RobloxRegion;
use crate::updater::UpdateState;

/// Helper: render a toggle switch with consistent styling
fn render_toggle(ui: &mut egui::Ui, enabled: bool) -> bool {
    let size = egui::vec2(TOGGLE_WIDTH, TOGGLE_HEIGHT);
    let (rect, response) = ui.allocate_exact_size(size, egui::Sense::click());
    let clicked = response.clicked();

    let bg = if enabled { ACCENT_PRIMARY } else { BG_ELEVATED };
    let knob_x = if enabled { rect.right() - (TOGGLE_KNOB_SIZE / 2.0) - 3.0 } else { rect.left() + (TOGGLE_KNOB_SIZE / 2.0) + 3.0 };

    ui.painter().rect_filled(rect, TOGGLE_HEIGHT / 2.0, bg);
    ui.painter().circle_filled(egui::pos2(knob_x, rect.center().y), TOGGLE_KNOB_SIZE / 2.0, TEXT_PRIMARY);

    clicked
}

/// Helper: render a setting row with label, description, and toggle
fn render_setting_row(ui: &mut egui::Ui, title: &str, description: &str, enabled: bool) -> bool {
    let mut clicked = false;
    ui.horizontal(|ui| {
        ui.vertical(|ui| {
            ui.label(egui::RichText::new(title).size(12.0).color(TEXT_PRIMARY));
            ui.label(egui::RichText::new(description).size(10.0).color(TEXT_MUTED));
        });
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            clicked = render_toggle(ui, enabled);
        });
    });
    clicked
}

impl BoosterApp {
    pub(crate) fn render_settings_tab(&mut self, ui: &mut egui::Ui) {
        // Tab selector
        ui.horizontal(|ui| {
            for (label, section) in [("General", SettingsSection::General), ("Account", SettingsSection::Account)] {
                let is_active = self.settings_section == section;
                let text_color = if is_active { ACCENT_PRIMARY } else { TEXT_SECONDARY };
                let bg = if is_active { ACCENT_PRIMARY.gamma_multiply(0.12) } else { egui::Color32::TRANSPARENT };

                if ui.add(
                    egui::Button::new(egui::RichText::new(label).size(13.0).color(text_color).strong())
                        .fill(bg).rounding(8.0).min_size(egui::vec2(90.0, BUTTON_MIN_HEIGHT))
                        .stroke(if is_active { egui::Stroke::new(1.0, ACCENT_PRIMARY.gamma_multiply(0.3)) } else { egui::Stroke::NONE })
                ).clicked() {
                    self.settings_section = section;
                }
                ui.add_space(SPACING_SM);
            }
        });

        ui.add_space(SPACING_LG);

        match self.settings_section {
            SettingsSection::General => self.render_general_settings(ui),
            SettingsSection::Performance => self.render_general_settings(ui), // Redirect to General
            SettingsSection::Account => self.render_account_settings(ui),
        }
    }

    #[allow(clippy::too_many_lines)]
    pub(crate) fn render_general_settings(&mut self, ui: &mut egui::Ui) {
        // About section
        card_frame()
            .show(ui, |ui| {
                ui.label(egui::RichText::new("About").size(14.0).color(TEXT_PRIMARY).strong());
                ui.add_space(SPACING_SM);
                ui.label(egui::RichText::new(format!("SwiftTunnel v{}", env!("CARGO_PKG_VERSION"))).size(13.0).color(TEXT_PRIMARY));
                ui.add_space(4.0);
                ui.label(egui::RichText::new("Game Booster & PC Optimization Suite").size(12.0).color(TEXT_SECONDARY));
                ui.add_space(4.0);
                ui.label(egui::RichText::new("Optimized for Roblox and other games").size(11.0).color(TEXT_MUTED));
            });

        ui.add_space(SPACING_MD);

        // Updates section
        let mut check_now = false;
        let mut toggle_auto_check = false;
        let current_auto_check = self.update_settings.auto_check;

        card_frame()
            .show(ui, |ui| {
                ui.label(egui::RichText::new("Updates").size(14.0).color(TEXT_PRIMARY).strong());
                ui.add_space(SPACING_SM);

                // Current version and check button
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(format!("Current version: {}", env!("CARGO_PKG_VERSION"))).size(12.0).color(TEXT_SECONDARY));

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        // Check for updates button
                        let update_state = self.update_state.lock().map(|s| s.clone()).unwrap_or(UpdateState::Idle);
                        let is_checking = matches!(update_state, UpdateState::Checking);

                        if is_checking {
                            ui.horizontal(|ui| {
                                ui.spinner();
                                ui.add_space(4.0);
                                ui.label(egui::RichText::new("Checking...").size(11.0).color(TEXT_SECONDARY));
                            });
                        } else {
                            if ui.add(
                                egui::Button::new(egui::RichText::new("Check for Updates").size(11.0).color(BG_BASE).strong())
                                    .fill(ACCENT_PRIMARY).rounding(6.0)
                            ).clicked() {
                                check_now = true;
                            }
                        }
                    });
                });

                ui.add_space(SPACING_SM);

                // Show update status
                let update_state = self.update_state.lock().map(|s| s.clone()).unwrap_or(UpdateState::Idle);
                match &update_state {
                    UpdateState::UpToDate => {
                        egui::Frame::NONE
                            .fill(STATUS_CONNECTED.gamma_multiply(0.1))
                            .rounding(6.0)
                            .inner_margin(egui::Margin::symmetric(10, 6))
                            .show(ui, |ui| {
                                ui.label(egui::RichText::new("You're on the latest version").size(12.0).color(STATUS_CONNECTED));
                            });
                    }
                    UpdateState::Available(info) => {
                        egui::Frame::NONE
                            .fill(ACCENT_PRIMARY.gamma_multiply(0.1))
                            .rounding(6.0)
                            .inner_margin(egui::Margin::symmetric(10, 6))
                            .show(ui, |ui| {
                                ui.label(egui::RichText::new(format!("Update v{} available", info.version)).size(12.0).color(ACCENT_PRIMARY));
                            });
                    }
                    UpdateState::Failed(msg) => {
                        egui::Frame::NONE
                            .fill(STATUS_ERROR.gamma_multiply(0.1))
                            .rounding(6.0)
                            .inner_margin(egui::Margin::symmetric(10, 6))
                            .show(ui, |ui| {
                                ui.label(egui::RichText::new(msg).size(12.0).color(STATUS_ERROR));
                            });
                    }
                    _ => {}
                }

                ui.add_space(SPACING_SM);

                // Auto-check toggle
                toggle_auto_check = render_setting_row(
                    ui,
                    "Check for updates on startup",
                    "Automatically check for new versions when the app starts",
                    current_auto_check,
                );
            });

        ui.add_space(SPACING_MD);

        // System Tray section
        let mut toggle_minimize_to_tray = false;
        let current_minimize_to_tray = self.minimize_to_tray;

        card_frame()
            .show(ui, |ui| {
                ui.label(egui::RichText::new("System Tray").size(14.0).color(TEXT_PRIMARY).strong());
                ui.add_space(SPACING_SM);

                toggle_minimize_to_tray = render_setting_row(
                    ui,
                    "Minimize to tray on close",
                    "Keep SwiftTunnel running in the background when you close the window",
                    current_minimize_to_tray,
                );

                ui.add_space(SPACING_SM);
                ui.label(egui::RichText::new("Tip: Click the tray icon to show the window. Right-click for more options.").size(10.0).color(TEXT_MUTED).italics());
            });

        ui.add_space(SPACING_MD);

        // Discord Rich Presence section
        let mut toggle_discord_rpc = false;
        let current_discord_rpc = self.enable_discord_rpc;

        card_frame()
            .show(ui, |ui| {
                ui.label(egui::RichText::new("Discord").size(14.0).color(TEXT_PRIMARY).strong());
                ui.add_space(SPACING_SM);

                toggle_discord_rpc = render_setting_row(
                    ui,
                    "Show status in Discord",
                    "Display your VPN connection and game activity on your Discord profile",
                    current_discord_rpc,
                );

                ui.add_space(SPACING_SM);
                if current_discord_rpc {
                    ui.label(egui::RichText::new("Your Discord friends can see your SwiftTunnel activity").size(10.0).color(TEXT_MUTED).italics());
                } else {
                    ui.label(egui::RichText::new("Discord Rich Presence is disabled").size(10.0).color(TEXT_MUTED).italics());
                }
            });

        ui.add_space(SPACING_MD);

        // Experimental Features section (only visible to testers)
        let is_tester = self.user_info.as_ref().map(|u| u.is_tester).unwrap_or(false);
        let mut toggle_experimental_mode = false;
        let mut toggle_auto_routing = false;
        let current_experimental_mode = self.experimental_mode;
        let current_auto_routing = self.auto_routing_enabled;

        card_frame()
            .show(ui, |ui| {
                ui.label(egui::RichText::new("Experimental").size(14.0).color(TEXT_PRIMARY).strong());
                ui.add_space(SPACING_SM);

                if !is_tester {
                    egui::Frame::NONE
                        .fill(BG_ELEVATED)
                        .rounding(6.0)
                        .inner_margin(egui::Margin::symmetric(10, 8))
                        .show(ui, |ui| {
                            ui.label(egui::RichText::new("Experimental features require tester access.").size(12.0).color(TEXT_SECONDARY));
                            ui.add_space(4.0);
                            ui.label(egui::RichText::new("Request tester access from an admin to unlock Practice Mode, Custom Relay, and Auto Routing.").size(10.0).color(TEXT_MUTED));
                        });
                    return;
                }

                // Experimental mode toggle
                toggle_experimental_mode = render_setting_row(
                    ui,
                    "Enable Practice Mode",
                    "Add artificial latency to simulate high-ping conditions",
                    current_experimental_mode,
                );

                ui.add_space(SPACING_SM);

                egui::Frame::NONE
                    .fill(STATUS_WARNING.gamma_multiply(0.08))
                    .rounding(6.0)
                    .inner_margin(egui::Margin::symmetric(10, 6))
                    .show(ui, |ui| {
                        ui.label(egui::RichText::new("Experimental features may be unstable or change without notice.").size(10.0).color(STATUS_WARNING));
                    });

                // Custom Relay section (only visible when experimental mode is enabled)
                if current_experimental_mode {
                    ui.add_space(SPACING_MD);
                    ui.add(egui::Separator::default().spacing(0.0));
                    ui.add_space(SPACING_MD);

                    ui.horizontal(|ui| {
                        ui.vertical(|ui| {
                            ui.horizontal(|ui| {
                                ui.label(egui::RichText::new("Custom Relay Server").size(13.0).color(TEXT_PRIMARY));
                                ui.add_space(4.0);
                                egui::Frame::NONE
                                    .fill(STATUS_WARNING.gamma_multiply(0.15))
                                    .rounding(4.0)
                                    .inner_margin(egui::Margin::symmetric(6, 2))
                                    .show(ui, |ui| {
                                        ui.label(egui::RichText::new("V3 ONLY").size(9.0).color(STATUS_WARNING).strong());
                                    });
                            });
                            ui.label(egui::RichText::new("Override the relay server for V3 mode. Format: host:port").size(11.0).color(TEXT_SECONDARY));
                        });
                    });

                    ui.add_space(SPACING_SM);

                    // Text input for custom relay
                    let mut custom_relay = self.custom_relay_server.clone();
                    let available_width = ui.available_width();

                    let (changed, clear_clicked) = ui.horizontal(|ui| {
                        let text_edit = egui::TextEdit::singleline(&mut custom_relay)
                            .hint_text("e.g., relay.example.com:51821 (leave empty for auto)")
                            .desired_width(available_width - 80.0);
                        let changed = ui.add(text_edit).changed();

                        // Clear button
                        let clear_clicked = if !custom_relay.is_empty() {
                            ui.add(
                                egui::Button::new(egui::RichText::new("Clear").size(11.0).color(TEXT_PRIMARY))
                                    .fill(BG_ELEVATED).rounding(4.0)
                            ).clicked()
                        } else {
                            false
                        };
                        (changed, clear_clicked)
                    }).inner;

                    if changed {
                        self.custom_relay_server = custom_relay;
                        self.mark_dirty();
                    }
                    if clear_clicked {
                        self.custom_relay_server.clear();
                        self.mark_dirty();
                        log::info!("Custom relay server cleared");
                    }

                    // Validation and status
                    ui.add_space(SPACING_SM);
                    if !self.custom_relay_server.is_empty() {
                        // Validate format: host:port where host can be IPv4, IPv6 with brackets, or hostname
                        // Examples: 1.2.3.4:51821, [::1]:51821, relay.example.com:51821
                        let is_valid = {
                            let s = &self.custom_relay_server;
                            if s.starts_with('[') {
                                // IPv6 format: [address]:port
                                if let Some(bracket_end) = s.find(']') {
                                    let after_bracket = &s[bracket_end + 1..];
                                    after_bracket.starts_with(':') && after_bracket[1..].parse::<u16>().is_ok()
                                } else {
                                    false
                                }
                            } else {
                                // IPv4 or hostname format: host:port (split on last colon)
                                if let Some(last_colon) = s.rfind(':') {
                                    let port_str = &s[last_colon + 1..];
                                    let host = &s[..last_colon];
                                    !host.is_empty() && port_str.parse::<u16>().is_ok()
                                } else {
                                    false
                                }
                            }
                        };

                        if is_valid {
                            egui::Frame::NONE
                                .fill(STATUS_CONNECTED.gamma_multiply(0.1))
                                .rounding(6.0)
                                .inner_margin(egui::Margin::symmetric(10, 6))
                                .show(ui, |ui| {
                                    ui.label(egui::RichText::new(format!("Using custom relay: {}", self.custom_relay_server)).size(11.0).color(STATUS_CONNECTED));
                                });
                        } else {
                            egui::Frame::NONE
                                .fill(STATUS_ERROR.gamma_multiply(0.1))
                                .rounding(6.0)
                                .inner_margin(egui::Margin::symmetric(10, 6))
                                .show(ui, |ui| {
                                    ui.label(egui::RichText::new("Invalid format. Use host:port (e.g., relay.example.com:51821 or [::1]:51821)").size(11.0).color(STATUS_ERROR));
                                });
                        }
                    } else {
                        ui.label(egui::RichText::new("Auto mode: Uses VPN server IP with port 51821").size(10.0).color(TEXT_MUTED));
                    }

                    // Auto Routing section
                    ui.add_space(SPACING_MD);
                    ui.add(egui::Separator::default().spacing(0.0));
                    ui.add_space(SPACING_MD);

                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("Auto Routing").size(13.0).color(TEXT_PRIMARY));
                        ui.add_space(4.0);
                        egui::Frame::NONE
                            .fill(ACCENT_PRIMARY.gamma_multiply(0.15))
                            .rounding(4.0)
                            .inner_margin(egui::Margin::symmetric(6, 2))
                            .show(ui, |ui| {
                                ui.label(egui::RichText::new("BETA").size(9.0).color(ACCENT_PRIMARY).strong());
                            });
                    });
                    ui.label(egui::RichText::new("Automatically switch relay server when your game server changes region").size(11.0).color(TEXT_SECONDARY));

                    ui.add_space(SPACING_SM);

                    toggle_auto_routing = render_setting_row(
                        ui,
                        "Enable auto routing",
                        "Detect game server region changes and switch relays automatically",
                        current_auto_routing,
                    );

                    ui.add_space(SPACING_SM);
                    if current_auto_routing {
                        egui::Frame::NONE
                            .fill(ACCENT_PRIMARY.gamma_multiply(0.08))
                            .rounding(6.0)
                            .inner_margin(egui::Margin::symmetric(10, 6))
                            .show(ui, |ui| {
                                ui.label(egui::RichText::new("When you teleport to a server in a different region, SwiftTunnel will automatically switch to the nearest relay for optimal latency.").size(10.0).color(ACCENT_PRIMARY));
                            });

                        // Region whitelist section
                        ui.add_space(SPACING_MD);
                        ui.add(egui::Separator::default().spacing(0.0));
                        ui.add_space(SPACING_MD);

                        ui.label(egui::RichText::new("Bypass VPN for these regions").size(13.0).color(TEXT_PRIMARY));
                        ui.label(egui::RichText::new("When auto-routing detects these game regions, traffic will use your direct connection instead of VPN.").size(11.0).color(TEXT_SECONDARY));
                        ui.add_space(SPACING_SM);

                        for region in RobloxRegion::all_regions() {
                            let name = region.display_name();
                            let is_whitelisted = self.whitelisted_regions.contains(name);
                            let mut checked = is_whitelisted;
                            if ui.checkbox(&mut checked, egui::RichText::new(name).size(12.0).color(TEXT_PRIMARY)).changed() {
                                if checked {
                                    self.whitelisted_regions.insert(name.to_string());
                                } else {
                                    self.whitelisted_regions.remove(name);
                                }
                                self.mark_dirty();

                                // Update auto-router in real-time if connected
                                if let Ok(conn) = self.vpn_connection.try_lock() {
                                    if let Some(router) = conn.auto_router() {
                                        router.set_whitelisted_regions(
                                            self.whitelisted_regions.iter().cloned().collect()
                                        );
                                    }
                                }
                            }
                        }
                    } else {
                        ui.label(egui::RichText::new("Auto-routing is disabled. You'll stay on your selected server.").size(10.0).color(TEXT_MUTED));
                    }
                }
            });

        // Handle actions after UI rendering
        if check_now {
            self.start_update_check();
        }
        if toggle_auto_check {
            self.update_settings.auto_check = !self.update_settings.auto_check;
            self.mark_dirty();
        }
        if toggle_minimize_to_tray {
            self.minimize_to_tray = !self.minimize_to_tray;
            // Also update the tray's setting
            if let Some(ref tray) = self.system_tray {
                tray.set_minimize_to_tray(self.minimize_to_tray);
            }
            self.mark_dirty();
        }
        if toggle_experimental_mode {
            self.experimental_mode = !self.experimental_mode;
            log::info!("Experimental mode: {}", self.experimental_mode);
            self.mark_dirty();
        }
        if toggle_discord_rpc {
            self.enable_discord_rpc = !self.enable_discord_rpc;
            self.discord_manager.set_enabled(self.enable_discord_rpc);
            log::info!("Discord RPC: {}", self.enable_discord_rpc);
            self.mark_dirty();
        }
        if toggle_auto_routing {
            self.auto_routing_enabled = !self.auto_routing_enabled;
            log::info!("Auto routing: {}", self.auto_routing_enabled);
            self.mark_dirty();
        }
    }

    pub(crate) fn render_account_settings(&mut self, ui: &mut egui::Ui) {
        match &self.auth_state {
            AuthState::LoggedOut | AuthState::Error(_) => self.render_login_form(ui),
            AuthState::LoggingIn => self.render_login_pending(ui),
            AuthState::AwaitingOAuthCallback(_) => self.render_awaiting_oauth_callback(ui),
            AuthState::LoggedIn(_) => self.render_logged_in(ui),
        }
    }

    pub(crate) fn render_login_form(&mut self, ui: &mut egui::Ui) {
        let can_login = !self.login_email.is_empty() && !self.login_password.is_empty();
        let mut do_login = false;
        let mut open_signup = false;

        card_frame()
            .show(ui, |ui| {
                ui.label(egui::RichText::new("Sign In").size(16.0).color(TEXT_PRIMARY).strong());
                ui.add_space(SPACING_MD);

                ui.label(egui::RichText::new("Email").size(12.0).color(TEXT_SECONDARY));
                ui.add_space(4.0);
                ui.add(egui::TextEdit::singleline(&mut self.login_email).hint_text("you@example.com").desired_width(f32::INFINITY));

                ui.add_space(SPACING_SM);
                ui.label(egui::RichText::new("Password").size(12.0).color(TEXT_SECONDARY));
                ui.add_space(4.0);
                ui.add(egui::TextEdit::singleline(&mut self.login_password).hint_text("********").password(true).desired_width(f32::INFINITY));

                ui.add_space(SPACING_LG);
                let btn_color = if can_login { ACCENT_PRIMARY } else { BG_ELEVATED };
                let btn_text_color = if can_login { BG_BASE } else { TEXT_MUTED };
                if ui.add(
                    egui::Button::new(egui::RichText::new("Sign In").size(14.0).color(btn_text_color).strong())
                        .fill(btn_color).rounding(8.0).min_size(egui::vec2(f32::INFINITY, 44.0))
                ).clicked() && can_login {
                    do_login = true;
                }

                ui.add_space(SPACING_SM);
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("No account?").size(12.0).color(TEXT_SECONDARY));
                    if ui.add(egui::Label::new(egui::RichText::new("Sign up").size(12.0).color(ACCENT_PRIMARY).underline()).sense(egui::Sense::click())).clicked() {
                        open_signup = true;
                    }
                });
            });

        if do_login { self.start_login(); }
        if open_signup { crate::utils::open_url("https://swifttunnel.net/signup"); }

        if let Some(error) = &self.auth_error.clone() {
            ui.add_space(SPACING_SM);
            egui::Frame::NONE
                .fill(STATUS_ERROR.gamma_multiply(0.1)).rounding(8.0).inner_margin(12)
                .show(ui, |ui| {
                    ui.label(egui::RichText::new(error).size(12.0).color(STATUS_ERROR));
                });
        }
    }

    pub(crate) fn render_logged_in(&mut self, ui: &mut egui::Ui) {
        let user_email = self.user_info.as_ref().map(|u| u.email.clone());
        let user_initial = user_email.as_ref()
            .and_then(|e| e.chars().next())
            .map(|c| c.to_uppercase().to_string())
            .unwrap_or_else(|| "U".to_string());

        let mut do_logout = false;

        card_frame()
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    // Avatar circle
                    let (rect, _) = ui.allocate_exact_size(egui::vec2(48.0, 48.0), egui::Sense::hover());
                    ui.painter().circle_filled(rect.center(), 24.0, ACCENT_PRIMARY.gamma_multiply(0.2));
                    ui.painter().circle_stroke(rect.center(), 24.0, egui::Stroke::new(1.5, ACCENT_PRIMARY.gamma_multiply(0.4)));
                    ui.painter().text(rect.center(), egui::Align2::CENTER_CENTER, &user_initial, egui::FontId::proportional(20.0), ACCENT_PRIMARY);

                    ui.add_space(SPACING_SM);
                    ui.vertical(|ui| {
                        if let Some(email) = &user_email {
                            ui.label(egui::RichText::new(email).size(14.0).color(TEXT_PRIMARY).strong());
                        }
                        ui.add_space(2.0);
                        egui::Frame::NONE
                            .fill(STATUS_CONNECTED.gamma_multiply(0.1))
                            .rounding(4.0)
                            .inner_margin(egui::Margin::symmetric(8, 3))
                            .show(ui, |ui| {
                                ui.label(egui::RichText::new("Signed in").size(11.0).color(STATUS_CONNECTED));
                            });
                    });

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.add(
                            egui::Button::new(egui::RichText::new("Sign Out").size(12.0).color(TEXT_SECONDARY))
                                .fill(BG_ELEVATED).rounding(6.0)
                                .stroke(egui::Stroke::new(1.0, BORDER_DEFAULT))
                        ).clicked() {
                            do_logout = true;
                        }
                    });
                });
            });

        if do_logout { self.logout(); }
    }
}
