//! Settings tab rendering - general settings, performance summary, account management

use super::*;
use super::theme::*;
use crate::auth::AuthState;
use crate::updater::UpdateState;

impl BoosterApp {
    pub(crate) fn render_settings_tab(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            for (label, section) in [("General", SettingsSection::General), ("Performance", SettingsSection::Performance), ("Account", SettingsSection::Account)] {
                let is_active = self.settings_section == section;
                let (bg, text) = if is_active { (BG_ELEVATED, TEXT_PRIMARY) } else { (egui::Color32::TRANSPARENT, TEXT_SECONDARY) };

                if ui.add(
                    egui::Button::new(egui::RichText::new(label).size(13.0).color(text))
                        .fill(bg).rounding(6.0).min_size(egui::vec2(80.0, 32.0))
                ).clicked() {
                    self.settings_section = section;
                }
                ui.add_space(8.0);
            }
        });

        ui.add_space(20.0);

        match self.settings_section {
            SettingsSection::General => self.render_general_settings(ui),
            SettingsSection::Performance => self.render_performance_settings(ui),
            SettingsSection::Account => self.render_account_settings(ui),
        }
    }

    pub(crate) fn render_general_settings(&mut self, ui: &mut egui::Ui) {
        // About section
        egui::Frame::NONE
            .fill(BG_CARD).stroke(egui::Stroke::new(1.0, BG_ELEVATED))
            .rounding(12.0).inner_margin(20)
            .show(ui, |ui| {
                ui.label(egui::RichText::new("About").size(14.0).color(TEXT_PRIMARY).strong());
                ui.add_space(12.0);
                ui.label(egui::RichText::new(format!("SwiftTunnel v{}", env!("CARGO_PKG_VERSION"))).size(13.0).color(TEXT_PRIMARY));
                ui.label(egui::RichText::new("Game Booster & PC Optimization Suite").size(12.0).color(TEXT_SECONDARY));
                ui.add_space(8.0);
                ui.label(egui::RichText::new("Optimized for Roblox and other games").size(11.0).color(TEXT_MUTED));
            });

        ui.add_space(16.0);

        // Updates section
        let mut check_now = false;
        let mut toggle_auto_check = false;
        let current_auto_check = self.update_settings.auto_check;

        egui::Frame::NONE
            .fill(BG_CARD).stroke(egui::Stroke::new(1.0, BG_ELEVATED))
            .rounding(12.0).inner_margin(20)
            .show(ui, |ui| {
                ui.label(egui::RichText::new("Updates").size(14.0).color(TEXT_PRIMARY).strong());
                ui.add_space(12.0);

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
                                egui::Button::new(egui::RichText::new("Check for Updates").size(11.0).color(TEXT_PRIMARY))
                                    .fill(ACCENT_PRIMARY).rounding(6.0)
                            ).clicked() {
                                check_now = true;
                            }
                        }
                    });
                });

                ui.add_space(12.0);

                // Show update status
                let update_state = self.update_state.lock().map(|s| s.clone()).unwrap_or(UpdateState::Idle);
                match &update_state {
                    UpdateState::UpToDate => {
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new("+").size(12.0).color(STATUS_CONNECTED));
                            ui.add_space(4.0);
                            ui.label(egui::RichText::new("You're on the latest version").size(12.0).color(STATUS_CONNECTED));
                        });
                    }
                    UpdateState::Available(info) => {
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new("~").size(12.0));
                            ui.add_space(4.0);
                            ui.label(egui::RichText::new(format!("Update v{} available", info.version)).size(12.0).color(ACCENT_PRIMARY));
                        });
                    }
                    UpdateState::Failed(msg) => {
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new("!").size(12.0).color(STATUS_ERROR));
                            ui.add_space(4.0);
                            ui.label(egui::RichText::new(msg).size(12.0).color(STATUS_ERROR));
                        });
                    }
                    _ => {}
                }

                ui.add_space(12.0);

                // Auto-check toggle
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.label(egui::RichText::new("Check for updates on startup").size(12.0).color(TEXT_PRIMARY));
                        ui.label(egui::RichText::new("Automatically check for new versions when the app starts").size(10.0).color(TEXT_MUTED));
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let size = egui::vec2(44.0, 24.0);
                        let (rect, response) = ui.allocate_exact_size(size, egui::Sense::click());
                        if response.clicked() {
                            toggle_auto_check = true;
                        }
                        let bg = if current_auto_check { ACCENT_PRIMARY } else { BG_ELEVATED };
                        let knob_x = if current_auto_check { rect.right() - 12.0 } else { rect.left() + 12.0 };
                        ui.painter().rect_filled(rect, 12.0, bg);
                        ui.painter().circle_filled(egui::pos2(knob_x, rect.center().y), 8.0, TEXT_PRIMARY);
                    });
                });
            });

        ui.add_space(16.0);

        // System Tray section
        let mut toggle_minimize_to_tray = false;
        let current_minimize_to_tray = self.minimize_to_tray;

        egui::Frame::NONE
            .fill(BG_CARD).stroke(egui::Stroke::new(1.0, BG_ELEVATED))
            .rounding(12.0).inner_margin(20)
            .show(ui, |ui| {
                ui.label(egui::RichText::new("System Tray").size(14.0).color(TEXT_PRIMARY).strong());
                ui.add_space(12.0);

                // Minimize to tray toggle
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.label(egui::RichText::new("Minimize to tray on close").size(12.0).color(TEXT_PRIMARY));
                        ui.label(egui::RichText::new("Keep SwiftTunnel running in the background when you close the window").size(10.0).color(TEXT_MUTED));
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let size = egui::vec2(44.0, 24.0);
                        let (rect, response) = ui.allocate_exact_size(size, egui::Sense::click());
                        if response.clicked() {
                            toggle_minimize_to_tray = true;
                        }
                        let bg = if current_minimize_to_tray { ACCENT_PRIMARY } else { BG_ELEVATED };
                        let knob_x = if current_minimize_to_tray { rect.right() - 12.0 } else { rect.left() + 12.0 };
                        ui.painter().rect_filled(rect, 12.0, bg);
                        ui.painter().circle_filled(egui::pos2(knob_x, rect.center().y), 8.0, TEXT_PRIMARY);
                    });
                });

                ui.add_space(8.0);
                ui.label(egui::RichText::new("Tip: Click the tray icon to show the window. Right-click for more options.").size(10.0).color(TEXT_MUTED).italics());
            });

        ui.add_space(16.0);

        // Experimental Features section
        let mut toggle_experimental_mode = false;
        let current_experimental_mode = self.experimental_mode;

        egui::Frame::NONE
            .fill(BG_CARD).stroke(egui::Stroke::new(1.0, BG_ELEVATED))
            .rounding(12.0).inner_margin(20)
            .show(ui, |ui| {
                ui.label(egui::RichText::new("* Experimental").size(14.0).color(TEXT_PRIMARY).strong());
                ui.add_space(12.0);

                // Experimental mode toggle
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.label(egui::RichText::new("Enable Experimental Features").size(13.0).color(TEXT_PRIMARY));
                        ui.label(egui::RichText::new("Unlock Practice Mode and other experimental features").size(11.0).color(TEXT_SECONDARY));
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let size = egui::vec2(44.0, 24.0);
                        let (rect, response) = ui.allocate_exact_size(size, egui::Sense::click());
                        if response.clicked() {
                            toggle_experimental_mode = true;
                        }
                        let bg = if current_experimental_mode { ACCENT_PRIMARY } else { BG_ELEVATED };
                        let knob_x = if current_experimental_mode { rect.right() - 12.0 } else { rect.left() + 12.0 };
                        ui.painter().rect_filled(rect, 12.0, bg);
                        ui.painter().circle_filled(egui::pos2(knob_x, rect.center().y), 8.0, TEXT_PRIMARY);
                    });
                });

                ui.add_space(8.0);
                ui.label(egui::RichText::new("! Experimental features may be unstable or change without notice.").size(10.0).color(STATUS_WARNING).italics());
            });

        ui.add_space(16.0);

        // Split Tunnel Routing Mode section
        let mut new_routing_mode = self.routing_mode;

        egui::Frame::NONE
            .fill(BG_CARD).stroke(egui::Stroke::new(1.0, BG_ELEVATED))
            .rounding(12.0).inner_margin(20)
            .show(ui, |ui| {
                ui.label(egui::RichText::new("Route Optimization").size(14.0).color(TEXT_PRIMARY).strong());
                ui.add_space(12.0);

                ui.label(egui::RichText::new("Choose how game traffic is optimized:").size(12.0).color(TEXT_SECONDARY));
                ui.add_space(12.0);

                // V1 Option
                let is_v1 = self.routing_mode == crate::settings::RoutingMode::V1;
                let v1_bg = if is_v1 { BG_ELEVATED } else { BG_CARD };
                let v1_border = if is_v1 { ACCENT_PRIMARY } else { BG_ELEVATED };

                let v1_response = egui::Frame::NONE
                    .fill(v1_bg)
                    .stroke(egui::Stroke::new(if is_v1 { 2.0 } else { 1.0 }, v1_border))
                    .rounding(8.0)
                    .inner_margin(12)
                    .show(ui, |ui| {
                        ui.set_min_width(ui.available_width() - 24.0);
                        ui.horizontal(|ui| {
                            // Radio button
                            let radio_color = if is_v1 { ACCENT_PRIMARY } else { TEXT_MUTED };
                            ui.painter().circle_stroke(
                                ui.cursor().min + egui::vec2(8.0, 10.0),
                                6.0,
                                egui::Stroke::new(2.0, radio_color),
                            );
                            if is_v1 {
                                ui.painter().circle_filled(
                                    ui.cursor().min + egui::vec2(8.0, 10.0),
                                    3.0,
                                    ACCENT_PRIMARY,
                                );
                            }
                            ui.add_space(20.0);

                            ui.vertical(|ui| {
                                ui.label(egui::RichText::new(crate::settings::RoutingMode::V1.display_name()).size(13.0).color(TEXT_PRIMARY).strong());
                                ui.label(egui::RichText::new(crate::settings::RoutingMode::V1.description()).size(11.0).color(TEXT_SECONDARY));
                            });
                        });
                    });

                if v1_response.response.interact(egui::Sense::click()).clicked() {
                    new_routing_mode = crate::settings::RoutingMode::V1;
                }

                ui.add_space(8.0);

                // V2 Option
                let is_v2 = self.routing_mode == crate::settings::RoutingMode::V2;
                let v2_bg = if is_v2 { BG_ELEVATED } else { BG_CARD };
                let v2_border = if is_v2 { ACCENT_PRIMARY } else { BG_ELEVATED };

                let v2_response = egui::Frame::NONE
                    .fill(v2_bg)
                    .stroke(egui::Stroke::new(if is_v2 { 2.0 } else { 1.0 }, v2_border))
                    .rounding(8.0)
                    .inner_margin(12)
                    .show(ui, |ui| {
                        ui.set_min_width(ui.available_width() - 24.0);
                        ui.horizontal(|ui| {
                            // Radio button
                            let radio_color = if is_v2 { ACCENT_PRIMARY } else { TEXT_MUTED };
                            ui.painter().circle_stroke(
                                ui.cursor().min + egui::vec2(8.0, 10.0),
                                6.0,
                                egui::Stroke::new(2.0, radio_color),
                            );
                            if is_v2 {
                                ui.painter().circle_filled(
                                    ui.cursor().min + egui::vec2(8.0, 10.0),
                                    3.0,
                                    ACCENT_PRIMARY,
                                );
                            }
                            ui.add_space(20.0);

                            ui.vertical(|ui| {
                                ui.horizontal(|ui| {
                                    ui.label(egui::RichText::new(crate::settings::RoutingMode::V2.display_name()).size(13.0).color(TEXT_PRIMARY).strong());
                                    ui.add_space(4.0);
                                    ui.label(egui::RichText::new("RECOMMENDED").size(9.0).color(STATUS_CONNECTED));
                                });
                                ui.label(egui::RichText::new(crate::settings::RoutingMode::V2.description()).size(11.0).color(TEXT_SECONDARY));
                            });
                        });
                    });

                if v2_response.response.interact(egui::Sense::click()).clicked() {
                    new_routing_mode = crate::settings::RoutingMode::V2;
                }

                ui.add_space(12.0);
                ui.label(egui::RichText::new("V2 is more efficient - only game server traffic uses bandwidth.").size(10.0).color(TEXT_MUTED).italics());
            });

        // Handle routing mode change
        if new_routing_mode != self.routing_mode {
            self.routing_mode = new_routing_mode;
            log::info!("Routing mode changed to: {:?}", new_routing_mode);
            self.mark_dirty();
        }

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
    }

    pub(crate) fn render_performance_settings(&mut self, ui: &mut egui::Ui) {
        // Performance settings are now in the Boost tab
        // This section shows a summary and link to Boost tab

        egui::Frame::NONE
            .fill(BG_CARD).stroke(egui::Stroke::new(1.0, BG_ELEVATED))
            .rounding(12.0).inner_margin(20)
            .show(ui, |ui| {
                ui.label(egui::RichText::new("Performance Boosts").size(14.0).color(TEXT_PRIMARY).strong());
                ui.add_space(8.0);
                ui.label(egui::RichText::new("All boost settings are now on the Boost tab for easier access.").size(12.0).color(TEXT_SECONDARY));
                ui.add_space(16.0);

                // Current status summary
                let fps_val = self.state.config.roblox_settings.target_fps;
                let fps = if fps_val >= 9999 { "Uncapped".to_string() } else { fps_val.to_string() };
                let system_boosts = [
                    self.state.config.system_optimization.set_high_priority,
                    self.state.config.system_optimization.timer_resolution_1ms,
                    self.state.config.system_optimization.mmcss_gaming_profile,
                    self.state.config.system_optimization.game_mode_enabled,
                ].iter().filter(|&&x| x).count();
                let network_boosts = [
                    self.state.config.network_settings.disable_nagle,
                    self.state.config.network_settings.disable_network_throttling,
                    self.state.config.network_settings.optimize_mtu,
                ].iter().filter(|&&x| x).count();

                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("FPS Target:").size(12.0).color(TEXT_SECONDARY));
                    ui.label(egui::RichText::new(&fps).size(12.0).color(ACCENT_PRIMARY));
                });
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("System Boosts:").size(12.0).color(TEXT_SECONDARY));
                    ui.label(egui::RichText::new(format!("{}/4 enabled", system_boosts)).size(12.0).color(ACCENT_PRIMARY));
                });
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Network Boosts:").size(12.0).color(TEXT_SECONDARY));
                    ui.label(egui::RichText::new(format!("{}/3 enabled", network_boosts)).size(12.0).color(ACCENT_PRIMARY));
                });

                ui.add_space(16.0);

                let mut go_to_boost = false;
                if ui.add(
                    egui::Button::new(egui::RichText::new("> Go to Boost Tab").size(13.0).color(TEXT_PRIMARY))
                        .fill(ACCENT_PRIMARY).rounding(8.0).min_size(egui::vec2(150.0, 36.0))
                ).clicked() {
                    go_to_boost = true;
                }

                if go_to_boost {
                    self.current_tab = Tab::Boost;
                }
            });
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

        egui::Frame::NONE
            .fill(BG_CARD).stroke(egui::Stroke::new(1.0, BG_ELEVATED))
            .rounding(12.0).inner_margin(20)
            .show(ui, |ui| {
                ui.label(egui::RichText::new("Sign In").size(16.0).color(TEXT_PRIMARY).strong());
                ui.add_space(16.0);

                ui.label(egui::RichText::new("Email").size(12.0).color(TEXT_SECONDARY));
                ui.add_space(4.0);
                ui.add(egui::TextEdit::singleline(&mut self.login_email).hint_text("you@example.com").desired_width(f32::INFINITY));

                ui.add_space(12.0);
                ui.label(egui::RichText::new("Password").size(12.0).color(TEXT_SECONDARY));
                ui.add_space(4.0);
                ui.add(egui::TextEdit::singleline(&mut self.login_password).hint_text("********").password(true).desired_width(f32::INFINITY));

                ui.add_space(20.0);
                let btn_color = if can_login { ACCENT_PRIMARY } else { BG_ELEVATED };
                if ui.add(
                    egui::Button::new(egui::RichText::new("Sign In").size(14.0).color(TEXT_PRIMARY))
                        .fill(btn_color).rounding(8.0).min_size(egui::vec2(f32::INFINITY, 44.0))
                ).clicked() && can_login {
                    do_login = true;
                }

                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("No account?").size(12.0).color(TEXT_SECONDARY));
                    if ui.add(egui::Label::new(egui::RichText::new("Sign up").size(12.0).color(ACCENT_PRIMARY).underline()).sense(egui::Sense::click())).clicked() {
                        open_signup = true;
                    }
                });
            });

        if do_login { self.start_login(); }
        if open_signup { let _ = open::that("https://swifttunnel.net/signup"); }

        if let Some(error) = &self.auth_error.clone() {
            ui.add_space(12.0);
            egui::Frame::NONE
                .fill(STATUS_ERROR.gamma_multiply(0.15)).rounding(8.0).inner_margin(12)
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

        egui::Frame::NONE
            .fill(BG_CARD).stroke(egui::Stroke::new(1.0, BG_ELEVATED))
            .rounding(12.0).inner_margin(20)
            .show(ui, |ui| {

                ui.horizontal(|ui| {
                    let (rect, _) = ui.allocate_exact_size(egui::vec2(48.0, 48.0), egui::Sense::hover());
                    ui.painter().circle_filled(rect.center(), 24.0, ACCENT_PRIMARY.gamma_multiply(0.3));
                    ui.painter().text(rect.center(), egui::Align2::CENTER_CENTER, &user_initial, egui::FontId::proportional(20.0), ACCENT_PRIMARY);

                    ui.add_space(12.0);
                    ui.vertical(|ui| {
                        if let Some(email) = &user_email {
                            ui.label(egui::RichText::new(email).size(14.0).color(TEXT_PRIMARY).strong());
                        }
                        ui.label(egui::RichText::new("Signed in").size(12.0).color(STATUS_CONNECTED));
                    });

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.add(
                            egui::Button::new(egui::RichText::new("Sign Out").size(12.0).color(TEXT_PRIMARY))
                                .fill(BG_ELEVATED).rounding(6.0)
                        ).clicked() {
                            do_logout = true;
                        }
                    });
                });
            });

        if do_logout { self.logout(); }

        ui.add_space(16.0);

        egui::Frame::NONE
            .fill(BG_CARD).stroke(egui::Stroke::new(1.0, BG_ELEVATED))
            .rounding(12.0).inner_margin(20)
            .show(ui, |ui| {
                ui.label(egui::RichText::new("Subscription").size(14.0).color(TEXT_PRIMARY).strong());
                ui.add_space(12.0);

                for (label, value) in [("Plan", "Free"), ("Status", "Active")] {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new(label).size(13.0).color(TEXT_SECONDARY));
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.label(egui::RichText::new(value).size(13.0).color(TEXT_PRIMARY));
                        });
                    });
                    ui.add_space(6.0);
                }
            });
    }
}
