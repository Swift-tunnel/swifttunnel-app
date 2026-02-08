//! Login screen rendering

use super::*;
use super::theme::*;

impl BoosterApp {
    /// Render the full login screen with email/password and Google OAuth options
    pub(crate) fn render_full_login_screen(&mut self, ui: &mut egui::Ui) {
        let can_login = !self.login_email.is_empty() && !self.login_password.is_empty();
        let mut do_login = false;
        let mut open_signup = false;
        let mut open_forgot_password = false;

        let available = ui.available_size();
        let card_max_width: f32 = 400.0;

        // Center the login content vertically and horizontally
        ui.vertical_centered(|ui| {
            // Vertical centering
            let card_estimated_height = 540.0;
            let top_space = ((available.y - card_estimated_height) / 2.0).max(20.0);
            ui.add_space(top_space);

            // Constrain content width
            ui.allocate_ui_with_layout(
                egui::vec2(card_max_width.min(available.x - 48.0), available.y),
                egui::Layout::top_down(egui::Align::LEFT),
                |ui| {
                    // Outer card with subtle border
                    egui::Frame::NONE
                        .fill(BG_CARD)
                        .stroke(egui::Stroke::new(1.0, BORDER_SUBTLE))
                        .rounding(12.0)
                        .inner_margin(egui::Margin::same(32))
                        .show(ui, |ui| {
                            // ── HEADER: Logo + SwiftTunnel text ──
                            ui.horizontal(|ui| {
                                let logo_size = 28.0;
                                if let Some(texture) = &self.logo_texture {
                                    let image = egui::Image::new(texture)
                                        .fit_to_exact_size(egui::vec2(logo_size, logo_size))
                                        .rounding(egui::CornerRadius::same(6));
                                    ui.add(image);
                                } else {
                                    let (rect, _) = ui.allocate_exact_size(egui::vec2(logo_size, logo_size), egui::Sense::hover());
                                    ui.painter().circle_filled(rect.center(), logo_size * 0.45, ACCENT_CYAN);
                                }

                                ui.add_space(8.0);
                                ui.label(egui::RichText::new("SwiftTunnel")
                                    .size(20.0)
                                    .color(TEXT_PRIMARY)
                                    .strong());
                            });

                            ui.add_space(SPACING_XL);

                            // ── WELCOME SECTION ──
                            ui.label(egui::RichText::new("Welcome back")
                                .size(13.0)
                                .color(ACCENT_PRIMARY));

                            ui.add_space(6.0);
                            ui.label(egui::RichText::new("Sign in to your account")
                                .size(24.0)
                                .color(TEXT_PRIMARY)
                                .strong());

                            ui.add_space(6.0);
                            ui.label(egui::RichText::new("Enter your credentials to access your dashboard")
                                .size(13.0)
                                .color(TEXT_SECONDARY));

                            ui.add_space(SPACING_LG);

                            // ── EMAIL FIELD ──
                            ui.label(egui::RichText::new("Email address")
                                .size(12.0)
                                .color(TEXT_SECONDARY));
                            ui.add_space(6.0);

                            egui::Frame::NONE
                                .fill(BG_INPUT)
                                .stroke(egui::Stroke::new(1.0, BORDER_DEFAULT))
                                .rounding(8.0)
                                .inner_margin(egui::Margin::symmetric(14, 12))
                                .show(ui, |ui| {
                                    ui.horizontal(|ui| {
                                        ui.label(egui::RichText::new("@")
                                            .size(14.0)
                                            .color(TEXT_MUTED));
                                        ui.add_space(10.0);

                                        let email_edit = egui::TextEdit::singleline(&mut self.login_email)
                                            .hint_text(egui::RichText::new("your.email@example.com").color(TEXT_MUTED))
                                            .desired_width(f32::INFINITY)
                                            .frame(false)
                                            .text_color(TEXT_PRIMARY);
                                        ui.add(email_edit);
                                    });
                                });

                            ui.add_space(SPACING_MD);

                            // ── PASSWORD FIELD ──
                            ui.horizontal(|ui| {
                                ui.label(egui::RichText::new("Password")
                                    .size(12.0)
                                    .color(TEXT_SECONDARY));

                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                    if ui.add(
                                        egui::Label::new(
                                            egui::RichText::new("Forgot password?")
                                                .size(12.0)
                                                .color(ACCENT_PRIMARY)
                                        ).sense(egui::Sense::click())
                                    ).clicked() {
                                        open_forgot_password = true;
                                    }
                                });
                            });
                            ui.add_space(6.0);

                            egui::Frame::NONE
                                .fill(BG_INPUT)
                                .stroke(egui::Stroke::new(1.0, BORDER_DEFAULT))
                                .rounding(8.0)
                                .inner_margin(egui::Margin::symmetric(14, 12))
                                .show(ui, |ui| {
                                    ui.horizontal(|ui| {
                                        ui.label(egui::RichText::new("\u{2022}")
                                            .size(14.0)
                                            .color(TEXT_MUTED));
                                        ui.add_space(10.0);

                                        let password_edit = egui::TextEdit::singleline(&mut self.login_password)
                                            .hint_text(egui::RichText::new("Enter your password").color(TEXT_MUTED))
                                            .password(true)
                                            .desired_width(f32::INFINITY)
                                            .frame(false)
                                            .text_color(TEXT_PRIMARY);
                                        ui.add(password_edit);
                                    });
                                });

                            ui.add_space(SPACING_LG);

                            // ── SIGN IN BUTTON ──
                            let btn_color = if can_login { ACCENT_PRIMARY } else { ACCENT_PRIMARY.gamma_multiply(0.4) };

                            let response = ui.add_sized(
                                egui::vec2(ui.available_width(), 44.0),
                                egui::Button::new(
                                    egui::RichText::new("Sign in")
                                        .size(14.0)
                                        .color(if can_login { egui::Color32::WHITE } else { egui::Color32::from_white_alpha(120) })
                                        .strong()
                                )
                                .fill(btn_color)
                                .rounding(8.0)
                            );

                            if response.clicked() && can_login {
                                do_login = true;
                            }

                            ui.add_space(SPACING_MD);

                            // ── DIVIDER ──
                            ui.horizontal(|ui| {
                                let available_width = ui.available_width();
                                let line_width = (available_width - 120.0) / 2.0;

                                ui.add_sized(
                                    egui::vec2(line_width, 1.0),
                                    egui::Separator::default().horizontal()
                                );
                                ui.add_space(8.0);
                                ui.label(egui::RichText::new("or continue with")
                                    .size(11.0)
                                    .color(TEXT_MUTED));
                                ui.add_space(8.0);
                                ui.add_sized(
                                    egui::vec2(line_width, 1.0),
                                    egui::Separator::default().horizontal()
                                );
                            });

                            ui.add_space(SPACING_MD);

                            // ── GOOGLE SIGN IN BUTTON ──
                            let google_response = ui.add_sized(
                                egui::vec2(ui.available_width(), 42.0),
                                egui::Button::new(
                                    egui::RichText::new("Sign in with Google")
                                        .size(13.0)
                                        .color(TEXT_PRIMARY)
                                )
                                .fill(BG_ELEVATED)
                                .stroke(egui::Stroke::new(1.0, BORDER_DEFAULT))
                                .rounding(8.0)
                            );

                            if google_response.clicked() {
                                self.start_google_login();
                            }

                            ui.add_space(SPACING_LG);

                            // ── SIGN UP LINK ──
                            ui.vertical_centered(|ui| {
                                ui.horizontal(|ui| {
                                    ui.label(egui::RichText::new("Don't have an account?")
                                        .size(12.0)
                                        .color(TEXT_SECONDARY));
                                    ui.add_space(4.0);
                                    if ui.add(
                                        egui::Label::new(
                                            egui::RichText::new("Sign up")
                                                .size(12.0)
                                                .color(ACCENT_PRIMARY)
                                        ).sense(egui::Sense::click())
                                    ).clicked() {
                                        open_signup = true;
                                    }
                                });
                            });

                            // ── ERROR MESSAGE ──
                            if let Some(error) = &self.auth_error.clone() {
                                ui.add_space(SPACING_MD);
                                egui::Frame::NONE
                                    .fill(STATUS_ERROR.gamma_multiply(0.1))
                                    .stroke(egui::Stroke::new(1.0, STATUS_ERROR.gamma_multiply(0.2)))
                                    .rounding(8.0)
                                    .inner_margin(12)
                                    .show(ui, |ui| {
                                        ui.horizontal(|ui| {
                                            ui.label(egui::RichText::new("!")
                                                .size(13.0)
                                                .color(STATUS_ERROR)
                                                .strong());
                                            ui.add_space(8.0);
                                            ui.label(egui::RichText::new(error)
                                                .size(12.0)
                                                .color(STATUS_ERROR));
                                        });
                                    });
                            }
                        });
                }
            );
        });

        if do_login { self.start_login(); }
        if open_signup { crate::utils::open_url("https://swifttunnel.net/signup"); }
        if open_forgot_password { crate::utils::open_url("https://swifttunnel.net/forgot-password"); }
    }

    /// Render the login pending spinner
    pub(crate) fn render_login_pending(&self, ui: &mut egui::Ui) {
        let available = ui.available_size();
        let is_large_screen = available.x > 800.0 && available.y > 600.0;
        let card_max_width: f32 = if is_large_screen { 380.0 } else { 300.0 };

        ui.vertical_centered(|ui| {
            // Center vertically
            let top_space = ((available.y - 200.0) / 2.0 - 60.0).max(40.0);
            ui.add_space(top_space);

            ui.allocate_ui_with_layout(
                egui::vec2(card_max_width.min(available.x - 40.0), available.y),
                egui::Layout::top_down(egui::Align::Center),
                |ui| {
                    egui::Frame::NONE
                        .fill(BG_CARD)
                        .stroke(egui::Stroke::new(1.0, BORDER_SUBTLE))
                        .rounding(12.0)
                        .inner_margin(36)
                        .show(ui, |ui| {
                            ui.vertical_centered(|ui| {
                                ui.add_space(SPACING_MD);
                                ui.spinner();
                                ui.add_space(SPACING_MD);
                                ui.label(egui::RichText::new("Signing in...")
                                    .size(16.0)
                                    .color(TEXT_PRIMARY)
                                    .strong());
                                ui.add_space(6.0);
                                ui.label(egui::RichText::new("Please wait")
                                    .size(13.0)
                                    .color(TEXT_SECONDARY));
                                ui.add_space(SPACING_MD);
                            });
                        });
                }
            );
        });
    }

    /// Render the OAuth callback waiting screen
    pub(crate) fn render_awaiting_oauth_callback(&mut self, ui: &mut egui::Ui) {
        let available = ui.available_size();
        let card_max_width: f32 = 400.0;
        let mut do_cancel = false;

        ui.vertical_centered(|ui| {
            // Center vertically
            let top_space = ((available.y - 300.0) / 2.0).max(40.0);
            ui.add_space(top_space);

            ui.allocate_ui_with_layout(
                egui::vec2(card_max_width.min(available.x - 40.0), available.y),
                egui::Layout::top_down(egui::Align::Center),
                |ui| {
                    egui::Frame::NONE
                        .fill(BG_CARD)
                        .stroke(egui::Stroke::new(1.0, BORDER_SUBTLE))
                        .rounding(12.0)
                        .inner_margin(36)
                        .show(ui, |ui| {
                            ui.vertical_centered(|ui| {
                                // Browser indicator
                                let (icon_rect, _) = ui.allocate_exact_size(egui::vec2(40.0, 40.0), egui::Sense::hover());
                                ui.painter().circle_filled(icon_rect.center(), 20.0, ACCENT_PRIMARY.gamma_multiply(0.1));
                                ui.painter().circle_stroke(icon_rect.center(), 14.0, egui::Stroke::new(2.0, ACCENT_PRIMARY.gamma_multiply(0.4)));

                                ui.add_space(SPACING_LG);

                                ui.label(egui::RichText::new("Complete sign in")
                                    .size(20.0)
                                    .color(TEXT_PRIMARY)
                                    .strong());

                                ui.add_space(SPACING_SM);

                                ui.label(egui::RichText::new("A browser window has opened.")
                                    .size(13.0)
                                    .color(TEXT_SECONDARY));
                                ui.add_space(4.0);
                                ui.label(egui::RichText::new("Please sign in with Google to continue.")
                                    .size(13.0)
                                    .color(TEXT_SECONDARY));

                                ui.add_space(SPACING_LG);

                                // Spinner
                                ui.spinner();

                                ui.add_space(6.0);

                                ui.label(egui::RichText::new("Waiting for authentication...")
                                    .size(12.0)
                                    .color(TEXT_MUTED));

                                ui.add_space(SPACING_LG);

                                // Cancel button
                                if ui.add(
                                    egui::Button::new(
                                        egui::RichText::new("Cancel")
                                            .size(13.0)
                                            .color(TEXT_SECONDARY)
                                    )
                                    .fill(egui::Color32::TRANSPARENT)
                                    .stroke(egui::Stroke::new(1.0, BORDER_DEFAULT))
                                    .rounding(8.0)
                                    .min_size(egui::vec2(100.0, 34.0))
                                ).clicked() {
                                    do_cancel = true;
                                }
                            });
                        });
                }
            );
        });

        if do_cancel {
            self.cancel_google_login();
        }
    }
}
