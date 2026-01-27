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
        let card_max_width: f32 = 420.0;

        // Center the login content vertically and horizontally
        ui.vertical_centered(|ui| {
            // Vertical centering
            let card_estimated_height = 520.0;
            let top_space = ((available.y - card_estimated_height) / 2.0).max(20.0);
            ui.add_space(top_space);

            // Constrain content width
            ui.allocate_ui_with_layout(
                egui::vec2(card_max_width.min(available.x - 48.0), available.y),
                egui::Layout::top_down(egui::Align::LEFT),
                |ui| {
                    // ─────────────────────────────────────────────────────────────
                    // HEADER: Logo + SwiftTunnel text
                    // ─────────────────────────────────────────────────────────────
                    ui.horizontal(|ui| {
                        // SwiftTunnel logo from embedded PNG
                        let logo_size = 32.0;
                        if let Some(texture) = &self.logo_texture {
                            let image = egui::Image::new(texture)
                                .fit_to_exact_size(egui::vec2(logo_size, logo_size))
                                .rounding(egui::CornerRadius::same(6));
                            ui.add(image);
                        } else {
                            // Fallback: simple colored circle if texture failed to load
                            let (rect, _) = ui.allocate_exact_size(egui::vec2(logo_size, logo_size), egui::Sense::hover());
                            ui.painter().circle_filled(rect.center(), logo_size * 0.45, ACCENT_CYAN);
                        }

                        ui.add_space(8.0);
                        ui.label(egui::RichText::new("SwiftTunnel")
                            .size(22.0)
                            .color(TEXT_PRIMARY)
                            .strong());
                    });

                    ui.add_space(40.0);

                    // ─────────────────────────────────────────────────────────────
                    // WELCOME SECTION
                    // ─────────────────────────────────────────────────────────────
                    ui.horizontal(|ui| {
                        // Sparkle icon (*)
                        ui.label(egui::RichText::new("*")
                            .size(14.0)
                            .color(ACCENT_CYAN));
                        ui.add_space(4.0);
                        ui.label(egui::RichText::new("Welcome back")
                            .size(14.0)
                            .color(ACCENT_CYAN));
                    });

                    ui.add_space(8.0);
                    ui.label(egui::RichText::new("Sign in to your account")
                        .size(28.0)
                        .color(TEXT_PRIMARY)
                        .strong());

                    ui.add_space(8.0);
                    ui.label(egui::RichText::new("Enter your credentials to access your dashboard")
                        .size(14.0)
                        .color(TEXT_SECONDARY));

                    ui.add_space(32.0);

                    // ─────────────────────────────────────────────────────────────
                    // EMAIL FIELD
                    // ─────────────────────────────────────────────────────────────
                    ui.label(egui::RichText::new("Email address")
                        .size(14.0)
                        .color(TEXT_PRIMARY));
                    ui.add_space(8.0);

                    // Custom input field with icon
                    egui::Frame::NONE
                        .fill(BG_INPUT)
                        .stroke(egui::Stroke::new(1.0, BG_ELEVATED))
                        .rounding(10.0)
                        .inner_margin(egui::Margin::symmetric(16, 14))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                // Mail icon
                                ui.label(egui::RichText::new("@")
                                    .size(16.0)
                                    .color(TEXT_MUTED));
                                ui.add_space(12.0);

                                // Email input
                                let email_edit = egui::TextEdit::singleline(&mut self.login_email)
                                    .hint_text(egui::RichText::new("your.email@example.com").color(TEXT_MUTED))
                                    .desired_width(f32::INFINITY)
                                    .frame(false)
                                    .text_color(TEXT_PRIMARY);
                                ui.add(email_edit);
                            });
                        });

                    ui.add_space(20.0);

                    // ─────────────────────────────────────────────────────────────
                    // PASSWORD FIELD
                    // ─────────────────────────────────────────────────────────────
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("Password")
                            .size(14.0)
                            .color(TEXT_PRIMARY));

                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.add(
                                egui::Label::new(
                                    egui::RichText::new("Forgot password?")
                                        .size(14.0)
                                        .color(ACCENT_PRIMARY)
                                ).sense(egui::Sense::click())
                            ).clicked() {
                                open_forgot_password = true;
                            }
                        });
                    });
                    ui.add_space(8.0);

                    // Custom password field with icon
                    egui::Frame::NONE
                        .fill(BG_INPUT)
                        .stroke(egui::Stroke::new(1.0, BG_ELEVATED))
                        .rounding(10.0)
                        .inner_margin(egui::Margin::symmetric(16, 14))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                // Lock icon
                                ui.label(egui::RichText::new("*")
                                    .size(16.0)
                                    .color(TEXT_MUTED));
                                ui.add_space(12.0);

                                // Password input
                                let password_edit = egui::TextEdit::singleline(&mut self.login_password)
                                    .hint_text(egui::RichText::new("Enter your password").color(TEXT_MUTED))
                                    .password(true)
                                    .desired_width(f32::INFINITY)
                                    .frame(false)
                                    .text_color(TEXT_PRIMARY);
                                ui.add(password_edit);
                            });
                        });

                    ui.add_space(28.0);

                    // ─────────────────────────────────────────────────────────────
                    // SIGN IN BUTTON
                    // ─────────────────────────────────────────────────────────────
                    let btn_color = if can_login { ACCENT_PRIMARY } else { ACCENT_PRIMARY.gamma_multiply(0.5) };

                    let response = ui.add_sized(
                        egui::vec2(ui.available_width(), 52.0),
                        egui::Button::new(
                            egui::RichText::new("Sign in   ->")
                                .size(16.0)
                                .color(egui::Color32::WHITE)
                                .strong()
                        )
                        .fill(btn_color)
                        .rounding(10.0)
                    );

                    if response.clicked() && can_login {
                        do_login = true;
                    }

                    ui.add_space(20.0);

                    // ─────────────────────────────────────────────────────────────
                    // DIVIDER
                    // ─────────────────────────────────────────────────────────────
                    ui.horizontal(|ui| {
                        let available_width = ui.available_width();
                        let line_width = (available_width - 120.0) / 2.0;

                        ui.add_sized(
                            egui::vec2(line_width, 1.0),
                            egui::Separator::default().horizontal()
                        );
                        ui.add_space(8.0);
                        ui.label(egui::RichText::new("or continue with")
                            .size(12.0)
                            .color(TEXT_MUTED));
                        ui.add_space(8.0);
                        ui.add_sized(
                            egui::vec2(line_width, 1.0),
                            egui::Separator::default().horizontal()
                        );
                    });

                    ui.add_space(20.0);

                    // ─────────────────────────────────────────────────────────────
                    // GOOGLE SIGN IN BUTTON
                    // ─────────────────────────────────────────────────────────────
                    let google_response = ui.add_sized(
                        egui::vec2(ui.available_width(), 48.0),
                        egui::Button::new(
                            egui::RichText::new("Sign in with Google")
                                .size(15.0)
                                .color(TEXT_PRIMARY)
                        )
                        .fill(BG_ELEVATED)
                        .stroke(egui::Stroke::new(1.0, BG_HOVER))
                        .rounding(10.0)
                    );

                    if google_response.clicked() {
                        self.start_google_login();
                    }

                    ui.add_space(24.0);

                    // ─────────────────────────────────────────────────────────────
                    // SIGN UP LINK
                    // ─────────────────────────────────────────────────────────────
                    ui.vertical_centered(|ui| {
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new("Don't have an account?")
                                .size(14.0)
                                .color(TEXT_SECONDARY));
                            ui.add_space(4.0);
                            if ui.add(
                                egui::Label::new(
                                    egui::RichText::new("Sign up")
                                        .size(14.0)
                                        .color(ACCENT_PRIMARY)
                                ).sense(egui::Sense::click())
                            ).clicked() {
                                open_signup = true;
                            }
                        });
                    });

                    // ─────────────────────────────────────────────────────────────
                    // ERROR MESSAGE
                    // ─────────────────────────────────────────────────────────────
                    if let Some(error) = &self.auth_error.clone() {
                        ui.add_space(20.0);
                        egui::Frame::NONE
                            .fill(STATUS_ERROR.gamma_multiply(0.15))
                            .stroke(egui::Stroke::new(1.0, STATUS_ERROR.gamma_multiply(0.3)))
                            .rounding(10.0)
                            .inner_margin(16)
                            .show(ui, |ui| {
                                    ui.horizontal(|ui| {
                                    ui.label(egui::RichText::new("!")
                                        .size(14.0)
                                        .color(STATUS_ERROR));
                                    ui.add_space(8.0);
                                    ui.label(egui::RichText::new(error)
                                        .size(13.0)
                                        .color(STATUS_ERROR));
                                });
                            });
                    }
                }
            );
        });

        if do_login { self.start_login(); }
        if open_signup { let _ = open::that("https://swifttunnel.net/signup"); }
        if open_forgot_password { let _ = open::that("https://swifttunnel.net/forgot-password"); }
    }

    /// Render the login pending spinner
    pub(crate) fn render_login_pending(&self, ui: &mut egui::Ui) {
        let available = ui.available_size();
        let is_large_screen = available.x > 800.0 && available.y > 600.0;
        let card_max_width: f32 = if is_large_screen { 400.0 } else { 320.0 };

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
                        .stroke(egui::Stroke::new(1.0, BG_ELEVATED))
                        .rounding(16.0)
                        .inner_margin(40)
                        .show(ui, |ui| {
                            ui.vertical_centered(|ui| {
                                ui.add_space(20.0);
                                ui.spinner();
                                ui.add_space(20.0);
                                ui.label(egui::RichText::new("Signing in...")
                                    .size(18.0)
                                    .color(TEXT_PRIMARY)
                                    .strong());
                                ui.add_space(8.0);
                                ui.label(egui::RichText::new("Please wait...")
                                    .size(14.0)
                                    .color(TEXT_SECONDARY));
                                ui.add_space(20.0);
                            });
                        });
                }
            );
        });
    }

    /// Render the OAuth callback waiting screen
    pub(crate) fn render_awaiting_oauth_callback(&mut self, ui: &mut egui::Ui) {
        let available = ui.available_size();
        let card_max_width: f32 = 420.0;
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
                        .stroke(egui::Stroke::new(1.0, BG_ELEVATED))
                        .rounding(16.0)
                        .inner_margin(40)
                        .show(ui, |ui| {
                            ui.vertical_centered(|ui| {
                                // Browser icon
                                ui.label(egui::RichText::new("o")
                                    .size(48.0));

                                ui.add_space(20.0);

                                ui.label(egui::RichText::new("Complete sign in")
                                    .size(22.0)
                                    .color(TEXT_PRIMARY)
                                    .strong());

                                ui.add_space(12.0);

                                ui.label(egui::RichText::new("A browser window has opened.")
                                    .size(14.0)
                                    .color(TEXT_SECONDARY));
                                ui.add_space(4.0);
                                ui.label(egui::RichText::new("Please sign in with Google to continue.")
                                    .size(14.0)
                                    .color(TEXT_SECONDARY));

                                ui.add_space(24.0);

                                // Spinner
                                ui.spinner();

                                ui.add_space(8.0);

                                ui.label(egui::RichText::new("Waiting for authentication...")
                                    .size(13.0)
                                    .color(TEXT_MUTED));

                                ui.add_space(32.0);

                                // Cancel button
                                if ui.add(
                                    egui::Button::new(
                                        egui::RichText::new("Cancel")
                                            .size(14.0)
                                            .color(TEXT_SECONDARY)
                                    )
                                    .fill(egui::Color32::TRANSPARENT)
                                    .stroke(egui::Stroke::new(1.0, BG_HOVER))
                                    .rounding(8.0)
                                    .min_size(egui::vec2(100.0, 36.0))
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
