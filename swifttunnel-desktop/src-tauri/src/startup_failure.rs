//! A failed launch needs a readable next step, not a setup-hook panic.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Stage {
    Engine,
    Account,
    Settings,
    Window,
}

impl Stage {
    fn message(self) -> &'static str {
        match self {
            Self::Engine => {
                "SwiftTunnel could not start its background engine. Restart your PC, then open SwiftTunnel again. If it still fails, contact support@swifttunnel.net with your latest SwiftTunnel log."
            }
            Self::Account => {
                "SwiftTunnel could not open your saved sign-in data. Close this message and try opening SwiftTunnel again. If it still fails, restart your PC and contact support@swifttunnel.net with your latest SwiftTunnel log."
            }
            Self::Settings => {
                "SwiftTunnel could not restore your saved game settings. Close this message and try opening SwiftTunnel again. If it still fails, contact support@swifttunnel.net with your latest SwiftTunnel log."
            }
            Self::Window => {
                "SwiftTunnel could not open its window. Restart your PC and try again. If it still fails, contact support@swifttunnel.net with your latest SwiftTunnel log."
            }
        }
    }
}

pub(crate) fn abort(stage: Stage, error: impl std::fmt::Display) -> ! {
    log::error!("SwiftTunnel startup failed during {stage:?}: {error}");
    show(stage.message());
    std::process::exit(1);
}

#[cfg(all(windows, not(test)))]
fn show(message: &str) {
    use windows::{
        Win32::UI::WindowsAndMessaging::{MB_ICONERROR, MB_OK, MessageBoxW},
        core::{PCWSTR, w},
    };
    let message: Vec<u16> = message.encode_utf16().chain(Some(0)).collect();
    unsafe {
        let _ = MessageBoxW(
            None,
            PCWSTR(message.as_ptr()),
            w!("SwiftTunnel could not open"),
            MB_OK | MB_ICONERROR,
        );
    }
}

#[cfg(any(not(windows), test))]
fn show(message: &str) {
    eprintln!("{message}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn startup_failure_child() {
        let stage = match std::env::var("SWIFTTUNNEL_TEST_STARTUP_FAILURE").as_deref() {
            Ok("engine") => Stage::Engine,
            Ok("account") => Stage::Account,
            Ok("settings") => Stage::Settings,
            Ok("window") => Stage::Window,
            _ => return,
        };
        abort(stage, "fixture-only private technical detail");
    }

    #[test]
    fn fatal_startup_exits_with_guidance_without_a_panic_or_technical_dialog_dump() {
        for stage in ["engine", "account", "settings", "window"] {
            let executable = std::env::current_exe().unwrap();
            let mut child = swifttunnel_core::hidden_command(executable.to_str().unwrap())
                .args([
                    "--exact",
                    "startup_failure::tests::startup_failure_child",
                    "--nocapture",
                ])
                .env("SWIFTTUNNEL_TEST_STARTUP_FAILURE", stage)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(4);
            let completed = loop {
                if child.try_wait().unwrap().is_some() {
                    break true;
                }
                if Instant::now() >= deadline {
                    break false;
                }
                std::thread::sleep(Duration::from_millis(10));
            };
            if !completed {
                let _ = child.kill();
            }
            let output = child.wait_with_output().unwrap();
            assert!(completed, "owned startup fixture failed to exit");
            assert_eq!(output.status.code(), Some(1));
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(stderr.contains("support@swifttunnel.net"));
            assert!(stderr.contains("try") || stderr.contains("Restart"));
            assert!(!stderr.contains("panicked"));
            assert!(!stderr.contains("private technical detail"));
        }
    }
}
