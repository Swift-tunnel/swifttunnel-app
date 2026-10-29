//! Report a failed native launch before a main window exists.

#[derive(Clone, Copy, Debug)]
pub enum Stage {
    Engine,
    Window,
}

impl Stage {
    fn message(self) -> &'static str {
        match self {
            Self::Engine => {
                "SwiftTunnel Lite could not start. Try opening it again. If it still fails, restart your PC and contact support@swifttunnel.net with your latest SwiftTunnel log."
            }
            Self::Window => {
                "SwiftTunnel Lite could not open its window. Try opening it again. If it still fails, restart your PC and contact support@swifttunnel.net with your latest SwiftTunnel log."
            }
        }
    }
}

pub fn abort(stage: Stage, error: impl std::fmt::Display) -> ! {
    log::error!("Lite startup failed during {stage:?}: {error}");
    show(stage.message());
    std::process::exit(1);
}

#[cfg(not(test))]
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
            w!("SwiftTunnel Lite could not open"),
            MB_OK | MB_ICONERROR,
        );
    }
}

#[cfg(test)]
fn show(message: &str) {
    eprintln!("{message}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn startup_failure_child() {
        let stage = match std::env::var("SWIFT_LITE_STARTUP_FAILURE_FIXTURE").as_deref() {
            Ok("engine") => Stage::Engine,
            Ok("window") => Stage::Window,
            _ => return,
        };
        abort(stage, "private fixture detail");
    }

    #[test]
    fn startup_failures_are_nonzero_and_explain_the_next_step() {
        for stage in ["engine", "window"] {
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            #[cfg(windows)]
            {
                use std::os::windows::process::CommandExt;
                command.creation_flags(0x0800_0000);
            }
            let mut child = command
                .args([
                    "--exact",
                    "startup_failure::tests::startup_failure_child",
                    "--nocapture",
                ])
                .env("SWIFT_LITE_STARTUP_FAILURE_FIXTURE", stage)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(5);
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
            assert!(completed, "owned startup fixture did not exit");
            assert_eq!(output.status.code(), Some(1));
            let message = String::from_utf8_lossy(&output.stderr);
            assert!(message.contains("SwiftTunnel Lite"));
            assert!(message.contains("support@swifttunnel.net"));
            assert!(message.contains("try") || message.contains("Try"));
            assert!(!message.contains("private fixture detail"));
            assert!(!message.contains("panicked"));
        }
    }
}
