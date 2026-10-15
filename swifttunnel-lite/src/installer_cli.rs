//! Tell installers and external callers whether a helper actually succeeded.

pub fn finish(action: &str, result: Result<(), String>) -> ! {
    let code = match result {
        Ok(()) => {
            log::info!("{action} finished");
            0
        }
        Err(error) => {
            log::error!("{action} failed: {error}");
            1
        }
    };
    std::process::exit(code);
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = "SWIFT_LITE_TEST_HELPER_EXIT";

    #[test]
    fn helper_child_fixture() {
        let Ok(mode) = std::env::var(FIXTURE) else {
            return;
        };
        let (action, outcome) = mode.split_once(':').unwrap();
        // Never call the real cleanup or driver functions in this fixture.
        finish(
            action,
            if outcome == "ok" {
                Ok(())
            } else {
                Err("fixture failure".into())
            },
        );
    }

    #[test]
    fn helper_failures_reach_the_parent_as_nonzero_process_status() {
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};
        for action in ["cleanup", "driver-install"] {
            for (outcome, expected) in [("ok", 0), ("error", 1)] {
                let mut child = Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", "installer_cli::tests::helper_child_fixture"])
                    .env(FIXTURE, format!("{action}:{outcome}"))
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap();
                let deadline = Instant::now() + Duration::from_secs(5);
                let status = loop {
                    if let Some(status) = child.try_wait().unwrap() {
                        break status;
                    }
                    if Instant::now() >= deadline {
                        let _ = child.kill();
                        panic!("owned helper fixture failed to exit");
                    }
                    std::thread::sleep(Duration::from_millis(5));
                };
                assert_eq!(status.code(), Some(expected), "{action}: {outcome}");
            }
        }
    }
}
