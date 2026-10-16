//! Close the running player before writing settings it saves again on exit.

pub fn run_edit<T>(work: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(work))
        .unwrap_or_else(|_| Err("The Roblox settings change stopped. Try again.".into()))
}

pub fn reset_saved_intent(
    report: &swifttunnel_core::roblox_optimizer::RobloxResetReport,
    intent: &mut swifttunnel_core::structs::RobloxSettingsConfig,
) -> bool {
    if !report.failures.is_empty() {
        return false;
    }
    *intent = swifttunnel_core::structs::RobloxSettingsConfig::default();
    true
}

pub fn apply_in_order<T>(
    prepare: impl FnOnce() -> Result<Option<T>, String>,
    apply: impl FnOnce() -> Result<Vec<String>, String>,
    reopen: impl FnOnce(T) -> Result<(), String>,
) -> Result<Vec<String>, String> {
    let restart_target = prepare()?;
    let mut warnings = apply()?;
    if let Some(target) = restart_target
        && let Err(error) = reopen(target)
    {
        warnings.push(format!(
            "Settings were saved, but Roblox could not reopen: {error}"
        ));
    }
    Ok(warnings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[test]
    fn an_incomplete_reset_does_not_discard_saved_preferences() {
        let mut intent = swifttunnel_core::structs::RobloxSettingsConfig {
            ultraboost: true,
            custom_fflags_enabled: true,
            custom_fflags_json: "saved payload".into(),
            ..Default::default()
        };
        let mut report = swifttunnel_core::roblox_optimizer::RobloxResetReport::default();
        report.failures.push("could not close Roblox".into());
        assert!(!reset_saved_intent(&report, &mut intent));
        assert!(intent.ultraboost);
        assert!(intent.custom_fflags_enabled);
        assert_eq!(intent.custom_fflags_json, "saved payload");
        report.failures.clear();
        assert!(reset_saved_intent(&report, &mut intent));
        assert!(!intent.ultraboost);
        assert!(!intent.custom_fflags_enabled);
    }

    #[test]
    fn an_edit_panic_returns_a_retryable_error() {
        assert_eq!(
            run_edit::<()>(|| panic!("owned failure")).unwrap_err(),
            "The Roblox settings change stopped. Try again."
        );
    }

    #[test]
    fn the_players_exit_save_happens_before_the_new_settings_are_written() {
        let file = RefCell::new("old settings".to_string());
        let events = RefCell::new(Vec::new());
        apply_in_order(
            || {
                events.borrow_mut().push("close");
                // Model Roblox saving its old in-memory settings on exit.
                *file.borrow_mut() = "old exit save".into();
                Ok(Some(()))
            },
            || {
                events.borrow_mut().push("write");
                *file.borrow_mut() = "new settings".into();
                Ok(Vec::new())
            },
            |()| {
                events.borrow_mut().push("open");
                assert_eq!(*file.borrow(), "new settings");
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(*events.borrow(), ["close", "write", "open"]);
    }

    #[test]
    fn a_player_that_cannot_close_prevents_writing_or_reopening() {
        let result = apply_in_order::<()>(
            || Err("Roblox is still running".into()),
            || panic!("must not write settings under a live player"),
            |_| panic!("must not reopen"),
        );
        assert_eq!(result.unwrap_err(), "Roblox is still running");
    }

    #[test]
    fn a_failed_write_does_not_reopen_the_player() {
        let result = apply_in_order(
            || Ok(Some(())),
            || Err("settings are locked".into()),
            |_| panic!("must not reopen after failed settings write"),
        );
        assert_eq!(result.unwrap_err(), "settings are locked");
    }

    #[test]
    fn partial_warnings_survive_a_reopen_failure() {
        let warnings = apply_in_order(
            || Ok(Some(())),
            || Ok(vec!["Some FastFlags could not be applied.".into()]),
            |_| Err("player unavailable".into()),
        )
        .unwrap();
        assert_eq!(warnings.len(), 2);
        assert_eq!(warnings[0], "Some FastFlags could not be applied.");
        assert!(warnings[1].contains("Settings were saved"));
    }

    #[test]
    fn applying_to_a_closed_player_does_not_launch_it() {
        assert!(
            apply_in_order::<()>(
                || Ok(None),
                || Ok(Vec::new()),
                |_| panic!("the player was not running"),
            )
            .unwrap()
            .is_empty()
        );
    }
}
