use std::path::PathBuf;
use swifttunnel_core::rolling_log::RollingLog;

use simplelog::{
    ColorChoice, CombinedLogger, Config, ConfigBuilder, LevelFilter, SharedLogger, TermLogger,
    TerminalMode, WriteLogger,
};

const APP_DIR: &str = "SwiftTunnel";
const LOG_DIR: &str = "logs";
const LOG_FILE: &str = "swifttunnel.log";
const PREVIOUS_LOG_FILE: &str = "swifttunnel.previous.log";

/// Roll the log over once it passes this size.
///
/// Two support logs arrived at **209 MB and 880 MB**, because nothing ever
/// rotated or truncated this file. That is bad twice over: it eats the user's
/// disk for months, and it makes the log unsendable, since Discord rejects
/// anything over 10 MB. The people most likely to hit a bug are the ones who
/// have run the app longest, so the ones with the most useful logs were exactly
/// the ones who could not hand them over.
///
/// Each file stays below that attachment limit. Rotation also runs during a
/// session, with an in-memory byte count instead of a metadata read per write.
const MAX_LOG_BYTES: u64 = 8 * 1024 * 1024;

pub fn log_file_path() -> PathBuf {
    log_dir().join(LOG_FILE)
}

/// Previous log, kept across one rotation.
///
/// Worth keeping: a crash usually needs the run *before* the restart, and
/// rotating at startup would otherwise throw that away exactly when it matters.
pub fn previous_log_file_path() -> PathBuf {
    log_dir().join(PREVIOUS_LOG_FILE)
}

fn log_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join(APP_DIR)
        .join(LOG_DIR)
}

fn level_from_env() -> LevelFilter {
    match std::env::var("RUST_LOG")
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "trace" => LevelFilter::Trace,
        "debug" => LevelFilter::Debug,
        "warn" => LevelFilter::Warn,
        "error" => LevelFilter::Error,
        "off" => LevelFilter::Off,
        _ => LevelFilter::Info,
    }
}

/// Log config for the file sink.
///
/// The default format prints time only. Adding the date and the module path
/// costs a few bytes a line and answers two questions that previously needed
/// guesswork: which day a line came from in a log spanning weeks, and which
/// subsystem emitted it. Rotation is what pays for the extra width.
fn file_config() -> Config {
    ConfigBuilder::new()
        .set_time_format_rfc3339()
        .set_target_level(LevelFilter::Error)
        .set_location_level(LevelFilter::Off)
        .build()
}

pub fn init() {
    let level = level_from_env();

    let mut loggers: Vec<Box<dyn SharedLogger>> = Vec::new();
    loggers.push(TermLogger::new(
        level,
        Config::default(),
        TerminalMode::Stderr,
        ColorChoice::Auto,
    ));

    let path = log_file_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    match RollingLog::open(&path, &previous_log_file_path(), MAX_LOG_BYTES) {
        Ok(file) => loggers.push(WriteLogger::new(level, file_config(), file)),
        Err(e) => {
            eprintln!(
                "SwiftTunnel: could not open log file {}: {}",
                path.display(),
                e
            );
        }
    }

    let _ = CombinedLogger::init(loggers);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cap_stays_under_the_discord_attachment_limit() {
        // The whole point of rotating is that a user can actually send the
        // file. A const block fails the build rather than a test run, which is
        // the right place to catch someone raising the cap.
        const {
            assert!(
                MAX_LOG_BYTES < 10 * 1024 * 1024,
                "log cap must stay under Discord's 10 MB limit"
            )
        };
    }

    #[test]
    fn current_and_previous_logs_are_separate_files() {
        assert_ne!(log_file_path(), previous_log_file_path());
        assert_eq!(
            log_file_path().parent(),
            previous_log_file_path().parent(),
            "both belong in the logs folder so one instruction finds them"
        );
    }
}
