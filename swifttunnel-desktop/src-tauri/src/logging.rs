use std::fs::OpenOptions;
use std::path::PathBuf;

use simplelog::{
    ColorChoice, CombinedLogger, Config, LevelFilter, SharedLogger, TermLogger, TerminalMode,
    WriteLogger,
};

const APP_DIR: &str = "SwiftTunnel";
const LOG_DIR: &str = "logs";
const LOG_FILE: &str = "swifttunnel.log";

pub fn log_file_path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join(APP_DIR)
        .join(LOG_DIR)
        .join(LOG_FILE)
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

pub fn init() {
    let level = level_from_env();
    let config = Config::default();

    let mut loggers: Vec<Box<dyn SharedLogger>> = Vec::new();
    loggers.push(TermLogger::new(
        level,
        config.clone(),
        TerminalMode::Stderr,
        ColorChoice::Auto,
    ));

    let path = log_file_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    match OpenOptions::new().create(true).append(true).open(&path) {
        Ok(file) => loggers.push(WriteLogger::new(level, config, file)),
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
