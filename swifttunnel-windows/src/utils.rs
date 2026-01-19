//! Utility functions for SwiftTunnel

use std::process::Command;

#[cfg(windows)]
use std::os::windows::process::CommandExt;

/// Windows CREATE_NO_WINDOW flag to prevent console windows from appearing
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;

/// Create a Command that won't show a console window on Windows
///
/// This is essential for GUI apps to prevent scary command prompts
/// from flashing when running shell commands in the background.
pub fn hidden_command(program: &str) -> Command {
    let mut cmd = Command::new(program);

    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);

    cmd
}
