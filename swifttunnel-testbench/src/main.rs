#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    std::process::exit(swifttunnel_desktop::run_testbench_harness(&args));
}
