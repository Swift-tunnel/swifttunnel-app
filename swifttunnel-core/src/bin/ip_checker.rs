mod testbench_shared;

use testbench_shared::{
    DEFAULT_TCP_PROBE_COUNT, DEFAULT_TCP_PROBE_TARGET, DEFAULT_UDP_ECHO_PAYLOAD_BYTES,
    DEFAULT_UDP_PROBE_COUNT, DEFAULT_UDP_PROBE_STARTUP_DELAY_MS, DEFAULT_UDP_PROBE_TARGET,
    get_public_ip, init_logging, run_tcp_probe, run_udp_echo_probe, run_udp_probe,
};

fn print_usage() {
    println!("Usage:");
    println!("  ip_checker.exe");
    println!("  ip_checker.exe --raw");
    println!(
        "  ip_checker.exe --udp-probe [--target {}] [--count {}] [--startup-delay-ms {}] [--port-file path]",
        DEFAULT_UDP_PROBE_TARGET, DEFAULT_UDP_PROBE_COUNT, DEFAULT_UDP_PROBE_STARTUP_DELAY_MS
    );
    println!(
        "  ip_checker.exe --udp-echo-probe --target host:port [--count {}] [--payload-bytes {}] [--startup-delay-ms {}] [--port-file path]",
        DEFAULT_UDP_PROBE_COUNT, DEFAULT_UDP_ECHO_PAYLOAD_BYTES, DEFAULT_UDP_PROBE_STARTUP_DELAY_MS
    );
    println!(
        "  ip_checker.exe --tcp-probe [--target {}] [--count {}] [--startup-delay-ms {}] [--port-file path]",
        DEFAULT_TCP_PROBE_TARGET, DEFAULT_TCP_PROBE_COUNT, DEFAULT_UDP_PROBE_STARTUP_DELAY_MS
    );
}

fn main() {
    init_logging();

    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print_usage();
        return;
    }

    if args.iter().any(|arg| arg == "--udp-echo-probe") {
        let mut target = DEFAULT_UDP_PROBE_TARGET.to_string();
        let mut count = DEFAULT_UDP_PROBE_COUNT;
        let mut payload_bytes = DEFAULT_UDP_ECHO_PAYLOAD_BYTES;
        let mut startup_delay_ms = DEFAULT_UDP_PROBE_STARTUP_DELAY_MS;
        let mut port_file = None;
        let mut idx = 0usize;

        while idx < args.len() {
            match args[idx].as_str() {
                "--udp-echo-probe" => idx += 1,
                "--target" => {
                    idx += 1;
                    let Some(value) = args.get(idx) else {
                        eprintln!("Missing value for --target");
                        std::process::exit(2);
                    };
                    target = value.clone();
                    idx += 1;
                }
                "--count" => {
                    idx += 1;
                    let Some(value) = args.get(idx) else {
                        eprintln!("Missing value for --count");
                        std::process::exit(2);
                    };
                    match value.parse::<usize>() {
                        Ok(parsed) => count = parsed,
                        Err(_) => {
                            eprintln!("Invalid integer for --count: {}", value);
                            std::process::exit(2);
                        }
                    }
                    idx += 1;
                }
                "--payload-bytes" => {
                    idx += 1;
                    let Some(value) = args.get(idx) else {
                        eprintln!("Missing value for --payload-bytes");
                        std::process::exit(2);
                    };
                    match value.parse::<usize>() {
                        Ok(parsed) => payload_bytes = parsed,
                        Err(_) => {
                            eprintln!("Invalid integer for --payload-bytes: {}", value);
                            std::process::exit(2);
                        }
                    }
                    idx += 1;
                }
                "--startup-delay-ms" => {
                    idx += 1;
                    let Some(value) = args.get(idx) else {
                        eprintln!("Missing value for --startup-delay-ms");
                        std::process::exit(2);
                    };
                    match value.parse::<u64>() {
                        Ok(parsed) => startup_delay_ms = parsed,
                        Err(_) => {
                            eprintln!("Invalid integer for --startup-delay-ms: {}", value);
                            std::process::exit(2);
                        }
                    }
                    idx += 1;
                }
                "--port-file" => {
                    idx += 1;
                    let Some(value) = args.get(idx) else {
                        eprintln!("Missing value for --port-file");
                        std::process::exit(2);
                    };
                    port_file = Some(std::path::PathBuf::from(value));
                    idx += 1;
                }
                other => {
                    eprintln!("Unknown argument: {}", other);
                    std::process::exit(2);
                }
            }
        }

        if let Err(err) = run_udp_echo_probe(
            &target,
            count,
            payload_bytes,
            startup_delay_ms,
            port_file.as_deref(),
        ) {
            eprintln!("UDP echo probe failed: {}", err);
            std::process::exit(1);
        }
        println!(
            "UDP echo probe complete: target={} count={} payload_bytes={}",
            target, count, payload_bytes
        );
        return;
    }

    if args.iter().any(|arg| arg == "--udp-probe") {
        let mut target = DEFAULT_UDP_PROBE_TARGET.to_string();
        let mut count = DEFAULT_UDP_PROBE_COUNT;
        let mut startup_delay_ms = DEFAULT_UDP_PROBE_STARTUP_DELAY_MS;
        let mut port_file = None;
        let mut idx = 0usize;

        while idx < args.len() {
            match args[idx].as_str() {
                "--udp-probe" => idx += 1,
                "--target" => {
                    idx += 1;
                    let Some(value) = args.get(idx) else {
                        eprintln!("Missing value for --target");
                        std::process::exit(2);
                    };
                    target = value.clone();
                    idx += 1;
                }
                "--count" => {
                    idx += 1;
                    let Some(value) = args.get(idx) else {
                        eprintln!("Missing value for --count");
                        std::process::exit(2);
                    };
                    match value.parse::<usize>() {
                        Ok(parsed) => count = parsed,
                        Err(_) => {
                            eprintln!("Invalid integer for --count: {}", value);
                            std::process::exit(2);
                        }
                    }
                    idx += 1;
                }
                "--startup-delay-ms" => {
                    idx += 1;
                    let Some(value) = args.get(idx) else {
                        eprintln!("Missing value for --startup-delay-ms");
                        std::process::exit(2);
                    };
                    match value.parse::<u64>() {
                        Ok(parsed) => startup_delay_ms = parsed,
                        Err(_) => {
                            eprintln!("Invalid integer for --startup-delay-ms: {}", value);
                            std::process::exit(2);
                        }
                    }
                    idx += 1;
                }
                "--port-file" => {
                    idx += 1;
                    let Some(value) = args.get(idx) else {
                        eprintln!("Missing value for --port-file");
                        std::process::exit(2);
                    };
                    port_file = Some(std::path::PathBuf::from(value));
                    idx += 1;
                }
                other => {
                    eprintln!("Unknown argument: {}", other);
                    std::process::exit(2);
                }
            }
        }

        if let Err(err) = run_udp_probe(&target, count, startup_delay_ms, port_file.as_deref()) {
            eprintln!("UDP probe failed: {}", err);
            std::process::exit(1);
        }
        println!("UDP probe complete: target={} count={}", target, count);
        return;
    }

    if args.iter().any(|arg| arg == "--tcp-probe") {
        let mut target = DEFAULT_TCP_PROBE_TARGET.to_string();
        let mut count = DEFAULT_TCP_PROBE_COUNT;
        let mut startup_delay_ms = DEFAULT_UDP_PROBE_STARTUP_DELAY_MS;
        let mut port_file = None;
        let mut idx = 0usize;

        while idx < args.len() {
            match args[idx].as_str() {
                "--tcp-probe" => idx += 1,
                "--target" => {
                    idx += 1;
                    let Some(value) = args.get(idx) else {
                        eprintln!("Missing value for --target");
                        std::process::exit(2);
                    };
                    target = value.clone();
                    idx += 1;
                }
                "--count" => {
                    idx += 1;
                    let Some(value) = args.get(idx) else {
                        eprintln!("Missing value for --count");
                        std::process::exit(2);
                    };
                    match value.parse::<usize>() {
                        Ok(parsed) => count = parsed,
                        Err(_) => {
                            eprintln!("Invalid integer for --count: {}", value);
                            std::process::exit(2);
                        }
                    }
                    idx += 1;
                }
                "--startup-delay-ms" => {
                    idx += 1;
                    let Some(value) = args.get(idx) else {
                        eprintln!("Missing value for --startup-delay-ms");
                        std::process::exit(2);
                    };
                    match value.parse::<u64>() {
                        Ok(parsed) => startup_delay_ms = parsed,
                        Err(_) => {
                            eprintln!("Invalid integer for --startup-delay-ms: {}", value);
                            std::process::exit(2);
                        }
                    }
                    idx += 1;
                }
                "--port-file" => {
                    idx += 1;
                    let Some(value) = args.get(idx) else {
                        eprintln!("Missing value for --port-file");
                        std::process::exit(2);
                    };
                    port_file = Some(std::path::PathBuf::from(value));
                    idx += 1;
                }
                other => {
                    eprintln!("Unknown argument: {}", other);
                    std::process::exit(2);
                }
            }
        }

        if let Err(err) = run_tcp_probe(&target, count, startup_delay_ms, port_file.as_deref()) {
            eprintln!("TCP probe failed: {}", err);
            std::process::exit(1);
        }
        println!("TCP probe complete: target={} count={}", target, count);
        return;
    }

    match get_public_ip() {
        Ok(ip) => {
            if args.iter().any(|arg| arg == "--raw") {
                println!("{}", ip);
            } else {
                println!("SwiftTunnel IP Checker");
                println!("Public IP: {}", ip);
            }
        }
        Err(err) => {
            eprintln!("Failed to determine public IP: {}", err);
            std::process::exit(1);
        }
    }
}
