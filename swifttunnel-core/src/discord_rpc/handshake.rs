//! Bound the local pipe's advertised frame before allocating its payload.

use discord_rich_presence::DiscordIpc;

// Discord's reference RPC client bounds a complete frame to 64 KiB.
const MAX_FRAME_BYTES: usize = 64 * 1024;

pub(super) fn connect(client: &mut impl DiscordIpc) -> Result<(), String> {
    client
        .connect_ipc()
        .map_err(|error| format!("Failed to connect to Discord: {error}"))?;
    client
        .send(
            serde_json::json!({ "v": 1, "client_id": client.get_client_id() }),
            0,
        )
        .map_err(|error| format!("Failed to send Discord handshake: {error}"))?;
    // The dependency's connect/send_handshake path uses an unbounded recv.
    // Read the same protocol through its exact-read primitive instead.
    read_ready(|buffer| client.read(buffer).map_err(|error| error.to_string()))
}

fn read_ready(mut read: impl FnMut(&mut [u8]) -> Result<(), String>) -> Result<(), String> {
    let mut header = [0; 8];
    read(&mut header).map_err(|error| format!("Could not read Discord handshake: {error}"))?;
    let opcode = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
    let length = u32::from_le_bytes([header[4], header[5], header[6], header[7]]) as usize;
    if opcode != 1 || length == 0 || length > MAX_FRAME_BYTES - header.len() {
        return Err("Discord returned an invalid handshake frame.".into());
    }
    let mut payload = vec![0; length];
    read(&mut payload).map_err(|error| format!("Could not read Discord handshake: {error}"))?;
    let value: serde_json::Value = serde_json::from_slice(&payload)
        .map_err(|_| "Discord returned an invalid handshake response.".to_string())?;
    if value.get("evt").and_then(serde_json::Value::as_str) != Some("READY") {
        return Err("Discord did not accept the presence connection.".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Read};

    fn frame(opcode: u32, payload: &[u8]) -> Vec<u8> {
        [
            opcode.to_le_bytes().as_slice(),
            &(payload.len() as u32).to_le_bytes(),
            payload,
        ]
        .concat()
    }

    fn verify(bytes: Vec<u8>) -> Result<(), String> {
        let mut reader = Cursor::new(bytes);
        read_ready(|buffer| reader.read_exact(buffer).map_err(|error| error.to_string()))
    }

    #[test]
    fn discord_handshake_accepts_ready_and_bounds_payload_before_reading_it() {
        let ready = br#"{"cmd":"DISPATCH","evt":"READY","data":{}}"#;
        assert!(verify(frame(1, ready)).is_ok());
        let mut largest = ready.to_vec();
        largest.resize(MAX_FRAME_BYTES - 8, b' ');
        assert!(verify(frame(1, &largest)).is_ok());
        for (opcode, length) in [
            (1u32, 0),
            (1, (MAX_FRAME_BYTES - 7) as u32),
            (1, u32::MAX),
            (2, 10),
            (3, 10),
        ] {
            let mut calls = 0;
            assert!(
                read_ready(|buffer| {
                    calls += 1;
                    assert_eq!(calls, 1, "invalid headers must not allocate/read a body");
                    assert_eq!(buffer.len(), 8);
                    buffer[..4].copy_from_slice(&opcode.to_le_bytes());
                    buffer[4..].copy_from_slice(&length.to_le_bytes());
                    Ok(())
                })
                .is_err()
            );
            assert_eq!(calls, 1);
        }
    }

    #[test]
    fn discord_handshake_rejects_truncation_bad_json_and_rejected_sessions() {
        assert!(verify(vec![1, 0, 0]).is_err());
        let ready = frame(1, br#"{"evt":"READY"}"#);
        assert!(verify(ready[..ready.len() - 1].to_vec()).is_err());
        for payload in [
            b"not json".as_slice(),
            br#"{"evt":"ERROR","data":{"message":"private fixture"}}"#,
            br#"{}"#,
            b"\xff",
        ] {
            let error = verify(frame(1, payload)).unwrap_err();
            assert!(!error.contains("private fixture"));
        }
    }
}
