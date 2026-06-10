//! Minimal, bounds-checked TLS ClientHello SNI extraction.
//!
//! Route Assist uses this to recognize which hostname a relayed HTTPS flow is
//! actually talking to. The parser is intentionally conservative: it only
//! understands a single ClientHello at the start of a TCP payload, never
//! allocates, and returns `None` for anything truncated, malformed, or not a
//! ClientHello. A `None` simply means "no SNI learned from this packet" — it
//! must never be treated as an error.

/// Cheap pre-filter: does this TCP payload plausibly start a TLS handshake
/// record carrying a ClientHello? Used to skip full parsing on ordinary
/// application-data packets.
pub fn looks_like_client_hello(payload: &[u8]) -> bool {
    // record type 0x16 (handshake), legacy version major 0x03,
    // handshake message type 0x01 (ClientHello)
    payload.len() >= 6 && payload[0] == 0x16 && payload[1] == 0x03 && payload[5] == 0x01
}

/// Extract the SNI host_name from a TLS ClientHello at the start of `payload`.
///
/// Returns the hostname with any trailing dot removed. Returns `None` when the
/// payload is not a ClientHello, the hello carries no SNI extension, the SNI
/// lies beyond the bytes available in this packet, or any length field is
/// inconsistent.
pub fn parse_client_hello_sni(payload: &[u8]) -> Option<&str> {
    if !looks_like_client_hello(payload) {
        return None;
    }

    // TLS record header: type(1) version(2) length(2). Parse only within this
    // record; a ClientHello whose SNI spans into a later record/segment is
    // skipped rather than guessed at.
    let record_len = u16::from_be_bytes([*payload.get(3)?, *payload.get(4)?]) as usize;
    let record_end = 5usize.checked_add(record_len)?.min(payload.len());
    let record = payload.get(5..record_end)?;

    // Handshake header: msg_type(1) length(3).
    let mut cursor = 4usize;

    // client_version(2) + random(32)
    cursor = cursor.checked_add(34)?;

    // legacy_session_id
    let session_id_len = *record.get(cursor)? as usize;
    cursor = cursor.checked_add(1)?.checked_add(session_id_len)?;

    // cipher_suites
    let cipher_len = u16::from_be_bytes([*record.get(cursor)?, *record.get(cursor + 1)?]) as usize;
    cursor = cursor.checked_add(2)?.checked_add(cipher_len)?;

    // legacy_compression_methods
    let compression_len = *record.get(cursor)? as usize;
    cursor = cursor.checked_add(1)?.checked_add(compression_len)?;

    // extensions
    let extensions_len =
        u16::from_be_bytes([*record.get(cursor)?, *record.get(cursor + 1)?]) as usize;
    cursor = cursor.checked_add(2)?;
    let extensions_end = cursor.checked_add(extensions_len)?.min(record.len());

    while cursor + 4 <= extensions_end {
        let ext_type = u16::from_be_bytes([record[cursor], record[cursor + 1]]);
        let ext_len = u16::from_be_bytes([record[cursor + 2], record[cursor + 3]]) as usize;
        cursor = cursor.checked_add(4)?;
        let ext_end = cursor.checked_add(ext_len)?;
        if ext_end > extensions_end {
            return None;
        }

        if ext_type == 0x0000 {
            return parse_server_name_extension(record.get(cursor..ext_end)?);
        }
        cursor = ext_end;
    }

    None
}

/// Parse the server_name extension body: list_length(2), then entries of
/// name_type(1) + name_length(2) + name. Only host_name (type 0) is used.
fn parse_server_name_extension(ext: &[u8]) -> Option<&str> {
    let list_len = u16::from_be_bytes([*ext.get(0)?, *ext.get(1)?]) as usize;
    let list_end = 2usize.checked_add(list_len)?.min(ext.len());
    let mut cursor = 2usize;

    while cursor + 3 <= list_end {
        let name_type = ext[cursor];
        let name_len = u16::from_be_bytes([ext[cursor + 1], ext[cursor + 2]]) as usize;
        cursor = cursor.checked_add(3)?;
        let name_end = cursor.checked_add(name_len)?;
        if name_end > list_end {
            return None;
        }

        if name_type == 0 {
            let name = std::str::from_utf8(ext.get(cursor..name_end)?).ok()?;
            if name.is_empty() || !name.bytes().all(|b| b.is_ascii_graphic()) {
                return None;
            }
            return Some(name.trim_end_matches('.'));
        }
        cursor = name_end;
    }

    None
}

#[cfg(test)]
pub(crate) fn build_client_hello_with_sni(host: &str) -> Vec<u8> {
    build_client_hello(Some(host))
}

#[cfg(test)]
pub(crate) fn build_client_hello_without_sni() -> Vec<u8> {
    build_client_hello(None)
}

#[cfg(test)]
fn build_client_hello(host: Option<&str>) -> Vec<u8> {
    let mut extensions = Vec::new();
    // An unrelated extension first (supported_versions-ish placeholder) so the
    // parser proves it walks past non-SNI extensions.
    extensions.extend_from_slice(&[0x00, 0x2B, 0x00, 0x03, 0x02, 0x03, 0x04]);
    if let Some(host) = host {
        let name = host.as_bytes();
        let mut sni = Vec::new();
        sni.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes()); // list len
        sni.push(0); // host_name
        sni.extend_from_slice(&(name.len() as u16).to_be_bytes());
        sni.extend_from_slice(name);
        extensions.extend_from_slice(&[0x00, 0x00]); // ext type: server_name
        extensions.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni);
    }

    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // client_version
    body.extend_from_slice(&[0u8; 32]); // random
    body.push(0); // session_id len
    body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // one cipher suite
    body.extend_from_slice(&[0x01, 0x00]); // one compression method: null
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    let mut handshake = vec![0x01]; // ClientHello
    handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]); // 3-byte len
    handshake.extend_from_slice(&body);

    let mut record = vec![0x16, 0x03, 0x01]; // handshake record, TLS 1.0 legacy
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sni_from_well_formed_client_hello() {
        let hello = build_client_hello_with_sni("clientsettingscdn.roblox.com");
        assert_eq!(
            parse_client_hello_sni(&hello),
            Some("clientsettingscdn.roblox.com")
        );
    }

    #[test]
    fn trims_trailing_dot_from_sni() {
        let hello = build_client_hello_with_sni("clientsettings.roblox.com.");
        assert_eq!(
            parse_client_hello_sni(&hello),
            Some("clientsettings.roblox.com")
        );
    }

    #[test]
    fn returns_none_without_sni_extension() {
        let hello = build_client_hello_without_sni();
        assert_eq!(parse_client_hello_sni(&hello), None);
    }

    #[test]
    fn returns_none_for_application_data_record() {
        let mut payload = build_client_hello_with_sni("clientsettings.roblox.com");
        payload[0] = 0x17; // application data, not handshake
        assert_eq!(parse_client_hello_sni(&payload), None);
        assert!(!looks_like_client_hello(&payload));
    }

    #[test]
    fn returns_none_for_server_hello() {
        let mut payload = build_client_hello_with_sni("clientsettings.roblox.com");
        payload[5] = 0x02; // ServerHello
        assert_eq!(parse_client_hello_sni(&payload), None);
    }

    #[test]
    fn returns_none_for_every_truncation_without_panicking() {
        let hello = build_client_hello_with_sni("clientsettingscdn.roblox.com");
        // The SNI host ends 0 bytes before the end of this hello, so every
        // strict prefix must fail closed.
        for len in 0..hello.len() {
            assert_eq!(
                parse_client_hello_sni(&hello[..len]),
                None,
                "truncation at {len} bytes should not parse"
            );
        }
    }

    #[test]
    fn returns_none_for_garbage() {
        let garbage = [0x16, 0x03, 0x01, 0xFF, 0xFF, 0x01, 0xDE, 0xAD, 0xBE, 0xEF];
        assert_eq!(parse_client_hello_sni(&garbage), None);

        let zeros = [0u8; 64];
        assert_eq!(parse_client_hello_sni(&zeros), None);
    }

    #[test]
    fn returns_none_for_non_ascii_hostname() {
        let hello = build_client_hello_with_sni("client\u{00e9}.roblox.com");
        assert_eq!(parse_client_hello_sni(&hello), None);
    }

    #[test]
    fn returns_none_when_sni_length_overruns_extension() {
        let mut hello = build_client_hello_with_sni("clientsettings.roblox.com");
        // Corrupt the host_name length (3 bytes after the SNI ext header) to
        // claim more bytes than the extension holds.
        let host = b"clientsettings.roblox.com";
        let pos = hello
            .windows(host.len())
            .position(|w| w == host)
            .expect("hostname present");
        hello[pos - 2..pos].copy_from_slice(&0xFFFFu16.to_be_bytes());
        assert_eq!(parse_client_hello_sni(&hello), None);
    }
}
