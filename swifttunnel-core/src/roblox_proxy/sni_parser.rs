//! TLS ClientHello SNI extraction and HTTP Host header parsing.
//!
//! Pure parsing — no I/O. Used by the TCP relay to determine the
//! upstream hostname from intercepted connections.

/// Result of parsing a TLS ClientHello for the SNI extension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SniInfo {
    /// The SNI hostname (e.g., "clientsettings.roblox.com").
    pub hostname: String,
    /// Byte offset within the buffer where the hostname string starts.
    /// Used to split the ClientHello for SNI fragmentation.
    pub hostname_offset: usize,
    /// Length of the hostname in bytes.
    pub hostname_len: usize,
}

/// Parse a TLS ClientHello and extract the SNI hostname.
///
/// Returns `None` if the buffer is not a valid ClientHello or lacks an SNI extension.
pub fn parse_sni(buf: &[u8]) -> Option<SniInfo> {
    // TLS Record Header: ContentType(1) + Version(2) + Length(2) = 5 bytes minimum
    if buf.len() < 5 {
        return None;
    }

    // ContentType must be Handshake (0x16)
    if buf[0] != 0x16 {
        return None;
    }

    let record_length = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    let record_end = 5usize.checked_add(record_length)?;
    if buf.len() < record_end {
        return None;
    }

    let hs = &buf[5..record_end];

    // Handshake: Type(1) + Length(3) — must be ClientHello (0x01)
    if hs.len() < 4 || hs[0] != 0x01 {
        return None;
    }

    // Start parsing ClientHello body (after 4-byte handshake header)
    let mut pos: usize = 4;

    // Version (2) + Random (32) = 34 bytes
    pos = pos.checked_add(34)?;
    if pos >= hs.len() {
        return None;
    }

    // Session ID (length-prefixed, 1-byte length)
    let session_id_len = hs[pos] as usize;
    pos = pos.checked_add(1 + session_id_len)?;
    if pos + 2 > hs.len() {
        return None;
    }

    // Cipher Suites (length-prefixed, 2-byte length)
    let cs_len = u16::from_be_bytes([hs[pos], hs[pos + 1]]) as usize;
    pos = pos.checked_add(2 + cs_len)?;
    if pos >= hs.len() {
        return None;
    }

    // Compression Methods (length-prefixed, 1-byte length)
    let comp_len = hs[pos] as usize;
    pos = pos.checked_add(1 + comp_len)?;
    if pos + 2 > hs.len() {
        return None;
    }

    // Extensions (length-prefixed, 2-byte length)
    let ext_total = u16::from_be_bytes([hs[pos], hs[pos + 1]]) as usize;
    pos = pos.checked_add(2)?;
    let ext_end = pos.checked_add(ext_total)?;
    if ext_end > hs.len() {
        return None;
    }

    // Walk extensions looking for SNI (type 0x0000)
    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([hs[pos], hs[pos + 1]]);
        let ext_len = u16::from_be_bytes([hs[pos + 2], hs[pos + 3]]) as usize;
        pos += 4;

        if pos + ext_len > ext_end {
            return None;
        }

        if ext_type == 0x0000 {
            // SNI: ServerNameListLen(2) + Type(1) + NameLen(2) + Name
            if ext_len < 5 {
                return None;
            }
            let name_type = hs[pos + 2];
            let name_len = u16::from_be_bytes([hs[pos + 3], hs[pos + 4]]) as usize;

            if name_type != 0x00 {
                // Not a hostname entry — skip
                pos += ext_len;
                continue;
            }

            let name_start = pos + 5;
            if name_start + name_len > pos + ext_len {
                return None;
            }

            let hostname = std::str::from_utf8(&hs[name_start..name_start + name_len])
                .ok()?
                .to_string();

            // Absolute offset: 5 (TLS record header) + name_start (within handshake)
            let absolute_offset = 5 + name_start;

            return Some(SniInfo {
                hostname,
                hostname_offset: absolute_offset,
                hostname_len: name_len,
            });
        }

        pos += ext_len;
    }

    None
}

/// Extract the `Host` header value from a raw HTTP request.
///
/// Returns the hostname without the port component, if present.
pub fn parse_http_host(buf: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(buf).ok()?;

    for line in text.lines() {
        if let Some(rest) = line
            .strip_prefix("Host:")
            .or_else(|| line.strip_prefix("host:"))
        {
            let host = rest.trim();
            // Strip port suffix (e.g., ":443")
            return Some(match host.rfind(':') {
                Some(i) if host[i + 1..].bytes().all(|b| b.is_ascii_digit()) => {
                    host[..i].to_string()
                }
                _ => host.to_string(),
            });
        }
    }

    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal TLS 1.2 ClientHello with the given SNI hostname.
    fn build_client_hello(hostname: &str) -> Vec<u8> {
        let name = hostname.as_bytes();

        // SNI extension data: ListLen(2) + Type(1) + NameLen(2) + Name
        let sni_data_len = 2 + 1 + 2 + name.len();
        let mut sni_ext = Vec::with_capacity(4 + sni_data_len);
        sni_ext.extend_from_slice(&[0x00, 0x00]); // Extension type: SNI
        sni_ext.extend_from_slice(&(sni_data_len as u16).to_be_bytes());
        sni_ext.extend_from_slice(&((1 + 2 + name.len()) as u16).to_be_bytes()); // list len
        sni_ext.push(0x00); // host name type
        sni_ext.extend_from_slice(&(name.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(name);

        // ClientHello body
        let mut ch = Vec::new();
        ch.extend_from_slice(&[0x03, 0x03]); // version TLS 1.2
        ch.extend_from_slice(&[0u8; 32]); // random
        ch.push(0x00); // session ID length
        ch.extend_from_slice(&[0x00, 0x02, 0x00, 0xFF]); // cipher suites
        ch.extend_from_slice(&[0x01, 0x00]); // compression methods
        ch.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes()); // extensions length
        ch.extend_from_slice(&sni_ext);

        // Handshake wrapper
        let mut hs = Vec::new();
        hs.push(0x01); // ClientHello
        let len = ch.len() as u32;
        hs.push((len >> 16) as u8);
        hs.push((len >> 8) as u8);
        hs.push(len as u8);
        hs.extend_from_slice(&ch);

        // TLS Record
        let mut record = Vec::new();
        record.push(0x16); // Handshake
        record.extend_from_slice(&[0x03, 0x01]); // TLS 1.0 record version
        record.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        record.extend_from_slice(&hs);

        record
    }

    #[test]
    fn parse_sni_valid_hostname() {
        let data = build_client_hello("clientsettings.roblox.com");
        let info = parse_sni(&data).expect("should parse SNI");
        assert_eq!(info.hostname, "clientsettings.roblox.com");
        assert_eq!(info.hostname_len, "clientsettings.roblox.com".len());
        // Verify offset points to the hostname bytes in the buffer
        assert_eq!(
            &data[info.hostname_offset..info.hostname_offset + info.hostname_len],
            b"clientsettings.roblox.com"
        );
    }

    #[test]
    fn parse_sni_short_hostname() {
        let data = build_client_hello("a.co");
        let info = parse_sni(&data).expect("should parse short SNI");
        assert_eq!(info.hostname, "a.co");
    }

    #[test]
    fn parse_sni_long_hostname() {
        let long = "subdomain.deeply.nested.example.roblox.com";
        let data = build_client_hello(long);
        let info = parse_sni(&data).expect("should parse long SNI");
        assert_eq!(info.hostname, long);
    }

    #[test]
    fn parse_sni_not_tls() {
        assert!(parse_sni(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n").is_none());
    }

    #[test]
    fn parse_sni_truncated_record_header() {
        assert!(parse_sni(&[0x16, 0x03]).is_none());
    }

    #[test]
    fn parse_sni_truncated_body() {
        // Valid header claiming 100 bytes but only 10 supplied
        let mut data = vec![0x16, 0x03, 0x01, 0x00, 0x64];
        data.extend_from_slice(&[0; 10]);
        assert!(parse_sni(&data).is_none());
    }

    #[test]
    fn parse_sni_no_extensions() {
        // Handshake with no extensions field
        let mut ch = Vec::new();
        ch.extend_from_slice(&[0x03, 0x03]); // version
        ch.extend_from_slice(&[0u8; 32]); // random
        ch.push(0x00); // session ID len
        ch.extend_from_slice(&[0x00, 0x02, 0x00, 0xFF]); // cipher suites
        ch.extend_from_slice(&[0x01, 0x00]); // compression

        let mut hs = vec![0x01];
        let len = ch.len() as u32;
        hs.push((len >> 16) as u8);
        hs.push((len >> 8) as u8);
        hs.push(len as u8);
        hs.extend_from_slice(&ch);

        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        record.extend_from_slice(&hs);

        assert!(parse_sni(&record).is_none());
    }

    #[test]
    fn parse_sni_empty_buffer() {
        assert!(parse_sni(&[]).is_none());
    }

    // -- HTTP Host parsing --

    #[test]
    fn parse_http_host_basic() {
        let req = b"GET / HTTP/1.1\r\nHost: clientsettings.roblox.com\r\n\r\n";
        assert_eq!(
            parse_http_host(req),
            Some("clientsettings.roblox.com".to_string())
        );
    }

    #[test]
    fn parse_http_host_with_port() {
        let req = b"GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n";
        assert_eq!(parse_http_host(req), Some("example.com".to_string()));
    }

    #[test]
    fn parse_http_host_lowercase_header() {
        let req = b"GET / HTTP/1.1\r\nhost: example.com\r\n\r\n";
        assert_eq!(parse_http_host(req), Some("example.com".to_string()));
    }

    #[test]
    fn parse_http_host_missing() {
        let req = b"GET / HTTP/1.1\r\nAccept: */*\r\n\r\n";
        assert!(parse_http_host(req).is_none());
    }

    #[test]
    fn parse_http_host_ipv6_no_strip() {
        // IPv6 literal in brackets should not strip the port-like suffix
        let req = b"GET / HTTP/1.1\r\nHost: [::1]:443\r\n\r\n";
        // rfind(':') finds the one after ']', digits after it -> stripped
        assert_eq!(parse_http_host(req), Some("[::1]".to_string()));
    }
}
