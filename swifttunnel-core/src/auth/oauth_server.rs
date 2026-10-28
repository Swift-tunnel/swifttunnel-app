//! Localhost HTTP server for OAuth callbacks
//!
//! This module implements a lightweight localhost HTTP server that receives
//! OAuth callbacks from the browser. This approach is more reliable than
//! deep links because:
//! - No second app instance is launched
//! - Works on all Windows versions
//! - Industry standard (used by Discord, Slack, VS Code, Spotify)

use log::{debug, error, info, warn};
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use url::Url;

/// Default port for OAuth callback server
pub const DEFAULT_OAUTH_PORT: u16 = 17435;
const MAX_CALLBACK_HEADERS: usize = 16 * 1024;
const CALLBACK_READ_BUDGET: Duration = Duration::from_secs(2);
const CALLBACK_WRITE_BUDGET: Duration = Duration::from_millis(500);
const CALLBACK_POLL: Duration = Duration::from_millis(100);

/// Callback data received from OAuth redirect
#[derive(Debug, Clone)]
pub struct OAuthCallbackData {
    pub token: String,
    pub state: String,
}

/// Localhost HTTP server for OAuth callbacks
pub struct OAuthServer {
    /// Channel to receive callback data
    receiver: Receiver<OAuthCallbackData>,
    /// Flag to stop the server
    stop_flag: Arc<AtomicBool>,
    /// Server thread handle
    thread_handle: Option<JoinHandle<()>>,
    /// Port the server is listening on
    port: u16,
}

impl OAuthServer {
    /// Start the OAuth callback server on localhost
    ///
    /// Tries the default port first, then falls back to a random available port.
    pub fn start(expected_state: &str) -> Result<Self, String> {
        if expected_state.is_empty() || expected_state.len() > 256 {
            return Err("Could not prepare browser sign-in. Please try again.".to_string());
        }
        // Try default port first
        let (server, port) = match TcpListener::bind(("127.0.0.1", DEFAULT_OAUTH_PORT)) {
            Ok(s) => {
                info!("OAuth server started on port {}", DEFAULT_OAUTH_PORT);
                (s, DEFAULT_OAUTH_PORT)
            }
            Err(e) => {
                warn!(
                    "Default port {} unavailable: {}, trying random port",
                    DEFAULT_OAUTH_PORT, e
                );
                // Try port 0 to get a random available port
                match TcpListener::bind(("127.0.0.1", 0)) {
                    Ok(s) => {
                        let port = s.local_addr().map(|address| address.port()).unwrap_or(0);
                        if port == 0 {
                            return Err("Failed to get assigned port".to_string());
                        }
                        info!("OAuth server started on fallback port {}", port);
                        (s, port)
                    }
                    Err(e) => {
                        error!("Failed to start OAuth server: {}", e);
                        return Err(format!("Failed to start OAuth server: {}", e));
                    }
                }
            }
        };

        Self::start_with_listener(server, port, expected_state.to_string())
    }

    fn start_with_listener(
        server: TcpListener,
        port: u16,
        expected_state: String,
    ) -> Result<Self, String> {
        server
            .set_nonblocking(true)
            .map_err(|error| format!("Could not prepare browser sign-in: {error}"))?;
        let (tx, rx) = mpsc::channel();
        let stop_flag = Arc::new(AtomicBool::new(false));
        let stop_flag_clone = Arc::clone(&stop_flag);

        let thread_handle = thread::Builder::new()
            .name("oauth-callback".into())
            .spawn(move || Self::run_server(server, tx, stop_flag_clone, expected_state))
            .map_err(|error| format!("Could not start browser sign-in: {error}"))?;

        Ok(Self {
            receiver: rx,
            stop_flag,
            thread_handle: Some(thread_handle),
            port,
        })
    }

    /// Get the port the server is listening on
    pub fn port(&self) -> u16 {
        self.port
    }

    /// One bounded connection at a time. A slow local peer cannot grow a
    /// connection-thread pool or make headers consume unbounded memory.
    fn run_server(
        server: TcpListener,
        tx: Sender<OAuthCallbackData>,
        stop_flag: Arc<AtomicBool>,
        expected_state: String,
    ) {
        info!("OAuth server thread started");
        let mut invalid_requests = 0u64;
        while !stop_flag.load(Ordering::Relaxed) {
            let mut peer = match server.accept() {
                Ok((peer, _)) => peer,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::park_timeout(CALLBACK_POLL);
                    continue;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    warn!("OAuth listener could not accept a connection: {error}");
                    break;
                }
            };
            let target = Self::read_target(&mut peer, &stop_flag);
            if stop_flag.load(Ordering::Relaxed) {
                break;
            }
            let callback = target
                .as_deref()
                .ok()
                .and_then(Self::parse_callback)
                .filter(|callback| callback.state == expected_state);
            if let Some(callback) = callback {
                info!(
                    "OAuth callback received: {} (query omitted)",
                    Self::log_safe_path(target.as_deref().unwrap_or("/invalid-request"))
                );
                // Deliver before replying: a closed browser must not lose a
                // valid callback. Only this worker can publish a callback.
                if let Err(error) = tx.send(callback) {
                    error!("Failed to send callback data: {error}");
                }
                if let Err(error) =
                    Self::respond(&mut peer, true, &Self::success_html(), &stop_flag)
                {
                    debug!("Could not reply to OAuth browser: {error}");
                }
                break;
            }
            invalid_requests = invalid_requests.saturating_add(1);
            if invalid_requests <= 4 || invalid_requests.is_power_of_two() {
                warn!(
                    "Invalid OAuth callback request #{invalid_requests}: {} (query omitted)",
                    Self::log_safe_path(target.as_deref().unwrap_or("/invalid-request"))
                );
            }
            let _ = Self::respond(
                &mut peer,
                false,
                &Self::error_html("Invalid callback parameters"),
                &stop_flag,
            );
        }
        info!("OAuth server thread exiting");
    }

    fn read_target(peer: &mut TcpStream, stop: &AtomicBool) -> io::Result<String> {
        peer.set_nonblocking(false)?;
        let deadline = Instant::now() + CALLBACK_READ_BUDGET;
        let mut bytes = [0u8; MAX_CALLBACK_HEADERS];
        let mut length = 0usize;
        loop {
            if stop.load(Ordering::Relaxed) {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "callback cancelled",
                ));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "callback headers timed out",
                ));
            }
            if length == bytes.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "callback headers too large",
                ));
            }
            peer.set_read_timeout(Some(remaining.min(CALLBACK_POLL)))?;
            let count = match peer.read(&mut bytes[length..]) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "callback closed",
                    ));
                }
                Ok(count) => count,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::TimedOut
                            | io::ErrorKind::WouldBlock
                            | io::ErrorKind::Interrupted
                    ) =>
                {
                    continue;
                }
                Err(error) => return Err(error),
            };
            let scan_from = length.saturating_sub(3);
            length += count;
            // Scan only new bytes plus the delimiter overlap. Slow drip input
            // must not cause the whole accumulated header to be reparsed.
            if !bytes[scan_from..length]
                .windows(4)
                .any(|part| part == b"\r\n\r\n")
            {
                continue;
            }
            let invalid = || io::Error::new(io::ErrorKind::InvalidData, "invalid callback request");
            let mut headers = [httparse::EMPTY_HEADER; 64];
            let mut request = httparse::Request::new(&mut headers);
            if !request
                .parse(&bytes[..length])
                .map_err(|_| invalid())?
                .is_complete()
                || request.method != Some("GET")
                || !matches!(request.version, Some(0 | 1))
                || request.headers.iter().any(|header| {
                    header.name.eq_ignore_ascii_case("transfer-encoding")
                        || (header.name.eq_ignore_ascii_case("content-length")
                            && std::str::from_utf8(header.value)
                                .ok()
                                .and_then(|value| value.trim().parse::<u64>().ok())
                                != Some(0))
                })
            {
                return Err(invalid());
            }
            return request.path.map(str::to_owned).ok_or_else(invalid);
        }
    }

    fn respond(
        peer: &mut TcpStream,
        success: bool,
        html: &str,
        stop: &AtomicBool,
    ) -> io::Result<()> {
        let status = if success { "200 OK" } else { "400 Bad Request" };
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{html}",
            html.len()
        );
        let deadline = Instant::now() + CALLBACK_WRITE_BUDGET;
        let mut remaining = response.as_bytes();
        while !remaining.is_empty() {
            if stop.load(Ordering::Relaxed) {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "callback cancelled",
                ));
            }
            let budget = deadline.saturating_duration_since(Instant::now());
            if budget.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "callback reply timed out",
                ));
            }
            peer.set_write_timeout(Some(budget.min(CALLBACK_POLL)))?;
            match peer.write(remaining) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "callback reply closed",
                    ));
                }
                Ok(written) => remaining = &remaining[written..],
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::TimedOut
                            | io::ErrorKind::WouldBlock
                            | io::ErrorKind::Interrupted
                    ) =>
                {
                    continue;
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    /// The path of a request URL, with the query discarded.
    ///
    /// Everything sensitive on this server arrives in the query string: the
    /// exchange token, which redeems for a session, and the state that binds
    /// it. The path alone still tells support whether the browser reached us
    /// and on which route, which is the whole diagnostic value of the line.
    fn log_safe_path(url_str: &str) -> String {
        let path = url_str.split(['?', '#']).next().unwrap_or("/");
        let mut characters = path.chars();
        let mut safe: String = characters
            .by_ref()
            .take(128)
            .map(|c| if c.is_control() { '_' } else { c })
            .collect();
        if characters.next().is_some() {
            safe.push_str("...");
        }
        safe
    }

    /// Parse the callback URL to extract token and state
    fn parse_callback(url_str: &str) -> Option<OAuthCallbackData> {
        if url_str.len() > 8192 || !url_str.starts_with("/callback?") {
            return None;
        }
        // Construct a full URL for parsing
        let full_url = format!("http://localhost{}", url_str);
        let url = Url::parse(&full_url).ok()?;

        // Check if this is the callback path
        if url.path() != "/callback" {
            return None;
        }

        let mut token = None;
        let mut state = None;

        for (key, value) in url.query_pairs() {
            match key.as_ref() {
                "token" if token.is_none() && value.len() <= 4096 => {
                    token = Some(value.to_string())
                }
                "state" if state.is_none() && value.len() <= 256 => state = Some(value.to_string()),
                "token" | "state" => return None,
                _ => {}
            }
        }

        match (token, state) {
            (Some(t), Some(s)) if !t.is_empty() && !s.is_empty() => {
                Some(OAuthCallbackData { token: t, state: s })
            }
            _ => None,
        }
    }

    /// Generate success HTML response
    fn success_html() -> String {
        r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>SwiftTunnel - Login Successful</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #f8fafc;
        }
        .container {
            text-align: center;
            padding: 3rem;
            max-width: 480px;
        }
        .success-icon {
            width: 80px;
            height: 80px;
            background: linear-gradient(135deg, #22c55e 0%, #16a34a 100%);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 1.5rem;
            box-shadow: 0 0 40px rgba(34, 197, 94, 0.3);
            animation: pulse 2s ease-in-out infinite;
        }
        @keyframes pulse {
            0%, 100% { transform: scale(1); box-shadow: 0 0 40px rgba(34, 197, 94, 0.3); }
            50% { transform: scale(1.05); box-shadow: 0 0 60px rgba(34, 197, 94, 0.4); }
        }
        .success-icon svg {
            width: 40px;
            height: 40px;
            fill: white;
        }
        h1 {
            font-size: 1.75rem;
            font-weight: 600;
            margin-bottom: 0.75rem;
            background: linear-gradient(135deg, #f8fafc 0%, #cbd5e1 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        p {
            color: #94a3b8;
            font-size: 1rem;
            line-height: 1.6;
        }
        .hint {
            margin-top: 2rem;
            padding: 1rem;
            background: rgba(255, 255, 255, 0.05);
            border-radius: 0.75rem;
            font-size: 0.875rem;
            color: #64748b;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="success-icon">
            <svg viewBox="0 0 24 24">
                <path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/>
            </svg>
        </div>
        <h1>Login Successful!</h1>
        <p>You've been signed in to SwiftTunnel. Return to the app to continue.</p>
        <div class="hint">You can close this window now.</div>
    </div>
</body>
</html>"#
            .to_string()
    }

    /// Generate error HTML response
    fn error_html(message: &str) -> String {
        format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>SwiftTunnel - Login Error</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #f8fafc;
        }}
        .container {{
            text-align: center;
            padding: 3rem;
            max-width: 480px;
        }}
        .error-icon {{
            width: 80px;
            height: 80px;
            background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 1.5rem;
            box-shadow: 0 0 40px rgba(239, 68, 68, 0.3);
        }}
        .error-icon svg {{
            width: 40px;
            height: 40px;
            fill: white;
        }}
        h1 {{
            font-size: 1.75rem;
            font-weight: 600;
            margin-bottom: 0.75rem;
        }}
        p {{
            color: #94a3b8;
            font-size: 1rem;
            line-height: 1.6;
        }}
        .message {{
            margin-top: 1rem;
            padding: 1rem;
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid rgba(239, 68, 68, 0.2);
            border-radius: 0.75rem;
            color: #fca5a5;
            font-size: 0.875rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="error-icon">
            <svg viewBox="0 0 24 24">
                <path d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z"/>
            </svg>
        </div>
        <h1>Login Failed</h1>
        <p>Something went wrong during sign-in. Please try again in the app.</p>
        <div class="message">{}</div>
    </div>
</body>
</html>"#,
            message
        )
    }

    /// Check if a callback has been received (non-blocking)
    pub fn try_recv_callback(&self) -> Option<OAuthCallbackData> {
        self.receiver.try_recv().ok()
    }

    /// Stop the OAuth server
    pub fn stop(&mut self) {
        info!("Stopping OAuth server");
        self.stop_flag.store(true, Ordering::Relaxed);

        // A stalled browser response must not hang cancellation or app exit.
        if let Some(handle) = self.thread_handle.take() {
            handle.thread().unpark();
            let deadline = std::time::Instant::now() + Duration::from_millis(500);
            while !handle.is_finished() && std::time::Instant::now() < deadline {
                thread::sleep(Duration::from_millis(10));
            }
            if handle.is_finished() {
                let _ = handle.join();
            } else {
                warn!("OAuth callback worker did not stop within 500ms; continuing shutdown");
            }
        }
    }
}

impl Drop for OAuthServer {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_server() -> OAuthServer {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        OAuthServer::start_with_listener(listener, port, "fixture".into()).unwrap()
    }

    fn fixture_peer(port: u16) -> TcpStream {
        let peer = TcpStream::connect(("127.0.0.1", port)).unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(4))).unwrap();
        peer.set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        peer
    }

    #[test]
    fn incomplete_request_expires_and_a_later_valid_callback_still_works() {
        let server = fixture_server();
        let mut slow_peer = fixture_peer(server.port());
        slow_peer
            .write_all(b"GET /callback?token=x&state=fixture HTTP/1.1\r\nHost: local")
            .unwrap();
        let mut response = [0u8; 64];
        let read = slow_peer.read(&mut response).unwrap();
        assert!(response[..read].starts_with(b"HTTP/1.1 400"));
        assert!(server.try_recv_callback().is_none());

        let mut valid_peer = fixture_peer(server.port());
        valid_peer
            .write_all(
                b"GET /callback?token=valid&state=fixture HTTP/1.1\r\nHost: localhost\r\n\r\n",
            )
            .unwrap();
        let read = valid_peer.read(&mut response).unwrap();
        assert!(response[..read].starts_with(b"HTTP/1.1 200"));
        assert_eq!(server.try_recv_callback().unwrap().token, "valid");
        assert!(server.try_recv_callback().is_none());
    }

    #[test]
    fn request_bodies_and_malformed_headers_do_not_consume_a_callback() {
        let server = fixture_server();
        for header in [
            "Content-Length: 1\r\n",
            "Content-Length: not-a-number\r\n",
            "Transfer-Encoding: chunked\r\n",
            "Bad Header: value\r\n",
            &"X-Fixture: x\r\n".repeat(65),
        ] {
            let mut peer = fixture_peer(server.port());
            let request = format!(
                "GET /callback?token=x&state=fixture HTTP/1.1\r\nHost: localhost\r\n{header}\r\n"
            );
            // No advertised body is sent: reject framing before waiting for it.
            peer.write_all(request.as_bytes()).unwrap();
            let mut response = [0u8; 64];
            let read = peer.read(&mut response).unwrap();
            assert!(response[..read].starts_with(b"HTTP/1.1 400"));
            assert!(server.try_recv_callback().is_none());
        }
    }

    #[test]
    fn stopping_an_active_partial_header_reader_releases_its_socket() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let (accepted, ready) = mpsc::sync_channel(1);
        let (completed, done) = mpsc::sync_channel(1);
        let worker = thread::spawn(move || {
            let (mut peer, _) = listener.accept().unwrap();
            accepted.send(()).unwrap();
            let result = OAuthServer::read_target(&mut peer, &worker_stop);
            drop(peer);
            completed
                .send(result.map_err(|error| error.kind()))
                .unwrap();
        });
        let mut peer = fixture_peer(port);
        peer.write_all(b"GET /callback?").unwrap();
        ready.recv_timeout(Duration::from_secs(2)).unwrap();
        stop.store(true, Ordering::Relaxed);
        let outcome = done.recv_timeout(Duration::from_secs(1));
        // Always join our owned worker, even if cancellation regresses.
        drop(peer);
        worker.join().unwrap();
        assert_eq!(outcome.unwrap(), Err(io::ErrorKind::Interrupted));
    }

    #[test]
    fn oversized_unfinished_headers_are_rejected_without_waiting_for_the_peer() {
        use std::io::{Read, Write};
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut server =
            OAuthServer::start_with_listener(listener, port, "fixture".into()).unwrap();
        let mut peer = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        peer.set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut request =
            b"GET /callback?token=x&state=fixture HTTP/1.1\r\nHost: localhost\r\nX-Fill: ".to_vec();
        request.extend(std::iter::repeat_n(b'x', 20 * 1024));
        peer.write_all(&request).unwrap();
        let mut response = [0u8; 64];
        let result = peer.read(&mut response);
        drop(peer);
        server.stop();
        assert!(
            result
                .as_ref()
                .is_ok_and(|count| *count > 0 && response[..*count].starts_with(b"HTTP/1.1 400")),
            "unfinished header was not rejected: {result:?}"
        );
        assert!(server.try_recv_callback().is_none());
    }

    #[test]
    fn callback_log_paths_bound_untrusted_text_and_cannot_inject_log_lines() {
        let input = format!(
            "/{}?token=secret-token&state=secret-state",
            "界".repeat(10_000)
        );
        let logged = OAuthServer::log_safe_path(&input);
        assert!(logged.chars().count() <= 131);
        assert!(!logged.contains("secret"));
        let logged = OAuthServer::log_safe_path("/bad\nforged-line\r\0?token=secret");
        assert!(!logged.chars().any(char::is_control));
    }

    #[tokio::test]
    async fn stale_or_invalid_requests_do_not_consume_the_pending_sign_in() {
        // An owned ephemeral port avoids the real app's callback listener.
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = OAuthServer::start_with_listener(listener, port, "current".into()).unwrap();
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap();
        let base = format!("http://127.0.0.1:{port}");
        for (method, path) in [
            (reqwest::Method::GET, "/callback?token=old&state=previous"),
            (
                reqwest::Method::GET,
                "/callback?token=x&state=current&state=previous",
            ),
            (reqwest::Method::POST, "/callback?token=x&state=current"),
            (reqwest::Method::GET, "/favicon.ico"),
        ] {
            let response = client
                .request(method, format!("{base}{path}"))
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
            assert!(server.try_recv_callback().is_none());
        }
        let response = client
            .get(format!("{base}/callback?token=valid&state=current"))
            .send()
            .await
            .unwrap();
        assert!(response.status().is_success());
        let callback = server
            .try_recv_callback()
            .expect("current callback delivered");
        assert_eq!(callback.state, "current");
        assert_eq!(callback.token, "valid");
        assert!(server.try_recv_callback().is_none());
    }

    #[test]
    fn callback_rejects_duplicate_and_oversized_credentials() {
        for path in [
            "/callback?token=first&token=second&state=s".to_string(),
            "/callback?token=t&state=first&state=second".to_string(),
            format!("/callback?token={}&state=s", "t".repeat(4097)),
            format!("/callback?token=t&state={}", "s".repeat(257)),
            format!("/callback?token=t&state=s&extra={}", "x".repeat(8192)),
        ] {
            assert!(OAuthServer::parse_callback(&path).is_none());
        }
        assert!(OAuthServer::start("").is_err());
        assert!(OAuthServer::start(&"s".repeat(257)).is_err());
    }

    #[test]
    fn cancellation_does_not_wait_forever_for_a_stalled_browser_worker() {
        let (release, rescue) = mpsc::channel::<()>();
        let (done, finished) = mpsc::channel();
        let (_, receiver) = mpsc::channel();
        let worker = thread::spawn(move || {
            let _ = rescue.recv();
        });
        let cancel = thread::spawn(move || {
            let mut server = OAuthServer {
                receiver,
                stop_flag: Arc::new(AtomicBool::new(false)),
                thread_handle: Some(worker),
                port: 0,
            };
            server.stop();
            let _ = done.send(());
        });
        let completed = finished.recv_timeout(Duration::from_secs(2)).is_ok();
        let _ = release.send(());
        cancel.join().unwrap();
        assert!(
            completed,
            "OAuth cancellation waited indefinitely for the worker"
        );
    }

    #[test]
    fn test_parse_callback_valid() {
        let result = OAuthServer::parse_callback("/callback?token=abc123&state=xyz789");
        assert!(result.is_some());
        let data = result.unwrap();
        assert_eq!(data.token, "abc123");
        assert_eq!(data.state, "xyz789");
    }

    #[test]
    fn test_parse_callback_missing_token() {
        let result = OAuthServer::parse_callback("/callback?state=xyz789");
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_callback_missing_state() {
        let result = OAuthServer::parse_callback("/callback?token=abc123");
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_callback_wrong_path() {
        let result = OAuthServer::parse_callback("/other?token=abc123&state=xyz789");
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_callback_empty_token() {
        let result = OAuthServer::parse_callback("/callback?token=&state=xyz789");
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_callback_url_encoded() {
        let result = OAuthServer::parse_callback("/callback?token=abc%20123&state=xyz%2B789");
        assert!(result.is_some());
        let data = result.unwrap();
        assert_eq!(data.token, "abc 123");
        assert_eq!(data.state, "xyz+789");
    }
}
