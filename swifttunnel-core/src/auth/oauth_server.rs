//! Localhost HTTP server for OAuth callbacks
//!
//! This module implements a lightweight localhost HTTP server that receives
//! OAuth callbacks from the browser. This approach is more reliable than
//! deep links because:
//! - No second app instance is launched
//! - Works on all Windows versions
//! - Industry standard (used by Discord, Slack, VS Code, Spotify)

use log::{debug, error, info, warn};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread::{self, JoinHandle};
use std::time::Duration;
use tiny_http::{Method, Response, Server, StatusCode};
use url::Url;

/// Default port for OAuth callback server
pub const DEFAULT_OAUTH_PORT: u16 = 17435;

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
        let (server, port) = match Server::http(format!("127.0.0.1:{}", DEFAULT_OAUTH_PORT)) {
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
                match Server::http("127.0.0.1:0") {
                    Ok(s) => {
                        let port = s.server_addr().to_ip().map(|a| a.port()).unwrap_or(0);
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
        server: Server,
        port: u16,
        expected_state: String,
    ) -> Result<Self, String> {
        let (tx, rx) = mpsc::channel();
        let stop_flag = Arc::new(AtomicBool::new(false));
        let stop_flag_clone = Arc::clone(&stop_flag);

        // Note: recv_timeout is used in run_server to check stop flag periodically

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

    /// Run the HTTP server and handle requests
    fn run_server(
        server: Server,
        tx: Sender<OAuthCallbackData>,
        stop_flag: Arc<AtomicBool>,
        expected_state: String,
    ) {
        info!("OAuth server thread started");

        loop {
            if stop_flag.load(Ordering::Relaxed) {
                info!("OAuth server received stop signal");
                break;
            }

            // Try to receive a request with timeout
            match server.recv_timeout(Duration::from_millis(100)) {
                Ok(Some(request)) => {
                    let url_str = request.url();
                    // Path only. The query on this callback carries the
                    // exchange token, which is redeemable for a session, and
                    // the state that binds it. Logging the whole URL put a live
                    // credential in a file users routinely attach to support
                    // tickets.
                    info!(
                        "OAuth server received request: {} (query omitted)",
                        Self::log_safe_path(url_str)
                    );

                    // A previous browser tab may reach the reused port after a
                    // new attempt starts. Ignore it without consuming the new
                    // attempt's one callback. The manager also verifies state
                    // before exchanging the token.
                    let callback = (request.method() == &Method::Get)
                        .then(|| Self::parse_callback(url_str))
                        .flatten()
                        .filter(|callback| callback.state == expected_state);
                    match callback {
                        Some(callback) => {
                            info!("OAuth callback parsed successfully");

                            // Deliver independently of whether the browser is
                            // still connected or can accept the response.
                            if let Err(e) = tx.send(callback) {
                                error!("Failed to send callback data: {}", e);
                            }

                            // Send success response to browser
                            let html = Self::success_html();
                            let response = Response::from_string(html)
                                .with_status_code(StatusCode(200))
                                .with_header(
                                    tiny_http::Header::from_bytes(
                                        &b"Content-Type"[..],
                                        &b"text/html; charset=utf-8"[..],
                                    )
                                    .unwrap(),
                                );

                            if let Err(e) = request.respond(response) {
                                warn!("Failed to send success response: {}", e);
                            }

                            // We're done after receiving the callback
                            break;
                        }
                        None => {
                            // Invalid request - send error response
                            warn!(
                                "Invalid OAuth callback request: {} (query omitted)",
                                Self::log_safe_path(url_str)
                            );
                            let html = Self::error_html("Invalid callback parameters");
                            let response = Response::from_string(html)
                                .with_status_code(StatusCode(400))
                                .with_header(
                                    tiny_http::Header::from_bytes(
                                        &b"Content-Type"[..],
                                        &b"text/html; charset=utf-8"[..],
                                    )
                                    .unwrap(),
                                );
                            let _ = request.respond(response);
                        }
                    }
                }
                Ok(None) => {
                    // Timeout, no request received - continue loop
                }
                Err(e) => {
                    // Connection error or timeout, continue
                    debug!("OAuth server recv error (likely timeout): {}", e);
                }
            }
        }

        info!("OAuth server thread exiting");
    }

    /// The path of a request URL, with the query discarded.
    ///
    /// Everything sensitive on this server arrives in the query string: the
    /// exchange token, which redeems for a session, and the state that binds
    /// it. The path alone still tells support whether the browser reached us
    /// and on which route, which is the whole diagnostic value of the line.
    fn log_safe_path(url_str: &str) -> &str {
        url_str.split(['?', '#']).next().unwrap_or("/")
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

    #[tokio::test]
    async fn stale_or_invalid_requests_do_not_consume_the_pending_sign_in() {
        // An owned ephemeral port avoids the real app's callback listener.
        let listener = Server::http("127.0.0.1:0").unwrap();
        let port = listener.server_addr().to_ip().unwrap().port();
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
