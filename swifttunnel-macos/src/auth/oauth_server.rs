//! Localhost HTTP server for OAuth callbacks
//!
//! This module implements a lightweight localhost HTTP server that receives
//! OAuth callbacks from the browser. This approach is more reliable than
//! deep links because:
//! - No second app instance is launched
//! - Works on all Windows versions
//! - Industry standard (used by Discord, Slack, VS Code, Spotify)

use log::{debug, error, info, warn};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use std::thread::{self, JoinHandle};
use std::time::Duration;
use tiny_http::{Response, Server, StatusCode};
use url::Url;

/// Default port for OAuth callback server
pub const DEFAULT_OAUTH_PORT: u16 = 17435;

/// Callback data received from OAuth redirect
#[derive(Debug, Clone)]
pub struct OAuthCallbackData {
    pub token: String,
    pub state: String,
}

/// Result from the OAuth server
pub enum OAuthServerResult {
    /// Callback received successfully
    Success(OAuthCallbackData),
    /// Server was stopped before callback received
    Cancelled,
    /// Server encountered an error
    Error(String),
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
    pub fn start() -> Result<Self, String> {
        // Try default port first
        let (server, port) = match Server::http(format!("127.0.0.1:{}", DEFAULT_OAUTH_PORT)) {
            Ok(s) => {
                info!("OAuth server started on port {}", DEFAULT_OAUTH_PORT);
                (s, DEFAULT_OAUTH_PORT)
            }
            Err(e) => {
                warn!("Default port {} unavailable: {}, trying random port", DEFAULT_OAUTH_PORT, e);
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

        let (tx, rx) = mpsc::channel();
        let stop_flag = Arc::new(AtomicBool::new(false));
        let stop_flag_clone = Arc::clone(&stop_flag);

        // Note: recv_timeout is used in run_server to check stop flag periodically

        let thread_handle = thread::spawn(move || {
            Self::run_server(server, tx, stop_flag_clone);
        });

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
    fn run_server(server: Server, tx: Sender<OAuthCallbackData>, stop_flag: Arc<AtomicBool>) {
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
                    info!("OAuth server received request: {}", url_str);

                    // Parse the callback URL
                    match Self::parse_callback(url_str) {
                        Some(callback) => {
                            info!("OAuth callback parsed successfully");

                            // Send success response to browser
                            let html = Self::success_html();
                            let response = Response::from_string(html)
                                .with_status_code(StatusCode(200))
                                .with_header(
                                    tiny_http::Header::from_bytes(
                                        &b"Content-Type"[..],
                                        &b"text/html; charset=utf-8"[..],
                                    ).unwrap()
                                );

                            if let Err(e) = request.respond(response) {
                                warn!("Failed to send success response: {}", e);
                            }

                            // Send callback data to main thread
                            if let Err(e) = tx.send(callback) {
                                error!("Failed to send callback data: {}", e);
                            }

                            // We're done after receiving the callback
                            break;
                        }
                        None => {
                            // Invalid request - send error response
                            warn!("Invalid OAuth callback request: {}", url_str);
                            let html = Self::error_html("Invalid callback parameters");
                            let response = Response::from_string(html)
                                .with_status_code(StatusCode(400))
                                .with_header(
                                    tiny_http::Header::from_bytes(
                                        &b"Content-Type"[..],
                                        &b"text/html; charset=utf-8"[..],
                                    ).unwrap()
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

    /// Parse the callback URL to extract token and state
    fn parse_callback(url_str: &str) -> Option<OAuthCallbackData> {
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
                "token" => token = Some(value.to_string()),
                "state" => state = Some(value.to_string()),
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
</html>"#.to_string()
    }

    /// Generate error HTML response
    fn error_html(message: &str) -> String {
        format!(r#"<!DOCTYPE html>
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
</html>"#, message)
    }

    /// Wait for the OAuth callback with a timeout
    pub fn wait_for_callback(&self, timeout: Duration) -> OAuthServerResult {
        match self.receiver.recv_timeout(timeout) {
            Ok(data) => OAuthServerResult::Success(data),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                info!("OAuth callback timed out");
                OAuthServerResult::Cancelled
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                info!("OAuth server disconnected before callback");
                OAuthServerResult::Cancelled
            }
        }
    }

    /// Check if a callback has been received (non-blocking)
    pub fn try_recv_callback(&self) -> Option<OAuthCallbackData> {
        self.receiver.try_recv().ok()
    }

    /// Stop the OAuth server
    pub fn stop(&mut self) {
        info!("Stopping OAuth server");
        self.stop_flag.store(true, Ordering::Relaxed);

        // Wait for thread to finish
        if let Some(handle) = self.thread_handle.take() {
            let _ = handle.join();
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
