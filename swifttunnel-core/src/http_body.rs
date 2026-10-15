//! Bound downloaded bodies before parsing or signature verification.

pub async fn read_json_bounded<T: serde::de::DeserializeOwned>(
    response: reqwest::Response,
    max_bytes: usize,
    what: &str,
) -> Result<T, String> {
    let bytes = read_bounded(response, max_bytes, what).await?;
    serde_json::from_slice(&bytes)
        .map_err(|_| format!("Could not read the {what}. Please try again."))
}

pub async fn read_bounded(
    mut response: reqwest::Response,
    max_bytes: usize,
    what: &str,
) -> Result<Vec<u8>, String> {
    let too_large = || format!("The {what} exceeds its {max_bytes} byte download limit.");
    if response
        .content_length()
        .is_some_and(|len| len > max_bytes as u64)
    {
        return Err(too_large());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| format!("Could not finish downloading the {what}. Please try again."))?
    {
        if chunk.len() > max_bytes.saturating_sub(bytes.len()) {
            return Err(too_large());
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[tokio::test]
    async fn json_reader_accepts_valid_json_and_rejects_malformed_or_oversized_bodies() {
        for (body, limit, expected) in [
            (r#"{"ok":true}"#, 32, Some(serde_json::json!({"ok":true}))),
            (r#"{"ok":"#, 32, None),
            (r#"{"ok":true}"#, 4, None),
        ] {
            let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
            let address = server.server_addr().to_ip().unwrap();
            let worker = std::thread::spawn(move || {
                let request = server
                    .recv_timeout(std::time::Duration::from_secs(3))
                    .unwrap()
                    .unwrap();
                let _ = request.respond(tiny_http::Response::from_string(body));
            });
            let response = reqwest::Client::builder()
                .no_proxy()
                .timeout(std::time::Duration::from_secs(2))
                .build()
                .unwrap()
                .get(format!("http://{address}"))
                .send()
                .await
                .unwrap();
            let result = read_json_bounded::<serde_json::Value>(response, limit, "test JSON").await;
            match expected {
                Some(expected) => assert_eq!(result.unwrap(), expected),
                None => assert!(result.is_err()),
            }
            worker.join().unwrap();
        }
    }

    async fn serve_and_read(wire: &'static [u8], limit: usize) -> Result<Vec<u8>, String> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (done, finish) = std::sync::mpsc::channel::<()>();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                .unwrap();
            let mut request = [0; 4096];
            let _ = socket.read(&mut request);
            let _ = socket.write_all(wire);
            // Deliberately keep oversized chunked bodies unfinished. Rejection
            // must happen before EOF, rather than after buffering everything.
            let _ = finish.recv_timeout(std::time::Duration::from_secs(3));
        });
        let response = reqwest::Client::builder()
            .no_proxy()
            .timeout(std::time::Duration::from_secs(2))
            .build()
            .unwrap()
            .get(format!("http://{address}"))
            .send()
            .await
            .unwrap();
        let result = read_bounded(response, limit, "test download").await;
        let _ = done.send(());
        server.join().unwrap();
        result
    }

    #[tokio::test]
    async fn rejects_chunked_overflow_before_end_of_body() {
        let result = serve_and_read(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n8\r\n12345678\r\n8\r\nabcdefgh\r\n", 12).await;
        assert!(result.unwrap_err().contains("download limit"));
    }

    #[tokio::test]
    async fn accepts_chunked_body_exactly_at_limit() {
        assert_eq!(serve_and_read(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n1234\r\n4\r\n5678\r\n0\r\n\r\n", 8).await.unwrap(), b"12345678");
    }

    #[tokio::test]
    async fn rejects_oversized_content_length_without_reading_body() {
        assert!(
            serve_and_read(b"HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\n", 8)
                .await
                .unwrap_err()
                .contains("download limit")
        );
    }
}
