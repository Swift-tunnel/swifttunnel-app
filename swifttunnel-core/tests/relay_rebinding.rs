//! Explicit local cross-repository check. Build swifttunnel-relay, set
//! SWIFTTUNNEL_TEST_RELAY_BINARY to that binary, then run this ignored test.
//! No driver, TUN, external network, or production credentials are used.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::{
    net::{SocketAddr, TcpListener, TcpStream, UdpSocket},
    process::{Child, Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use swifttunnel_core::vpn::udp_relay::{RelayAuthAckStatus, UdpRelay};

struct LocalRelay(Child);
impl Drop for LocalRelay {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn socket() -> UdpSocket {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    socket
}

fn ticket(key: &Ed25519KeyPair, relay: &UdpRelay, jti: &str) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let payload = serde_json::to_vec(&serde_json::json!({
        "v": 1, "iss": "swifttunnel-web", "aud": "swifttunnel-relay",
        "sub": "local-owner", "sid": relay.session_id_hex(), "srv": "local-test",
        "iat": now, "exp": now + 300, "jti": jti, "lease": true
    }))
    .unwrap();
    format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(&payload),
        URL_SAFE_NO_PAD.encode(key.sign(&payload).as_ref())
    )
}

// The client always sees the same relay address. Changing `outside` simulates
// its router replacing only the external UDP source port.
fn proxy_exchange(front: &UdpSocket, outside: &UdpSocket, relay: SocketAddr) -> Vec<u8> {
    let mut frame = [0u8; 2048];
    let (len, client) = front.recv_from(&mut frame).unwrap();
    outside.send_to(&frame[..len], relay).unwrap();
    let (len, source) = outside.recv_from(&mut frame).unwrap();
    assert_eq!(source, relay);
    front.send_to(&frame[..len], client).unwrap();
    frame[..len].to_vec()
}

#[tokio::test]
#[ignore = "requires SWIFTTUNNEL_TEST_RELAY_BINARY pointing to a local relay build"]
async fn real_relay_recovers_changed_nat_port_with_fresh_owner_ticket() {
    let binary = std::env::var_os("SWIFTTUNNEL_TEST_RELAY_BINARY")
        .expect("set SWIFTTUNNEL_TEST_RELAY_BINARY to a locally built relay");
    let key = Ed25519KeyPair::from_seed_unchecked(&[42; 32]).unwrap();
    for datapath in ["v1", "v2"] {
        let reserved = socket();
        let server_addr = reserved.local_addr().unwrap();
        drop(reserved);
        let stats = TcpListener::bind("127.0.0.1:0").unwrap();
        let stats_addr = stats.local_addr().unwrap();
        drop(stats);
        let mut command = Command::new(&binary);
        command
            .env_clear()
            .env("RELAY_PORT", server_addr.port().to_string())
            .env("RELAY_STATS_PORT", stats_addr.port().to_string())
            .env("RELAY_STATS_TOKEN", "local-test")
            .env("RELAY_HEALTH_PORT", "0")
            .env("RELAY_AUTH_MODE", "required")
            .env(
                "RELAY_AUTH_PUBLIC_KEY_B64",
                URL_SAFE_NO_PAD.encode(key.public_key().as_ref()),
            )
            .env("RELAY_SERVER_ID", "local-test")
            .env("RELAY_DATAPATH", datapath)
            .env("RELAY_TCP_ENABLED", "false")
            .env("RELAY_TUN_UDP", "false")
            .env("RELAY_SHARDS", "1")
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            // Windows networking needs the system directory in the environment.
            if let Some(root) = std::env::var_os("SystemRoot") {
                command.env("SystemRoot", root);
            }
            command.creation_flags(0x08000000);
        }
        let _child = LocalRelay(command.spawn().unwrap());
        let deadline = Instant::now() + Duration::from_secs(5);
        while TcpStream::connect_timeout(&stats_addr, Duration::from_millis(50)).is_err() {
            assert!(Instant::now() < deadline, "{datapath} did not start");
            std::thread::sleep(Duration::from_millis(20));
        }

        let front = socket();
        let original = socket();
        let changed = socket();
        let client = UdpRelay::new(front.local_addr().unwrap()).unwrap();
        let mut buffer = [0u8; 2048];
        let first = ticket(&key, &client, "initial");
        let mut auth =
            Box::pin(client.authenticate_addr_with_ticket(&first, front.local_addr().unwrap()));
        assert!(futures_util::poll!(auth.as_mut()).is_pending());
        assert_eq!(proxy_exchange(&front, &original, server_addr)[9], 0);
        assert!(
            client
                .receive_inbound_payload(&mut buffer)
                .unwrap()
                .is_none()
        );
        assert_eq!(auth.await.unwrap(), Some(RelayAuthAckStatus::Ok));

        // An authenticated ping is a processing barrier, before moving ports.
        client.send_keepalive_now().unwrap();
        assert_eq!(proxy_exchange(&front, &original, server_addr)[8], 0xa4);
        assert!(
            client
                .receive_inbound_payload(&mut buffer)
                .unwrap()
                .is_none()
        );

        client.send_keepalive_now().unwrap();
        let hint = proxy_exchange(&front, &changed, server_addr);
        assert_eq!(
            &hint[8..],
            &[0xa2, 9],
            "{datapath} accepted an unverified port"
        );
        assert!(
            client
                .receive_inbound_payload(&mut buffer)
                .unwrap()
                .is_none()
        );
        tokio::time::timeout(
            Duration::from_millis(100),
            client.wait_for_lease_refresh(Duration::from_secs(120)),
        )
        .await
        .expect("real relay hint did not wake client renewal");

        // Substitute a locally signed ticket for the web request. Exercise the
        // production client handshake and relay verification/endpoint update.
        let fresh = ticket(&key, &client, "rebound");
        let mut auth =
            Box::pin(client.authenticate_addr_with_ticket(&fresh, front.local_addr().unwrap()));
        assert!(futures_util::poll!(auth.as_mut()).is_pending());
        assert_eq!(proxy_exchange(&front, &changed, server_addr)[9], 0);
        assert!(
            client
                .receive_inbound_payload(&mut buffer)
                .unwrap()
                .is_none()
        );
        assert_eq!(auth.await.unwrap(), Some(RelayAuthAckStatus::Ok));
        client.send_keepalive_now().unwrap();
        assert_eq!(proxy_exchange(&front, &changed, server_addr)[8], 0xa4);
        assert!(
            client
                .receive_inbound_payload(&mut buffer)
                .unwrap()
                .is_none()
        );

        // Knowledge of the session id from the old endpoint cannot move it back.
        let mut ping = client.session_id_bytes().to_vec();
        ping.push(0xa3);
        ping.extend_from_slice(&[0; 12]);
        original.send_to(&ping, server_addr).unwrap();
        let len = original.recv(&mut buffer).unwrap();
        assert_eq!(&buffer[8..len], &[0xa2, 9]);
        client.send_keepalive_now().unwrap();
        assert_eq!(proxy_exchange(&front, &changed, server_addr)[8], 0xa4);
        assert!(
            client
                .receive_inbound_payload(&mut buffer)
                .unwrap()
                .is_none()
        );
    }
}
