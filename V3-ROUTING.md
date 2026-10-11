# V3 routing: authenticated, unencrypted UDP relay

## Overview

SwiftTunnel forwards selected game traffic through a relay. The UDP relay does
not add encryption or per-packet cryptographic integrity. Its signed-ticket
handshake authorizes use of the relay; it is not an encrypted tunnel handshake.
Whether a route is faster depends on both network legs and current conditions.
There is no fixed latency advantage over a direct connection or another protocol.

This describes the app and the current relay implementation. For relay deployment
options, see the [relay README](https://github.com/Swift-tunnel/swifttunnel-relay/blob/main/README.md).
Operator settings and older deployments may differ; this document is not a live
fleet audit. Legacy WireGuard mode comparisons are not specifications for V3.

## Packet framing

The first eight bytes identify the session. Data frames carry an **IP packet**,
including the destination, rather than just an unaddressed UDP payload.

```text
Client -> Relay: [session_id:8][inner IP packet]
Client -> Relay: [session_id:8][0xA1][token_len:2][relay_ticket_utf8]
Client -> Relay: [session_id:8][0xA3][seq:4][client_ts_mono_ms:8]
Relay -> Client: [session_id:8][reconstructed IP packet]
Relay -> Client: [session_id:8][0xA2][status:1]
Relay -> Client: [session_id:8][0xA4][seq:4][client_ts_mono_ms:8][server_rx_ts_mono_ms:8]
```

Control-frame numeric fields use network byte order. The default user-space UDP
datapath extracts the inner UDP payload and sends it to the game server; replies
are rebuilt as IP packets before returning to the client. TUN-backed forwarding
can handle TCP and optionally UDP with the same client-facing session prefix.
The list above covers data, authentication and ping/pong, not every optional
control frame supported by newer relays.

The relay's default UDP port is 51821. Clients use the address and port from the
server-list API rather than assuming every relay uses that port. Current app
keepalive/ping scheduling uses a 15-second interval. A ping/pong measures the
client-to-relay round trip, not the round trip to Roblox.

## Tickets and session authorization

1. The signed-in app chooses a relay and generates a random eight-byte session ID.
2. It requests a short-lived ticket over HTTPS from `/api/vpn/relay-ticket`, using
   its account authentication and the selected relay/session identifiers.
3. The app sends the ticket in an `0xA1` authentication frame to that relay.
4. The relay verifies the Ed25519 signature using its configured public key. The
   ticket is encoded as a base64 payload and signature separated by a dot; the
   signature covers the decoded claims. Validation checks the version, issuer,
   audience, account (`sub`), session (`sid`), relay (`srv`), issued/expiry times,
   lease flag and unique ticket identifier (`jti`).
5. The relay rejects spent tickets. Each `jti` can be accepted once within the
   replay-cache lifetime. Reuse returns status 7, not successful authentication.
6. The app requires an `0xA2` acknowledgment with status 0 (`Ok`) before treating
   the relay as authenticated. A timeout or rejection is not a successful connect.
7. The current client refreshes its ticket/lease on a 120-second schedule. The
   signed expiry remains authoritative; refreshing is not an unlimited grant.
   Quota or account rejection terminates the connection. The official clients
   also count down the server-reported remaining free allowance locally.

The current relay defaults to `RELAY_AUTH_MODE=required`. Both `required` and
`optional` gate forwarding on valid authentication. Turning authentication off
requires the explicit unsafe opt-in `RELAY_ALLOW_INSECURE=1`; it is not an
equivalent secure configuration.

The relay binds authenticated sessions to an account and a validated client
endpoint. A bare session ID does not authorize changing the session owner or
moving return traffic to another IP. Endpoint changes require reauthentication
under the deployed relay's policy; current source validates the full socket
address for ordinary packets. Expired leases stop forwarding, including replies.
The relay also applies destination policy and resource limits; those controls
depend on the deployed configuration.

## Connection and routing behavior

The app fetches the server list, authenticates its selected relay, and configures
Windows packet interception for eligible processes. V3 does not need a WireGuard
handshake or a Wintun adapter. Route Assist and country-bypass modes can route
additional Roblox web/API traffic, so V3 is not limited to gameplay UDP in every
configuration.

- Initial selection can use measured client-to-relay latency. Once a game target
  is known, available second-leg measurements can estimate the full route.
- Estimated game ping adds two measured round trips. It is labelled as an
  estimate, not Roblox's own NetworkPing. Missing measurements are not zero ping.
- Regional Automatic compares relays in the selected region at eligible game
  join boundaries. A manually pinned relay remains selected.
- Every automatic switch authenticates the candidate before changing the route.
  Failed authentication leaves traffic on the existing authenticated relay.
- Active game flows are not moved just because a new latency sample arrives.
  Changing the relay's public source IP can break the game's connection.
- Manual pins, custom relays, Route Assist and country bypass retain their own
  routing policies; regional Automatic does not override those modes.

Win32 Roblox player/studio matching uses known process names, not broad substring
matches. The generic `Windows10Universal.exe` Store-app host is not eligible.
Process filtering is a client behavior, not proof of process identity available
to a remote relay.

### Traffic QoS

On Windows the client marks its relay UDP socket with DSCP EF (46) on a best-effort
basis. Networks can ignore or change that marking. The latency network throttling
boost can add a SwiftTunnel-process/UDP-scoped QoS policy and restores snapshotted
global QoS registry values on cleanup. Do not restore the removed broad Gaming
QoS policies for Roblox executables or `Windows10Universal.exe`.

## Security limits

Signed tickets prevent a client from inventing an account authorization or lease
without the signing key. Session/source checks and replay rejection limit specific
forms of unauthorized reuse. They do **not** encrypt the ticket, authenticate every
data packet, or authenticate the relay's acknowledgment cryptographically.

For the UDP transport, an on-path observer can see the outer addresses, session
ID, authentication frame, visible ticket claims, inner addressing, packet sizes
and timing, and any payload that lacks independent encryption. An on-path attacker
may modify, inject, delay or drop traffic. A relay operator can inspect the inner
traffic it forwards. The eight-byte session ID is not a secret encryption key.

HTTPS to SwiftTunnel's website protects login and ticket fetching in transit.
Relayed HTTPS remains protected by its own TLS connection, provided the client
validates certificates. Any encryption supplied by Roblox applies independently;
this document does not claim every game packet is encrypted or audit Roblox's
transport. Neither an allowlist nor process filtering provides confidentiality.

The destination normally sees the relay's public IP for forwarded traffic. That
does not make SwiftTunnel an anonymity service or protect all traffic on the PC.
Report suspected vulnerabilities through [SECURITY.md](SECURITY.md).

## Implementation and troubleshooting

| Source | Responsibility |
|---|---|
| `swifttunnel-core/src/vpn/udp_relay.rs` | Framing, auth handshake, ping/pong, relay socket |
| `swifttunnel-core/src/vpn/connection.rs` | Connection lifecycle, lease refresh and cleanup |
| `swifttunnel-core/src/vpn/auto_routing.rs` | Guarded route selection at join boundaries |
| `swifttunnel-core/src/vpn/route_measurements.rs` | Measured route estimates |
| `swifttunnel-core/src/vpn/parallel_interceptor.rs` | Packet interception and inbound delivery |
| Relay repository `src/main.rs` and datapaths | Ticket validation and forwarding enforcement |

Check failures in order: website/sign-in reachability, ticket issuance, relay auth
acknowledgment, outbound packets, return packets and Windows injection. A responding
relay ping does not prove the game destination is reachable. Check the actual
API-provided relay endpoint rather than testing a hardcoded relay ID or port.
For support, include app version, selected relay, approximate failure time and a
sanitized diagnostic log. Do not post live tickets or authentication credentials.
