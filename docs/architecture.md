# NetScope Architecture

## 1. Crate Boundaries

```text
+-------------------------------------------------------+
|                   crates/netscope-app                 |
|  eframe 0.37 (App::logic + App::ui) | tray-icon 0.26  |
|  Views: Internet Check, Ping, Traceroute, MTR,        |
|         DNS Lookup, SSL Certificate                   |
+---------------------------+---------------------------+
                            | tokio::sync::mpsc + ctx.request_repaint()
                            v
+-------------------------------------------------------+
|                   crates/netscope-core                |
|  Pure async diagnostics engine (zero UI dependencies) |
|  net_info | icmp | internet_check | dns | tls | stats |
+-------------------------------------------------------+
```

- **`netscope-core`** owns all networking, probing, DNS, TLS verification, GeoIP classification, speed testing, `iperf3` orchestration, persistent state (`history.rs`), and statistical calculation. It can be driven by the GUI, future CLI subcommands, or automated tests without linking `eframe`/`wgpu`.
- **`netscope-app`** owns the Tokio multi-thread runtime (`rt`), background task cancellation (`tokio_util` is avoided by using `std::sync::Arc<AtomicBool>` / `tokio::sync::watch` to minimize crates), `eframe::App` state, `egui` rendering, and the OS tray icon.

---

## 2. Concurrency & Hidden-Window Loop (`eframe 0.37`)

`eframe 0.37` splits `App` into two callbacks:
1. `App::logic(&mut self, ctx, frame)` — invoked before `ui()`, and **also invoked while the main window is hidden** whenever `ctx.request_repaint()` or `ctx.request_repaint_after(...)` triggers.
2. `App::ui(&mut self, ui, frame)` — invoked only while the window is visible.

### Data Flow
- Background tasks spawned on `self.rt` send incremental updates over bounded/unbounded `std::sync::mpsc::Sender` or `tokio::sync::mpsc::UnboundedSender`, then immediately call `ctx.request_repaint()`.
- `App::logic()` drains pending messages from active tools and the 60-second background network monitor, polls `tray-icon` / `MenuEvent` receivers, handles `CloseRequested -> Hide to Tray`, and refreshes tray menu labels (`Public IP`, `VPN`, `DNS Leak`).
- When the window is hidden, `App::logic()` calls `ctx.request_repaint_after(Duration::from_millis(250))` so tray menu clicks react within 250ms while consuming negligible CPU.

---

## 3. Unprivileged ICMP Design (`icmp.rs`)

- Uses `socket2::Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4))` (and `IPV6` / `ICMPV6` for IPv6 targets) inside `tokio::task::spawn_blocking`.
- Each probe opens a lightweight socket, sets `IP_TTL` / `unicast_hops_v6` and `SO_RCVTIMEO`, transmits an ICMP Echo Request (`type = 8, code = 0` for v4; `type = 128, code = 0` for v6) with a unique monotonic `(identifier, sequence)`, and reads the reply:
  - **macOS cross-socket delivery quirk:** Empirically verified on macOS: `SOCK_DGRAM` `IPPROTO_ICMP` delivers incoming ICMP packets (including `TimeExceeded` and `DestUnreach` triggered by unrelated traffic) across all open ICMP sockets on the host, prepended with the 20+ byte IPv4 header (`buf[0] >> 4 == 4`). The parser detects the version nibble, advances by `ihl = (buf[0] & 0x0f) * 4`, and strictly filters both `EchoReply` `(id, seq)` AND the embedded original IP+ICMP `(id, seq)` inside `TimeExceeded` / `DestUnreach` payloads while clamping remaining `SO_RCVTIMEO`.
  - **Linux behavior:** Kernel strips the IPv4 header before delivering to userspace and rewrites `id` to the socket's bound port (`local_addr().port()`), which the matcher accepts alongside the transmitted `id`.
  - **Fallback:** If socket creation returns `PermissionDenied` (e.g., restricted Linux sysctl `net.ipv4.ping_group_range` or Windows), Ping falls back cleanly to system `ping` output parsing.
- **MTR:** First runs a fast parallel TTL discovery pass (`1..=max_hops`), then continuously sends one probe per active hop each interval round, accumulating per-hop RTT stats, a 40-slot ring buffer for the loss/latency heatmap, and consecutive-loss outage events.

---

## 4. TLS Inspection & Custom CA Verification (`tls.rs`)

- Installs `rustls::crypto::aws_lc_rs::default_provider()` once per process.
- Uses a custom `CapturingCertVerifier` implementing `rustls::client::danger::ServerCertVerifier`:
  1. Captures `end_entity` + `intermediates` DER certificates.
  2. Runs native OS trust verification via `rustls_platform_verifier::Verifier` (validates chain, hostname/SNI, time validity against macOS Keychain / Linux OpenSSL trust / Windows CryptoAPI).
  3. Optionally validates the captured chain against a user-supplied PEM CA bundle (`WebPkiServerVerifier` with custom `RootCertStore`) — useful for corporate MITM proxies and private PKIs.
  4. Returns `ServerCertVerified::assertion()` so the handshake finishes and reports negotiated TLS version and cipher suite even on broken/expired/untrusted endpoints.
- `x509-parser` extracts full metadata (CN, SANs, key algorithm & bits, signature algorithm, validity countdown, SHA-256 fingerprint, PEM export).
