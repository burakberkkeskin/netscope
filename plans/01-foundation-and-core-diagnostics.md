# Plan 01: Foundation, Core Diagnostics Engine & Menu Bar MVP

> **Phase:** 1 of 5
> **Status:** Done (Phase 1 MVP Ready for Review)

---

## 1. Context & Goal (Why)

Build a personal, zero-telemetry, cross-platform native network diagnostics desktop application (**NetScope**) written in pure Rust. Phase 1 establishes the workspace architecture, long-term memory structure, background Menu Bar / System Tray monitor, and the first 6 essential diagnostics tools:
1. **Internet Check** (5-stage visual pipeline diagnosis: This Mac -> Router -> Internet -> DNS -> Web + sparklines + check history)
2. **Ping** (unprivileged ICMP echo + live RTT plot + statistics + sample table)
3. **Traceroute** (hop-by-hop multi-probe ICMP path discovery + reverse DNS PTR)
4. **MTR** (continuous hop stats + 40-round loss/latency heatmap + outage log)
5. **DNS Lookup** (`dig`-style record inspection across System, 1.1.1.1, 8.8.8.8, 9.9.9.9, or Custom resolver)
6. **SSL Certificate Inspector** (live TLS handshake capturing full chain + OS trust evaluation + optional custom CA PEM verification for private/enterprise CAs + explicit failure reasons)

Plus persistent background **Menu Bar / System Tray** status (Public IP, ISP/Org, VPN interface status, DNS Leak check, Show/Hide window on close).

---

## 2. Decisions & Rejected Alternatives (ADR)

### ADR-001: Pure Rust (`eframe`/`egui` + `netscope-core`) over SwiftUI or Tauri
- **Chosen:** Workspace split into UI-free `netscope-core` + `eframe`/`egui` desktop UI (`netscope-app`).
- **Why:** Runs natively on macOS today while keeping Linux and Windows GUI compilation straightforward without WebView, Node.js, or Swift/Rust FFI bridges. `egui` gives direct `Painter` and `egui_plot` control for network pipelines, sparklines, and MTR heatmaps with minimal runtime footprint.
- **Rejected:**
  - *SwiftUI only:* Locks out Linux/Windows workstations.
  - *Tauri v2:* Introduces Node/WebView overhead and higher idle memory for a background tray utility.

### ADR-002: Unprivileged `SOCK_DGRAM` + `IPPROTO_ICMP` over `sudo` raw sockets or shelling out
- **Chosen:** `socket2` datagram ICMP socket (`SOCK_DGRAM`, `Protocol::ICMPV4`) with `IP_TTL`, spawning per-probe sockets in `spawn_blocking`, plus automatic `ping` CLI fallback if `PermissionDenied`.
- **Why:** Verified empirically on macOS 27.2.1 (`arm64`): `SOCK_DGRAM` ICMP returns both `Type 11 Time Exceeded` (at intermediate TTLs) and `Type 0 Echo Reply` without root privileges. Portable response parser strips the 20-byte IPv4 header when `buf[0] >> 4 == 4` (macOS behavior) and accepts raw ICMP directly (Linux behavior).
- **Rejected:** Requiring root privileges / helper daemon in Phase 1 (unnecessary friction).

### ADR-003: `tray-icon` with `ksni` on Linux
- **Chosen:** `tray-icon 0.26` using default native macOS/Windows backends and `ksni` (StatusNotifierItem D-Bus) on Linux.
- **Why:** Eliminates GTK3 / `libappindicator` shared-library runtime dependencies on Linux desktops while sharing one cross-platform tray abstraction.

### ADR-004: Capturing `ServerCertVerifier` in `rustls` for TLS Inspection
- **Chosen:** Custom `CapturingCertVerifier` wrapping `rustls_platform_verifier::Verifier` (and optional custom root store from user PEM file) that records the raw DER chain and verification errors before allowing the inspection handshake to complete.
- **Why:** Standard TLS clients abort before exposing the chain or cipher when a certificate is expired, self-signed, or hostname-mismatched—precisely the cases network engineers need to inspect. Using `rustls-platform-verifier` checks against the real macOS Keychain / OS trust store rather than a static webpki bundle alone.

---

## 3. Execution Checklist

### Repository & Architecture Setup
- [x] Initialize `netscope` git repo, `.gitignore`, `LICENSE`, `AGENTS.md`, `plans/`, `docs/architecture.md`, `README.md`
- [x] Create Cargo workspace (`Cargo.toml`, `crates/netscope-core/Cargo.toml`, `crates/netscope-app/Cargo.toml`)

### `netscope-core` Diagnostics Engine
- [x] `stats.rs`: Latency statistics (`min`, `median`, `avg`, `max`, `jitter`, `stdev`, `loss_pct`) + unit tests
- [x] `net_info.rs`: Local interface & gateway detection (`netdev`), smart VPN tunnel detection, public IP + ISP + DNS egress IP leak check
- [x] `icmp.rs`: Portable macOS/Linux `SOCK_DGRAM` ICMPv4/v6 packet builder, strict `(id, seq)` + embedded-header demux parser, `PermissionDenied` fallback, Ping, Traceroute, and MTR (heatmap ring buffer + outage log) + tests
- [x] `internet_check.rs`: 5-stage diagnostic pipeline (LocalLink, Router, Internet, DNS, Web) + deterministic verdict engine + unit & integration tests
- [x] `dns.rs`: `hickory-resolver` query engine supporting `A/AAAA/CNAME/MX/TXT/NS/SOA/PTR/SRV/CAA` across System/Cloudflare/Google/Quad9/Custom servers + `dig`-style formatter
- [x] `tls.rs`: `tokio-rustls` + `rustls-platform-verifier` + `x509-parser` inspection with custom CA PEM support and human-readable failure diagnosis

### `netscope-app` GUI & Menu Bar
- [x] `theme.rs`: Light/Dark Apple-inspired palette and shared card/badge/kv UI helpers
- [x] `tray.rs`: Programmatic RGBA menu bar icon + live status menu items + event polling
- [x] `app.rs`: `eframe::App` (`logic` + `ui`), close-to-tray behavior, background status refresh, sidebar navigation, toolbar
- [x] `views/internet_check.rs`: Summary verdict banner, painted 5-node pipeline, sparkline details, connection & earlier-checks cards
- [x] `views/ping.rs`: Live metric cards, `egui_plot` RTT timeline, sample log table
- [x] `views/traceroute.rs`: Streaming hop table with 3 probes, avg latency, status badge
- [x] `views/mtr.rs`: Live hop stats table + painted 40-slot loss/latency heatmap + outage log
- [x] `views/dns.rs`: Record type pills, resolver selector (default `System`), records table, `dig` text copy
- [x] `views/tls.rs`: Trust diagnosis banner, custom CA PEM input, chain list, certificate detail inspector
- [x] `scripts/bundle-macos.sh`: Release `.app` packager (`dist/NetScope.app`)

### Verification & Memory Sync
- [x] `cargo test --workspace` passes all unit & integration tests (20/20 passed)
- [x] `cargo clippy --workspace --all-targets -- -D warnings` passes cleanly (0 warnings)
- [x] `cargo build --release` builds cleanly (25 MB binary, strictly Apple system framework dependencies via `otool -L`)
- [x] Launch `target/release/netscope` smoke test (3s clean startup without panic/error)
- [x] Update `plans/01-foundation-and-core-diagnostics.md` checkboxes & Handoff, create clean initial commit

---

## 4. Current State / Handoff

- **Status:** Done (Phase 1 MVP Ready for Review)
- **Last Completed:** Full Phase 1 implementation, verification (`cargo test --workspace` 20/20 passed, `cargo clippy --workspace --all-targets -- -D warnings` 0 warnings, `cargo build --release` 25 MB binary, `./scripts/bundle-macos.sh` -> `dist/NetScope.app`, 3s runtime smoke test `SMOKE_ALIVE=true`), and `docs/architecture.md` sync.
- **Verified Runtime Notes:**
  - `otool -L target/release/netscope` links only macOS system frameworks + `libSystem` / `libobjc` / `libiconv` (zero Homebrew/OpenSSL/WebView runtime dependencies).
  - macOS `SOCK_DGRAM` `IPPROTO_ICMP` delivers incoming ICMP errors across open ICMP sockets, solved cleanly via atomic per-probe IDs + `(id, seq)` / embedded-header demux in `icmp.rs`.
  - Default DNS Lookup resolver set to `System` so queries work seamlessly behind strict DNS egress policies (OPNsense + AdGuard).
- **Next Step:** User visual/interactive review of `dist/NetScope.app` (`open dist/NetScope.app`), then draft `plans/02-lan-discovery-and-port-scanner.md` for Phase 2.
- **Blockers:** None
