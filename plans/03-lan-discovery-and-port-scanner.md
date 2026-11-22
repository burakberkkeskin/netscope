# Plan 03: LAN Scanner, Network Guard, TCP/UDP Port Scanner & Subnet Calculator

> **Phase:** 3 of 5 (Network Discovery, Port Security & Subnetting)
> **Status:** Done

---

## 1. Context & Goal (Why)

Extend **NetScope** with the local network discovery and port engineering toolkit inspired by Netutilus while maintaining 100% pure-Rust, zero external crate additions, and strict OPSEC (zero hardcoded personal IP/hostname strings so the repository is ready for public open-source release):

1. **LAN Scanner & Network Guard (`lan_scanner.rs` + `views/lan_scanner.rs`):**
   - Auto-detect the active local IPv4 subnet (e.g., `/24` from `net_info::get_local_network_info()`).
   - High-speed concurrent ICMP ping + quick TCP touch sweep (`64` parallel workers) to populate the OS neighbor cache and measure host latency.
   - Cross-platform neighbor / ARP table reader (`arp -an` on macOS/Windows, `/proc/net/arp` + `ip neigh` on Linux) normalizing macOS short hex octets (`1:b:c` -> `01:0B:0C:...`).
   - Built-in IEEE OUI MAC vendor lookup table (Apple, Synology, Proxmox, Raspberry Pi, Ubiquiti, TP-Link, Intel, Espressif, Sonos, Philips Hue, Samsung, Xiaomi, etc.).
   - Quick service port probe (`22, 53, 80, 443, 445, 548, 631, 3389, 5000, 5001, 7000, 8006, 8080, 8123, 8443, 9000, 62078`) + device role/model inference (`Gateway`, `This Host`, `NAS / Storage`, `Proxmox VE`, `Home Assistant`, `Printer`, `Apple Device`, etc.) and detail inspector pane with quick-jump to **Ping** or **Port Scan**.
   - **Network Guard:** Persistent known-MAC baseline in `PersistedState` (`state.json`) that flags newly joined / unknown devices (`NEW` badge + alert counter) and supports periodic auto-rescan (`Off`, `5 min`, `15 min`, `30 min`).
2. **Port Scanner (`port_scan.rs` + `views/port_scan.rs`):**
   - Concurrent TCP Connect + UDP probe scanner with presets (`Common 30`, `Web & Infra`, `Top 100`, `Custom Range / List` such as `20-1024,5000,8006,8080-8090`).
   - Service name mapping + asynchronous protocol banner & version grabber (SSH banner, HTTP/HTTPS `Server:` header, SMTP/FTP/POP3/IMAP/Redis greeting).
3. **Subnet Calculator (`subnet.rs` + `views/subnet_calc.rs`):**
   - Instant IPv4 CIDR (`192.168.1.0/24` or IP + prefix slider `/1..=/32`) and IPv6 CIDR (`2001:db8::/64`) calculator.
   - Displays network address, broadcast, first/last usable host, total/usable host count, netmask, wildcard mask, binary octet bitmask breakdown, RFC address scope classification, and an interactive **Subnet Splitter** (split `/24` into `/25`, `/26`, `/27`, `/28` child blocks).

---

## 2. Decisions & Rejected Alternatives (ADR)

### ADR-009: Unprivileged Ping+TCP Touch Sweep + OS ARP Table Normalization over Raw `pcap` / `libnet`
- **Chosen:** Trigger kernel ARP resolution using unprivileged ICMP `SOCK_DGRAM` probes + a fast non-blocking TCP connect touch on port `80`/`443`, then read the kernel ARP cache (`/proc/net/arp` on Linux, `arp -an` on macOS/Windows) and normalize MAC addresses to canonical uppercase `AA:BB:CC:DD:EE:FF`.
- **Why:** Raw Ethernet ARP frame injection (`pnet` / `pcap`) requires `root` / `CAP_NET_RAW` or WinPcap/Npcap drivers. Unprivileged Ping+TCP touch triggers the OS kernel to send ARP requests itself without root privileges on macOS, Linux, and Windows.
- **Rejected:** `libpnet` / `pcap` (requires root and C libraries).

### ADR-010: Protocol-Aware Banner Grabbing with Safe Timeouts
- **Chosen:** For open TCP ports, wait 250ms for server-first banners (SSH, SMTP, FTP, POP3, IMAP); if silent on HTTP-like ports (`80, 81, 3000, 5000, 5001, 8000, 8006, 8080, 8123, 8888, 9000, 9090`), send a minimal `HEAD / HTTP/1.0\r\nHost: <target>\r\n\r\n` request and extract the HTTP status line + `Server:` header.
- **Why:** Identifies exact software versions (e.g., `OpenSSH_9.8`, `nginx/1.26`, `AirTunes/770.8.1`, `Synology DSM`) cleanly within 400ms per open port without external fingerprint databases.

---

## 3. Execution Checklist

- [x] Implement `crates/netscope-core/src/subnet.rs` (IPv4 & IPv6 CIDR math, binary mask breakdown, RFC scope, subnet splitter + unit tests)
- [x] Implement `crates/netscope-core/src/port_scan.rs` (port spec parser, TCP/UDP scanner, banner/version grabber + `AirTunes`/DSM/Proxmox disambiguation + unit tests)
- [x] Implement `crates/netscope-core/src/lan_scanner.rs` (ARP reader with `/usr/sbin/arp` macOS path, MAC normalizer rejecting redacted `02:00:00:00:00:00`, OUI vendor DB, concurrent LAN sweep, service/model inference, Network Guard diffing + unit tests)
- [x] Extend `crates/netscope-core/src/history.rs` with Network Guard known-device baseline (`KnownLanDevice`) and sanitized load filtering
- [x] Build `crates/netscope-app/src/views/lan_scanner.rs` (6-column table + filter + Network Guard baseline & auto-rescan bar + right-hand device inspector + Ping/Port Scan jump)
- [x] Build `crates/netscope-app/src/views/port_scan.rs` (presets, range input, live progress pill, open/closed/filtered results table with service & version banners)
- [x] Build `crates/netscope-app/src/views/subnet_calc.rs` (IPv4/IPv6 CIDR calculator, binary visualizer, subnet splitter table)
- [x] Wire `NETWORK TOOLS` scrollable sidebar section in `crates/netscope-app/src/app.rs`, add `NSLocalNetworkUsageDescription` in `scripts/bundle-macos.sh`, & run visual QA `--screenshot-dir` steps (`12-lan-scanner.png`, `13-port-scan.png`, `14-subnet-calculator.png`)
- [x] Verify `cargo test --workspace` (40/40 passed), `cargo clippy --workspace --all-targets -- -D warnings` (0 warnings), `./scripts/bundle-macos.sh`, and visual PNG inspection (`ui-audit-phase3-v3`)

---

## 4. Current State / Handoff

- **Status:** Done (Visually Audited across all 14 screens)
- **Last Completed:** Implemented and visually verified LAN Scanner + Network Guard, TCP/UDP Port Scanner (with banner/version detection), and IPv4/IPv6 Subnet Calculator + Splitter (`cargo clippy` 0 warnings, `cargo test --workspace` 40/40 passed, rebuilt `dist/NetScope.app`).
- **Next Step:** Proceed to Phase 4 (`04-wifi-analyzer-and-domain-tools.md`: Wi-Fi Analyzer & Channel Recommendation, DNS Propagation, Whois/RDAP, and Email Check SPF/DKIM/DMARC/MX), followed by Phase 5 and public GitHub CI/CD release setup.
- **Blockers:** None
