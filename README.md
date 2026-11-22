# NetScope

[![CI](https://github.com/burakberkkeskin/netscope/actions/workflows/ci.yml/badge.svg)](https://github.com/burakberkkeskin/netscope/actions/workflows/ci.yml)
[![Release](https://github.com/burakberkkeskin/netscope/actions/workflows/release.yml/badge.svg)](https://github.com/burakberkkeskin/netscope/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A cross-platform (**macOS**, **Linux**, **Windows**), pure-Rust native network diagnostics desktop application and Menu Bar / System Tray monitor. Built with zero telemetry, zero external runtime dependencies, and unprivileged operation (no `root` required for Ping, Traceroute, MTR, `iperf3`, or LAN scanning).

---

## Features & Tools (13 Built-In Modules)

### Diagnostics
- **Menu Bar / System Tray Monitor:** Keeps running after closing the main window; displays public IP, ASN/ISP, VPN interface status (`utun`, `wg`, `tailscale`, etc.), and DNS egress consistency (`DNS Matches` / `Upstream DNS` / `DNS Leak!`).
- **Internet Check:** 5-stage visual pipeline (`This Host -> Router -> Internet -> DNS -> Web`) pinpointing whether an outage is on your machine, local router, ISP link, DNS resolver, or HTTP stack—tolerating routers that drop ICMP echo when upstream connectivity works.
- **Path Troubleshoot:** Hop-by-hop latency waterfall classifying segments (`LAN`, `CGNAT`, `ISP`, `Transit`, `Target`) and filtering mid-hop ICMP control-plane rate-limiting.
- **Ping:** Unprivileged `SOCK_DGRAM` ICMPv4/v6 pinger with live RTT plot, jitter/median/loss telemetry, and sample log.
- **Traceroute:** Multi-probe hop discovery with parallel reverse DNS (`PTR`) resolution and RTT stats.
- **Visual Traceroute:** Offline embedded Natural Earth 50m vector world map (with country borders, zero external tile servers) featuring 32x cursor-anchored zoom, quick regional focus, `Hop 0` public egress origin plotting, radial co-located hop separation, and **Anycast Edge PoP detection** (`CF-RAY` / `x-amz-cf-pop` / `x-served-by` IATA matching + fiber speed-of-light RTT validation).
- **MTR:** Continuous hop statistics with a 40-round **Loss/Latency Heatmap** and automatic **Outage Log**.
- **Speed Test:** 4-stream parallel HTTP/1.1 download/upload throughput test with concurrent loaded ping for **Bufferbloat Grading (`A+..F`)** and persistent run history.
- **iperf3 Client:** Built-in **zero-dependency pure-Rust ESnet `iperf3` v3.17 wire-protocol client**—no OS `iperf3` binary required on the client machine. Supports `-c`, `-p`, `-t`, `-P` (1–32 streams), `-R` (reverse download), `--bidir`, `-u` (UDP with `-b` bitrate pacing & RFC 1889 jitter/loss), `-O` (omit slow-start), `-l` (buffer size), `-N` (`TCP_NODELAY`), saved server profiles, and run history.

### Network Tools
- **LAN Scanner & Network Guard:** High-speed concurrent ICMP + TCP touch sweep merged with OS ARP cache (`arp -an` / `/proc/net/arp`), IEEE OUI MAC vendor lookup, reverse DNS hostnames, quick open-service inspection (SSH, HTTP/S, SMB, AirPlay, DSM, Proxmox, Home Assistant, etc.), and **Network Guard** baseline alerts when a new device joins.
- **Port Scan:** Concurrent TCP Connect + UDP scanner (`Common 30`, `Web & Infra`, `Top 100`, or custom port/range specs) with asynchronous protocol banner & HTTP `Server:` version detection.
- **Subnet Calculator:** Instant IPv4 & IPv6 CIDR calculator displaying netmask, wildcard mask, usable range, RFC scope, binary bitmask breakdown, and an interactive **Subnet Splitter**.

### DNS & Domains
- **DNS Lookup:** `dig`-style resolver queries (`A`, `AAAA`, `MX`, `TXT`, `NS`, `CNAME`, `SOA`, `CAA`, `SRV`, `PTR`) via `System`, Cloudflare (`1.1.1.1`), Google (`8.8.8.8`), Quad9 (`9.9.9.9`), or custom resolvers.
- **SSL Certificate Inspector:** Full X.509 certificate chain viewer, SAN/key-usage inspection, OS trust-store diagnosis (`rustls-platform-verifier`), SNI override, and optional Custom CA PEM verification.

---

## Downloads

Pre-built binaries for **macOS (Apple Silicon `.dmg` / `.app.zip`)**, **Linux (`x86_64 .tar.gz`)**, and **Windows (`x86_64 .zip`)** alongside `SHA256SUMS.txt` are published automatically on [GitHub Releases](https://github.com/burakberkkeskin/netscope/releases).

> **macOS Gatekeeper Note:** Release binaries are currently unsigned (ad-hoc). If macOS warns on first launch, run:
> ```bash
> xattr -dr com.apple.quarantine /Applications/NetScope.app
> ```

---

## Building from Source

Requires Rust `1.88+` (Edition 2024).

### Linux Prerequisites (Ubuntu / Debian)
```bash
sudo apt-get update && sudo apt-get install -y \
  cmake pkg-config libxkbcommon-dev libxcb-render0-dev libxcb-shape0-dev \
  libxcb-xfixes0-dev libwayland-dev libgl1-mesa-dev libdbus-1-dev
```

### Windows Prerequisites
Install [NASM](https://www.nasm.us/) (`winget install NASM.NASM`) and ensure it is on `PATH` for `aws-lc-rs`.

### Build, Test & Package
```bash
# Run unit & diagnostic tests (use `-- --skip live_` in firewalled/offline environments)
cargo test --workspace

# Strict Clippy check
cargo clippy --workspace --all-targets -- -D warnings

# Run release binary
cargo run --release -p netscope-app

# Package macOS .app bundle into dist/NetScope.app
./scripts/bundle-macos.sh
```

---

## Roadmap

Roadmap plans and Architectural Decision Records (ADRs) live in [`plans/README.md`](plans/README.md):
- **Phase 1:** Foundation, Menu Bar Monitor, Internet Check, Ping, Traceroute, MTR, DNS Lookup, SSL Certificate Inspector — **Completed**
- **Phase 2:** Visual Traceroute (Offline Vector Map, Deep Zoom, Hop 0 Origin, Anycast Edge PoP), Path Troubleshoot, 4-Stream Speed Test + Bufferbloat, Native Rust `iperf3` Wire Client, Persistent History — **Completed**
- **Phase 3:** LAN Scanner + Network Guard, Port Scan + Banner Grabbing, IPv4/IPv6 Subnet Calculator + Splitter — **Completed**
- **Phase 4:** Wi-Fi Analyzer & Channel Recommendation, DNS Propagation, Whois / RDAP & GeoIP Lookup, Email Security Check (SPF/DKIM/DMARC/MX) — **Planned**
- **Phase 5:** Live Interface Monitor, Background Uptime Monitor & Built-in Diagnostic Guides — **Planned**

---

## License

MIT — see [`LICENSE`](LICENSE).
