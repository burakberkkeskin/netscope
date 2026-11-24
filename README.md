# NetScope

[![CI](https://github.com/burakberkkeskin/netscope/actions/workflows/ci.yml/badge.svg)](https://github.com/burakberkkeskin/netscope/actions/workflows/ci.yml)
[![Release](https://github.com/burakberkkeskin/netscope/actions/workflows/release.yml/badge.svg)](https://github.com/burakberkkeskin/netscope/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A cross-platform (**macOS**, **Linux**, **Windows**), pure-Rust native network diagnostics desktop application and Menu Bar / System Tray monitor. Built with zero telemetry, zero external runtime dependencies, and unprivileged operation (no `root` required for Ping, Traceroute, MTR, `iperf3`, or LAN scanning).

---

## Features & Tools (15 Built-In Modules)

### Health Checks
- **Menu Bar / System Tray Monitor:** Optional toggleable system tray icon (`Tray: On` / `Tray: Off` in the sidebar); when enabled, keeps running after closing the main window and displays public IP, ASN/ISP, VPN interface status (`utun`, `wg`, `tailscale`, etc.), and DNS egress consistency (`DNS Matches` / `Upstream DNS` / `DNS Leak!`). When disabled, closing the window quits cleanly.
- **Internet Check:** 5-stage visual pipeline (`This Host -> Router -> Internet -> DNS -> Web`) pinpointing whether an outage is on your machine, local router, ISP link, DNS resolver, or HTTP stack—tolerating routers that drop ICMP echo when upstream connectivity works, with one-click jumps to **Path Troubleshoot** and **IPv6 Check**.
- **IPv6 Check:** 6-stage IPv6 readiness suite (`Local Stack -> Router (NDP) -> ICMPv6 -> DNS v6 -> HTTPS v6 -> PMTUD`) inspecting GUA/SLAAC/ULA addressing, Router Advertisement flags (`M`/`O`/`A`/`L`) & lifetimes, scoped link-local gateway reachability, `AAAA` & IPv6 DoH transport, Dual-Stack parity (`IPv6` vs `IPv4`, Happy Eyeballs & PoP peering), NAT66 detection, and unprivileged 32 KB full-MSS PMTUD blackhole detection.
- **Path Troubleshoot:** Hop-by-hop latency waterfall classifying segments (`LAN`, `CGNAT`, `ISP`, `Transit`, `Target`) and filtering mid-hop ICMP control-plane rate-limiting.

### Path & Probes
All probing tools below support an `[Auto | IPv4 | IPv6]` stack selector to force `A` or `AAAA` target resolution on dual-stack hosts:
- **Ping:** Unprivileged `SOCK_DGRAM` ICMPv4/v6 pinger with live RTT plot, jitter/median/loss telemetry, and sample log.
- **Traceroute:** Multi-probe hop discovery with parallel reverse DNS (`PTR`) resolution and RTT stats.
- **Visual Traceroute:** Offline embedded Natural Earth 50m vector world map (with country borders, zero external tile servers) featuring 32x cursor-anchored zoom, quick regional focus, `Hop 0` public egress origin plotting, radial co-located hop separation, and **Anycast Edge PoP detection** (`CF-RAY` / `x-amz-cf-pop` / `x-served-by` IATA matching + fiber speed-of-light RTT validation).
- **MTR:** Continuous hop statistics with a 40-round **Loss/Latency Heatmap** and automatic **Outage Log**.

### Bandwidth
- **Speed Test:** 4-stream parallel HTTP/1.1 download/upload throughput test with a 4-step phase stepper, peak Mbps / jitter telemetry, area-filled throughput charts, persistent run history, and a detailed **Bufferbloat Analyzer (`A+..F`)** featuring idle/DL/UL latency breakdown, Loaded RTT timeline, per-workload readiness pills (Video Calls, Gaming, VoIP, Web), and SQM recommendations.
- **iperf3 Client:** Built-in **zero-dependency pure-Rust ESnet `iperf3` v3.17 wire-protocol client**—no OS `iperf3` binary required on the client machine. Supports `[Auto | IPv4 | IPv6]`, `-c`, `-p`, `-t`, `-P` (1–32 streams), `-R` (reverse download), `--bidir`, `-u` (UDP with `-b` bitrate pacing & RFC 1889 jitter/loss), `-O` (omit slow-start), `-l` (buffer size), `-N` (`TCP_NODELAY`), saved server profiles, and run history.

### Network Tools
- **LAN Scanner & Network Guard:** High-speed concurrent ICMP + TCP touch sweep merged with OS ARP cache (`arp -an` / `/proc/net/arp`), IEEE OUI MAC vendor lookup, reverse DNS hostnames, quick open-service inspection (SSH, HTTP/S, SMB, AirPlay, DSM, Proxmox, Home Assistant, etc.), and **Network Guard** baseline alerts when a new device joins.
- **Port Scan:** Concurrent TCP Connect + UDP scanner (`[Auto | IPv4 | IPv6]`, `Common 30`, `Web & Infra`, `Top 100`, or custom port/range specs) with asynchronous protocol banner & HTTP `Server:` version detection.
- **Subnet Calculator:** Instant IPv4 & IPv6 CIDR calculator displaying netmask, wildcard mask, usable range, RFC scope, binary bitmask breakdown, and an interactive **Subnet Splitter**.

### DNS & Domains
- **DNS Lookup:** `dig`-style resolver queries (`A`, `AAAA`, `MX`, `TXT`, `NS`, `CNAME`, `SOA`, `CAA`, `SRV`, `PTR`) with 1-click resolver pills (`System`, `1.1.1.1`, `8.8.8.8`, `9.9.9.9`, custom), KPI summary strip, Structured Table / Raw `dig` view toggle, click-to-copy values, and direct `Check Propagation ->` jump.
- **DNS Propagation:** Concurrent multi-region propagation check across `System Default` and 13 global RFC 8484 DoH resolvers with normalized RRset consensus and optional expected-value cutover matching.
- **SSL Certificate Inspector:** Full X.509 certificate chain viewer, SAN/key-usage inspection, OS trust-store diagnosis (`rustls-platform-verifier`), SNI override, and optional Custom CA PEM verification.

---

## Installation

Pre-built binaries are published on [GitHub Releases](https://github.com/burakberkkeskin/netscope/releases) with `SHA256SUMS.txt` checksums:

- **macOS (Apple Silicon `arm64`, macOS 13+):** `NetScope-vX.Y.Z-macos-arm64.dmg` / `NetScope-vX.Y.Z-macos-arm64.zip`
- **Linux (`x86_64`):** `NetScope-vX.Y.Z-linux-x86_64.tar.gz`
- **Windows (`x86_64`):** `NetScope-vX.Y.Z-windows-x86_64.zip`

### macOS (Apple Silicon)

**Quick Install via `curl` (Recommended — avoids browser quarantine):**
```bash
TAG=$(curl -fsSL https://api.github.com/repos/burakberkkeskin/netscope/releases/latest | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n1)
curl -fL "https://github.com/burakberkkeskin/netscope/releases/download/${TAG}/NetScope-${TAG}-macos-arm64.zip" -o /tmp/NetScope.zip
rm -rf /Applications/NetScope.app && ditto -x -k /tmp/NetScope.zip /Applications && rm /tmp/NetScope.zip
open /Applications/NetScope.app
```

**Manual `.dmg` Install:**
1. Open `NetScope-vX.Y.Z-macos-arm64.dmg` and drag `NetScope.app` onto `Applications` (do **not** launch directly from inside the read-only disk image).
2. **If downloaded in a browser (Safari, Chrome, Brave, etc.):** Release bundles are ad-hoc signed (`codesign -`) without a paid Apple Developer ID / notarization, so browsers attach `com.apple.quarantine` and macOS warns **`"NetScope" is damaged and can't be opened`**. Clear quarantine once after copying to `/Applications`:
   ```bash
   xattr -dr com.apple.quarantine /Applications/NetScope.app
   open /Applications/NetScope.app
   ```
3. On first run, allow **Local Network** access when prompted so **LAN Scanner**, router probes, and local gateway checks can operate.

### Linux (`x86_64`)

**Quick Install via `curl`:**
```bash
TAG=$(curl -fsSL https://api.github.com/repos/burakberkkeskin/netscope/releases/latest | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n1)
curl -fL "https://github.com/burakberkkeskin/netscope/releases/download/${TAG}/NetScope-${TAG}-linux-x86_64.tar.gz" -o /tmp/netscope.tar.gz
mkdir -p ~/.local/bin && tar -xzf /tmp/netscope.tar.gz -C ~/.local/bin ./netscope && rm /tmp/netscope.tar.gz
chmod +x ~/.local/bin/netscope
```

- Ensure desktop runtime libraries are installed (`libxkbcommon`, `libxcb`, `libwayland`, `libgl`, `libdbus`; see [Linux Prerequisites](#linux-prerequisites-ubuntu--debian) below for Debian/Ubuntu package names).
- **Unprivileged ICMP note:** Most modern distros allow non-root `SOCK_DGRAM` ICMP sockets by default. On hardened kernels where Ping/Traceroute/MTR fail with permission errors, inspect or widen `net.ipv4.ping_group_range`:
  ```bash
  sysctl net.ipv4.ping_group_range
  sudo sysctl -w net.ipv4.ping_group_range="0 2147483647"
  ```

### Windows (`x86_64`)

**Quick Install via PowerShell (`curl.exe`):**
```powershell
$tag = (Invoke-RestMethod https://api.github.com/repos/burakberkkeskin/netscope/releases/latest).tag_name
curl.exe -fL "https://github.com/burakberkkeskin/netscope/releases/download/$tag/NetScope-$tag-windows-x86_64.zip" -o "$env:TEMP\NetScope.zip"
Expand-Archive "$env:TEMP\NetScope.zip" "$env:LOCALAPPDATA\Programs\NetScope" -Force
Remove-Item "$env:TEMP\NetScope.zip"
& "$env:LOCALAPPDATA\Programs\NetScope\netscope.exe"
```

- Because the Windows binary is not Authenticode-signed, **Windows Defender SmartScreen** may show *"Windows protected your PC"* on first launch — click **More info** and then **Run anyway**.

### Verify Checksums (Optional)
```bash
# macOS
shasum -a 256 -c SHA256SUMS.txt --ignore-missing

# Linux
sha256sum -c SHA256SUMS.txt --ignore-missing
```

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
# Run unit, diagnostic, and headless `egui::Context::run_ui` UI E2E tests (use `-- --skip live_` in firewalled/offline environments)
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
- **Phase 4 (`v0.4.0`):** Global DNS Propagation Checker — **Completed**
- **Phase 5 (`v0.5.0`):** IPv6 Diagnostics & Readiness Suite — **Completed**
- **Phase 6 (`v0.6.0`):** Self-GeoIP Accuracy, Toggleable Menu Bar Tray, Speed Test / Bufferbloat / DNS / Chart UI/UX Overhaul & Deterministic UI E2E Tests — **Completed**
- **Phase 7 (`v0.7.0`):** Whois / RDAP & GeoIP Lookup — **Planned**
- **Phase 8 (`v0.8.0`):** Email Security Check (`SPF`, `DKIM`, `DMARC`, `MX`) — **Planned**
- **Phase 9 (`v0.9.0`):** Wi-Fi Analyzer & Channel Recommendation — **Planned**
- **Phase 10 (`v0.10.0`):** Live Interface Monitor — **Planned**

---

## License

MIT — see [`LICENSE`](LICENSE).
