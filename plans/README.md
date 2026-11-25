# NetScope Roadmap & Plans Index

Chronological roadmap, architectural decision records (ADRs), and task checklists for **NetScope**.

---

## Standards & Operating Rules

1. **Sequential Naming**: Plans follow `NN-topic-slug.md` (`01-foundation-and-core-diagnostics.md`, etc.).
2. **ADR Before Code**: Document architectural choices and rejected alternatives in the plan file.
3. **Verify Before Checking Off**: Mark `- [x]` only after running tests / clippy / runtime smoke verification.
4. **Handoff Discipline**: Keep `Current State / Handoff` accurate at the end of every session.

---

## Milestones

| Phase | Plan File | Scope | Status |
| :--- | :--- | :--- | :--- |
| **01** | [`01-foundation-and-core-diagnostics.md`](./01-foundation-and-core-diagnostics.md) | Workspace, Menu Bar/Tray (Public IP, VPN, DNS Leak), Internet Check, Ping, Traceroute, MTR (Heatmap + Outage Log), DNS Lookup, SSL/TLS Chain Inspector | ✅ **Completed** |
| **02** | [`02-ui-fixes-map-troubleshoot-speedtest-iperf3.md`](./02-ui-fixes-map-troubleshoot-speedtest-iperf3.md) | UI Bug Fixes, Persistent Host/Server History, Visual Traceroute (Offline Vector World Map + GeoIP), Hop-by-Hop Path Troubleshoot, 4-Stream Speed Test (Bufferbloat), `iperf3` Client | ✅ **Completed** |
| **03** | [`03-lan-discovery-and-port-scanner.md`](./03-lan-discovery-and-port-scanner.md) | LAN Scanner (ARP + PTR + OUI), Network Guard alerts, TCP/UDP Port Scan + banner/service detection, Subnet Calculator & Splitter | ✅ **Completed** |
| **04 (`v0.4.0`)** | [`04-dns-propagation.md`](./04-dns-propagation.md) | Global DNS Propagation Checker (System + 13 RFC 8484 DoH resolvers, consensus & expected-value matching) | ✅ **Completed** |
| **05 (`v0.5.0`)** | [`05-ipv6-diagnostics.md`](./05-ipv6-diagnostics.md) | IPv6 Diagnostics & Readiness (GUA/SLAAC/ULA/RA/DAD, 6-stage pipeline, PMTUD & blackhole test, Dual-Stack Happy Eyeballs) | ✅ **Completed** |
| **06 (`v0.6.0`)** | [`06-ux-polish-tray-toggle-geoip-and-e2e.md`](./06-ux-polish-tray-toggle-geoip-and-e2e.md) | Self-GeoIP Accuracy, Toggleable Menu Bar Tray, Speed Test / Bufferbloat / DNS / Chart UI/UX Overhaul & Deterministic UI E2E Tests | ✅ **Completed** |
| **07 (`v0.7.0`)** | [`07-speedtest-dns-ipv6-slaac-and-readme-showcase.md`](./07-speedtest-dns-ipv6-slaac-and-readme-showcase.md) | Speed Test Streaming Fix & Bufferbloat Sub-Tabs, DNS `ALL`/System IP/3s Timeout UX, IPv6 SLAAC Formatted/Raw Inspector & OPSEC-Safe README Showcase | ✅ **Completed** |
| **08 (`v0.8.0`)** | `08-whois-rdap-geoip.md` | Whois / RDAP & GeoIP Lookup (IANA RDAP bootstrap + port-43 WHOIS fallback + GeoIP/ASN/PTR) | 📋 **Planned** |
| **09 (`v0.9.0`)** | `09-email-security-check.md` | Email Security Check (`SPF` recursive lookup audit, `DKIM`, `DMARC`, `MX`) | 📋 **Planned** |
| **10 (`v0.10.0`)** | `10-wifi-analyzer.md` | Wi-Fi Analyzer & Channel Recommendation (`CoreWLAN` / `nl80211` / WLAN API) | 📋 **Planned** |
| **11 (`v0.11.0`)** | `11-live-interface-monitor.md` | Live Interface Monitor (real-time per-interface Rx/Tx throughput, packet/error stats) | 📋 **Planned** |

> **Scope Notes:** `Background Uptime Monitor` and `Built-in Diagnostic Guides` were dropped as out-of-scope for an interactive desktop diagnostics utility (NetScope already embeds contextual diagnoses inline within each tool).
