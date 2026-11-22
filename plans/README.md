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
| **04** | `04-wifi-analyzer-and-domain-tools.md` | Wi-Fi Analyzer & Channel Recommendation (`CoreWLAN` / `nl80211` / WLAN API), DNS Propagation, Whois/RDAP, Email Check (SPF/DKIM/DMARC/MX) | 📋 **Planned** |
| **05** | `05-monitors-history-and-reports.md` | Live Interface Monitor, Uptime Monitor (SQLite 1-yr history, alerts, PDF reports), Built-in Guides | 📋 **Planned** |
