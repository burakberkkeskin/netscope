# Plan 04: Global DNS Propagation Checker

> **Phase:** 4 of 8 (`v0.4.0`)
> **Status:** Done

---

## 1. Context & Goal (Why)

Extend **NetScope** (`DNS & DOMAINS`) with a **Global DNS Propagation Checker** (`dns_propagation.rs` + `views/dns_propagation.rs`) that concurrently checks how a domain record (`A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`, `SOA`, `PTR`, `SRV`, `CAA`) resolves across the local OS resolver (`System Default`) and 13 globally distributed public resolvers (North America, Europe, APAC, Global Anycast), helping operators verify DNS cutovers, TTL convergence, and split-horizon discrepancies.

---

## 2. Decisions & Rejected Alternatives (ADR)

### ADR-011: RFC 8484 DoH over HTTP/2 POST + Local System Resolver over Direct UDP/53
- **Chosen:** Query the 13 global resolvers via RFC 8484 DNS-over-HTTPS (`POST application/dns-message` over HTTP/2 using existing `reqwest` + `hickory-proto` DNS wire serialization) alongside the local `System Default` resolver via `hickory-resolver`.
- **Why:** Direct outbound `UDP/53` and `TCP/53` queries to external IPs (`1.1.1.1`, `8.8.8.8`, etc.) are frequently blocked or intercepted on enterprise/homelab egress firewalls (e.g., OPNsense/AdGuard rules forcing DNS through the local filter), causing direct UDP probes to time out. RFC 8484 `POST` over HTTPS/443 works reliably through standard egress firewalls and requires zero new crate dependencies. Default HTTP/2 negotiation is preserved because providers such as Quad9 (`dns.quad9.net`) reject HTTP/1.1 requests with `HTTP 505`.
- **Rejected:** Direct `UDP/53` sockets to public resolver IPs (fails on port-53-restricted networks), third-party JSON DNS APIs (limited to Google/Cloudflare and non-standard across global providers).

### ADR-012: Normalized Answer-Set Consensus & Optional Expected-Value Matching
- **Chosen:** Normalize each resolver's answer set (lowercase, strip trailing `.` on hostnames, sort and deduplicate) into a canonical `normalized_key`, compute majority consensus across `Resolved` nodes, and allow an optional user-supplied `Expected` filter (supports substring/exact match or comma-separated values) to override consensus grading during active DNS migrations.
- **Why:** Round-robin DNS (e.g., Cloudflare/CDN `A` records returned in different orders by different resolvers) must still be graded as consistent (`Match`), whereas split-horizon or stale caches need clear `Divergent` / `No Data` / `NXDOMAIN` badges.
- **Rejected:** Strict raw string equality on unsorted records (produces false `Divergent` alerts on multi-A/NS round-robin responses).

---

## 3. Execution Checklist

- [x] Implement `crates/netscope-core/src/dns_propagation.rs` (14 resolvers: `System Default` + 13 verified RFC 8484 DoH endpoints, `build_wire_query`, `parse_wire_response`, `normalize_answer_key`, `evaluate_propagation`, `format_propagation_report`, streaming `run_propagation` + unit & live tests)
- [x] Export `pub mod dns_propagation;` in `crates/netscope-core/src/lib.rs`
- [x] Build `crates/netscope-app/src/views/dns_propagation.rs` (domain input + `History ▾` + optional `Expected` input, `DnsRecordType` pills, live consensus summary banner, sorted 6-column table with status pills & hover tooltips for long answers)
- [x] Wire `ToolTab::DnsPropagation` into `crates/netscope-app/src/views/mod.rs` and `crates/netscope-app/src/app.rs` (`DNS & DOMAINS` nav, `Clear`, `Copy Output`, `Quit` cleanup, and step 15 in `drive_screenshots`)
- [x] Bump workspace version to `0.4.0` in `Cargo.toml`, update `plans/README.md` & `README.md`
- [x] Verify `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, `./scripts/bundle-macos.sh`, and visual PNG audit (`15-dns-propagation.png`)

---

## 4. Current State / Handoff

- **Status:** Done (Visually Audited across all 15 screens)
- **Last Completed:** Implemented and verified Global DNS Propagation Checker (`cargo clippy --workspace --all-targets -- -D warnings` 0 warnings, `cargo test --workspace` 47/47 passed including `live_dns_propagation_cloudflare_a`, rebuilt `dist/NetScope.app` v0.4.0, fixed `TableBuilder` `id_salt` collision & column widths, visually confirmed `15-dns-propagation.png` with 14/14 resolvers).
- **Next Step:** Confirm scope of `Built-in Diagnostic Guides`, then plan and implement Phase 5 (`v0.5.0`: `Whois / RDAP & GeoIP Lookup`).
- **Blockers:** None
