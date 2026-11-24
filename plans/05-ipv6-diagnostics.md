# Plan 05: IPv6 Diagnostics & Readiness Suite

> **Phase:** 5 of 9 (`v0.5.0`)
> **Status:** Done

---

## 1. Context & Goal (Why)

Extend **NetScope** (`DIAGNOSTICS`) with a dedicated **IPv6 Diagnostics & Readiness** module (`ipv6_check.rs` + `views/ipv6_check.rs`) that inspects local IPv6 stack provisioning (`GUA`, `SLAAC`, `ULA`, `Link-Local`, privacy extensions, `DAD` health, Router Advertisements `M`/`O`/`A`/`L` flags, lifetimes), probes the link-local default gateway via scoped ICMPv6, tests global ICMPv6 & DNS `AAAA`/IPv6 transport, measures Dual-Stack parity (`IPv6` vs `IPv4`, Happy Eyeballs & PoP peering), detects NAT66, and runs an unprivileged Path MTU / PMTUD blackhole verification.

---

## 2. Decisions & Rejected Alternatives (ADR)

### ADR-013: Cross-Platform IPv6 Addressing (`netdev 0.47` `Ipv6AddrFlags`) + Unprivileged OS NDP/RA Enrichment
- **Chosen:** Use `netdev 0.47` (`ipv6`, `ipv6_scope_ids`, `ipv6_addr_flags`, `mtu`, `gateway.ipv6`, `dns_servers`) as the cross-platform baseline, enriched without root on macOS via `/sbin/ifconfig <iface>` (`autoconf`/`secured`/`temporary`/`nd6 options`), `/usr/sbin/ndp -r` (`M`/`O` RA flags, preference, expiration), `/usr/sbin/ndp -p` (advertised prefixes, `A`/`L` SLAAC flags, `vltime`/`pltime`), and `/usr/sbin/scutil --dns` (IPv6 nameservers); on Linux via `ip -6 route show default dev <iface>` and `/etc/resolv.conf`; and on Windows via `netdev` native flags.
- **Why:** Raw Router Solicitation (`ICMPv6 Type 133`) sockets require `root` / `CAP_NET_RAW`. Reading the kernel neighbor/prefix cache (`ndp -r`, `ndp -p`, `ip -6`) plus `netdev`'s OS interface flags captures real SLAAC/DHCPv6 provisioning state cleanly with zero privileges.
- **Rejected:** Raw ICMPv6 Router Solicitation daemon (requires elevated permissions).

### ADR-014: Unprivileged PMTUD & Blackhole Detection via 32 KB Forced-IPv6 TLS Transfer + Kernel Route MTU
- **Chosen:** Execute a forced-IPv6 32 KB HTTPS/TLS transfer (`speed.cloudflare.com/__down?bytes=32768`) to exercise full-MSS TCP segments end-to-end (detecting PMTUD blackholes where small packets pass while large frames stall, and triggering OS ICMPv6 Packet Too Big caching), then inspect the OS learned route MTU (`/sbin/route -n get -inet6 <target>` on macOS, `ip -6 route get <target>` on Linux) against link MTU and RFC 8200 minimum (`1280 B`).
- **Why:** Empirically verified on macOS: setting `IPV6_DONTFRAG` on unprivileged `IPPROTO_ICMPV6` sockets fails with `EPERM`, so `ping6` silently source-fragments packets and masks Path MTU limits (e.g., PPPoE `1484 B` vs Wi-Fi `1500 B`). Forced-IPv6 full-MSS TLS transfer + kernel route cache inspection uncovers real Path MTU and PMTUD blackholes without root.
- **Rejected:** `ping6 -D` (fails with `Operation not permitted` for unprivileged users on macOS).

### ADR-015: Deterministic Dual-Stack IPv6 vs IPv4 Probing (Happy Eyeballs RFC 8305)
- **Chosen:** Resolve `AAAA` and `A` explicitly and bind two separate `reqwest::Client` workers with `.resolve(host, SocketAddr::new(ip, 443))` and `.local_address(IpAddr::V6(Ipv6Addr::UNSPECIFIED) / IpAddr::V4(Ipv4Addr::UNSPECIFIED))`.
- **Why:** Standard dual-stack HTTP clients silently fall back to the other address family when one stack is broken or slow, hiding IPv6 failures or PoP peering discrepancies (e.g., IPv6 egress via `AMS` vs IPv4 egress via `IST`).
- **Rejected:** Default OS Happy Eyeballs client (masks broken IPv6 behind silent IPv4 fallback).

---

## 3. Execution Checklist

- [x] Add `probe_once_v6_scoped` in `crates/netscope-core/src/icmp.rs` for link-local `fe80::...%scope_id` ICMPv6 echo probing
- [x] Implement `crates/netscope-core/src/ipv6_check.rs` (scope classifier, macOS/Linux parsers, 6-stage async pipeline, dual-stack & NAT66 probe, PMTUD 32 KB + route MTU check, 10-item readiness checklist + unit & live tests)
- [x] Export `pub mod ipv6_check;` in `crates/netscope-core/src/lib.rs`
- [x] Build `crates/netscope-app/src/views/ipv6_check.rs` (6-node pipeline, ADR-006 2-column Addressing/Provisioning & Dual-Stack/PMTUD cards, Path MTU bar, 10-row `TableBuilder` checklist)
- [x] Wire `ToolTab::Ipv6Diagnostics` into `crates/netscope-app/src/views/mod.rs` and `crates/netscope-app/src/app.rs` (`DIAGNOSTICS` nav, `Clear`, `Copy Output`, `Quit` cleanup, steps 16–17 Light/Dark in `drive_screenshots`)
- [x] Bump workspace version to `0.5.0` in `Cargo.toml`, update `plans/README.md` & `README.md`
- [x] Verify `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, `./scripts/bundle-macos.sh`, and visual PNG audit (`16-ipv6-diagnostics.png`, `17-ipv6-diagnostics-dark.png`)

---

## 4. Current State / Handoff

- **Status:** Done (Visually Audited in Light & Dark Mode)
- **Last Completed:** Implemented and verified IPv6 Diagnostics & Readiness suite (`cargo clippy --workspace --all-targets -- -D warnings` 0 warnings, `cargo test --workspace` 54/54 passed, rebuilt `dist/NetScope.app` v0.5.0, visually confirmed `16-ipv6-diagnostics.png` & `17-ipv6-diagnostics-dark.png`).
- **Next Step:** Proceed to Plan 06 (`v0.6.0`: Self-GeoIP Accuracy, Toggleable Menu Bar Tray, Speed Test / Bufferbloat / DNS Lookup / Chart UI/UX Overhaul & Deterministic UI E2E Tests).
- **Blockers:** None
