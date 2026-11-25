# Plan 07: Speed Test & Bufferbloat Overhaul, DNS Lookup UX, IPv6 SLAAC Inspector & README Showcase

> **Phase:** 7 (`v0.7.0`)
> **Status:** Done

---

## 1. Context & Goal (Why)

Resolve empirical bugs and UX gaps discovered during live usage on a dual-stack PPPoE/OPNsense network (`~1000/45 Mbps` with `1484 B` PPPoE MTU and firewalled outbound port 53), plus add OPSEC-clean visual screenshots to `README.md`:

1. **Speed Test & Bufferbloat Accuracy + Sub-Tab UI:**
   - Fix `0.0 Mbps` download caused by Cloudflare returning `HTTP 429 Too Many Requests` when `Referer: https://speed.cloudflare.com/` is absent (and silent status-code ignoring).
   - Fix sawtooth/triangular upload graphs and under-reported upload throughput (`~25 Mbps` vs `~45 Mbps`) caused by discrete blocking 1 MiB POSTs that only increment byte counters after HTTP response completion; switch upload to continuous `tokio-rustls` streaming HTTP/1.1 POSTs with 32 KiB slices, 1.0s warmup (cancelling `SO_SNDBUF`), and a 1.0s sliding-window throughput smoother.
   - Add `[Auto | IPv4 | IPv6]` stack selector (`Auto` races TCP connect v4 vs v6 to pick the closest Cloudflare edge PoP instead of detouring across high-RTT IPv6 transit), display active `Edge PoP` (`CF-RAY` colo + IP family), and separate **Speed Test**, **Bufferbloat**, and **History** into crisp dedicated sub-tabs under `Speed & Bufferbloat`.
2. **DNS Lookup Overhaul:**
   - Add `ALL` record option executing parallel lookups across `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`, `SOA`, `CAA` (or `PTR` for IP inputs), avoiding the RFC 8482 `ANY` stub trap.
   - Detect and display actual OS system DNS server IP(s) (`scutil --dns` on macOS + `hickory_resolver::system_conf` fallback) in the resolver bar, KPI card, and `;; SERVER:` raw dig header.
   - Shorten resolver timeout to `3.0s` (`attempts = 1` + hard async timeout) so firewalled external resolvers (e.g. blocked `1.1.1.1:53`) fail fast with a clear diagnostic message.
   - Eliminate stale results & race conditions via monotonic `request_id` superseding, an active `Cancel` button, and distinct UI states for `Found`, `NoRecords` (`NODATA`), `NxDomain`, and `Timeout/Error`.
3. **IPv6 Diagnostics — SLAAC/RA Formatted & Raw Inspector + PMTUD Fix:**
   - Add missing `Referer: https://speed.cloudflare.com/` header to the 32 KB full-MSS PMTUD transfer (fixes `HTTP 429`).
   - Enrich local IPv6 inventory with macOS `ndp -i <iface>` (`linkmtu`, `curhlim`, `basereachable`, `reachable`, `retrans`, `nd6` flags) and full raw SLAAC/NDP OS output (plus Linux `ip -6` / `/proc/sys/net/ipv6/conf` equivalents).
   - Add a dedicated **SLAAC & Router Advertisement (RA) Inspector** card with `Formatted | Raw` toggle displaying router parameters, RA-advertised Link MTU, RDNSS servers, and **all** advertised prefixes (both GUA and ULA).
4. **OPSEC-Safe README Showcase Screenshots:**
   - Add `--demo-screenshots <dir>` mode rendering RFC 5737 / RFC 3849 sanitized fixture data into `docs/screenshots/` (1 Hero + 4 clickable thumbnails) with zero leakage of real public IPs, IPv6 prefixes, city, or LAN hosts.

---

## 2. Decisions & Rejected Alternatives (ADR)

### ADR-019: Single `Speed & Bufferbloat` Sidebar Entry with Dedicated Sub-Tabs (`Speed Test` | `Bufferbloat` | `History`)
- **Chosen:** Keep one sidebar item (`Speed & Bufferbloat`) sharing a single ~18s saturation run, while separating Throughput, Bufferbloat diagnostics, and History into focused internal sub-tabs with a compact shared summary strip.
- **Why:** Bufferbloat inherently requires saturating both download and upload links; splitting into two sidebar tools would force users to run two identical 18s saturation tests and bloat the 15-item sidebar, while sub-tabs give both views clean, uncluttered canvases.
- **Rejected:** Two separate sidebar items (`Speed Test` + `Bufferbloat`).

### ADR-020: Continuous `tokio-rustls` Streaming Upload + 1.0s Sliding-Window Smoother
- **Chosen:** Replace discrete 1 MiB `reqwest` POST loops with 4 concurrent `tokio-rustls` HTTP/1.1 streaming `POST /__up` streams writing 32 KiB slices continuously (`Content-Length: 16 MiB`), discarding the first 1.0s warmup so initial `SO_SNDBUF` fill cancels cleanly, and computing chart samples over a 1.0s sliding window.
- **Why:** Eliminates zero-new-dependency overhead (`tokio-rustls` is already in `netscope-core`), removes HTTP turnaround gaps (restoring true ~44+ Mbps upload on a 45 Mbps line), and removes 250ms sampling sawtooth artifacts.
- **Rejected:** Adding new HTTP streaming crates or keeping discrete chunk POSTs.

### ADR-021: Parallel Multi-Type `ALL` DNS Lookup (Avoiding RFC 8482 `ANY`)
- **Chosen:** Query `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`, `SOA`, `CAA` concurrently via `JoinSet` when `DnsRecordType::All` is selected (or `PTR` when input is an IP address), merging answers in canonical type order.
- **Why:** Major resolvers (Cloudflare, etc.) implement RFC 8482 and respond to `ANY` with a synthetic `HINFO` record instead of real RRsets.
- **Rejected:** Sending a single `RecordType::ANY` DNS packet.

### ADR-022: Deterministic OPSEC-Clean `--demo-screenshots` Mode for `README.md`
- **Chosen:** Populate deterministic RFC 5737 (`203.0.113.x`, `198.51.100.x`) and RFC 3849 (`2001:db8::/32`) demo fixtures when launched with `--demo-screenshots <dir>` to generate repeatable, privacy-safe PNGs for `docs/screenshots/`.
- **Why:** Guarantees zero accidental leakage of real residential IPs, ISP delegated IPv6 prefixes, geolocation, or homelab LAN inventory into public git history.
- **Rejected:** Manually blurring live screenshots.

---

## 3. Execution Checklist

- [x] Core + UI: Fix Speed Test (Referer/Origin, HTTP status check, `tokio-rustls` streaming upload, 1s sliding window, `[Auto|IPv4|IPv6]` & `CF-RAY` PoP) and refactor `views/speedtest.rs` into `Speed Test` | `Bufferbloat` | `History` sub-tabs
- [x] Core + UI: Overhaul DNS Lookup (`ALL` parallel query, OS system DNS server detection, 3s fast timeout, monotonic `request_id` cancel/supersede, distinct `Found`/`NoRecords`/`NxDomain`/`Error` states)
- [x] Core + UI: Upgrade IPv6 Check (fix PMTUD `Referer`, parse `ndp -i <iface>` RA Link MTU / timers + raw SLAAC dump, add Formatted/Raw SLAAC & RA Inspector showing all prefixes)
- [x] App + README: Implement `--demo-screenshots <dir>` OPSEC-safe showcase generator, generate & visually verify `docs/screenshots/*.png`, update `README.md` with Hero + 2×2 clickable thumbnail grid
- [x] Tests & Verification: Add unit + headless `egui::Context::run_ui` UI E2E tests, pass `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, live smoke test, and rebuild `./scripts/bundle-macos.sh`

---

## 4. Current State / Handoff

- **Status:** Done
- **Last Completed:** Fixed Speed Test (`787.8 Mbps DL` / `41.9 Mbps UL` smooth via `Cloudflare IST (IPv4)` live-verified), refactored into `Speed & Bufferbloat` sub-tabs (`Speed Test | Bufferbloat | History`), overhauled DNS Lookup (`ALL` parallel query, detected System DNS IP, 3s timeout, stale-result fix), added Formatted/Raw SLAAC & RA Inspector + PMTUD `Referer` fix to IPv6 Check, generated & visually audited 5 OPSEC-safe showcase screenshots into `docs/screenshots/`, updated `README.md`, and rebuilt `dist/NetScope.app`.
- **Next Step:** Ready for release tagging (`v0.7.0`) or starting Phase 08 (`Whois / RDAP & GeoIP Lookup`).
- **Blockers:** None
