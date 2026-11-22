# Plan 02: UI Layout Fixes, Persistent History, Visual Traceroute, Path Troubleshoot, Speed Test & iperf3

> **Phase:** 2 of 6 (Extension of Core Diagnostics & UX Polish)
> **Status:** Done

---

## 1. Context & Goal (Why)

Address UI layout issues identified during interactive macOS testing of Phase 1 (`STAGE DETAILS` right-to-left vertical collapse, bottom-up `MENU BAR MONITOR` card inversion, sidebar button borders, light-mode muted contrast, and false-positive router/DNS badges) while adding four requested core diagnostics & workflow upgrades:
1. **Persistent Target & Run History** (`history.rs` + `widgets.rs` `History ▾` picker across all tools)
2. **Visual Traceroute** (embedded offline Natural Earth 110m vector world map + `earcutr` triangulation + GeoIP enrichment + geodesic arcs)
3. **Path Troubleshoot** (hop-by-hop latency/loss/jitter waterfall + control-plane ICMP rate-limit filtering)
4. **Speed Test & iperf3 Client** (4-stream Cloudflare throughput + bufferbloat grade `A+..F`; native `iperf3` wrapper with `--json-stream` / `-J` fallback and saved LAN/VPN server profiles)

---

## 2. Decisions & Rejected Alternatives (ADR)

### ADR-005: Embedded Offline Natural Earth 50m Country Vector Map + `earcutr` over Web Tile Maps
- **Chosen:** Embed 204 KB pre-extracted Natural Earth 50m country boundary & landmass rings (`crates/netscope-app/assets/world_land.json`, with `0.08°` fine resolution across Türkiye/Mediterranean/neighboring borders and adaptive simplification globally to stay under `epaint`'s 16-bit vertex batch limit), triangulated at runtime via `earcutr 0.5` and rendered with cursor-anchored zoom up to `32x`, radial co-located hop separation, and on-map city/RTT callout pills.
- **Why:** Zero external map tile servers, zero API keys, zero WebView/MapKit platform lock-in, works identically on macOS/Linux/Windows and offline/air-gap networks while still offering crisp country borders and intra-country hop inspection (e.g., Ankara -> Istanbul hops inside Türkiye).
- **Rejected:** MapKit (macOS-only), Slippy raster tile fetchers (adds async image decoding, disk tile cache, and external tile server dependency).

### ADR-006: Explicit Fixed-Width `Layout::top_down` Columns in `egui` over `right_to_left` Containers
- **Chosen:** Replace nested `ui.vertical` inside `Layout::right_to_left` with explicit `allocate_ui_with_layout(vec2(width, height), Layout::top_down(Align::LEFT), ...)` and `TextWrapMode::Extend` for metric columns, and wrap bottom-anchored `bottom_up` sidebar cards in an inner `Layout::top_down(Align::Min)`.
- **Why:** Prevents `egui` from shrinking vertical columns to 1-character width or inverting internal card widget order.

### ADR-007: OPSEC-Safe GeoIP Classification + Anycast Edge PoP & Speed-of-Light RTT Reconciliation
- **Chosen:** Classify RFC1918 (`10/8`, `172.16/12`, `192.168/16`), CGNAT (`100.64/10`), loopback, link-local, and ULA (`fc00::/7`) strictly offline before any `ipwho.is` lookup. For Anycast CDN/DNS networks (Cloudflare, Fastly, CloudFront, Google, Quad9, Akamai), perform a 1.2s non-redirect HTTP `HEAD` probe to extract the serving Edge PoP airport code (`CF-RAY`, `x-amz-cf-pop`, `x-served-by`) and map it to its real city coordinates (`IST` -> Istanbul, `AMS` -> Amsterdam, `FRA` -> Frankfurt), plus enforce a fiber speed-of-light (`~100 km/ms` RTT) constraint (`reconcile_hop_with_speed_of_light`) so ICMP-only Anycast hops cannot falsely jump to a US registry HQ when measured RTT proves they are local. In `path_troubleshoot.rs` and `internet_check.rs`, compare per-hop ICMP drops/spikes against downstream healthy hops so router control-plane ICMP rate limits are flagged accurately rather than falsely blamed.

### ADR-008: Separate HTTP/1.1 Clients for Speed Test + Zero-Dependency Native Rust `iperf3` Wire Client
- **Chosen:** 4 independent `reqwest::Client::builder().http1_only()` workers so Cloudflare speed test streams open 4 real parallel TCP connections instead of multiplexing over a single HTTP/2 connection; for `iperf3`, implement a 100% pure-Rust ESnet `iperf3` v3.17 wire-protocol client directly in `netscope-core/src/iperf3.rs` (37-byte session cookie, `PARAM_EXCHANGE`, `CREATE_STREAMS`, `TEST_START`/`TEST_RUNNING`, `TEST_END`, `EXCHANGE_RESULTS`, `DISPLAY_RESULTS`, `IPERF_DONE`) supporting `-c`, `-p`, `-t`, `-P` (1..32 streams), `-R` (Reverse download), `--bidir` (simultaneous upload+download), `-u` (UDP with 64-bit `[sec][usec][seq]` header, pacing & RFC 1889 jitter/loss), `-b` (target Mbps), `-O` (omit warmup seconds), `-l` (buffer/payload size), and `-N` (`TCP_NODELAY`) with zero OS binary requirement and zero external crate bloat.

---

## 3. Execution Checklist

- [x] Fix `STAGE DETAILS` wrapped metric text & sparkline overlap (`views/internet_check.rs`)
- [x] Fix upside-down `MENU BAR MONITOR` bottom-left card, nav button strokes, duplicate Copy button, and light-mode contrast (`app.rs`, `theme.rs`)
- [x] Fix gateway ICMP ignore false-positive (`internet_check.rs`) and non-VPN upstream DNS label (`net_info.rs`, `tray.rs`)
- [x] Implement persistent JSON state (`history.rs`) and reusable `History ▾` picker (`widgets.rs`) across all tools
- [x] Generate compact offline `assets/world_land.json` (Natural Earth 50m country polygons & borders, 204.5 KB) + `geoip.rs` + `views/visual_traceroute.rs` with 32x cursor-anchored zoom, `Türkiye` quick-focus, radial co-located hop separation, and city/RTT callout badges
- [x] Implement `path_troubleshoot.rs` + `views/path_troubleshoot.rs` + quick-jump from Internet Check
- [x] Implement `speedtest.rs` + `views/speedtest.rs` (4-stream Cloudflare + Bufferbloat grade)
- [x] Implement `iperf3.rs` + `views/iperf3.rs` (saved server profiles + live stream + run history)
- [x] Verify `cargo test --workspace` (31/31 passed), `cargo clippy --workspace --all-targets -- -D warnings` (0 warnings), `./scripts/bundle-macos.sh`, and 3s smoke test
- [x] Add zero-permission `--screenshot-dir` framebuffer capture (`egui::ViewportCommand::Screenshot` + `png`), run visual audit across all 11 screens (including `11-visual-traceroute-turkiye-zoom.png`), and fix secondary layout issues (`MENU BAR MONITOR` height, `STAGE DETAILS` grid alignment, `Visual Traceroute` Route column stacking, `MTR`/`Path Troubleshoot` hostname truncation, `egui_plot` axis label collision, `iperf3` split panel width, Dark Mode text contrast, `epaint` u16 vertex budget)

---

## 4. Current State / Handoff

- **Status:** Done (Visually Audited across all 10 screens)
- **Last Completed:** Added `--screenshot-dir` framebuffer QA mode, visually inspected every tab in light & dark mode, resolved all layout/contrast issues, verified `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, and rebuilt `dist/NetScope.app`.
- **Next Step:** User visual confirmation of `dist/NetScope.app`, then proceed to Phase 3 (LAN Discovery + Network Guard + Port Scanner + Subnet Calculator).
- **Blockers:** None
