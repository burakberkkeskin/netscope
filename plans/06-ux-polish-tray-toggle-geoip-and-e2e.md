# Plan 06: Self-GeoIP Accuracy, Toggleable Menu Bar Tray, Speed Test / Bufferbloat / DNS / Chart UI/UX Overhaul & Deterministic UI E2E Tests

> **Phase:** 6 of 10 (`v0.6.0`)
> **Status:** Done

---

## 1. Context & Goal (Why)

Address real-world accuracy, usability, visual polish, and deterministic test coverage gaps identified during live daily usage:
1. **Self-GeoIP Origin Accuracy ("This Mac" City):** Commercial/sinkholed or coarse ISP block registries (`ip.guide`) locate dynamic residential pools at a regional POP (e.g., Eskişehir) rather than the user's true city/province (Zonguldak / Ereğli). Use Cloudflare's unblocked edge telemetry (`speed.cloudflare.com/meta`) to seed `GEO_CACHE` accurately for Hop 0 and `PublicNetworkStatus`, plus `db-ip` city fallback.
2. **Toggleable Menu Bar / System Tray:** Allow disabling/re-enabling the OS menu bar / system tray icon at runtime via `PersistedState.menu_bar_enabled` (`Tray: On` / `Tray: Off`); when disabled, closing the window quits cleanly instead of hiding to background.
3. **Speed Test & Bufferbloat UI/UX Overhaul:** Add 4-step phase stepper, peak Mbps KPIs, detailed Bufferbloat diagnostics card (3 latency comparison bars, workload impact pills for Video Calls / Gaming / VoIP / Web Browsing, SQM/FQ-CoDel tip, dedicated Loaded Latency timeline plot), and area-filled throughput chart.
4. **DNS Lookup UI/UX Overhaul:** Replace resolver dropdown with 1-click resolver pills, add summary KPI strip (`Records`, `Query Time`, `Min TTL`, `Resolver`), Structured Table vs Raw `dig` Output view toggle, click-to-copy values, and direct `Check Propagation ->` jump.
5. **General Chart & Table Polish:** Upgrade `Ping` and `iperf3` charts with area fills, legends, dashed median/average reference lines, and add unique `.id_salt(...)` to every `TableBuilder` in the app.
6. **Deterministic Core Unit + Headless UI E2E Test Suite:** Add headless `egui::Context::run_ui` E2E tests inside `netscope-app` testing all 15 tabs in Light/Dark mode, real pointer navigation, theme toggle, tray toggle, DNS jump, Bufferbloat grades, IPv6 states, Subnet Calculator, and Visual Traceroute without GPU/display/network or AI dependency.

---

## 2. Decisions & Rejected Alternatives (ADR)

### ADR-016: Cloudflare `/meta` Self-GeoIP Origin + `GEO_CACHE` Seeding
- **Chosen:** Query `https://speed.cloudflare.com/meta` (with `Referer: https://speed.cloudflare.com/`) during `fetch_public_network_status()`, parse `clientIp`, `city`, `region` (stripping `" Province"`), `country`, `asn`, `asOrganization`, and coordinates, and seed `GEO_CACHE` for both the `/meta` client IP and the active `PublicNetworkStatus.public_ip`; also add `api.db-ip.com/v2/free/{ip}` for non-Anycast hops missing `city`.
- **Why:** Cloudflare `/meta` is not blocked by privacy/adblock DNS lists and resolves edge-observed city/province accuracy (`Ereğli, Zonguldak`) where coarse `/21` registry lookups return `Eskişehir`.
- **Rejected:** Hardcoding city overrides or relying solely on `ip.guide`.

### ADR-017: Runtime Toggleable Menu Bar / System Tray (`PersistedState.menu_bar_enabled`)
- **Chosen:** Persist `menu_bar_enabled: bool` (default `true`) in `state.json`. Toggling `Tray: Off` drops `TrayController` immediately (removing the OS status item) and makes window close quit the process; toggling `Tray: On` recreates `TrayController` and populates it with the latest `PublicNetworkStatus`.
- **Why:** Gives users full control over background tray persistence without restarting the app or adding a separate settings modal.
- **Rejected:** Requiring an app restart or CLI flag to disable the tray icon.

### ADR-018: Deterministic Headless `egui::Context::run_ui` UI E2E Tests
- **Chosen:** Extract `NetScopeApp::render_ui(&mut self, ui: &mut egui::Ui)` and `NetScopeApp::new_headless_for_test()` and drive real layout, rendering, and pointer click events via `egui::Context::run_ui(RawInput, ...)` in `cargo test`.
- **Why:** Runs 100% deterministically with zero display server, GPU, network, or AI dependency across macOS, Linux CI, and Windows, catching widget panics, NaN coordinates, navigation regressions, and state-transition bugs immediately.
- **Rejected:** Screen-scraping/AI-vision test loops in CI (slow, non-deterministic, requires display server).

---

## 3. Execution Checklist

- [x] Update `plans/README.md` with Phase 06 (`v0.6.0`) and shifted Phases 07–10
- [x] Add Cloudflare `/meta` self-GeoIP + `seed_cache` + `db-ip` city fallback in `geoip.rs` & wire into `net_info.rs` (+ offline tests)
- [x] Add `menu_bar_enabled` persistence in `history.rs` and live `Tray: On` / `Tray: Off` toggle in `app.rs` (+ tests)
- [x] Upgrade Speed Test & Bufferbloat core (`speedtest.rs`) and UI (`views/speedtest.rs`)
- [x] Upgrade DNS Lookup UI (`views/dns.rs`) + `Check Propagation ->` jump in `app.rs`
- [x] Upgrade charts (`views/ping.rs`, `views/iperf3.rs`) & add unique `.id_salt(...)` across all `TableBuilder`s
- [x] Implement 8 deterministic headless `egui::Context::run_ui` UI E2E tests in `crates/netscope-app/src/app.rs`
- [x] Bump version to `0.6.0`, run `clippy`, `cargo test --workspace`, `./scripts/bundle-macos.sh`, visual screenshot audit, and release `v0.6.0`

---

## 4. Current State / Handoff

- **Status:** Done
- **Last Completed:** Shipped `v0.6.0` (`clippy` 0 warnings, `cargo test --workspace` 66/66 passed [8/8 UI E2E + 58/58 core], `./scripts/bundle-macos.sh` packaged `/Users/berk/Repos/netscope/dist/NetScope.app`, and visual screenshot audit inspected).
- **Next Step:** Decide between UX polish follow-ups or starting Phase 07 (`v0.7.0` Whois / RDAP & GeoIP Lookup).
- **Blockers:** None
