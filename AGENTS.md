# AGENTS.md — NetScope Agent Instruction Manual

> **Scope**: Repository-level operational guidelines, architectural invariants, and long-term memory for AI agents working on **NetScope** (`netscope`).
>
> **Repository**: `netscope` (Pure-Rust Cross-Platform Network Diagnostics Suite)
> **Owner**: Burak Berk Keskin ("Berk")

---

## Strict Language & Style Policy

- **100% English Repository & UI**: All filenames, docs (`AGENTS.md`, `plans/`, `docs/`, `README.md`), comments, commits, identifiers, and UI strings must be written in clear technical English.
- **Simple, Never Sloppy**: Keep logic direct, modular, and free of speculative abstractions or unused dependencies. Every phase must pass tests and `clippy -D warnings`.

---

## Mandatory Dual-Role Principle (Documentation & Memory Keeper)

Every AI agent working on this repository must keep long-term memory synchronized:
1. Before making code changes, read the active plan in `plans/` and `docs/architecture.md`.
2. Check off completed tasks (`- [ ]` -> `- [x]`) in `plans/` immediately after verification.
3. Record significant architectural decisions and rejected alternatives in the active plan's ADR section.
4. Update `Current State / Handoff` at the end of every work session.

---

## Architectural Invariants

1. **Pure Rust & Minimal External Dependencies**:
   - Single-language Cargo workspace (`crates/netscope-core`, `crates/netscope-app`).
   - Zero Node.js, Electron, WebView, or external runtime dependencies.
   - Linux system tray uses `tray-icon` with `default-features = false, features = ["ksni"]` to avoid GTK3/`libappindicator` runtime requirements.
2. **Core Engine Strictly UI-Free**:
   - `netscope-core` must NEVER depend on `egui`, `eframe`, `tray-icon`, or any windowing library. It exposes async functions, structured events, and `tokio::sync::mpsc` streams usable from GUI, CLI, or tests.
3. **Zero-Root Unprivileged Diagnostics**:
   - Ping, Traceroute, and MTR use unprivileged `SOCK_DGRAM` + `IPPROTO_ICMP` with `IP_TTL` (`socket2`), parsing both macOS (IPv4-header-prefixed) and Linux (stripped) kernel buffers cleanly, with an automatic fallback to system `ping` if `PermissionDenied` occurs.
4. **Zero-Telemetry & OPSEC-First**:
   - No analytics, telemetry, crash uploaders, or third-party tracking.
   - Public IP / DNS leak checks only query explicit, documented endpoints (`1.1.1.1/cdn-cgi/trace`, `ipinfo.io/json`, `o-o.myaddr.l.google.com`) and fail gracefully when offline or behind restricted enterprise proxies.
5. **Cross-Platform Desktop Readiness**:
   - Designed for macOS first, structured to compile cleanly on Linux and Windows. Platform-specific behavior must be isolated cleanly with `#[cfg(...)]` and documented fallbacks.
6. **Pinned Security & GUI Versions**:
   - `rustls` is pinned to `0.23` (matching `rustls-platform-verifier 0.7`, `tokio-rustls 0.26`, `hickory-resolver 0.26`) with `aws-lc-rs` crypto provider installed idempotently before any TLS handshake.
   - `eframe` / `egui` / `egui_extras` stay on `0.37` with `egui_plot` `0.38`. Note `eframe 0.37` uses `App::logic` + `App::ui` (replacing legacy `App::update`).

---

## Workspace Layout

```text
netscope/
├── AGENTS.md                   # Repository invariants & build runbook
├── Cargo.toml                  # Cargo workspace definition
├── LICENSE                     # MIT License
├── README.md                   # Project overview & quickstart
├── plans/                      # Phased roadmap, ADRs & live checklists
│   ├── README.md
│   └── 01-foundation-and-core-diagnostics.md
├── docs/
│   └── architecture.md         # Core/UI decoupling, ICMP, TLS & tray internals
├── scripts/
│   └── bundle-macos.sh         # Builds release binary into dist/NetScope.app
└── crates/
    ├── netscope-core/          # Pure async diagnostics & networking library
    └── netscope-app/           # Cross-platform eframe GUI + tray monitor
```

---

## Build, Test & Package Commands

```bash
# Run all unit & diagnostic tests
cargo test --workspace

# Strict lint check (must pass with zero warnings)
cargo clippy --workspace --all-targets -- -D warnings

# Debug / Release run
cargo run --release -p netscope-app

# Automated visual UI audit across all screens (headless-friendly, zero TCC needed)
cargo run --release -p netscope-app -- --screenshot-dir /tmp/netscope-audit

# Package macOS .app bundle into dist/NetScope.app
./scripts/bundle-macos.sh
```
