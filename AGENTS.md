# AGENTS.md

This file provides guidance to AI agents when working with code in this repository.

## What this is

A Tauri 2 (Rust) desktop launcher for the DMM version of Gakuen Idolmaster, for Windows and Linux. It replaces DMM GAME PLAYER: it handles login, the launch token, game file downloads and launching. It also gets past DMM's Japan region check with **user-space** VPN engines (OpenVPN + WireGuard over a smoltcp TCP/IP stack), so it never creates a network adapter or changes routes. This is a fork. Its additions are English localization, Proton/Linux support (including the CrackProof anti-debug driver fix), a Localify installer and a self-updater. README.md describes user-facing behavior in detail. Keep it in sync when behavior changes, because the README is written as a behavior spec.

## Commands

```
cargo build --release --bin GakumasLauncher      # main app -> target/release/GakumasLauncher(.exe)
cargo build --release --locked --bins            # what CI builds (includes the dev probe binaries)
cargo test                                       # unit tests (inline #[cfg(test)] modules) + tests/
cargo test --lib launcher::                      # tests in one module
cargo test --lib <test_name>                     # a single unit test
cargo test --offline --test proxy_wireguard      # offline end-to-end: CONNECT proxy over a loopback WireGuard peer
```

On Linux, building needs the GTK 3 / WebKit2GTK 4.1 dev packages (see `.github/workflows/build.yml` for the exact apt list). `proton.rs` is compiled only on non-Windows (`#[cfg(not(windows))]`), and `dpapi.rs`/`winutil.rs` only on Windows, so a test run on one OS doesn't cover the other OS's modules.

Dev-only binaries in `src/bin/` exercise the core without the UI. They print no secrets:

- `launcher_cli`: the full login → tunnel → launch-token → update flow (`--mode vpngate|direct|file`, `--status-only`, `--launch`).
- `vpngate_probe` / `vpnfile_probe`: connect a tunnel and call the DMM API through it.

## Release / versioning

Pushing a `v*` tag runs CI, which builds Windows and Linux and publishes `GakumasLauncher.exe` and `GakumasLauncher-linux` to a GitHub release. CI passes the tag version to the compiler through the `LAUNCHER_VERSION` env var (`option_env!` in `updater.rs`) and patches only `tauri.conf.json`. **Don't bump `Cargo.toml`/`Cargo.lock` for releases.** The build must stay `--locked`. Local builds report `Cargo.toml`'s version and refuse to self-replace. `updater::REPO` is hard-coded to `Portalboy07/gakumas-launcher-fork` (a unit test asserts it): every build, forks included, updates from that repo.

## Architecture

**Split:** `src/lib.rs` (`gakumas_launcher` crate) holds the UI-independent core. `src/main.rs` is the Tauri app: `AppState`, all `#[tauri::command]` handlers registered in `generate_handler!`, and window management. `src/profile_setup.rs` is a main-only module. The UI is a single static file, `ui/index.html` (no bundler, `withGlobalTauri`). It calls commands with `invoke(...)` and listens for the `progress` / `close-blocked` events. Adding a command means writing the handler in `main.rs`, registering it in `generate_handler!`, and calling it from `index.html`.

**Core flow (`launcher.rs`):** verify the saved login token → open a Japan connection (built-in VPN Gate tunnel, a user VPN file, or direct) → get the launch token through that connection → download changed game files over the **normal** connection → launch. `Store` owns the data dir (`<app_local_data>/data`), which holds `settings.json`, the encrypted token, the device ID, the VPN Gate list cache, the VPN file and the update/Localify records. Shared files are guarded by module-level static mutexes. The shared tunnel is a process-wide singleton (`shared_tunnel` / `rotate_tunnel_if` / `reset_shared_tunnel`), and a failed tunnel is rotated to another VPN Gate server.

**Network stack:** `openvpn.rs` (TCP/UDP, tls-auth/tls-crypt, CBC/GCM) and `wireguard.rs` (boringtun) produce IP packets. `netstack.rs` (`TunnelStack`, smoltcp) runs TCP over them. `http.rs` builds HTTP requests and handles DMM's API formats. `vpngate.rs` parses the VPN Gate server list and holds the built-in University of Tsukuba profile (`vpngate_builtin.ovpn`). `www.vpngate.net` only offers TLS 1.2 CBC suites, so it uses `native-tls`. Everything else uses rustls/ureq. `browser_proxy.rs` is a loopback HTTPS CONNECT proxy, so the in-app DMM browser window (a WebView with `dmm_browser.js` injected) can go through the tunnel. The login window uses the system connection and `keep_login.js`. The code never reads, fills in or submits passwords: WebView2 stores them itself.

**Platform layer (`platform.rs`):** one interface for launching, process detection, paths and secret encryption. On Windows it delegates to `dpapi.rs`/`winutil.rs`. On Linux it uses an AES-256-GCM keystore, a `/proc` scan and `proton.rs`. `main.rs` sets the `GAKUMAS_BASE_DIR` env var so the platform layer can find the data dir without an `AppHandle`.

**Proton (`proton.rs`, Linux only):** detects Proton installs and installs DW-Proton into Steam's `compatibilitytools.d`. It creates the prefix with `wineboot` and `winetricks` from PATH (corefonts, powershell, webview2, vcrun2022) and keeps a persistent appdata symlink in the prefix. Before launch it installs the `usrdrv017764.sys` anti-debug driver and starts its service **in the same Wine session** as the game, using a generated CMD script, because Wine's `NtLoadDriver` is a stub. It sets `WINE_SERVICES_SESSION0=1` and `version.dll=n,b`. The DXVK DLLs in `assets/dxvk/x86_64/` are embedded with `include_bytes!`. They must stay the exact GE-Proton10-31 build, because the in-game Vuplex webview needs it (see `assets/dxvk/SOURCE.md`).

**Updates:** `github.rs` holds the shared release lookup, semver comparison, SHA-256 checks and the 24 h interval. `updates.rs` runs one combined check with `Scope::Daily` (on launch, both components) or `Scope::Launcher` / `Scope::Localify` (panel buttons: one component, without moving the daily clock). The daily clock moves only when every lookup succeeds. `updater.rs` swaps the launcher binary (`self-replace`). `localify.rs` installs `chinosk6/gakuen-imas-localify`. A first install extracts `gakumas-local/`, and on non-Chinese systems it rewrites the configs to point at the English translation data. An update replaces only `version.dll`. Installing is refused while the game is running.

## Conventions

- Older code comments and doc comments are in **Korean** (this is a fork of a Korean project). Newer fork code and all user-facing strings are in **English**. Write new comments and UI text in English.
- Errors are `Result<_, String>` with user-readable messages, because they're shown directly in the UI.
- `Researches/` is git-ignored scratch space (everything except its `.gitignore`).
- Windows release builds link the CRT statically (`.cargo/config.toml`), so the exe doesn't need the VC++ redistributable.
