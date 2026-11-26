//! Linux-only Proton support: find installations, create a Wine prefix and
//! install the Windows runtime components the game needs.
//!
//! All data is kept in the Tauri app-local-data folder. The selected Proton and
//! prefix are stored in the same `settings.json` the launcher uses.

use std::collections::HashSet;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::{http, launcher::Store, localify};

const BUNDLE_ID: &str = "local.gakumas.launcher";
const DEPS_MARKER: &str = ".gakumas-deps-ok";

/// DXVK v2.7.1-451-g3731c2f5: the exact build shipped in GE-Proton10-31
/// (upstream commit 3731c2f5b67942f5eafbb12e7444b787dfb12775).
/// This specific build is required for Vuplex's D3D11 shared-texture/fence
/// handoff to work under Proton. Provenance and hashes: assets/dxvk/SOURCE.md;
/// license: assets/dxvk/LICENSE.
const DXVK_D3D11_X64_SHA256: &str =
    "3ba898530288520aedfe0876c6a98939c2684af1792c720d259f3b1d30393296";
const DXVK_DXGI_X64_SHA256: &str =
    "793f542bd38669757c59f87c7f188e30bb51f01f86a7177a4c6a1fe3fff8090f";
const DXVK_D3D11_X64: &[u8] = include_bytes!("../assets/dxvk/x86_64/d3d11.dll");
const DXVK_DXGI_X64: &[u8] = include_bytes!("../assets/dxvk/x86_64/dxgi.dll");
const DXVK_LICENSE: &[u8] = include_bytes!("../assets/dxvk/LICENSE");

/// The anti-debug driver the original executable asks Wine to load via the
/// (stubbed) NtLoadDriver. Sourced from LOLDrivers; SHA-256 verified.
const DRIVER_URL: &str = "https://media.githubusercontent.com/media/magicsword-io/LOLDrivers/main/drivers/ed96f1a99a3693d40cc302d5ae0840b8.bin";
const DRIVER_SHA256: &str = "64035e86735d0c01e0eb0862def6a48f012ec0a8e701874092ee1506ab65d273";
const DW_RELEASES_API: &str =
    "https://api.github.com/repos/dawn-winery/dwproton-mirror/releases/latest";

fn sha256_hex(data: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, data);
    digest
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Find installed Proton versions. Returns (display name, path) pairs.
pub fn detect_candidates() -> Vec<(String, String)> {
    let Some(home) = std::env::var_os("HOME") else {
        return Vec::new();
    };
    let home = PathBuf::from(home);

    // (directory, only names starting with Proton/DW-Proton)
    let mut roots: Vec<(PathBuf, bool)> = vec![
        (home.join(".steam/root/compatibilitytools.d"), false),
        (home.join(".local/share/Steam/compatibilitytools.d"), false),
        (home.join(".steam/steam/steamapps/common"), true),
        (home.join(".local/share/Steam/steamapps/common"), true),
    ];

    let mut found: Vec<(String, String)> = Vec::new();
    for (dir, filtered) in roots.drain(..) {
        let Ok(entries) = fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if filtered && !(name.starts_with("Proton") || name.starts_with("DW-Proton")) {
                continue;
            }
            if let Some(candidate) = candidate(&entry.path(), &name) {
                found.push(candidate);
            }
        }
    }

    let mut seen = HashSet::new();
    let mut out: Vec<(String, String)> = Vec::new();
    for c in found {
        if seen.insert(c.1.clone()) {
            out.push(c);
        }
    }
    out.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    out
}

/// A directory containing a `proton` script, or a path to a `proton` file.
/// Resolve symlinks so the same install reached through two Steam paths is
/// only listed once.
fn candidate(path: &Path, name: &str) -> Option<(String, String)> {
    if !(path.is_file() || (path.is_dir() && path.join("proton").is_file())) {
        return None;
    }
    let real = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    Some((name.to_string(), real.to_string_lossy().into_owned()))
}

/// Locate the Tauri app-local-data folder without an `AppHandle`.
pub(crate) fn find_base() -> Option<PathBuf> {
    // main.rs publishes the real Tauri app-local-data dir at startup.
    if let Some(dir) = std::env::var_os("GAKUMAS_BASE_DIR") {
        let base = PathBuf::from(dir);
        if base.join("data").join("settings.json").is_file() {
            return Some(base);
        }
    }
    let mut bases = Vec::new();
    if let Some(xdg) = std::env::var_os("XDG_DATA_HOME") {
        bases.push(PathBuf::from(xdg).join(BUNDLE_ID));
    }
    if let Some(home) = std::env::var_os("HOME") {
        bases.push(PathBuf::from(home).join(".local/share").join(BUNDLE_ID));
    }
    bases
        .into_iter()
        .find(|b| b.join("data").join("settings.json").is_file())
}

/// Read one setting directly, avoiding `Store::settings()` recursion.
fn raw_setting(key: &str) -> Option<String> {
    let base = find_base()?;
    let text = fs::read_to_string(base.join("data").join("settings.json")).ok()?;
    let v: Value = serde_json::from_str(text.trim_start_matches('\u{feff}')).ok()?;
    let s = v[key].as_str()?.trim();
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

/// The prefix explicitly configured by the user (no default fallback).
pub(crate) fn configured_prefix() -> Option<PathBuf> {
    raw_setting("proton_prefix").map(PathBuf::from)
}

/// The Proton explicitly configured by the user.
pub(crate) fn configured_proton() -> Option<PathBuf> {
    raw_setting("proton_path").map(PathBuf::from)
}

pub fn default_prefix(base: &Path) -> PathBuf {
    base.join("proton-prefix")
}

fn load_settings(base: &Path) -> crate::launcher::Settings {
    match Store::new(base.join("data")) {
        Ok(store) => store.settings(),
        Err(_) => crate::launcher::Settings::default(),
    }
}

/// Status consumed by the UI. Always returns an object with the same keys.
pub fn status(base: &Path) -> Value {
    let candidates = detect_candidates();
    let settings = load_settings(base);

    let proton = settings
        .proton_path
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| {
            candidates
                .first()
                .map(|(_, path)| path.clone())
                .unwrap_or_default()
        });

    let prefix = settings
        .proton_prefix
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| default_prefix(base).to_string_lossy().into_owned());
    let prefix_path = PathBuf::from(&prefix);
    let prefix_exists = prefix_path.is_dir();
    let deps_installed = prefix_exists && prefix_path.join(DEPS_MARKER).is_file();

    let list: Vec<Value> = candidates
        .iter()
        .map(|(name, path)| json!({ "name": name, "path": path }))
        .collect();

    json!({
        "available": true,
        "proton": proton,
        "prefix": prefix,
        "prefix_exists": prefix_exists,
        "deps_installed": deps_installed,
        "candidates": list,
    })
}

/// An empty path means "use the default" and is stored as unset.
fn optional_path(path: &str) -> Option<String> {
    Some(path.trim().to_string()).filter(|p| !p.is_empty())
}

pub fn set_path(base: &Path, store: &Store, path: &str) -> Result<Value, String> {
    let mut settings = store.settings();
    settings.proton_path = optional_path(path);
    store.save_settings(&settings)?;
    Ok(status(base))
}

pub fn set_prefix(base: &Path, store: &Store, path: &str) -> Result<Value, String> {
    let mut settings = store.settings();
    settings.proton_prefix = optional_path(path);
    store.save_settings(&settings)?;
    Ok(status(base))
}

/// Save the Proton path and prefix together (one settings write) and return
/// the resulting status (one candidate scan).
pub fn set_paths(base: &Path, store: &Store, proton: &str, prefix: &str) -> Result<Value, String> {
    let mut settings = store.settings();
    settings.proton_path = optional_path(proton);
    settings.proton_prefix = optional_path(prefix);
    store.save_settings(&settings)?;
    Ok(status(base))
}

/// Resolve the configured Proton, or the first detected one.
fn selected_proton(settings: &crate::launcher::Settings) -> Result<PathBuf, String> {
    settings
        .proton_path
        .as_ref()
        .filter(|s| !s.trim().is_empty())
        .map(PathBuf::from)
        .or_else(|| detect_candidates().into_iter().next().map(|(_, p)| PathBuf::from(p)))
        .ok_or_else(|| {
            "No Proton installation found. Install DW-Proton or select a Proton path first.".into()
        })
}

/// Wine executables shipped inside a Proton installation.
fn proton_scripts(proton: &Path) -> Vec<PathBuf> {
    let mut scripts = Vec::new();
    if proton.is_file() {
        scripts.push(proton.to_path_buf());
        if let Some(parent) = proton.parent() {
            scripts.push(parent.join("files/bin/wine64"));
            scripts.push(parent.join("files/bin/wine"));
        }
    } else {
        scripts.push(proton.join("proton"));
        scripts.push(proton.join("files/bin/wine64"));
        scripts.push(proton.join("files/bin/wine"));
    }
    scripts
}

fn is_proton_script(path: &Path) -> bool {
    path.file_name()
        .is_some_and(|n| n.to_string_lossy().eq_ignore_ascii_case("proton"))
}

/// The Proton script always uses `<STEAM_COMPAT_DATA_PATH>/pfx` as its prefix.
/// Link that location to the prefix we report in the UI so both agree.
fn compat_data(prefix: &Path) -> Result<PathBuf, String> {
    let compat = prefix
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
        .join("proton-compat");
    fs::create_dir_all(&compat)
        .map_err(|e| format!("Failed to create the Proton data folder: {e}"))?;
    let pfx = compat.join("pfx");
    match fs::symlink_metadata(&pfx) {
        Ok(meta) if meta.file_type().is_symlink() => {
            if fs::read_link(&pfx).ok().as_deref() != Some(prefix) {
                fs::remove_file(&pfx)
                    .map_err(|e| format!("Failed to replace the Proton prefix link: {e}"))?;
                std::os::unix::fs::symlink(prefix, &pfx)
                    .map_err(|e| format!("Failed to link the Proton prefix: {e}"))?;
            }
        }
        Ok(_) => {} // a real directory from an earlier run: leave it alone
        Err(_) => {
            std::os::unix::fs::symlink(prefix, &pfx)
                .map_err(|e| format!("Failed to link the Proton prefix: {e}"))?;
        }
    }
    Ok(compat)
}

/// Colon-separated host GStreamer plugin dirs that actually exist.
fn host_gstreamer_path() -> String {
    let candidates = [
        "/usr/lib64/gstreamer-1.0",
        "/usr/lib/gstreamer-1.0",
        "/usr/lib/x86_64-linux-gnu/gstreamer-1.0",
        "/usr/lib/aarch64-linux-gnu/gstreamer-1.0",
    ];
    let existing: Vec<&str> = candidates
        .iter()
        .copied()
        .filter(|p| Path::new(p).is_dir())
        .collect();
    let mut value = existing.join(":");
    if let Ok(extra) = std::env::var("GST_PLUGIN_PATH_1_0") {
        if !extra.is_empty() {
            if !value.is_empty() {
                value.push(':');
            }
            value.push_str(&extra);
        }
    }
    value
}

/// Set the environment and leading argument required by a runner.
fn prepare_command(cmd: &mut Command, runner: &Path, prefix: &Path) -> Result<(), String> {
    cmd.env("WINEPREFIX", prefix)
        .env("WINEARCH", "win64")
        .env("PROTON_VERB", "runinprefix")
        .env("WINE_SERVICES_SESSION0", "1")
        // Proton overrides GST_PLUGIN_SYSTEM_PATH with its own bundled dirs;
        // add the host H.264 plugins as a user path so in-game videos decode.
        // Detect the distro's plugin dir rather than hardcoding one layout.
        .env("GST_PLUGIN_PATH_1_0", host_gstreamer_path());
    if is_proton_script(runner) {
        cmd.env("STEAM_COMPAT_DATA_PATH", compat_data(prefix)?)
            .arg("runinprefix");
    }
    Ok(())
}

fn find_tool(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn winetricks_has_verb(tool: &Path, verb: &str) -> bool {
    fs::read_to_string(tool)
        .map(|s| s.contains(&format!("w_metadata {verb} ")))
        .unwrap_or(false)
}

/// Quote a path for safe use inside a POSIX shell script.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// A tiny shim that makes any tool which expects a `wine` binary use the
/// selected Proton. Proton's paths can contain spaces, and its own `wine64`
/// may not exist, so pointing winetricks at it directly is unreliable.
fn wine_wrapper(base: &Path, proton_script: &Path) -> Result<PathBuf, String> {
    fs::create_dir_all(base)
        .map_err(|e| format!("Failed to create the launcher data folder: {e}"))?;
    let path = base.join("wine-wrapper.sh");
    let body = format!(
        "#!/bin/sh\nexec {} runinprefix \"$@\"\n",
        shell_quote(&proton_script.to_string_lossy())
    );
    fs::write(&path, body).map_err(|e| format!("Failed to create the Wine wrapper: {e}"))?;
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(&path)
        .map_err(|e| e.to_string())?
        .permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&path, perms).map_err(|e| e.to_string())?;
    Ok(path)
}

/// Install WebView2 without relying on a winetricks verb: download Microsoft's
/// bootstrapper and run it silently through the Proton shim.
fn install_webview2_direct(
    base: &Path,
    wine: &Path,
    prefix: &Path,
    compat: &Path,
    progress: &dyn Fn(&str, Option<f32>),
) -> Result<(), String> {
    let download_dir = tempfile::tempdir_in(base)
        .map_err(|e| format!("Failed to stage the WebView2 installer: {e}"))?;
    let installer = download_dir.path().join("MicrosoftEdgeWebview2Setup.exe");
    progress("Downloading the WebView2 runtime installer...", None);
    http::download_file(
        &ureq::agent(),
        "https://go.microsoft.com/fwlink/p/?LinkId=2124703",
        &installer,
        None,
        |_| Ok(()),
    )?;
    progress("Installing the WebView2 runtime...", None);
    let mut cmd = Command::new(wine);
    cmd.arg(&installer).arg("/silent").arg("/install");
    cmd.env("WINEPREFIX", prefix)
        .env("WINEARCH", "win64")
        .env("PROTON_VERB", "runinprefix")
        .env("STEAM_COMPAT_DATA_PATH", compat);
    let status = cmd
        .status()
        .map_err(|e| format!("Failed to install the WebView2 runtime: {e}"))?;
    if !status.success() {
        return Err(format!("Failed to install the WebView2 runtime ({status})"));
    }
    Ok(())
}

/// Keep Unity's `persistentDataPath` outside the Proton prefix.
///
/// The game's asset-cache index lives under
/// `AppData/LocalLow/BANDAI NAMCO Entertainment Inc_`. If the prefix is
/// deleted, that index is lost and the game re-downloads its ~7 GB `octo/v1`
/// asset cache from the game folder. Move the real directory into the
/// launcher's app-data folder and leave a symlink in the prefix, so a new
/// prefix points at the same data.
fn ensure_game_appdata(prefix: &Path, base: &Path) -> Result<(), String> {
    use std::os::unix::fs::symlink;

    let name = "BANDAI NAMCO Entertainment Inc_";
    let link = prefix
        .join("drive_c/users/steamuser/AppData/LocalLow")
        .join(name);
    let stable = base.join("game-appdata").join(name);

    fs::create_dir_all(stable.parent().ok_or("Invalid app-data path")?)
        .map_err(|e| format!("Failed to create the game app-data folder: {e}"))?;

    match fs::symlink_metadata(&link) {
        Ok(meta) if meta.file_type().is_symlink() => {
            if fs::read_link(&link).ok().as_deref() == Some(stable.as_path()) {
                fs::create_dir_all(&stable)
                    .map_err(|e| format!("Failed to create the game app-data folder: {e}"))?;
                return verify_game_appdata(&link, &stable);
            }
            let wrong = link.with_file_name(format!("{name}.wrong-link"));
            fs::rename(&link, &wrong)
                .map_err(|e| format!("Failed to set aside an old app-data link: {e}"))?;
        }
        Ok(_) => {
            // A real directory: move it to the stable location. If that is not
            // possible (different filesystems), merge its contents instead.
            if !stable.exists() && fs::rename(&link, &stable).is_ok() {
                symlink(&stable, &link)
                    .map_err(|e| format!("Failed to link game app-data: {e}"))?;
                return verify_game_appdata(&link, &stable);
            }
            copy_tree(&link, &stable)?;
            let backup = link.with_file_name(format!("{name}.prefix-backup"));
            fs::rename(&link, &backup)
                .map_err(|e| format!("Failed to set aside the old app-data folder: {e}"))?;
        }
        Err(_) => {}
    }

    fs::create_dir_all(&stable)
        .map_err(|e| format!("Failed to create the game app-data folder: {e}"))?;
    symlink(&stable, &link).map_err(|e| format!("Failed to link game app-data: {e}"))?;
    verify_game_appdata(&link, &stable)
}

/// Confirm the prefix path is a symlink to the stable folder, which exists.
fn verify_game_appdata(link: &Path, stable: &Path) -> Result<(), String> {
    let meta = fs::symlink_metadata(link)
        .map_err(|e| format!("Game app-data link is missing: {e}"))?;
    if !meta.file_type().is_symlink() {
        return Err(format!("{} is not a symlink", link.display()));
    }
    if fs::read_link(link).ok().as_deref() != Some(stable) {
        return Err(format!("{} points at the wrong target", link.display()));
    }
    if !stable.is_dir() {
        return Err(format!("Game app-data folder {} is missing", stable.display()));
    }
    Ok(())
}

/// Copy `src` into `dst` without deleting either tree. Existing files are left
/// untouched, so this is safe when a stable app-data folder already exists.
fn copy_tree(src: &Path, dst: &Path) -> Result<(), String> {
    fs::create_dir_all(dst).map_err(|e| format!("Failed to create {}: {e}", dst.display()))?;
    for entry in fs::read_dir(src).map_err(|e| format!("Failed to read {}: {e}", src.display()))? {
        let entry = entry.map_err(|e| e.to_string())?;
        let source = entry.path();
        let target = dst.join(entry.file_name());
        let kind = entry.file_type().map_err(|e| e.to_string())?;
        if kind.is_dir() {
            copy_tree(&source, &target)?;
        } else if kind.is_file() && !target.exists() {
            fs::copy(&source, &target)
                .map_err(|e| format!("Failed to copy {}: {e}", source.display()))?;
        }
    }
    Ok(())
}

/// Install the tested DXVK D3D11/DXGI pair where Wine can find it.
/// `WINEDLLOVERRIDES=d3d11=n;dxgi=n` makes Wine load native DLLs. The game
/// process searches the game folder, but Vuplex's Chromium child searches
/// its own executable folder, so both locations need the pair.
fn install_dxvk(game: &Path, progress: &dyn Fn(&str, Option<f32>)) -> Result<(), String> {
    if !game.exists() {
        return Err(format!("Game folder not found: {}", game.display()));
    }
    let locations = [
        game.to_path_buf(),
        game.join("gakumas_Data/Plugins/x86_64/VuplexWebViewChromium"),
    ];
    for (name, data, expected) in [
        ("d3d11.dll", DXVK_D3D11_X64, DXVK_D3D11_X64_SHA256),
        ("dxgi.dll", DXVK_DXGI_X64, DXVK_DXGI_X64_SHA256),
    ] {
        let actual = sha256_hex(data);
        if actual != expected {
            return Err(format!("Bundled {name} failed its SHA-256 check ({actual})"));
        }
        for dir in &locations {
            if !dir.is_dir() {
                continue;
            }
            let path = dir.join(name);
            let current = fs::read(&path).ok();
            if current.as_deref().map(|bytes| sha256_hex(bytes) == expected).unwrap_or(false) {
                continue;
            }
            progress(&format!("Installing bundled DXVK {name} in {}...", dir.display()), None);
            fs::write(&path, data)
                .map_err(|e| format!("Failed to write {}: {e}", path.display()))?;
        }
    }
    let license = game.join("DXVK-LICENSE.txt");
    let _ = fs::write(&license, DXVK_LICENSE);
    Ok(())
}

/// Create the prefix and install the Windows runtime dependencies.
pub fn setup(
    base: &Path,
    store: &Store,
    progress: &dyn Fn(&str, Option<f32>),
) -> Result<String, String> {
    let settings = store.settings();
    let proton = selected_proton(&settings)?;
    let prefix = settings
        .proton_prefix
        .as_ref()
        .filter(|s| !s.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| default_prefix(base));

    fs::create_dir_all(&prefix)
        .map_err(|e| format!("Failed to create the Proton prefix folder: {e}"))?;

    // 1) Generate the prefix with wineboot through Proton.
    progress("Creating the Proton prefix (wineboot)...", None);
    let mut last_error = String::from("no usable Proton or Wine executable found");
    let mut created = false;
    for script in proton_scripts(&proton) {
        if !script.is_file() {
            continue;
        }
        let mut cmd = Command::new(&script);
        if let Err(e) = prepare_command(&mut cmd, &script, &prefix) {
            last_error = e;
            continue;
        }
        let result = cmd.arg("wineboot.exe").output();
        match result {
            Ok(output) => {
                // wineboot commonly returns a non-zero code even when the
                // prefix was created correctly, so check the prefix itself.
                if output.status.success() || prefix.join("drive_c").is_dir() {
                    created = true;
                    break;
                }
                last_error = format!("{} exited with {}", script.display(), output.status);
            }
            Err(e) => last_error = format!("{}: {e}", script.display()),
        }
    }
    if !created {
        return Err(format!("Failed to create the Proton prefix: {last_error}"));
    }
    ensure_game_appdata(&prefix, base)?;

    // 2) Install the Windows runtime components using the system winetricks
    // and the selected Proton only. No Heroic / protontricks dependency.
    let tool = find_tool("winetricks").ok_or_else(|| {
        "winetricks was not found in PATH. Please install winetricks and try again.".to_string()
    })?;
    let script = proton_scripts(&proton)
        .into_iter()
        .find(|p| p.is_file())
        .ok_or_else(|| format!("Proton script not found: {}", proton.display()))?;
    let compat = compat_data(&prefix)?;
    let wine = wine_wrapper(base, &script)?;

    for component in ["corefonts", "powershell", "vcrun2022"] {
        progress(
            &format!("Installing {component}..."),
            None,
        );
        let mut cmd = Command::new(&tool);
        cmd.arg("--unattended").arg(component);
        cmd.env("WINEPREFIX", &prefix)
            .env("WINEARCH", "win64")
            .env("WINE", &wine)
            .env("PROTON_VERB", "runinprefix")
            .env("STEAM_COMPAT_DATA_PATH", &compat);
        let status = cmd
            .status()
            .map_err(|e| format!("Failed to run {}: {e}", tool.display()))?;
        if !status.success() {
            return Err(format!(
                "Failed to install {component} ({status}). Check the network connection and try again."
            ));
        }
    }

    if winetricks_has_verb(&tool, "webview2") {
        progress("Installing webview2...", None);
        let mut cmd = Command::new(&tool);
        cmd.arg("--unattended").arg("webview2");
        cmd.env("WINEPREFIX", &prefix)
            .env("WINEARCH", "win64")
            .env("WINE", &wine)
            .env("PROTON_VERB", "runinprefix")
            .env("STEAM_COMPAT_DATA_PATH", &compat);
        let status = cmd
            .status()
            .map_err(|e| format!("Failed to run {}: {e}", tool.display()))?;
        if !status.success() {
            return Err(format!("Failed to install webview2 ({status})"));
        }
    } else {
        install_webview2_direct(base, &wine, &prefix, &compat, progress)?;
    }

    let _ = install_mod_fonts(&prefix);

    if let Some(game) = settings.game_path.as_ref().filter(|s| !s.trim().is_empty()) {
        install_dxvk(Path::new(game), progress)?;
    }

    fs::write(prefix.join(DEPS_MARKER), b"ok\n")
        .map_err(|e| format!("Failed to save the dependency marker: {e}"))?;

    Ok("Proton prefix created and dependencies installed successfully.".into())
}

/// Download and install the latest DW-Proton release into Steam's
/// compatibilitytools directory. DW-Proton is needed for the original game
/// executable because it handles the CrackProof driver path.
pub fn install_dw_proton(
    base: &Path,
    store: &Store,
    progress: &dyn Fn(&str, Option<f32>),
) -> Result<Value, String> {
    // Already installed: just select the newest DW-Proton, no download.
    let installed = detect_candidates()
        .into_iter()
        .filter(|(name, _)| name.to_lowercase().contains("dwproton"))
        .max_by(|a, b| a.0.cmp(&b.0))
        .map(|(_, path)| path);
    if let Some(path) = installed {
        let mut settings = store.settings();
        settings.proton_path = Some(path.clone());
        store.save_settings(&settings)?;
        let mut result = status(base);
        if let Some(obj) = result.as_object_mut() {
            obj.insert("message".into(), json!(format!("DW-Proton already installed: {path}")));
        }
        return Ok(result);
    }

    progress("Fetching the DW-Proton release list...", None);
    let agent = ureq::agent();
    let response = agent
        .get(DW_RELEASES_API)
        .call()
        .map_err(|e| format!("Failed to reach the DW-Proton releases: {e}"))?;
    let body = response
        .into_string()
        .map_err(|e| format!("Failed to read the release list: {e}"))?;
    let release: Value =
        serde_json::from_str(&body).map_err(|e| format!("Failed to parse the release list: {e}"))?;
    let tag = release["tag_name"].as_str().unwrap_or("dwproton");
    let asset = release["assets"]
        .as_array()
        .and_then(|assets| {
            assets.iter().find(|a| {
                a["name"]
                    .as_str()
                    .is_some_and(|n| n.ends_with(".tar.xz") && !n.ends_with(".torrent"))
            })
        })
        .ok_or("No DW-Proton archive was found in the latest release")?;
    let url = asset["browser_download_url"]
        .as_str()
        .ok_or("Missing DW-Proton download URL")?;
    let size = asset["size"]
        .as_u64()
        .filter(|&size| size > 0)
        .ok_or("Invalid DW-Proton archive size in the release metadata")?;

    let archive = base.join(format!("dwproton-{tag}-x86_64.tar.xz"));
    if !http::cached_file_has_size(&archive, size) {
        progress(&format!("Downloading {tag} (about 330 MB)..."), None);
        http::download_file(&agent, url, &archive, Some(size), |_| Ok(()))?;
    }

    let home = std::env::var_os("HOME").map(PathBuf::from);
    let compat_dir = home
        .as_ref()
        .map(|h| h.join(".steam/root/compatibilitytools.d"))
        .filter(|p| p.is_dir())
        .or_else(|| {
            home.as_ref()
                .map(|h| h.join(".local/share/Steam/compatibilitytools.d"))
        })
        .ok_or("Could not locate the Steam compatibilitytools.d directory")?;
    fs::create_dir_all(&compat_dir).map_err(|e| e.to_string())?;

    progress(&format!("Extracting {tag}..."), None);
    let exit = Command::new("tar")
        .arg("-xJf")
        .arg(&archive)
        .arg("-C")
        .arg(&compat_dir)
        .status()
        .map_err(|e| format!("Failed to extract DW-Proton: {e}"))?;
    if !exit.success() {
        return Err("Failed to extract DW-Proton".to_string());
    }

    // Select the freshly installed DW-Proton automatically.
    if let Some((_, path)) = detect_candidates()
        .into_iter()
        .find(|(name, _)| name.to_lowercase().contains("dwproton"))
    {
        let mut settings = store.settings();
        settings.proton_path = Some(path);
        store.save_settings(&settings)?;
    }
    let mut result = status(base);
    if let Some(obj) = result.as_object_mut() {
        obj.insert("message".into(), json!("DW-Proton installed and selected"));
    }
    Ok(result)
}

/// The Localify UI loads two hardcoded Windows fonts. Copy files from the
/// prefix's own corefonts installation under those names as fallbacks.
fn install_mod_fonts(prefix: &Path) -> Result<(), String> {
    let fonts = prefix.join("drive_c/windows/Fonts");
    fs::create_dir_all(&fonts).map_err(|e| format!("Failed to create the Fonts folder: {e}"))?;

    let source = ["arialuni.ttf", "arial.ttf", "times.ttf"]
        .iter()
        .map(|name| fonts.join(name))
        .find(|path| path.is_file())
        .or_else(|| {
            fs::read_dir(&fonts).ok().and_then(|entries| {
                entries.flatten().find_map(|entry| {
                    let path = entry.path();
                    (path.is_file()
                        && path.extension().and_then(|e| e.to_str()) == Some("ttf"))
                    .then_some(path)
                })
            })
        })
        .ok_or("corefonts are not installed in this prefix yet")?;

    for name in ["msyh.ttc", "segoeui.ttf"] {
        let target = fonts.join(name);
        if !target.exists() {
            fs::copy(&source, &target)
                .map_err(|e| format!("Failed to install {name}: {e}"))?;
        }
    }
    Ok(())
}

/// Download the latest Localify release and extract it into the game folder.
/// The archive places `version.dll` and `gakumas-local/` at the game root.
pub fn install_localify(
    base: &Path,
    store: &Store,
    progress: &dyn Fn(&str, Option<f32>),
) -> Result<String, String> {
    let game_path = store
        .settings()
        .game_path
        .filter(|p| !p.trim().is_empty())
        .ok_or("Please select the game folder first")?;
    let game_dir = PathBuf::from(game_path);
    if !game_dir.is_dir() {
        return Err(format!("Game folder not found: {}", game_dir.display()));
    }

    let (version, archive) = localify::cached_archive(base, progress)?;
    progress("Extracting Localify into the game folder...", None);
    let exit = Command::new("unzip")
        .arg("-o")
        .arg("-q")
        .arg(&archive)
        .arg("-d")
        .arg(&game_dir)
        .status()
        .map_err(|e| format!("Failed to extract Localify: {e}"))?;
    if !exit.success() {
        return Err("Failed to extract Localify".to_string());
    }
    if !game_dir.join("version.dll").is_file() {
        return Err("version.dll was not found after installing Localify".to_string());
    }

    progress("Installing fonts required by the Localify menu...", None);
    let prefix = configured_prefix()
        .or_else(|| find_base().map(|b| default_prefix(&b)))
        .unwrap_or_else(|| base.join("proton-prefix"));
    let _ = install_mod_fonts(&prefix);

    Ok(format!("Localify {version} installed. version.dll is next to the game executable."))
}

/// Place the verified anti-debug driver into the prefix so the launch script
/// can register and start it. The game calls NtLoadDriver, which Wine stubs.
fn ensure_driver_file(base: &Path, prefix: &Path) -> Result<(), String> {
    let system_driver = prefix.join("drive_c/windows/system32/usrdrv017764.sys");
    if system_driver.is_file() {
        return Ok(());
    }
    let candidate = base.join("usrdrv017764.sys");
    if !fs::File::open(&candidate).is_ok_and(|file| verify_driver(file).is_ok()) {
        http::download_file(&ureq::agent(), DRIVER_URL, &candidate, None, |file| {
            verify_driver(file)
        })?;
    }
    fs::create_dir_all(system_driver.parent().unwrap_or(prefix)).map_err(|e| e.to_string())?;
    fs::copy(&candidate, &system_driver)
        .map_err(|e| format!("Failed to install the game driver: {e}"))?;
    Ok(())
}

fn verify_driver(mut reader: impl Read) -> Result<(), String> {
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).map_err(|e| e.to_string())?;
    if sha256_hex(&bytes) != DRIVER_SHA256 {
        return Err("The downloaded anti-debug driver failed verification".into());
    }
    Ok(())
}

/// Convert a Linux path into the Z: drive path Wine exposes for the host root.
fn windows_path(path: &Path) -> String {
    let s = path.to_string_lossy();
    if s.starts_with('/') {
        format!("Z:{}", s.replace('/', "\\"))
    } else {
        s.replace('/', "\\")
    }
}

/// Launch the Windows game through the configured Proton.
pub fn launch_game(exe: &Path, args: &str, cwd: &Path) -> Result<(), String> {
    let proton = configured_proton()
        .or_else(|| detect_candidates().into_iter().next().map(|(_, p)| PathBuf::from(p)))
        .ok_or_else(|| {
            "No Proton installation found. Select one in the Proton settings first.".to_string()
        })?;

    let proton_script = proton_scripts(&proton)
        .into_iter()
        .find(|p| p.is_file())
        .ok_or_else(|| format!("Proton script not found: {}", proton.display()))?;

    let cwd = if cwd.as_os_str().is_empty() {
        exe.parent().unwrap_or(Path::new("."))
    } else {
        cwd
    };

    let prefix = configured_prefix()
        .or_else(|| find_base().map(|b| default_prefix(&b)))
        .unwrap_or_else(|| PathBuf::from("proton-prefix"));

    let base = find_base().unwrap_or_else(|| {
        prefix
            .parent()
            .unwrap_or(Path::new("."))
            .to_path_buf()
    });
    ensure_driver_file(&base, &prefix)?;
    ensure_game_appdata(&prefix, &base)?;

    // The driver service and the game must run in the SAME Wine session.
    // A service started in one Proton invocation is gone in the next one, so
    // register/start it and launch the game from a single CMD script.
    // Launch by file name after cd: Wine only prepends the executable's
    // directory to the DLL search path when the exe is launched relatively,
    // which is what makes a game-folder version.dll (localization mod) load.
    let script_dir = exe
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(cwd);
    let exe_name = exe
        .file_name()
        .unwrap_or(exe.as_os_str())
        .to_string_lossy();
    // Self-heal: make sure the tested DXVK pair is present even if the
    // dependency setup was skipped (the marker already existed).
    install_dxvk(script_dir, &|_: &str, _: Option<f32>| {})?;
    let script_path = prefix.join("drive_c/gakumas-launch.cmd");
    let script_body = format!(
        "@echo off\r\n\
         sc.exe query usrdrv017764 >nul 2>&1\r\n\
         if errorlevel 1060 sc.exe create usrdrv017764 type= kernel start= demand binPath= C:\\windows\\system32\\usrdrv017764.sys\r\n\
         reg.exe add HKLM\\SYSTEM\\CurrentControlSet\\Services\\usrdrv017764 /v ImagePath /t REG_EXPAND_SZ /d C:\\windows\\system32\\usrdrv017764.sys /f >nul 2>&1\r\n\
         sc.exe stop usrdrv017764 >nul 2>&1\r\n\
         sc.exe start usrdrv017764 >nul 2>&1\r\n\
         cd /d \"{}\"\r\n\
         \"{}\" {}\r\n",
        windows_path(script_dir),
        exe_name,
        args
    );
    fs::write(&script_path, script_body)
        .map_err(|e| format!("Failed to write the launch script: {e}"))?;

    let mut cmd = Command::new(&proton_script);
    prepare_command(&mut cmd, &proton_script, &prefix)?;
    // version.dll: localization proxy; winmm=b: ignore leftover shims;
    // d3d11/dxgi=n: use the tested DXVK pair bundled in the game folder.
    cmd.env("WINEDLLOVERRIDES",
            "version.dll=n,b;winmm=b;d3d11=n;dxgi=n");
    cmd.arg("cmd.exe")
        .arg("/c")
        .arg(windows_path(&script_path));

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("Failed to launch the game: {e}"))?;

    // Watch briefly. Proton can exit with code 0 without actually starting
    // the game (for example when wine crashes), so success is only reported
    // when a game process is visible or Proton is still running.
    let name = exe
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("gakumas.exe");
    let deadline = Instant::now() + Duration::from_secs(12);
    loop {
        if crate::platform::is_process_running(name) {
            return Ok(());
        }
        match child
            .try_wait()
            .map_err(|e| format!("Failed to check the game process: {e}"))?
        {
            Some(status) => {
                return Err(format!(
                    "The game did not start (Proton exited with {status}). Try another executable or Proton version."
                ));
            }
            None if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(200));
            }
            None => return Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_installed_proton() {
        let candidates = detect_candidates();
        assert!(
            candidates
                .iter()
                .any(|(name, _)| name.to_lowercase().contains("proton")),
            "expected at least one Proton candidate, got {candidates:?}"
        );
        for (_, path) in &candidates {
            assert!(Path::new(path).exists(), "candidate path missing: {path}");
        }
    }

    #[test]
    fn status_has_ui_contract_keys() {
        let base = Path::new("/tmp/opencode/proton-status-test");
        let s = status(base);
        for key in [
            "available",
            "proton",
            "prefix",
            "prefix_exists",
            "deps_installed",
            "candidates",
        ] {
            assert!(s.get(key).is_some(), "status is missing key {key}");
        }
        assert_eq!(s["available"], json!(true));
        assert!(s["candidates"].is_array());
        assert!(s["prefix"].as_str().is_some_and(|p| p.ends_with("proton-prefix")));
    }

    #[test]
    fn set_paths_saves_proton_and_prefix_together() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path();
        let store = Store::new(base.join("data")).unwrap();

        let s = set_paths(base, &store, " /opt/proton/proton ", " /tmp/prefix ").unwrap();
        assert_eq!(s["proton"], json!("/opt/proton/proton"));
        assert_eq!(s["prefix"], json!("/tmp/prefix"));
        // Persisted, as a restart would read it.
        let saved = Store::new(base.join("data")).unwrap().settings();
        assert_eq!(saved.proton_path.as_deref(), Some("/opt/proton/proton"));
        assert_eq!(saved.proton_prefix.as_deref(), Some("/tmp/prefix"));

        // Clearing both fields restores the defaults.
        let s = set_paths(base, &store, "", "  ").unwrap();
        let saved = store.settings();
        assert_eq!(saved.proton_path, None);
        assert_eq!(saved.proton_prefix, None);
        assert_eq!(s["prefix"], json!(default_prefix(base).to_string_lossy()));

        // The standalone selection still changes only the Proton path.
        set_prefix(base, &store, "/tmp/prefix").unwrap();
        set_path(base, &store, "/opt/other/proton").unwrap();
        let saved = store.settings();
        assert_eq!(saved.proton_path.as_deref(), Some("/opt/other/proton"));
        assert_eq!(saved.proton_prefix.as_deref(), Some("/tmp/prefix"));
    }

    #[test]
    fn finds_system_winetricks() {
        let tool = find_tool("winetricks").expect("winetricks in PATH");
        assert!(tool.is_file());
    }

    #[test]
    fn wine_wrapper_quotes_spaces_in_proton_path() {
        let base = Path::new("/tmp/opencode/proton-wrapper-test");
        let script = Path::new("/home/portal/.steam/root/compatibilitytools.d/Proton-GE Latest/proton");
        let wrapper = wine_wrapper(base, script).expect("wrapper");
        let body = fs::read_to_string(wrapper).expect("read wrapper");
        assert!(body.starts_with("#!/bin/sh"));
        assert!(body.contains("runinprefix"));
        assert!(body.contains("Proton-GE Latest"));
    }

    #[test]
    fn moves_real_game_appdata_into_a_symlink() {
        let dir = tempfile::tempdir().expect("tempdir");
        let prefix = dir.path().join("prefix");
        let base = dir.path().join("data");
        let leaf = "BANDAI NAMCO Entertainment Inc_";
        let link = prefix.join("drive_c/users/steamuser/AppData/LocalLow").join(leaf);
        fs::create_dir_all(link.join("gakumas")).expect("create real dir");
        fs::write(link.join("gakumas/cache.bin"), b"index").expect("write cache");

        ensure_game_appdata(&prefix, &base).expect("migrate");

        let stable = base.join("game-appdata").join(leaf);
        assert!(fs::symlink_metadata(&link).expect("link").file_type().is_symlink());
        assert_eq!(fs::read_link(&link).expect("target"), stable);
        assert_eq!(fs::read(link.join("gakumas/cache.bin")).expect("read via link"), b"index");
        verify_game_appdata(&link, &stable).expect("verify");
    }

    #[test]
    fn keeps_an_existing_correct_symlink() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().expect("tempdir");
        let prefix = dir.path().join("prefix");
        let base = dir.path().join("data");
        let leaf = "BANDAI NAMCO Entertainment Inc_";
        let link = prefix.join("drive_c/users/steamuser/AppData/LocalLow").join(leaf);
        let stable = base.join("game-appdata").join(leaf);
        fs::create_dir_all(&stable).expect("stable dir");
        fs::write(stable.join("marker"), b"ok").expect("marker");
        fs::create_dir_all(link.parent().expect("parent")).expect("link parent");
        symlink(&stable, &link).expect("symlink");

        ensure_game_appdata(&prefix, &base).expect("no-op");
        assert_eq!(fs::read_link(&link).expect("target"), stable);
        assert_eq!(fs::read(stable.join("marker")).expect("marker"), b"ok");
    }

    #[test]
    fn replaces_a_wrong_symlink() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().expect("tempdir");
        let prefix = dir.path().join("prefix");
        let base = dir.path().join("data");
        let leaf = "BANDAI NAMCO Entertainment Inc_";
        let link = prefix.join("drive_c/users/steamuser/AppData/LocalLow").join(leaf);
        let stable = base.join("game-appdata").join(leaf);
        fs::create_dir_all(&stable).expect("stable dir");
        fs::create_dir_all(link.parent().expect("parent")).expect("link parent");
        symlink(dir.path().join("somewhere-else"), &link).expect("wrong symlink");

        ensure_game_appdata(&prefix, &base).expect("replace wrong link");
        assert_eq!(fs::read_link(&link).expect("target"), stable);
        verify_game_appdata(&link, &stable).expect("verify");
    }
}
