//! Launcher self-update: find the newest release on GitHub, download this
//! platform's binary, verify it against the release's SHA-256 digest, and swap
//! it in for the running executable. The new version runs after a restart.
//!
//! Checking is shared with Localify (see [`crate::updates`]); an update is
//! installed only when the user asks for it.

use std::fs::{self, File};
use std::io::{Read, Seek};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

use serde::Serialize;
use serde_json::Value;

use crate::launcher::{Store, UpdateCheck};
use crate::{github, http};

/// `owner/name` of the repository this build updates from. The release
/// workflow sets it to the repository that built the release.
pub const REPO: &str = match option_env!("LAUNCHER_REPO") {
    Some(repo) => repo,
    None => "Portalboy07/gakumas-launcher-fork",
};

/// The release tag's version, set by the release workflow. Local builds leave
/// it unset: they show `Cargo.toml`'s version and do not replace themselves.
const RELEASE_VERSION: Option<&str> = option_env!("LAUNCHER_VERSION");

#[cfg(windows)]
const ASSET_NAME: &str = "GakumasLauncher.exe";
#[cfg(not(windows))]
const ASSET_NAME: &str = "GakumasLauncher-linux";

/// The first bytes of an executable for this platform (PE or ELF).
#[cfg(windows)]
const EXE_MAGIC: &[u8] = b"MZ";
#[cfg(not(windows))]
const EXE_MAGIC: &[u8] = b"\x7fELF";

/// Release binaries are far smaller; a larger asset is not a launcher build.
const MAX_BINARY_SIZE: u64 = 256 * 1024 * 1024;
const DOWNLOAD_FILE: &str = "launcher-update.download";

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct Status {
    /// Version of the running launcher.
    pub current: String,
    /// Built by the release workflow. Local builds can check for updates but not install them.
    pub release_build: bool,
    /// Newest release tag for this platform seen by the last successful check.
    pub latest: Option<String>,
    /// `latest` is newer than the running launcher and not installed yet.
    pub update_available: bool,
    /// Unix time in seconds of the last successful check.
    pub checked_at: Option<u64>,
    /// Where releases are published.
    pub url: String,
    /// Version installed in this session. It runs once the launcher restarts.
    pub restart_pending: Option<String>,
}

/// The update installed in this session, and the executable path to restart.
struct Installed {
    version: String,
    exe: PathBuf,
}

static INSTALLED: Mutex<Option<Installed>> = Mutex::new(None);

pub fn current_version() -> &'static str {
    RELEASE_VERSION.unwrap_or(env!("CARGO_PKG_VERSION"))
}

pub fn releases_url() -> String {
    format!("https://github.com/{REPO}/releases")
}

fn installed_version() -> Option<String> {
    INSTALLED.lock().unwrap_or_else(|e| e.into_inner()).as_ref().map(|i| i.version.clone())
}

fn make_status(check: &UpdateCheck, current: &str, restart_pending: Option<String>) -> Status {
    let update_available = restart_pending.is_none()
        && check.launcher.as_deref().is_some_and(|tag| github::is_newer(tag, current));
    Status {
        current: current.to_string(),
        release_build: RELEASE_VERSION.is_some(),
        latest: check.launcher.clone(),
        update_available,
        checked_at: check.launcher_checked_at,
        url: releases_url(),
        restart_pending,
    }
}

/// The launcher's state from the saved update check (no network).
pub fn status(check: &UpdateCheck) -> Status {
    make_status(check, current_version(), installed_version())
}

/// The newest release with a binary for this platform, as `(tag, asset)`.
/// Prereleases count only when the running launcher is a prerelease itself.
fn select_release<'a>(releases: &'a [Value], current: &str) -> Option<(String, &'a Value)> {
    let allow_pre = github::parse_version(current).is_some_and(|v| !v.pre.is_empty());
    releases
        .iter()
        .filter(|r| !github::is_draft(r) && (allow_pre || !github::is_prerelease(r)))
        .filter_map(|r| {
            let tag = r["tag_name"].as_str()?;
            let version = github::parse_version(tag).filter(|v| allow_pre || v.pre.is_empty())?;
            let asset = github::find_asset(r, |name| name == ASSET_NAME)?;
            Some((version, tag, asset))
        })
        // GitHub lists newest first; reversing keeps the newest of equal versions.
        .rev()
        .max_by(|a, b| a.0.cmp(&b.0))
        .map(|(_, tag, asset)| (tag.to_string(), asset))
}

/// The newest launcher release tag for this platform, if any.
pub fn latest_tag(agent: &ureq::Agent) -> Result<Option<String>, String> {
    let releases = github::releases(agent, REPO)?;
    Ok(select_release(&releases, current_version()).map(|(tag, _)| tag))
}

/// Check the download's digest and that it is an executable for this platform.
fn verify_binary(file: &mut File, sha256: &str) -> Result<(), String> {
    let actual = github::sha256_hex(&mut *file).map_err(|e| format!("Could not read the download: {e}"))?;
    if actual != sha256 {
        return Err("The launcher download does not match the release's SHA-256 digest".into());
    }
    file.rewind().map_err(|e| format!("Could not read the download: {e}"))?;
    let mut magic = vec![0u8; EXE_MAGIC.len()];
    file.read_exact(&mut magic).map_err(|e| format!("Could not read the download: {e}"))?;
    if magic != EXE_MAGIC {
        return Err(format!("{ASSET_NAME} in the release is not an executable for this platform"));
    }
    Ok(())
}

/// Download the newest release and replace the running executable with it.
/// Called only from the UI. `base` holds the download while it is checked.
pub fn update(store: &Store, base: &Path, progress: &dyn Fn(&str, Option<f32>)) -> Result<String, String> {
    if RELEASE_VERSION.is_none() {
        return Err(format!(
            "This is a local build, so it does not replace itself. Download a release from {}.",
            releases_url()
        ));
    }
    if let Some(version) = installed_version() {
        return Ok(format!("Launcher {version} is already installed. Restart the launcher to use it."));
    }
    progress("Checking the latest launcher release...", None);
    let agent = github::agent();
    let releases = github::releases(&agent, REPO)?;
    let (tag, asset) = select_release(&releases, current_version())
        .ok_or_else(|| format!("No launcher release has {ASSET_NAME}"))?;
    // Record the lookup. The daily clock stays put: Localify was not looked up.
    let now = github::now_secs();
    let _ = store.update_update_check(|c| {
        c.launcher = Some(tag.clone());
        c.launcher_checked_at = Some(now);
    });
    if !github::is_newer(&tag, current_version()) {
        return Ok(format!("The launcher is up to date (v{}).", current_version()));
    }
    let asset = github::parse_asset(asset)?;
    if asset.size > MAX_BINARY_SIZE {
        return Err(format!("{ASSET_NAME} in {tag} is unexpectedly large"));
    }
    let exe = std::env::current_exe().map_err(|e| format!("Could not find the running launcher: {e}"))?;

    fs::create_dir_all(base).map_err(|e| format!("Could not create {}: {e}", base.display()))?;
    let download = base.join(DOWNLOAD_FILE);
    let label = format!("Downloading launcher {tag}...");
    progress(&label, None);
    let report = |done: u64, total: Option<u64>| {
        progress(&label, total.filter(|&t| t > 0).map(|t| done as f32 * 100.0 / t as f32));
    };
    http::download_file_with_progress(&agent, &asset.url, &download, Some(asset.size), &report, |file| {
        verify_binary(file, &asset.sha256)
    })?;

    progress("Installing the launcher update...", None);
    let replaced = self_replace::self_replace(&download);
    let _ = fs::remove_file(&download);
    replaced.map_err(|e| {
        format!("Could not replace {}: {e}. Download {tag} from {} instead.", exe.display(), releases_url())
    })?;
    *INSTALLED.lock().unwrap_or_else(|e| e.into_inner()) = Some(Installed { version: tag.clone(), exe });
    Ok(format!("Launcher {tag} installed. Restart the launcher to use it."))
}

/// Start the update installed in this session with the same arguments. The
/// caller exits afterwards. The executable path was saved before the swap
/// because on Linux the running process's own path points at the replaced file.
pub fn start_installed() -> Result<(), String> {
    let installed = INSTALLED.lock().unwrap_or_else(|e| e.into_inner());
    let installed = installed.as_ref().ok_or("No launcher update is waiting for a restart")?;
    Command::new(&installed.exe)
        .args(std::env::args_os().skip(1))
        .spawn()
        .map_err(|e| format!("Could not start {}: {e}", installed.exe.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::Write;

    fn release(tag: &str, prerelease: bool, assets: &[&str]) -> Value {
        let assets: Vec<Value> = assets.iter().map(|name| json!({ "name": name })).collect();
        json!({ "tag_name": tag, "prerelease": prerelease, "draft": false, "assets": assets })
    }

    fn selected(releases: &[Value], current: &str) -> Option<String> {
        select_release(releases, current).map(|(tag, _)| tag)
    }

    #[test]
    fn selects_the_highest_stable_release_with_this_platforms_binary() {
        let releases = [
            release("v0.2.10", false, &[ASSET_NAME]),
            release("v0.4.0", false, &["something-else"]),
            release("v0.3.0", false, &[ASSET_NAME]),
            release("v0.2.9", false, &[ASSET_NAME]),
        ];
        assert_eq!(selected(&releases, "0.2.9").as_deref(), Some("v0.3.0"));
    }

    #[test]
    fn prereleases_are_offered_only_to_prerelease_builds() {
        let releases = [
            release("v0.4.0-beta.1", true, &[ASSET_NAME]),
            release("v0.4.0-rc.1", false, &[ASSET_NAME]),
            release("v0.3.0", false, &[ASSET_NAME]),
        ];
        assert_eq!(selected(&releases, "0.3.0").as_deref(), Some("v0.3.0"));
        assert_eq!(selected(&releases, "0.4.0-alpha.1").as_deref(), Some("v0.4.0-rc.1"));
    }

    #[test]
    fn drafts_and_unversioned_tags_are_skipped() {
        let mut draft = release("v9.0.0", false, &[ASSET_NAME]);
        draft["draft"] = json!(true);
        let releases = [draft, release("latest", false, &[ASSET_NAME])];
        assert_eq!(selected(&releases, "0.3.0"), None);
    }

    #[test]
    fn status_reports_an_update_until_it_is_installed() {
        let check = UpdateCheck { launcher: Some("v0.4.0".into()), launcher_checked_at: Some(1), ..Default::default() };
        assert!(make_status(&check, "0.3.0", None).update_available);
        assert!(!make_status(&check, "0.4.0", None).update_available);
        assert!(!make_status(&check, "0.5.0", None).update_available);
        let pending = make_status(&check, "0.3.0", Some("v0.4.0".into()));
        assert!(!pending.update_available);
        assert_eq!(pending.restart_pending.as_deref(), Some("v0.4.0"));
    }

    #[test]
    fn verify_binary_checks_digest_and_executable_header() {
        let dir = tempfile::tempdir().unwrap();
        let write = |name: &str, data: &[u8]| {
            let path = dir.path().join(name);
            File::create(&path).unwrap().write_all(data).unwrap();
            (File::open(&path).unwrap(), github::sha256_hex(data).unwrap())
        };
        let mut exe = EXE_MAGIC.to_vec();
        exe.extend_from_slice(b"rest of the binary");
        let (mut file, sha) = write("good", &exe);
        assert!(verify_binary(&mut file, &sha).is_ok());
        let (mut file, _) = write("tampered", &exe);
        assert!(verify_binary(&mut file, &"0".repeat(64)).is_err());
        let (mut file, sha) = write("text", b"<html>not a binary</html>");
        assert!(verify_binary(&mut file, &sha).is_err());
    }
}
