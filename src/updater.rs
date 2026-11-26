//! Launcher self-update: check GitHub releases and replace the running exe.
//!
//! The UI only triggers the network/update work on a button click (plus a
//! cached check at startup). No background installation is performed.

use std::fs;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use self_update::backends::github::ReleaseList;

const REPO_OWNER: &str = "Portalboy07";
const REPO_NAME: &str = "gakumas-launcher-fork";
pub const RELEASES_URL: &str =
    "https://github.com/Portalboy07/gakumas-launcher-fork/releases";

#[cfg(windows)]
const ASSET_NAME: &str = "GakumasLauncher.exe";
#[cfg(not(windows))]
const ASSET_NAME: &str = "GakumasLauncher-linux";

const CHECK_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
const CACHE_FILE: &str = "launcher-update.json";

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct Status {
    /// Version compiled into this launcher (`CARGO_PKG_VERSION`).
    pub current: String,
    /// Newest release tag seen by the last successful check.
    pub latest: Option<String>,
    /// The latest release is newer than the running launcher.
    pub update_available: bool,
    /// Unix time in seconds of the last successful check.
    pub checked_at: Option<u64>,
    /// Where releases are published.
    pub url: String,
}

#[derive(Serialize, Deserialize, Default, Clone)]
struct Cache {
    #[serde(default)]
    latest: Option<String>,
    #[serde(default)]
    checked_at: Option<u64>,
}

pub fn current_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn read_cache(base: &Path) -> Cache {
    fs::read(base.join(CACHE_FILE))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

fn write_cache(base: &Path, cache: &Cache) -> Result<(), String> {
    let text = serde_json::to_string_pretty(cache).map_err(|e| e.to_string())?;
    let tmp = base.join(format!("{CACHE_FILE}.tmp"));
    fs::write(&tmp, text).map_err(|e| format!("Failed to save update cache: {e}"))?;
    fs::rename(&tmp, base.join(CACHE_FILE))
        .map_err(|e| format!("Failed to save update cache: {e}"))?;
    Ok(())
}

/// Compare bare semver strings, ignoring a leading `v` on the release tag.
fn is_newer(latest: &str, current: &str) -> bool {
    let numbers = |v: &str| -> Vec<u64> {
        v.trim().trim_start_matches('v').split('.')
            .map(|part| part.parse::<u64>().unwrap_or(0))
            .collect()
    };
    let latest = numbers(latest);
    let current = numbers(current);
    for i in 0..latest.len().max(current.len()) {
        let a = *latest.get(i).unwrap_or(&0);
        let b = *current.get(i).unwrap_or(&0);
        if a != b {
            return a > b;
        }
    }
    false
}

fn make_status(cache: &Cache) -> Status {
    let latest = cache.latest.clone();
    Status {
        current: current_version().to_string(),
        update_available: latest
            .as_deref()
            .is_some_and(|tag| is_newer(tag, current_version())),
        latest,
        checked_at: cache.checked_at,
        url: RELEASES_URL.to_string(),
    }
}

pub fn status(base: &Path) -> Status {
    make_status(&read_cache(base))
}

/// Look up the newest release tag with `self_update`. With `force = false` a
/// successful check is reused for 24 hours.
pub fn check(base: &Path, force: bool) -> Result<Status, String> {
    let cached = read_cache(base);
    if !force {
        if let Some(at) = cached.checked_at {
            let age = now_secs().saturating_sub(at);
            if age < CHECK_INTERVAL.as_secs() {
                return Ok(make_status(&cached));
            }
        }
    }

    let releases = ReleaseList::configure()
        .repo_owner(REPO_OWNER)
        .repo_name(REPO_NAME)
        .build()
        .map_err(|e| format!("Failed to configure release check: {e}"))?
        .fetch()
        .map_err(|e| format!("Failed to check launcher releases: {e}"))?;
    let latest = releases
        .latest()
        .ok_or("No launcher releases found")?
        .version()
        .to_string();

    let cache = Cache {
        latest: Some(latest),
        checked_at: Some(now_secs()),
    };
    write_cache(base, &cache)?;
    Ok(make_status(&cache))
}

/// Download and replace the running executable. Called only from a UI button.
pub fn update() -> Result<String, String> {
    let status = self_update::backends::github::Update::configure()
        .repo_owner(REPO_OWNER)
        .repo_name(REPO_NAME)
        .current_version(current_version())
        .bin_name("GakumasLauncher")
        .asset_matcher(|assets| assets.iter().find(|a| a.name() == ASSET_NAME).cloned())
        .no_confirm(true)
        .show_output(false)
        .show_download_progress(false)
        .build()
        .map_err(|e| format!("Failed to configure launcher update: {e}"))?
        .update()
        .map_err(|e| format!("Launcher update failed: {e}"))?;

    if status.is_updated() {
        Ok(format!("Launcher updated to {}. Restart it to use the new version.", status.version()))
    } else {
        Ok(format!("Launcher is already up to date ({})", status.version()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_comparison_ignores_v_prefix() {
        assert!(is_newer("v0.2.9", "0.1.2"));
        assert!(!is_newer("v0.1.2", "0.1.2"));
        assert!(!is_newer("v0.1.1", "0.1.2"));
        assert!(is_newer("1.0.0", "0.9.9"));
    }
}
