//! GitHub release lookups shared by the launcher and Localify updaters.

use std::io::{self, Read};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::Value;

/// Automatic update checks on launch run at most this often.
pub const CHECK_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// An agent for GitHub API calls and release downloads. The read timeout
/// applies to each read, so a stalled connection fails instead of leaving the
/// launcher busy, while a slow but steady download still finishes.
pub fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(15))
        .timeout_read(Duration::from_secs(30))
        .timeout_write(Duration::from_secs(30))
        .user_agent(concat!("GakumasLauncher/", env!("CARGO_PKG_VERSION")))
        .build()
}

/// The repository's most recent releases, newest first (GitHub's order).
pub fn releases(agent: &ureq::Agent, repo: &str) -> Result<Vec<Value>, String> {
    let url = format!("https://api.github.com/repos/{repo}/releases?per_page=20");
    let response = agent
        .get(&url)
        .set("Accept", "application/vnd.github+json")
        .call()
        .map_err(|e| match e {
            ureq::Error::Status(403 | 429, r) if r.header("x-ratelimit-remaining") == Some("0") => {
                "GitHub's API rate limit was reached. Try again later.".to_string()
            }
            ureq::Error::Status(code, _) => format!("GitHub returned HTTP {code} for the {repo} releases"),
            e => format!("Could not reach GitHub: {e}"),
        })?;
    let body = response
        .into_string()
        .map_err(|e| format!("Could not read the {repo} releases: {e}"))?;
    serde_json::from_str(&body).map_err(|e| format!("Could not parse the {repo} releases: {e}"))
}

pub fn is_draft(release: &Value) -> bool {
    release["draft"].as_bool().unwrap_or(false)
}

pub fn is_prerelease(release: &Value) -> bool {
    release["prerelease"].as_bool().unwrap_or(false)
}

/// The first asset of `release` whose name satisfies `matches`.
pub fn find_asset<'a>(release: &'a Value, matches: impl Fn(&str) -> bool) -> Option<&'a Value> {
    release["assets"]
        .as_array()?
        .iter()
        .find(|a| a["name"].as_str().is_some_and(&matches))
}

/// A release asset and the SHA-256 digest GitHub computed for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asset {
    pub url: String,
    pub size: u64,
    /// Lowercase hex.
    pub sha256: String,
}

/// Read an asset's download URL, size and SHA-256 digest. Assets without a
/// digest are rejected because the download could not be verified.
pub fn parse_asset(asset: &Value) -> Result<Asset, String> {
    let name = asset["name"].as_str().unwrap_or("the release asset");
    let url = asset["browser_download_url"]
        .as_str()
        .ok_or_else(|| format!("Missing download URL for {name}"))?;
    let size = asset["size"]
        .as_u64()
        .filter(|&size| size > 0)
        .ok_or_else(|| format!("Invalid size for {name} in the release metadata"))?;
    let sha256 = asset["digest"]
        .as_str()
        .and_then(|d| d.strip_prefix("sha256:"))
        .filter(|hex| hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or_else(|| format!("{name} has no SHA-256 digest to verify the download"))?;
    Ok(Asset { url: url.to_string(), size, sha256: sha256.to_ascii_lowercase() })
}

/// Parse a release tag such as `v1.2.3` as semver.
pub fn parse_version(tag: &str) -> Option<semver::Version> {
    let tag = tag.trim();
    let bare = tag.strip_prefix('v').or_else(|| tag.strip_prefix('V')).unwrap_or(tag);
    semver::Version::parse(bare).ok()
}

/// Whether `latest` is an update over `installed`. Both are compared as
/// semver when they parse, so an older tag never counts as an update;
/// otherwise any different tag does.
pub fn is_newer(latest: &str, installed: &str) -> bool {
    match (parse_version(latest), parse_version(installed)) {
        (Some(latest), Some(installed)) => latest > installed,
        _ => latest.trim() != installed.trim(),
    }
}

/// A check is due when none has run yet, the interval has passed, or the
/// saved time is in the future (the clock was moved back).
pub fn check_due(checked_at: Option<u64>, now: u64) -> bool {
    checked_at.map_or(true, |t| t > now || now - t >= CHECK_INTERVAL.as_secs())
}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Lowercase hex SHA-256 of everything `reader` yields.
pub fn sha256_hex(mut reader: impl Read) -> io::Result<String> {
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        ctx.update(&buf[..n]);
    }
    Ok(ctx.finish().as_ref().iter().map(|b| format!("{b:02x}")).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn versions_compare_as_semver_with_a_v_prefix() {
        assert!(is_newer("v0.3.1", "0.3.0"));
        assert!(is_newer("v0.10.0", "0.9.9"));
        assert!(!is_newer("v0.3.0", "0.3.0"));
        assert!(!is_newer("v0.2.9", "0.3.0"));
        assert!(is_newer("v0.4.0-beta.1", "0.3.0"));
        assert!(!is_newer("v0.4.0-beta.1", "0.4.0"));
    }

    #[test]
    fn unparseable_tags_count_as_newer_only_when_different() {
        assert!(is_newer("nightly-2", "nightly-1"));
        assert!(!is_newer("nightly-1", "nightly-1"));
        assert_eq!(parse_version("3.5"), None);
    }

    #[test]
    fn check_is_due_once_a_day_or_when_the_clock_goes_back() {
        let day = CHECK_INTERVAL.as_secs();
        assert!(check_due(None, 1_000));
        assert!(!check_due(Some(1_000), 1_000 + day - 1));
        assert!(check_due(Some(1_000), 1_000 + day));
        assert!(check_due(Some(5_000), 1_000));
    }

    #[test]
    fn sha256_matches_known_vector() {
        assert_eq!(
            sha256_hex(&b"abc"[..]).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn asset_requires_url_size_and_sha256_digest() {
        let digest = format!("sha256:{}", "AB".repeat(32));
        let asset = json!({ "name": "a.zip", "browser_download_url": "https://example.invalid/a.zip", "size": 10, "digest": digest });
        assert_eq!(parse_asset(&asset).unwrap().sha256, "ab".repeat(32));
        for key in ["browser_download_url", "size", "digest"] {
            let mut broken = asset.clone();
            broken.as_object_mut().unwrap().remove(key);
            assert!(parse_asset(&broken).is_err(), "{key}");
        }
        let mut sha1 = asset.clone();
        sha1["digest"] = json!("sha1:abc");
        assert!(parse_asset(&sha1).is_err());
    }

    #[test]
    fn find_asset_matches_by_name() {
        let release = json!({ "assets": [{ "name": "a.apk" }, { "name": "b.zip" }] });
        assert_eq!(find_asset(&release, |n| n.ends_with(".zip")).unwrap()["name"], "b.zip");
        assert!(find_asset(&release, |n| n == "c").is_none());
    }
}
