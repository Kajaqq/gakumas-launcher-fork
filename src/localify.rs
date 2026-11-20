//! Install Localify's DLL, seed the default translation config if missing,
//! and track the installed release so the launcher can report updates.

use std::fs;
use std::io::{self, Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use serde_json::Value;

use crate::{http, launcher::Store};

const RELEASES_API: &str = "https://api.github.com/repos/chinosk6/gakuen-imas-localify/releases";
const DLL_NAME: &str = "version.dll";
const MAX_DLL_SIZE: u64 = 64 * 1024 * 1024;
const DEFAULT_CONFIG: &[u8] = include_bytes!("localify-config.json");
const ARCHIVE_PREFIX: &str = "DMM_GakumasLocalify_";
/// The automatic update check on launch runs at most this often.
pub const UPDATE_CHECK_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// What the launcher knows about Localify in the selected game folder.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct Status {
    /// `version.dll` is present in the game folder.
    pub installed: bool,
    /// Tag of the installed release, when the DLL still matches the recorded SHA-256.
    pub version: Option<String>,
    /// Newest release tag seen by the last update check.
    pub latest: Option<String>,
    /// The installed release is known and differs from `latest`.
    pub update_available: bool,
    /// Unix time in seconds of the last successful update check.
    pub checked_at: Option<u64>,
}

/// The newest release that ships a DMM build of Localify.
struct Release {
    tag: String,
    url: String,
    size: u64,
    sha256: String,
}

pub fn install(
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

    let (version, archive) = cached_archive(base, progress)?;
    progress("Installing the Localify DLL...", None);
    let zip =
        fs::File::open(&archive).map_err(|e| format!("Could not open Localify archive: {e}"))?;
    let dll_sha256 = install_dll(zip, &game_dir)?;
    let checked_at = now_secs();
    let saved = store.update_localify(|r| {
        r.tag = Some(version.clone());
        r.dll_sha256 = Some(dll_sha256);
        // Installing just read the release list, so it counts as an update check.
        r.latest_tag = Some(version.clone());
        r.checked_at = Some(checked_at);
    });
    match saved {
        Ok(_) => Ok(format!("Localify {version} installed.")),
        Err(e) => Ok(format!("Localify {version} installed, but its version could not be recorded: {e}")),
    }
}

/// Report the installed Localify release without using the network.
pub fn status(store: &Store) -> Status {
    let record = store.localify();
    let dll = store
        .settings()
        .game_path
        .filter(|p| !p.trim().is_empty())
        .map(|p| PathBuf::from(p).join(DLL_NAME))
        .filter(|p| p.is_file());
    let version = match (&dll, record.tag, record.dll_sha256) {
        (Some(dll), Some(tag), Some(expected)) => fs::File::open(dll)
            .and_then(sha256_hex)
            .is_ok_and(|actual| actual == expected)
            .then_some(tag),
        _ => None,
    };
    let update_available = matches!((&version, &record.latest_tag), (Some(v), Some(latest)) if v != latest);
    Status {
        installed: dll.is_some(),
        version,
        latest: record.latest_tag,
        update_available,
        checked_at: record.checked_at,
    }
}

/// Look up the newest release and save its tag. Unless `force` is set, this
/// only reaches GitHub when Localify is installed and the last check is older
/// than [`UPDATE_CHECK_INTERVAL`].
pub fn check_for_updates(store: &Store, force: bool) -> Result<Status, String> {
    let current = status(store);
    if !force && (!current.installed || !check_due(current.checked_at, now_secs())) {
        return Ok(current);
    }
    let release = latest_release(&ureq::agent())?;
    let checked_at = now_secs();
    store.update_localify(|r| {
        r.latest_tag = Some(release.tag);
        r.checked_at = Some(checked_at);
    })?;
    Ok(status(store))
}

/// A check is due when none has run yet, the interval has passed, or the
/// saved time is in the future (the clock was moved back).
fn check_due(checked_at: Option<u64>, now: u64) -> bool {
    checked_at.map_or(true, |t| t > now || now - t >= UPDATE_CHECK_INTERVAL.as_secs())
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Download the newest Localify archive into `base` unless a verified copy is
/// already there, and delete older cached archives.
pub(crate) fn cached_archive(
    base: &Path,
    progress: &dyn Fn(&str, Option<f32>),
) -> Result<(String, PathBuf), String> {
    progress("Checking the latest Localify release...", None);
    let agent = ureq::agent();
    let release = latest_release(&agent)?;
    let archive = base.join(format!("{ARCHIVE_PREFIX}{}.zip", release.tag));
    let cached = http::cached_file_has_size(&archive, release.size)
        && fs::File::open(&archive).is_ok_and(|mut file| verify_archive(&mut file, &release.sha256).is_ok());
    if !cached {
        progress(&format!("Downloading Localify {}...", release.tag), None);
        http::download_file(&agent, &release.url, &archive, Some(release.size), |file| {
            verify_archive(file, &release.sha256)
        })?;
    }
    prune_archives(base, &archive);
    Ok((release.tag, archive))
}

fn latest_release(agent: &ureq::Agent) -> Result<Release, String> {
    let body = agent
        .get(RELEASES_API)
        .call()
        .map_err(|e| format!("Failed to reach the Localify releases: {e}"))?
        .into_string()
        .map_err(|e| e.to_string())?;
    let releases: Vec<Value> =
        serde_json::from_str(&body).map_err(|e| format!("Failed to parse releases: {e}"))?;
    parse_latest_release(&releases)
}

fn parse_latest_release(releases: &[Value]) -> Result<Release, String> {
    let (tag, asset) = releases
        .iter()
        .find_map(|r| {
            let tag = r["tag_name"].as_str()?;
            let asset = r["assets"].as_array()?.iter().find(|a| {
                a["name"]
                    .as_str()
                    .is_some_and(|n| n.starts_with("DMM_GakumasLocalify_v") && n.ends_with(".zip"))
            })?;
            Some((tag, asset))
        })
        .ok_or("No DMM_GakumasLocalify_v*.zip asset found")?;
    if !valid_tag(tag) {
        return Err(format!("Unexpected Localify release tag: {tag}"));
    }
    let url = asset["browser_download_url"]
        .as_str()
        .ok_or("Missing Localify download URL in the release metadata")?;
    let size = asset["size"]
        .as_u64()
        .filter(|&size| size > 0)
        .ok_or("Invalid Localify archive size in the release metadata")?;
    let sha256 = asset["digest"]
        .as_str()
        .and_then(|d| d.strip_prefix("sha256:"))
        .filter(|hex| hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or("The Localify release has no SHA-256 digest to verify the download")?;
    Ok(Release {
        tag: tag.to_string(),
        url: url.to_string(),
        size,
        sha256: sha256.to_ascii_lowercase(),
    })
}

/// The tag becomes part of a cache file name, so allow only plain characters.
fn valid_tag(tag: &str) -> bool {
    !tag.is_empty()
        && tag.len() <= 64
        && tag.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

/// Remove cached Localify archives other than `keep`. Failures are harmless.
fn prune_archives(base: &Path, keep: &Path) {
    let Ok(entries) = fs::read_dir(base) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path != keep && name.starts_with(ARCHIVE_PREFIX) && name.ends_with(".zip") && path.is_file() {
            let _ = fs::remove_file(&path);
        }
    }
}

fn sha256_hex(mut reader: impl Read) -> io::Result<String> {
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

/// Check the archive against the release's SHA-256, then that it holds the DLL.
fn verify_archive(file: &mut fs::File, sha256: &str) -> Result<(), String> {
    let actual = sha256_hex(&mut *file).map_err(|e| format!("Could not read Localify archive: {e}"))?;
    if actual != sha256 {
        return Err("The Localify archive does not match the release's SHA-256 digest".into());
    }
    file.rewind().map_err(|e| format!("Could not read Localify archive: {e}"))?;
    validate_archive(file)
}

fn open_archive<R: Read + Seek>(reader: R) -> Result<zip::ZipArchive<R>, String> {
    zip::ZipArchive::new(reader).map_err(|e| format!("Invalid Localify archive: {e}"))
}

fn localify_dll<R: Read + Seek>(
    archive: &mut zip::ZipArchive<R>,
) -> Result<zip::read::ZipFile<'_, R>, String> {
    let dll = archive
        .by_name(DLL_NAME)
        .map_err(|e| format!("Could not read {DLL_NAME} from Localify archive: {e}"))?;
    if !dll.is_file() || dll.size() == 0 || dll.size() > MAX_DLL_SIZE {
        return Err(format!("Invalid {DLL_NAME} in Localify archive"));
    }
    Ok(dll)
}

fn validate_archive(reader: impl Read + Seek) -> Result<(), String> {
    let mut archive = open_archive(reader)?;
    localify_dll(&mut archive).map(|_| ())
}

/// Install the DLL and return its SHA-256.
fn install_dll(reader: impl Read + Seek, game_dir: &Path) -> Result<String, String> {
    let mut archive = open_archive(reader)?;
    let dll = localify_dll(&mut archive)?;
    let expected = dll.size();
    let mut staged = tempfile::NamedTempFile::new_in(game_dir).map_err(|e| format!("Could not stage {DLL_NAME}: {e}"))?;
    let copied = std::io::copy(&mut dll.take(MAX_DLL_SIZE + 1), &mut staged)
        .map_err(|e| format!("Could not extract {DLL_NAME}: {e}"))?;
    if copied != expected {
        return Err(format!("Unexpected size for {DLL_NAME} in Localify archive"));
    }
    staged.as_file_mut().rewind().map_err(|e| format!("Could not read {DLL_NAME}: {e}"))?;
    let sha256 = sha256_hex(staged.as_file_mut()).map_err(|e| format!("Could not read {DLL_NAME}: {e}"))?;
    let local = game_dir.join("gakumas-local");
    fs::create_dir_all(&local)
        .map_err(|e| format!("Could not create gakumas-local: {e}"))?;
    install_default_config(&local)
        .map_err(|e| format!("Could not create gakumas-local/config.json: {e}"))?;
    staged.persist(game_dir.join(DLL_NAME)).map_err(|e| format!("Could not install {DLL_NAME}: {e}"))?;
    Ok(sha256)
}

fn install_default_config(local: &Path) -> io::Result<()> {
    let path = local.join("config.json");
    if path.is_file() {
        return Ok(());
    }
    let mut config = tempfile::NamedTempFile::new_in(local)?;
    config.write_all(DEFAULT_CONFIG)?;
    match config.persist_noclobber(&path) {
        Ok(_) => Ok(()),
        Err(e) if e.error.kind() == io::ErrorKind::AlreadyExists && path.is_file() => Ok(()),
        Err(e) => Err(e.error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::launcher::Settings;
    use serde_json::json;
    use std::io::Cursor;
    use zip::write::SimpleFileOptions;

    fn archive(entries: &[(&str, &[u8])]) -> Cursor<Vec<u8>> {
        let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for (name, data) in entries {
            zip.start_file(*name, SimpleFileOptions::default()).unwrap();
            zip.write_all(data).unwrap();
        }
        zip.finish().unwrap()
    }

    fn sha(data: &[u8]) -> String {
        sha256_hex(data).unwrap()
    }

    /// A store whose settings point at `game`.
    fn store_for(game: &Path) -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path().to_path_buf()).unwrap();
        let settings = Settings { game_path: Some(game.display().to_string()), ..Settings::default() };
        store.save_settings(&settings).unwrap();
        (dir, store)
    }

    fn release_json(tag: &str, digest: Option<&str>) -> Value {
        let mut asset = json!({
            "name": format!("DMM_GakumasLocalify_{tag}.zip"),
            "browser_download_url": "https://example.invalid/a.zip",
            "size": 10,
        });
        if let Some(d) = digest {
            asset["digest"] = json!(d);
        }
        json!({ "tag_name": tag, "assets": [asset] })
    }

    #[test]
    fn installs_only_the_dll_and_default_config() {
        let game = tempfile::tempdir().unwrap();
        let zip = archive(&[(DLL_NAME, b"dll"), ("gakumas-local/config.json", b"bundled"), ("extra.dll", b"skip")]);
        assert_eq!(install_dll(zip, game.path()).unwrap(), sha(b"dll"));
        assert_eq!(fs::read(game.path().join(DLL_NAME)).unwrap(), b"dll");
        let local = game.path().join("gakumas-local");
        assert_eq!(fs::read(local.join("config.json")).unwrap(), DEFAULT_CONFIG);
        assert_eq!(local.read_dir().unwrap().count(), 1);
        assert_eq!(game.path().read_dir().unwrap().count(), 2);
    }

    #[test]
    fn update_preserves_existing_localization_files() {
        let game = tempfile::tempdir().unwrap();
        let local = game.path().join("gakumas-local");
        fs::create_dir(&local).unwrap();
        fs::write(local.join("config.json"), b"custom").unwrap();
        fs::write(game.path().join(DLL_NAME), b"old").unwrap();
        install_dll(archive(&[(DLL_NAME, b"new"), ("gakumas-local/config.json", b"bundled")]), game.path()).unwrap();
        assert_eq!(fs::read(game.path().join(DLL_NAME)).unwrap(), b"new");
        assert_eq!(fs::read(local.join("config.json")).unwrap(), b"custom");
    }

    #[test]
    fn sha256_matches_known_vector() {
        assert_eq!(sha(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    #[test]
    fn archive_with_wrong_digest_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.zip");
        let zip = archive(&[(DLL_NAME, b"dll")]).into_inner();
        fs::write(&path, &zip).unwrap();
        let mut file = fs::File::open(&path).unwrap();
        assert!(verify_archive(&mut file, &sha(b"something else")).is_err());
        let mut file = fs::File::open(&path).unwrap();
        assert!(verify_archive(&mut file, &sha(&zip)).is_ok());
    }

    #[test]
    fn release_requires_a_sha256_digest() {
        let digest = format!("sha256:{}", "AB".repeat(32));
        let release = parse_latest_release(&[release_json("v3.5.0", Some(&digest))]).unwrap();
        assert_eq!(release.tag, "v3.5.0");
        assert_eq!(release.sha256, "ab".repeat(32));
        assert!(parse_latest_release(&[release_json("v3.5.0", None)]).is_err());
        assert!(parse_latest_release(&[release_json("v3.5.0", Some("sha1:abc"))]).is_err());
    }

    #[test]
    fn release_tag_with_path_characters_is_rejected() {
        let digest = format!("sha256:{}", "a".repeat(64));
        assert!(parse_latest_release(&[release_json("../v1", Some(&digest))]).is_err());
    }

    #[test]
    fn pruning_keeps_only_the_current_archive() {
        let dir = tempfile::tempdir().unwrap();
        let keep = dir.path().join("DMM_GakumasLocalify_v2.zip");
        for name in ["DMM_GakumasLocalify_v1.zip", "DMM_GakumasLocalify_v2.zip", "other.zip", "dw-proton.tar.xz"] {
            fs::write(dir.path().join(name), b"x").unwrap();
        }
        prune_archives(dir.path(), &keep);
        let mut left: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        left.sort();
        assert_eq!(left, ["DMM_GakumasLocalify_v2.zip", "dw-proton.tar.xz", "other.zip"]);
    }

    #[test]
    fn check_is_due_once_a_day_or_when_the_clock_goes_back() {
        let day = UPDATE_CHECK_INTERVAL.as_secs();
        assert!(check_due(None, 1_000));
        assert!(!check_due(Some(1_000), 1_000 + day - 1));
        assert!(check_due(Some(1_000), 1_000 + day));
        assert!(check_due(Some(5_000), 1_000));
    }

    #[test]
    fn store_keeps_the_localify_record() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path().to_path_buf()).unwrap();
        assert_eq!(store.localify(), Default::default());
        store.update_localify(|r| r.tag = Some("v1".into())).unwrap();
        store.update_localify(|r| r.latest_tag = Some("v2".into())).unwrap();
        let record = store.localify();
        assert_eq!(record.tag.as_deref(), Some("v1"));
        assert_eq!(record.latest_tag.as_deref(), Some("v2"));
    }

    #[test]
    fn status_reports_the_recorded_version_only_while_the_dll_matches() {
        let game = tempfile::tempdir().unwrap();
        let (_data, store) = store_for(game.path());
        assert!(!status(&store).installed);

        fs::write(game.path().join(DLL_NAME), b"dll").unwrap();
        let unknown = status(&store);
        assert!(unknown.installed && unknown.version.is_none() && !unknown.update_available);

        store
            .update_localify(|r| {
                r.tag = Some("v1".into());
                r.dll_sha256 = Some(sha(b"dll"));
                r.latest_tag = Some("v2".into());
            })
            .unwrap();
        let known = status(&store);
        assert_eq!(known.version.as_deref(), Some("v1"));
        assert!(known.update_available);

        fs::write(game.path().join(DLL_NAME), b"replaced").unwrap();
        let replaced = status(&store);
        assert!(replaced.installed && replaced.version.is_none() && !replaced.update_available);
    }

    #[test]
    fn automatic_check_skips_the_network_when_not_due() {
        let game = tempfile::tempdir().unwrap();
        let (_data, store) = store_for(game.path());
        // Not installed: no check, even though none has run.
        assert_eq!(check_for_updates(&store, false).unwrap().checked_at, None);
        // Installed and checked just now: the saved result is returned.
        fs::write(game.path().join(DLL_NAME), b"dll").unwrap();
        let now = now_secs();
        store.update_localify(|r| { r.latest_tag = Some("v9".into()); r.checked_at = Some(now); }).unwrap();
        let s = check_for_updates(&store, false).unwrap();
        assert_eq!((s.latest.as_deref(), s.checked_at), (Some("v9"), Some(now)));
    }
}
