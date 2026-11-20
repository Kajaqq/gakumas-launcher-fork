//! Install Localify and track the installed release so the launcher can
//! report updates.
//!
//! A first install (no `gakumas-local` folder yet) extracts the release's
//! `gakumas-local` folder. Outside Chinese systems it leaves out the bundled
//! Chinese `local-files` and points the config at the English translation
//! data. An update replaces only `version.dll`.

use std::fs;
use std::io::{self, Read, Seek};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use serde_json::{json, Value};

use crate::{http, launcher::Store, platform};

const RELEASES_API: &str = "https://api.github.com/repos/chinosk6/gakuen-imas-localify/releases";
const DLL_NAME: &str = "version.dll";
const MAX_DLL_SIZE: u64 = 64 * 1024 * 1024;
const ARCHIVE_PREFIX: &str = "DMM_GakumasLocalify_";
const LOCAL_DIR: &str = "gakumas-local";
const LOCAL_FILES: &str = "local-files";
const ENGLISH_ASSETS_URL: &str = "https://api.github.com/repos/NatsumeLS/Gakumas-Translation-Data-EN/releases/latest";
/// Upper bound for any single file extracted from the archive.
const MAX_ENTRY_SIZE: u64 = 64 * 1024 * 1024;
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
    let english = !platform::system_language_is_chinese();
    let (dll_sha256, first_install) = install_from_archive(zip, &game_dir, english)?;
    let checked_at = now_secs();
    let saved = store.update_localify(|r| {
        r.tag = Some(version.clone());
        r.dll_sha256 = Some(dll_sha256);
        // Installing just read the release list, so it counts as an update check.
        r.latest_tag = Some(version.clone());
        r.checked_at = Some(checked_at);
    });
    let done = match (first_install, english) {
        (true, true) => format!("Localify {version} installed with the English translation settings."),
        (true, false) => format!("Localify {version} installed."),
        (false, _) => format!("Localify updated to {version} (only version.dll was replaced)."),
    };
    match saved {
        Ok(_) => Ok(done),
        Err(e) => Ok(format!("{done} Its version could not be recorded: {e}")),
    }
}

/// Install from a verified archive. Returns the DLL's SHA-256 and whether this
/// was a first install (the game folder had no `gakumas-local` folder).
fn install_from_archive(
    reader: impl Read + Seek,
    game_dir: &Path,
    english: bool,
) -> Result<(String, bool), String> {
    if game_dir.join(LOCAL_DIR).exists() {
        Ok((install_dll(reader, game_dir)?, false))
    } else {
        Ok((install_fresh(reader, game_dir, english)?, true))
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

/// Extract the DLL next to the game, without touching anything else. Returns its SHA-256.
fn install_dll(reader: impl Read + Seek, game_dir: &Path) -> Result<String, String> {
    let mut archive = open_archive(reader)?;
    let (staged, sha256) = stage_dll(&mut archive, game_dir)?;
    staged.persist(game_dir.join(DLL_NAME)).map_err(|e| format!("Could not install {DLL_NAME}: {e}"))?;
    Ok(sha256)
}

/// Copy the DLL into a temporary file in `game_dir` and hash it.
fn stage_dll<R: Read + Seek>(
    archive: &mut zip::ZipArchive<R>,
    game_dir: &Path,
) -> Result<(tempfile::NamedTempFile, String), String> {
    let dll = localify_dll(archive)?;
    let expected = dll.size();
    let mut staged = tempfile::NamedTempFile::new_in(game_dir).map_err(|e| format!("Could not stage {DLL_NAME}: {e}"))?;
    let copied = io::copy(&mut dll.take(MAX_DLL_SIZE + 1), &mut staged)
        .map_err(|e| format!("Could not extract {DLL_NAME}: {e}"))?;
    if copied != expected {
        return Err(format!("Unexpected size for {DLL_NAME} in Localify archive"));
    }
    staged.as_file_mut().rewind().map_err(|e| format!("Could not read {DLL_NAME}: {e}"))?;
    let sha256 = sha256_hex(staged.as_file_mut()).map_err(|e| format!("Could not read {DLL_NAME}: {e}"))?;
    Ok((staged, sha256))
}

/// First install: extract the DLL and the archive's `gakumas-local` folder.
/// With `english`, leave out `local-files` and switch the config to the
/// English translation data. Returns the DLL's SHA-256.
fn install_fresh(reader: impl Read + Seek, game_dir: &Path, english: bool) -> Result<String, String> {
    let mut archive = open_archive(reader)?;
    // Build the folder beside the game first so a failure leaves nothing half-extracted.
    let staging = tempfile::Builder::new()
        .prefix(".localify-")
        .tempdir_in(game_dir)
        .map_err(|e| format!("Could not stage {LOCAL_DIR}: {e}"))?;
    let local = staging.path().join(LOCAL_DIR);
    fs::create_dir_all(&local).map_err(|e| format!("Could not stage {LOCAL_DIR}: {e}"))?;
    extract_local_dir(&mut archive, staging.path(), english)?;
    if english {
        patch_json(
            &local.join("config.json"),
            &[
                ("useAPIAssets", json!(true)),
                ("useAPIAssetsURL", json!(ENGLISH_ASSETS_URL)),
                ("useAPITextureAssets", json!(false)),
            ],
        )?;
        patch_json(&local.join("localizationConfig.json"), &[("replaceFont", json!(false))])?;
    }
    let (dll, sha256) = stage_dll(&mut archive, game_dir)?;
    // The DLL goes in first: if moving the folder then fails, the next
    // install still sees no gakumas-local and runs as a first install again.
    dll.persist(game_dir.join(DLL_NAME)).map_err(|e| format!("Could not install {DLL_NAME}: {e}"))?;
    fs::rename(&local, game_dir.join(LOCAL_DIR)).map_err(|e| format!("Could not install {LOCAL_DIR}: {e}"))?;
    Ok(sha256)
}

/// Extract the entries under `gakumas-local/` into `dest`, skipping
/// `gakumas-local/local-files/` when `skip_local_files` is set. Entries
/// outside that folder or with unsafe paths are ignored.
fn extract_local_dir<R: Read + Seek>(
    archive: &mut zip::ZipArchive<R>,
    dest: &Path,
    skip_local_files: bool,
) -> Result<(), String> {
    let failed = |e: &dyn std::fmt::Display| format!("Could not extract {LOCAL_DIR}: {e}");
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).map_err(|e| failed(&e))?;
        let Some(path) = entry.enclosed_name() else { continue };
        let Ok(inner) = path.strip_prefix(LOCAL_DIR) else { continue };
        if skip_local_files && inner.starts_with(LOCAL_FILES) {
            continue;
        }
        let target = dest.join(&path);
        if entry.is_dir() {
            fs::create_dir_all(&target).map_err(|e| failed(&e))?;
            continue;
        }
        let size = entry.size();
        if size > MAX_ENTRY_SIZE {
            return Err(failed(&format!("{} is too large", path.display())));
        }
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(|e| failed(&e))?;
        }
        let mut out = fs::File::create(&target).map_err(|e| failed(&e))?;
        let copied = io::copy(&mut Read::by_ref(&mut entry).take(size + 1), &mut out).map_err(|e| failed(&e))?;
        if copied != size {
            return Err(failed(&format!("unexpected size for {}", path.display())));
        }
    }
    Ok(())
}

/// Set top-level keys in a JSON config, keeping every other setting. A missing
/// file is created with just these keys. Written with Localify's four-space indent.
fn patch_json(path: &Path, values: &[(&str, Value)]) -> Result<(), String> {
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let mut doc = match fs::read(path) {
        Ok(bytes) => {
            let text = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(&bytes);
            serde_json::from_slice(text).map_err(|e| format!("Could not parse {name}: {e}"))?
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => json!({}),
        Err(e) => return Err(format!("Could not read {name}: {e}")),
    };
    let object = doc.as_object_mut().ok_or_else(|| format!("{name} is not a JSON object"))?;
    for (key, value) in values {
        object.insert(key.to_string(), value.clone());
    }
    let mut out = Vec::new();
    let formatter = serde_json::ser::PrettyFormatter::with_indent(b"    ");
    doc.serialize(&mut serde_json::Serializer::with_formatter(&mut out, formatter))
        .map_err(|e| format!("Could not write {name}: {e}"))?;
    fs::write(path, out).map_err(|e| format!("Could not write {name}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::launcher::Settings;
    use std::io::{Cursor, Write};
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

    const CONFIG: &[u8] = br#"{
    "transRemoteZipUrl": "https://example.invalid/zh.zip",
    "useAPIAssets": false,
    "useAPIAssetsURL": "https://example.invalid/zh",
    "useAPITextureAssets": true
}"#;
    const LOCALIZATION_CONFIG: &[u8] = br#"{"enabled": true, "renderScale": 0.7699999809265137, "replaceFont": true}"#;

    /// The layout of a real DMM_GakumasLocalify release.
    fn release_archive(dll: &[u8]) -> Cursor<Vec<u8>> {
        archive(&[
            ("gakumas-local/config.json", CONFIG),
            ("gakumas-local/localizationConfig.json", LOCALIZATION_CONFIG),
            ("gakumas-local/version.txt", b"3.5.0"),
            ("gakumas-local/local-files/genericTrans.json", b"{}"),
            ("gakumas-local/local-files/sub/font.ttf", b"font"),
            (DLL_NAME, dll),
        ])
    }

    fn read_json(path: &Path) -> Value {
        serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<_> = fs::read_dir(dir).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
        names.sort();
        names
    }

    #[test]
    fn first_install_outside_china_uses_english_settings() {
        let game = tempfile::tempdir().unwrap();
        let (dll_sha, first) = install_from_archive(release_archive(b"dll"), game.path(), true).unwrap();
        assert!(first);
        assert_eq!(dll_sha, sha(b"dll"));
        assert_eq!(fs::read(game.path().join(DLL_NAME)).unwrap(), b"dll");
        assert_eq!(names(game.path()), [LOCAL_DIR, DLL_NAME]);

        let local = game.path().join(LOCAL_DIR);
        assert_eq!(names(&local), ["config.json", "localizationConfig.json", "version.txt"]);
        let config = read_json(&local.join("config.json"));
        assert_eq!(config["useAPITextureAssets"], json!(false));
        assert_eq!(config["useAPIAssetsURL"], json!(ENGLISH_ASSETS_URL));
        assert_eq!(config["useAPIAssets"], json!(true));
        // Everything else is left as the release ships it.
        assert_eq!(config["transRemoteZipUrl"], json!("https://example.invalid/zh.zip"));
        let localization = read_json(&local.join("localizationConfig.json"));
        assert_eq!(localization["replaceFont"], json!(false));
        assert_eq!(localization["enabled"], json!(true));
        assert_eq!(localization["renderScale"], json!(0.7699999809265137));
        assert!(String::from_utf8(fs::read(local.join("config.json")).unwrap()).unwrap().contains("\n    \"useAPIAssets\""));
    }

    #[test]
    fn first_install_on_chinese_system_keeps_the_release_files() {
        let game = tempfile::tempdir().unwrap();
        let (_, first) = install_from_archive(release_archive(b"dll"), game.path(), false).unwrap();
        assert!(first);
        let local = game.path().join(LOCAL_DIR);
        assert_eq!(fs::read(local.join("config.json")).unwrap(), CONFIG);
        assert_eq!(fs::read(local.join("localizationConfig.json")).unwrap(), LOCALIZATION_CONFIG);
        assert_eq!(fs::read(local.join("local-files/sub/font.ttf")).unwrap(), b"font");
    }

    #[test]
    fn update_replaces_only_the_dll() {
        let game = tempfile::tempdir().unwrap();
        let local = game.path().join(LOCAL_DIR);
        fs::create_dir_all(local.join("local-files")).unwrap();
        fs::write(local.join("config.json"), b"custom").unwrap();
        fs::write(game.path().join(DLL_NAME), b"old").unwrap();
        let (dll_sha, first) = install_from_archive(release_archive(b"new"), game.path(), true).unwrap();
        assert!(!first);
        assert_eq!(dll_sha, sha(b"new"));
        assert_eq!(fs::read(game.path().join(DLL_NAME)).unwrap(), b"new");
        assert_eq!(fs::read(local.join("config.json")).unwrap(), b"custom");
        assert_eq!(names(&local), ["config.json", "local-files"]);
        assert!(fs::read_dir(local.join("local-files")).unwrap().next().is_none());
        assert_eq!(names(game.path()), [LOCAL_DIR, DLL_NAME]);
    }

    #[test]
    fn first_install_ignores_entries_outside_gakumas_local() {
        let game = tempfile::tempdir().unwrap();
        let zip = archive(&[
            ("../escape.txt", b"x"),
            ("other/file.txt", b"x"),
            ("gakumas-local/../../escape2.txt", b"x"),
            ("gakumas-local/config.json", b"{}"),
            (DLL_NAME, b"dll"),
        ]);
        install_from_archive(zip, game.path(), true).unwrap();
        assert_eq!(names(game.path()), [LOCAL_DIR, DLL_NAME]);
        assert!(!game.path().parent().unwrap().join("escape.txt").exists());
        // localizationConfig.json was missing, so it is created with just the patched key.
        assert_eq!(read_json(&game.path().join(LOCAL_DIR).join("localizationConfig.json")), json!({ "replaceFont": false }));
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
