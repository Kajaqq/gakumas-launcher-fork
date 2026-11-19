//! Install Localify's DLL and seed the default translation config if missing.

use std::fs;
use std::io::{self, Read, Seek, Write};
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::launcher::Store;

const RELEASES_API: &str = "https://api.github.com/repos/chinosk6/gakuen-imas-localify/releases";
const DLL_NAME: &str = "version.dll";
const MAX_DLL_SIZE: u64 = 64 * 1024 * 1024;
const DEFAULT_CONFIG: &[u8] = include_bytes!("localify-config.json");

fn download(url: &str, path: &Path) -> Result<(), String> {
    let response = ureq::get(url)
        .call()
        .map_err(|e| format!("Failed to download Localify: {e}"))?;
    let mut reader = response.into_reader();
    let mut file = fs::File::create(path).map_err(|e| e.to_string())?;
    std::io::copy(&mut reader, &mut file).map_err(|e| e.to_string())?;
    Ok(())
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

    progress("Checking the latest Localify release...", None);
    let body = ureq::get(RELEASES_API)
        .call()
        .map_err(|e| format!("Failed to reach the Localify releases: {e}"))?
        .into_string()
        .map_err(|e| e.to_string())?;
    let releases: Vec<Value> =
        serde_json::from_str(&body).map_err(|e| format!("Failed to parse releases: {e}"))?;
    let (version, url) = releases
        .iter()
        .find_map(|r| {
            let tag = r["tag_name"].as_str()?;
            let asset = r["assets"].as_array()?.iter().find(|a| {
                a["name"]
                    .as_str()
                    .is_some_and(|n| n.starts_with("DMM_GakumasLocalify_v") && n.ends_with(".zip"))
            })?;
            Some((tag.to_string(), asset["browser_download_url"].as_str()?.to_string()))
        })
        .ok_or("No DMM_GakumasLocalify_v*.zip asset found")?;

    let archive = base.join(format!("DMM_GakumasLocalify_{version}.zip"));
    if !archive.is_file() {
        progress(&format!("Downloading Localify {version}..."), None);
        download(&url, &archive)?;
    }
    progress("Installing the Localify DLL...", None);
    let zip = fs::File::open(&archive).map_err(|e| format!("Could not open Localify archive: {e}"))?;
    install_dll(zip, &game_dir)?;
    Ok(format!("Localify {version} installed."))
}

fn install_dll(reader: impl Read + Seek, game_dir: &Path) -> Result<(), String> {
    let mut archive = zip::ZipArchive::new(reader).map_err(|e| format!("Invalid Localify archive: {e}"))?;
    let dll = archive.by_name(DLL_NAME).map_err(|e| format!("Could not read {DLL_NAME} from Localify archive: {e}"))?;
    let expected = dll.size();
    if !dll.is_file() || expected == 0 || expected > MAX_DLL_SIZE {
        return Err(format!("Invalid {DLL_NAME} in Localify archive"));
    }

    let mut staged = tempfile::NamedTempFile::new_in(game_dir).map_err(|e| format!("Could not stage {DLL_NAME}: {e}"))?;
    let copied = std::io::copy(&mut dll.take(MAX_DLL_SIZE + 1), &mut staged)
        .map_err(|e| format!("Could not extract {DLL_NAME}: {e}"))?;
    if copied != expected {
        return Err(format!("Unexpected size for {DLL_NAME} in Localify archive"));
    }
    let local = game_dir.join("gakumas-local");
    fs::create_dir_all(&local)
        .map_err(|e| format!("Could not create gakumas-local: {e}"))?;
    install_default_config(&local)
        .map_err(|e| format!("Could not create gakumas-local/config.json: {e}"))?;
    staged.persist(game_dir.join(DLL_NAME)).map_err(|e| format!("Could not install {DLL_NAME}: {e}"))?;
    Ok(())
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

    #[test]
    fn installs_only_the_dll_and_default_config() {
        let game = tempfile::tempdir().unwrap();
        let zip = archive(&[(DLL_NAME, b"dll"), ("gakumas-local/config.json", b"bundled"), ("extra.dll", b"skip")]);
        install_dll(zip, game.path()).unwrap();
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
}
