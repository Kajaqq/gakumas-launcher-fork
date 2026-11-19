//! Cross-platform Localify installer: download the latest release and extract
//! it into the game folder so `version.dll` sits next to `gakumas.exe`.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

use crate::launcher::Store;

const RELEASES_API: &str = "https://api.github.com/repos/chinosk6/gakuen-imas-localify/releases";

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
    progress("Extracting Localify into the game folder...", None);

    #[cfg(windows)]
    {
        let script = format!(
            "Expand-Archive -Force -LiteralPath '{}' -DestinationPath '{}'",
            archive.to_string_lossy().replace('\'', "''"),
            game_dir.to_string_lossy().replace('\'', "''")
        );
        let status = Command::new("powershell")
            .args(["-NoProfile", "-Command", &script])
            .status()
            .map_err(|e| format!("Failed to extract Localify: {e}"))?;
        if !status.success() {
            return Err("Failed to extract Localify".to_string());
        }
    }
    #[cfg(not(windows))]
    {
        let status = Command::new("unzip")
            .arg("-o")
            .arg("-q")
            .arg(&archive)
            .arg("-d")
            .arg(&game_dir)
            .status()
            .map_err(|e| format!("Failed to extract Localify: {e}"))?;
        if !status.success() {
            return Err("Failed to extract Localify".to_string());
        }
    }

    if !game_dir.join("version.dll").is_file() {
        return Err("version.dll was not found after installing Localify".to_string());
    }
    Ok(format!("Localify {version} installed."))
}
