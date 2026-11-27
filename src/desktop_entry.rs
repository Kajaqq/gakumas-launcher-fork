//! Linux desktop integration: a `.desktop` entry and icon for the window's app id.
//!
//! On Wayland a GTK 3 window cannot hand its icon to the compositor. KWin, the
//! Plasma task manager and GNOME Shell instead look up the desktop entry whose
//! file name matches the window's `app_id` (`local.gakumas.launcher`, from
//! `identifier` with `enableGTKAppId`) and show its `Icon=`. Without that entry
//! they fall back to the generic Wayland icon, both when started from a terminal
//! and from a differently named shortcut. The launcher ships as a bare binary,
//! so it installs the entry into the user's data dir itself on startup.
//!
//! The module builds on every platform so its tests run anywhere; only the
//! Linux build calls [`install`].
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Must equal `identifier` in tauri.conf.json: it is the Wayland `app_id`.
pub const APP_ID: &str = "local.gakumas.launcher";
const APP_NAME: &str = "Gakumas Launcher";
const ICON_PNG: &[u8] = include_bytes!("../icons/icon.png");
/// Entries without this line were edited by the user and are left alone.
const MANAGED_KEY: &str = "X-GakumasLauncher-Managed=true";

/// `$XDG_DATA_HOME`, or `~/.local/share` when unset or not absolute.
fn data_home() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("XDG_DATA_HOME") {
        let dir = PathBuf::from(dir);
        if dir.is_absolute() {
            return Some(dir);
        }
    }
    let home = std::env::var_os("HOME")?;
    Some(PathBuf::from(home).join(".local/share"))
}

/// The path the entry's `Exec=` should start. Inside an AppImage the running
/// executable lives in a temporary mount, so the image itself is used instead.
fn launcher_path() -> Option<PathBuf> {
    if let Some(image) = std::env::var_os("APPIMAGE") {
        let image = PathBuf::from(image);
        if image.is_absolute() {
            return Some(image);
        }
    }
    std::env::current_exe().ok()
}

/// Quote one `Exec=` argument per the Desktop Entry spec: the whole value is
/// first unescaped as a string (`\\` -> `\`), then `"`, `` ` ``, `$` and `\`
/// need a backslash inside the double quotes, and `%` is written as `%%`.
fn exec_quote(arg: &str) -> String {
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('"');
    for c in arg.chars() {
        match c {
            '\\' => out.push_str("\\\\\\\\"),
            '"' | '`' | '$' => {
                out.push_str("\\\\");
                out.push(c);
            }
            '%' => out.push_str("%%"),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Escape a plain string value (`Icon=`, `Path=`): only `\` and line breaks matter.
fn string_value(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

fn desktop_entry(exe: &Path, icon: &Path) -> String {
    format!(
        "[Desktop Entry]\n\
         Type=Application\n\
         Name={APP_NAME}\n\
         Comment=DMM Gakumas launcher\n\
         Exec={exec}\n\
         Icon={icon}\n\
         Terminal=false\n\
         Categories=Game;\n\
         StartupWMClass={APP_ID}\n\
         {MANAGED_KEY}\n",
        exec = exec_quote(&exe.to_string_lossy()),
        icon = string_value(&icon.to_string_lossy()),
    )
}

/// Write `data` to `path` unless it already holds exactly that. Returns whether it wrote.
fn write_if_changed(path: &Path, data: &[u8]) -> io::Result<bool> {
    if fs::read(path).map(|old| old == data).unwrap_or(false) {
        return Ok(false);
    }
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    // Write next to the target and rename, so a reader never sees half a file.
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, data)?;
    fs::rename(&tmp, path)?;
    Ok(true)
}

/// Install or refresh the icon and desktop entry. Cheap when nothing changed:
/// two small reads and no writes. Errors are returned for logging only; the
/// launcher works without the entry, just with the generic icon.
pub fn install() -> io::Result<()> {
    let base = data_home().ok_or_else(|| io::Error::other("no HOME or XDG_DATA_HOME"))?;
    let exe = launcher_path().ok_or_else(|| io::Error::other("cannot resolve executable path"))?;
    install_into(&base, &exe)
}

fn install_into(base: &Path, exe: &Path) -> io::Result<()> {
    // Same folder as the app's data (Tauri's app_local_data_dir on Linux).
    let icon = base.join(APP_ID).join("icon.png");
    let mut changed = write_if_changed(&icon, ICON_PNG)?;

    // Also offer it by name through the icon theme, for shells that prefer that.
    let themed = base.join("icons/hicolor/512x512/apps").join(format!("{APP_ID}.png"));
    let _ = write_if_changed(&themed, ICON_PNG);

    let entry = base.join("applications").join(format!("{APP_ID}.desktop"));
    let user_owned = fs::read_to_string(&entry)
        .map(|old| !old.lines().any(|l| l.trim() == MANAGED_KEY))
        .unwrap_or(false);
    if !user_owned {
        changed |= write_if_changed(&entry, desktop_entry(exe, &icon).as_bytes())?;
    }

    if changed {
        refresh_caches();
    }
    Ok(())
}

/// Ask KDE to rebuild its service cache so the menu and task manager see the
/// entry right away. Best effort: sycoca notices the change on its own, just
/// later, and other desktops watch the folder directly.
#[cfg(all(target_os = "linux", not(test)))]
fn refresh_caches() {
    use std::process::{Command, Stdio};
    for tool in ["kbuildsycoca6", "kbuildsycoca5"] {
        let spawned = Command::new(tool)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        if let Ok(mut child) = spawned {
            // Rebuilding takes a moment; reap it off the main thread so the
            // window isn't held up and no zombie is left behind.
            std::thread::spawn(move || {
                let _ = child.wait();
            });
            break;
        }
    }
}

#[cfg(any(not(target_os = "linux"), test))]
fn refresh_caches() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exec_quotes_plain_path() {
        assert_eq!(exec_quote("/opt/GakumasLauncher"), "\"/opt/GakumasLauncher\"");
    }

    #[test]
    fn exec_escapes_reserved_characters() {
        assert_eq!(
            exec_quote("/home/a b/$x/100%/q\"t`/back\\slash"),
            "\"/home/a b/\\\\$x/100%%/q\\\\\"t\\\\`/back\\\\\\\\slash\""
        );
    }

    #[test]
    fn entry_names_app_id_and_icon() {
        let text = desktop_entry(Path::new("/opt/g/GakumasLauncher"), Path::new("/h/.local/share/x/icon.png"));
        assert!(text.starts_with("[Desktop Entry]\n"));
        assert!(text.contains("\nExec=\"/opt/g/GakumasLauncher\"\n"));
        assert!(text.contains("\nIcon=/h/.local/share/x/icon.png\n"));
        assert!(text.contains(&format!("\nStartupWMClass={APP_ID}\n")));
        assert!(text.contains(&format!("\n{MANAGED_KEY}\n")));
    }

    #[test]
    fn app_id_matches_tauri_identifier() {
        let conf: serde_json::Value =
            serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        assert_eq!(conf["identifier"], APP_ID);
        assert_eq!(conf["app"]["enableGTKAppId"], true);
    }

    #[test]
    fn install_writes_then_respects_user_edits() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path();
        let exe = base.join("bin/GakumasLauncher");
        install_into(base, &exe).unwrap();

        let entry = base.join("applications").join(format!("{APP_ID}.desktop"));
        let icon = base.join(APP_ID).join("icon.png");
        assert_eq!(fs::read(&icon).unwrap(), ICON_PNG);
        assert_eq!(fs::read_to_string(&entry).unwrap(), desktop_entry(&exe, &icon));

        // A moved binary refreshes the managed entry.
        let moved = base.join("elsewhere/GakumasLauncher");
        install_into(base, &moved).unwrap();
        assert_eq!(fs::read_to_string(&entry).unwrap(), desktop_entry(&moved, &icon));

        // Once the user drops the marker, the entry is theirs.
        fs::write(&entry, "[Desktop Entry]\nName=Mine\n").unwrap();
        install_into(base, &exe).unwrap();
        assert_eq!(fs::read_to_string(&entry).unwrap(), "[Desktop Entry]\nName=Mine\n");
    }
}
