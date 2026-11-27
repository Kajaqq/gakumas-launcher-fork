//! Cross-platform helpers used by the launcher.
//!
//! On Windows these delegate to the existing native DPAPI / Win32 implementations.
//! On Linux they use a small AES-256-GCM keystore, a `/proc` process scan and
//! the Proton launcher to provide the same interface.

use std::path::{Path, PathBuf};
use std::time::Duration;

// ---------------------------------------------------------------------------
// Windows: delegate to the existing native implementations.
// ---------------------------------------------------------------------------

#[cfg(windows)]
pub use crate::dpapi::{protect, unprotect, unprotect_powershell_secure_string};

#[cfg(windows)]
pub fn launch(
    exe: &Path,
    args: &str,
    cwd: &Path,
    elevated: bool,
    watch: Duration,
) -> Result<(), String> {
    crate::winutil::launch(exe, args, cwd, elevated, watch)
}

#[cfg(windows)]
pub fn is_process_running(name: &str) -> bool {
    crate::winutil::is_process_running(name)
}

#[cfg(windows)]
pub fn appdata_dir() -> Option<PathBuf> {
    std::env::var_os("APPDATA")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

#[cfg(windows)]
pub fn user_profile_dir() -> Option<PathBuf> {
    std::env::var_os("USERPROFILE")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

/// Whether the user's display language is Chinese (any region).
#[cfg(windows)]
pub fn system_language_is_chinese() -> bool {
    const LANG_CHINESE: u16 = 0x04;
    // The low 10 bits of a LANGID are the primary language.
    let langid = unsafe { windows_sys::Win32::Globalization::GetUserDefaultUILanguage() };
    langid & 0x3ff == LANG_CHINESE
}

// ---------------------------------------------------------------------------
// Linux / other Unix: std-only implementations.
// ---------------------------------------------------------------------------

#[cfg(not(windows))]
mod unix {
    use super::*;

    use std::ffi::OsStr;
    use std::fs;
    use std::os::unix::ffi::OsStrExt;

    use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};

    /// Blob layout: magic | 16-byte salt | 12-byte nonce | ciphertext | 16-byte tag.
    const MAGIC: &[u8; 8] = b"GKP-LNX1";
    const SALT_LEN: usize = 16;
    const NONCE_LEN: usize = 12;

    fn random<const N: usize>() -> Result<[u8; N], String> {
        let mut b = [0u8; N];
        getrandom::getrandom(&mut b)
            .map_err(|e| format!("Failed to generate random data: {e}"))?;
        Ok(b)
    }

    /// HKDF-SHA256 key from the machine id, the user name and a per-blob salt.
    fn derive_key(salt: &[u8]) -> Result<[u8; 32], String> {
        let mut ikm = Vec::new();
        match fs::read("/etc/machine-id") {
            Ok(m) => ikm.extend_from_slice(&m),
            Err(_) => ikm.extend_from_slice(b"gakumas-unknown-machine"),
        }
        let user = std::env::var("USER")
            .or_else(|_| std::env::var("LOGNAME"))
            .unwrap_or_default();
        ikm.extend_from_slice(user.as_bytes());
        ikm.extend_from_slice(salt);

        // ring 0.17's HKDF API: Salt -> Prk -> Okm. HKDF_SHA256 yields 32 bytes.
        let hkdf_salt = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, salt);
        let prk = hkdf_salt.extract(&ikm);
        let okm = prk
            .expand(
                &[b"gakumas-launcher-keystore-v1"],
                ring::hkdf::HKDF_SHA256,
            )
            .map_err(|_| "Failed to derive the encryption key".to_string())?;
        let mut key = [0u8; 32];
        okm.fill(&mut key)
            .map_err(|_| "Failed to derive the encryption key".to_string())?;
        Ok(key)
    }

    fn cipher(key: &[u8; 32]) -> Result<LessSafeKey, String> {
        let key = UnboundKey::new(&aead::AES_256_GCM, key)
            .map_err(|_| "Invalid encryption key".to_string())?;
        Ok(LessSafeKey::new(key))
    }

    pub fn protect(data: &[u8]) -> Result<Vec<u8>, String> {
        let salt = random::<SALT_LEN>()?;
        let nonce = random::<NONCE_LEN>()?;
        let key = derive_key(&salt)?;
        let cipher = cipher(&key)?;

        let mut body = data.to_vec();
        let tag = cipher
            .seal_in_place_separate_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(&MAGIC[..]),
                &mut body,
            )
            .map_err(|_| "Failed to encrypt the data".to_string())?;

        let mut out =
            Vec::with_capacity(MAGIC.len() + SALT_LEN + NONCE_LEN + body.len() + tag.as_ref().len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&salt);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&body);
        out.extend_from_slice(tag.as_ref());
        Ok(out)
    }

    pub fn unprotect(blob: &[u8]) -> Result<Vec<u8>, String> {
        let header = MAGIC.len() + SALT_LEN + NONCE_LEN;
        if blob.len() < header + 16 || &blob[..MAGIC.len()] != &MAGIC[..] {
            return Err("Saved data is missing or has an invalid format".into());
        }
        let salt = &blob[MAGIC.len()..MAGIC.len() + SALT_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&blob[MAGIC.len() + SALT_LEN..header]);

        let key = derive_key(salt)?;
        let cipher = cipher(&key)?;
        let mut body = blob[header..].to_vec();
        let plain = cipher
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(&MAGIC[..]),
                &mut body,
            )
            .map_err(|_| "Failed to decrypt the saved data (wrong user or machine?)".to_string())?;
        Ok(plain.to_vec())
    }

    pub fn unprotect_powershell_secure_string(_text: &str) -> Result<String, String> {
        Err("Reading Windows PowerShell encrypted tokens is only supported on Windows".into())
    }

    /// Scan `/proc/*/cmdline` for a process whose executable has this name.
    pub fn is_process_running(name: &str) -> bool {
        let name = name
            .trim()
            .trim_end_matches(".exe")
            .to_ascii_lowercase();
        if name.is_empty() {
            return false;
        }
        let Ok(entries) = fs::read_dir("/proc") else {
            return false;
        };
        for entry in entries.flatten() {
            let Ok(cmdline) = fs::read(entry.path().join("cmdline")) else {
                continue;
            };
            let Some(first) = cmdline.split(|&b| b == 0).next() else {
                continue;
            };
            if first.is_empty() {
                continue;
            }
            let base = Path::new(OsStr::from_bytes(first))
                .file_name()
                .map(|n| {
                    n.to_string_lossy()
                        .trim_end_matches(".exe")
                        .to_ascii_lowercase()
                })
                .unwrap_or_default();
            if base == name {
                return true;
            }
        }
        false
    }

    /// The Windows user profile inside the configured Proton prefix, if any.
    fn prefix_user_dir() -> Option<PathBuf> {
        Some(crate::proton::wine_user_dir(&crate::proton::configured_prefix()?))
            .filter(|dir| dir.is_dir())
    }

    pub fn appdata_dir() -> Option<PathBuf> {
        prefix_user_dir().map(|p| p.join("AppData").join("Roaming"))
    }

    pub fn user_profile_dir() -> Option<PathBuf> {
        prefix_user_dir()
    }

    /// Whether the user's display language is Chinese, following the usual
    /// precedence of the locale environment variables.
    pub fn system_language_is_chinese() -> bool {
        ["LANGUAGE", "LC_ALL", "LC_MESSAGES", "LANG"]
            .iter()
            .find_map(|key| std::env::var(key).ok().filter(|v| !v.is_empty()))
            .is_some_and(|value| locale_is_chinese(&value))
    }

    /// `LANGUAGE` may list several languages separated by colons; the first one wins.
    pub(super) fn locale_is_chinese(value: &str) -> bool {
        let first = value.split(':').next().unwrap_or_default();
        first.get(..2).is_some_and(|lang| lang.eq_ignore_ascii_case("zh"))
            && first[2..].chars().next().map_or(true, |c| matches!(c, '_' | '-' | '.' | '@'))
    }

    #[cfg(test)]
    mod tests {
        use super::locale_is_chinese;

        #[test]
        fn chinese_locales_are_recognized() {
            for value in ["zh_CN.UTF-8", "zh_TW", "zh", "zh-HK", "zh_CN:en_US", "ZH_cn"] {
                assert!(locale_is_chinese(value), "{value}");
            }
            for value in ["en_US.UTF-8", "ja_JP", "C", "zha", "en_US:zh_CN"] {
                assert!(!locale_is_chinese(value), "{value}");
            }
        }
    }
}

#[cfg(not(windows))]
pub use unix::{
    appdata_dir, is_process_running, protect, unprotect, unprotect_powershell_secure_string,
    system_language_is_chinese, user_profile_dir,
};

#[cfg(not(windows))]
pub fn launch(
    exe: &Path,
    args: &str,
    cwd: &Path,
    _elevated: bool,
    _watch: Duration,
) -> Result<(), String> {
    crate::proton::launch_game(exe, args, cwd)
}
