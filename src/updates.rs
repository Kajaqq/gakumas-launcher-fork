//! Update checks for the launcher and Localify, through one helper.
//!
//! - [`Scope::Daily`] runs on launch: it looks up both components when the
//!   last complete daily check is older than [`github::CHECK_INTERVAL`] or the
//!   clock went back. Localify is looked up only while it is installed.
//! - [`Scope::Launcher`] and [`Scope::Localify`] are the panels' buttons: they
//!   look up only that component, every time, and leave the daily clock alone.
//! - The daily clock moves only when every lookup succeeded, so a failed lookup
//!   is retried on the next launch. Successful lookups are saved either way.

use serde::{Deserialize, Serialize};

use crate::launcher::{Store, UpdateCheck};
use crate::{github, localify, updater};

/// What a check looks up.
#[derive(Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    /// Both components, at most once per [`github::CHECK_INTERVAL`].
    Daily,
    /// Only the launcher, now.
    Launcher,
    /// Only Localify, now.
    Localify,
}

#[derive(Serialize, Clone, Debug)]
pub struct Updates {
    pub launcher: updater::Status,
    pub localify: localify::Status,
    /// This call asked GitHub instead of reusing the saved lookups.
    pub checked: bool,
    /// Lookups that failed, one per line. The other results are still current.
    pub error: Option<String>,
}

fn updates(store: &Store, check: &UpdateCheck, checked: bool, error: Option<String>) -> Updates {
    Updates {
        launcher: updater::status(check),
        localify: localify::status(store, check),
        checked,
        error,
    }
}

/// Both components against the saved lookups (no network).
pub fn status(store: &Store) -> Updates {
    updates(store, &store.update_check(), false, None)
}

/// Fold lookup results into the saved check and return the failures. `None`
/// means that component was not looked up. With `daily`, the daily clock
/// moves when nothing failed.
fn apply(
    check: &mut UpdateCheck,
    launcher: Option<Result<Option<String>, String>>,
    localify: Option<Result<String, String>>,
    daily: bool,
    now: u64,
) -> Vec<String> {
    let mut errors = Vec::new();
    match launcher {
        Some(Ok(tag)) => {
            check.launcher = tag;
            check.launcher_checked_at = Some(now);
        }
        Some(Err(e)) => errors.push(format!("Launcher: {e}")),
        None => {}
    }
    match localify {
        Some(Ok(tag)) => {
            check.localify = Some(tag);
            check.localify_checked_at = Some(now);
        }
        Some(Err(e)) => errors.push(format!("Localify: {e}")),
        None => {}
    }
    if daily && errors.is_empty() {
        check.checked_at = Some(now);
    }
    errors
}

/// Look up the newest releases in `scope`.
pub fn check(store: &Store, scope: Scope) -> Result<Updates, String> {
    let saved = store.update_check();
    let (launcher, localify) = match scope {
        Scope::Daily if !github::check_due(saved.checked_at, github::now_secs()) => {
            return Ok(updates(store, &saved, false, None));
        }
        Scope::Daily => (true, localify::is_installed(store)),
        Scope::Launcher => (true, false),
        Scope::Localify => (false, true),
    };
    let agent = github::agent();
    let launcher = launcher.then(|| updater::latest_tag(&agent));
    let localify = localify.then(|| localify::latest_tag(&agent));
    let mut errors = Vec::new();
    let daily = scope == Scope::Daily;
    let saved = store.update_update_check(|c| errors = apply(c, launcher, localify, daily, github::now_secs()))?;
    let error = (!errors.is_empty()).then(|| errors.join("\n"));
    Ok(updates(store, &saved, true, error))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_complete_daily_check_saves_both_tags_and_moves_the_clock() {
        let mut check = UpdateCheck::default();
        let errors = apply(&mut check, Some(Ok(Some("v0.4.0".into()))), Some(Ok("v3.5.0".into())), true, 100);
        assert!(errors.is_empty());
        assert_eq!(
            check,
            UpdateCheck {
                checked_at: Some(100),
                launcher: Some("v0.4.0".into()),
                launcher_checked_at: Some(100),
                localify: Some("v3.5.0".into()),
                localify_checked_at: Some(100),
            }
        );
    }

    #[test]
    fn a_button_check_updates_only_its_component_and_not_the_daily_clock() {
        let saved = UpdateCheck {
            checked_at: Some(5),
            launcher: Some("v0.3.0".into()),
            launcher_checked_at: Some(5),
            localify: Some("v3.4.1".into()),
            localify_checked_at: Some(5),
        };
        let mut check = saved.clone();
        assert!(apply(&mut check, Some(Ok(Some("v0.4.0".into()))), None, false, 100).is_empty());
        assert_eq!(check.checked_at, Some(5));
        assert_eq!((check.launcher.as_deref(), check.launcher_checked_at), (Some("v0.4.0"), Some(100)));
        assert_eq!((check.localify.as_deref(), check.localify_checked_at), (Some("v3.4.1"), Some(5)));

        let mut check = saved;
        assert!(apply(&mut check, None, Some(Ok("v3.5.0".into())), false, 100).is_empty());
        assert_eq!(check.checked_at, Some(5));
        assert_eq!((check.launcher.as_deref(), check.launcher_checked_at), (Some("v0.3.0"), Some(5)));
        assert_eq!((check.localify.as_deref(), check.localify_checked_at), (Some("v3.5.0"), Some(100)));
    }

    #[test]
    fn a_failed_daily_lookup_keeps_the_clock_but_saves_the_other_result() {
        let mut check = UpdateCheck { checked_at: Some(5), launcher: Some("v0.3.0".into()), ..Default::default() };
        let errors = apply(&mut check, Some(Ok(Some("v0.4.0".into()))), Some(Err("offline".into())), true, 100);
        assert_eq!(errors, ["Localify: offline"]);
        assert_eq!(check.checked_at, Some(5));
        assert_eq!(check.launcher.as_deref(), Some("v0.4.0"));
        assert_eq!(check.localify_checked_at, None);
    }

    #[test]
    fn a_recent_daily_check_is_reused_without_the_network() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path().to_path_buf()).unwrap();
        let now = github::now_secs();
        store
            .update_update_check(|c| {
                c.checked_at = Some(now);
                c.launcher = Some("v99.0.0".into());
                c.launcher_checked_at = Some(now);
            })
            .unwrap();
        let u = check(&store, Scope::Daily).unwrap();
        assert!(!u.checked);
        assert_eq!(u.launcher.latest.as_deref(), Some("v99.0.0"));
        assert_eq!(u.launcher.checked_at, Some(now));
        assert!(u.launcher.update_available);
        assert_eq!(u.localify.checked_at, None);
    }

    #[test]
    fn scopes_parse_from_the_ui_names() {
        for (name, scope) in [("daily", Scope::Daily), ("launcher", Scope::Launcher), ("localify", Scope::Localify)] {
            assert_eq!(serde_json::from_value::<Scope>(serde_json::json!(name)).unwrap(), scope);
        }
    }
}
