//! One update check for the launcher and Localify: a single clock and one set
//! of rules, so the two panels never disagree about when they last checked.
//!
//! - On launch the check runs when the last complete check is older than
//!   [`github::CHECK_INTERVAL`] or the clock went back; the buttons always run it.
//! - Localify is looked up only while it is installed, unless the user asked.
//! - The clock moves only when every lookup succeeded, so a failed lookup is
//!   retried on the next launch. Successful lookups are saved either way.

use serde::Serialize;

use crate::launcher::{Store, UpdateCheck};
use crate::{github, localify, updater};

#[derive(Serialize, Clone, Debug)]
pub struct Updates {
    pub launcher: updater::Status,
    pub localify: localify::Status,
    /// This call asked GitHub instead of reusing the saved check.
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

/// Both components against the saved check (no network).
pub fn status(store: &Store) -> Updates {
    updates(store, &store.update_check(), false, None)
}

/// Fold lookup results into the saved check and return the failures. The
/// clock moves only when nothing failed. `localify` is `None` when Localify
/// was not looked up.
fn apply(
    check: &mut UpdateCheck,
    launcher: Result<Option<String>, String>,
    localify: Option<Result<String, String>>,
    now: u64,
) -> Vec<String> {
    let mut errors = Vec::new();
    match launcher {
        Ok(tag) => check.launcher = tag,
        Err(e) => errors.push(format!("Launcher: {e}")),
    }
    match localify {
        Some(Ok(tag)) => check.localify = Some(tag),
        Some(Err(e)) => errors.push(format!("Localify: {e}")),
        None => {}
    }
    if errors.is_empty() {
        check.checked_at = Some(now);
    }
    errors
}

/// Look up the newest launcher and Localify releases when a check is due, or
/// always with `force`.
pub fn check(store: &Store, force: bool) -> Result<Updates, String> {
    let saved = store.update_check();
    if !force && !github::check_due(saved.checked_at, github::now_secs()) {
        return Ok(updates(store, &saved, false, None));
    }
    let agent = github::agent();
    let launcher = updater::latest_tag(&agent);
    let localify = (force || localify::is_installed(store)).then(|| localify::latest_tag(&agent));
    let mut errors = Vec::new();
    let saved = store.update_update_check(|c| errors = apply(c, launcher, localify, github::now_secs()))?;
    let error = (!errors.is_empty()).then(|| errors.join("\n"));
    Ok(updates(store, &saved, true, error))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_complete_check_saves_both_tags_and_moves_the_clock() {
        let mut check = UpdateCheck::default();
        let errors = apply(&mut check, Ok(Some("v0.4.0".into())), Some(Ok("v3.5.0".into())), 100);
        assert!(errors.is_empty());
        assert_eq!(check, UpdateCheck { checked_at: Some(100), launcher: Some("v0.4.0".into()), localify: Some("v3.5.0".into()) });
    }

    #[test]
    fn skipping_localify_keeps_its_saved_tag() {
        let mut check = UpdateCheck { localify: Some("v3.4.1".into()), ..Default::default() };
        assert!(apply(&mut check, Ok(None), None, 100).is_empty());
        assert_eq!(check.localify.as_deref(), Some("v3.4.1"));
        assert_eq!(check.launcher, None);
        assert_eq!(check.checked_at, Some(100));
    }

    #[test]
    fn a_failed_lookup_keeps_the_clock_but_saves_the_other_result() {
        let mut check = UpdateCheck { checked_at: Some(5), launcher: Some("v0.3.0".into()), localify: None };
        let errors = apply(&mut check, Ok(Some("v0.4.0".into())), Some(Err("offline".into())), 100);
        assert_eq!(errors, ["Localify: offline"]);
        assert_eq!(check.checked_at, Some(5));
        assert_eq!(check.launcher.as_deref(), Some("v0.4.0"));
    }

    #[test]
    fn a_recent_check_is_reused_without_the_network() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path().to_path_buf()).unwrap();
        let now = github::now_secs();
        store
            .update_update_check(|c| {
                c.checked_at = Some(now);
                c.launcher = Some("v99.0.0".into());
            })
            .unwrap();
        let u = check(&store, false).unwrap();
        assert!(!u.checked);
        assert_eq!(u.launcher.latest.as_deref(), Some("v99.0.0"));
        assert!(u.launcher.update_available);
        assert_eq!(u.localify.checked_at, Some(now));
    }
}
