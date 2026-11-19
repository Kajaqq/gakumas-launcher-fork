//! One-shot DMM profile setup using only the web session from launcher login.
//! No WebView is created here, and cookies never go to disk or logs.

use std::time::{Duration, Instant};

use cookie_store::CookieStore;
use gakumas_launcher::{browser_proxy, launcher::{self, Store, MODE_DIRECT}};
use tauri::{Url, WebviewWindow};

pub const SETUP_URL: &str = "https://accounts.dmm.com/service/login/password?channel=games&path=https%3A%2F%2Fpersonal.games.dmm.com%2Fprofile%2Fregist%2Fskip%3Fback_url%3Dhttps%253A%252F%252Fsite-gameplayer.dmm.com%252Fgameplayer%252Fgame%252Finstaller%252Fwin%252Fx86%252Fgakumas%252Fcl%252Fgeneral";
const SKIP_URL: &str = "https://personal.games.dmm.com/profile/regist/skip";
const INSTALLER_PATH: &str = "/gameplayer/game/installer/win/x86/gakumas/cl/general";
const BUDGET: Duration = Duration::from_secs(35);

pub struct Session {
    token_digest: ring::digest::Digest,
    cookies: CookieStore,
}

impl Session {
    pub fn new(token: &str, cookies: CookieStore) -> Self {
        Self { token_digest: digest_token(token), cookies }
    }

    pub fn for_token(&self, token: &str) -> Option<CookieStore> {
        (self.token_digest.as_ref() == digest_token(token).as_ref()).then(|| self.cookies.clone())
    }
}

fn digest_token(token: &str) -> ring::digest::Digest {
    ring::digest::digest(&ring::digest::SHA256, token.as_bytes())
}

pub fn capture(window: &WebviewWindow) -> Result<CookieStore, String> {
    let mut jar = CookieStore::default();
    for url in [SETUP_URL, SKIP_URL] {
        let url: Url = url.parse().expect("official DMM URL");
        let cookies = window.cookies_for_url(url.clone())
            .map_err(|_| "could not read the DMM login session")?;
        for cookie in cookies {
            let _ = jar.insert_raw(&cookie, &url);
        }
    }
    if jar.iter_unexpired().next().is_none() {
        return Err("DMM login did not leave a reusable web session".into());
    }
    Ok(jar)
}

#[derive(Debug, PartialEq, Eq)]
enum SetupHop { Account, Profile, Installer }

fn classify(url: &Url) -> Result<SetupHop, String> {
    if url.scheme() != "https" || url.port().is_some() || !url.username().is_empty() || url.password().is_some() {
        return Err("DMM setup redirected to an unexpected address".into());
    }
    match url.host_str() {
        Some("accounts.dmm.com") => Ok(SetupHop::Account),
        Some("personal.games.dmm.com") => Ok(SetupHop::Profile),
        // Visit the official Gakumas handoff. Do not process its body or invoke
        // a native installer/custom URL scheme if it redirects there.
        Some("site-gameplayer.dmm.com") if url.path().trim_end_matches('/') == INSTALLER_PATH => Ok(SetupHop::Installer),
        _ => Err("DMM setup redirected outside the supported profile flow".into()),
    }
}

pub fn visit(store: &Store, mode: &str, cookies: CookieStore) -> Result<(), String> {
    let mut builder = ureq::AgentBuilder::new()
        .try_proxy_from_env(false)
        .cookie_store(cookies)
        .redirects(0)
        .timeout_connect(Duration::from_secs(10));
    let proxy = if mode == MODE_DIRECT {
        None
    } else {
        let proxy = browser_proxy::start(store, mode)?;
        builder = builder.proxy(ureq::Proxy::new(proxy.url()).map_err(|_| "invalid VPN proxy endpoint")?);
        Some(proxy)
    };
    let result = visit_with_agent(&builder.build());
    drop(proxy);
    result
}

fn visit_with_agent(agent: &ureq::Agent) -> Result<(), String> {
    let deadline = Instant::now() + BUDGET;
    walk_setup(|url, remaining| {
        let response = match agent.get(url.as_str()).timeout(remaining).call() {
            Ok(response) => response,
            Err(ureq::Error::Status(code, _)) => return Err(format!("DMM background setup got HTTP {code}")),
            Err(ureq::Error::Transport(e)) => return Err(format!("DMM background setup request failed ({:?})", e.kind())),
        };
        Ok((response.status(), response.header("Location").map(str::to_owned)))
    }, deadline)
}

fn walk_setup(
    mut get: impl FnMut(&Url, Duration) -> Result<(u16, Option<String>), String>,
    deadline: Instant,
) -> Result<(), String> {
    let mut url: Url = SETUP_URL.parse().expect("official DMM URL");
    for _ in 0..10 {
        let hop = classify(&url)?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() { return Err("DMM background setup timed out".into()); }
        let (status, location) = get(&url, remaining)?;
        launcher::netlog(&format!("[profile] {hop:?} returned HTTP {status}"));
        if matches!(status, 301 | 302 | 303 | 307 | 308) {
            let next = location.as_deref().and_then(|location| url.join(location).ok())
                .ok_or("DMM background setup returned an invalid redirect")?;
            if hop == SetupHop::Installer && classify(&next).is_err() {
                launcher::netlog("[profile] stopped after the installer handoff without opening it");
                return Ok(());
            }
            url = next;
        } else {
            // A 200 isn't proof of registration. The caller must retry launch
            // with the same account; never infer success from the page alone.
            return Ok(());
        }
    }
    Err("DMM background setup redirected too many times".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn web_session_is_tied_to_the_login_that_created_it() {
        let session = Session::new("current", CookieStore::default());
        assert!(session.for_token("current").is_some());
        assert!(session.for_token("different").is_none());
    }

    #[test]
    fn redirect_policy_only_visits_the_expected_https_hosts() {
        let classify_url = |s: &str| classify(&Url::parse(s).unwrap());
        assert_eq!(classify_url(SETUP_URL), Ok(SetupHop::Account));
        assert_eq!(classify_url(SKIP_URL), Ok(SetupHop::Profile));
        assert_eq!(classify_url(&format!("https://site-gameplayer.dmm.com{INSTALLER_PATH}")), Ok(SetupHop::Installer));
        for url in ["http://accounts.dmm.com/", "https://accounts.dmm.com.example/", "https://accounts.dmm.com:8443/", "https://user@accounts.dmm.com/", "dmmgameplayer://open"] {
            assert!(classify_url(url).is_err(), "accepted {url}");
        }
    }

    #[test]
    fn gets_official_handoff_but_never_opens_its_native_redirect() {
        let mut replies = [
            (SetupHop::Account, 302, SKIP_URL.to_owned()),
            (SetupHop::Profile, 301, "/profile/regist/skip/".into()),
            (SetupHop::Profile, 302, format!("https://site-gameplayer.dmm.com{INSTALLER_PATH}")),
            (SetupHop::Installer, 302, "dmmgameplayer://open".into()),
        ].into_iter();
        walk_setup(|url, _| {
            let (expected, status, location) = replies.next().expect("unexpected request");
            assert_eq!(classify(url), Ok(expected));
            Ok((status, Some(location)))
        }, Instant::now() + BUDGET).unwrap();
        assert!(replies.next().is_none());
    }
}
