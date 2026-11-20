//! 런처 핵심 흐름 (UI 와 무관)
//!
//! 로그인 토큰 확인 → 일본 연결(VPN Gate 내장 터널 또는 사용자의 VPN) → 실행 토큰 발급 →
//! 업데이트(바뀐 파일만, 일반 회선) → 게임 실행

use std::collections::HashSet;
use std::sync::Arc;
use std::fs;
use std::io::{Read, Write};
use std::num::NonZeroU64;
use std::path::{Component, Path, PathBuf};
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

use md5::{Digest, Md5};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::http::{self, CLIENT_VERSION, DMM_HOST};
use crate::netstack::{IpTunnel, TunnelStack};
use crate::openvpn::{self, ConnectOptions, OvpnConfig, Tunnel};
use crate::wireguard::{WgConfig, WgTunnel};
use crate::{platform, vpngate};

pub const PRODUCT_ID: &str = "gakumas";
const USER_AGENT: &str = "DMMGamePlayer5-Win/5.5.22 Electron/34.3.0";
/// 이보다 최근에 받은 목록이면 "갱신" 때 다시 받지 않음 (시작할 때 받은 목록을 그대로 씀)
pub const VPNGATE_RECENT: Duration = Duration::from_secs(10 * 60);
const VPNGATE_OFFICIAL_TRIES: usize = 3;
const VPNGATE_MORE_TRIES: usize = 5;
/// DMM 이 VPN 서버를 거부할 때 다른 서버로 바꿔 시도하는 최대 횟수
const VPNGATE_LAUNCH_ATTEMPTS: usize = 4;

/// 진행 상황 알림 (메시지, 진행률 0~100)
pub type ProgressFn<'a> = &'a dyn Fn(&str, Option<f32>);
/// 로그인 주소를 받아 로그인 완료 후의 code 를 돌려주는 함수 (UI 가 로그인 창으로 구현)
pub type CodeFn<'a> = &'a dyn Fn(&str, SignIn) -> Result<String, String>;

/// How the sign-in window should appear.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignIn {
    /// The user has to fill in the form, so show the window as soon as it exists.
    Interactive,
    /// A saved DMM browser session may finish sign-in by itself, so stay hidden briefly first.
    ReuseSession,
}
pub type ProfileSetupFn<'a> = &'a dyn Fn(&str, &str) -> Result<(), String>;

pub const MODE_VPNGATE: &str = "vpngate";
pub const MODE_DIRECT: &str = "direct";
/// 사용자의 VPN 설정 파일(.ovpn / WireGuard .conf)로 프로그램 안에서 연결
pub const MODE_FILE: &str = "file";
/// 설정 파일의 OpenVPN 서버를 몇 곳까지 시도할지
const VPN_FILE_TRIES: usize = 5;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Settings {
    #[serde(default = "default_mode")]
    pub mode: String,
    #[serde(default)]
    pub game_path: Option<String>,
    #[serde(default)]
    pub game_type: Option<String>,
    #[serde(default)]
    pub installed_version: Option<String>,
    /// 프로그램을 켜면 바로 게임 시작
    #[serde(default)]
    pub auto_start: bool,
    /// 게임을 실행하고 나면 런처를 닫음
    #[serde(default)]
    pub close_after_launch: bool,
    /// Linux: selected Proton installation (script or directory)
    #[serde(default)]
    pub proton_path: Option<String>,
    /// Linux: Wine prefix used by Proton
    #[serde(default)]
    pub proton_prefix: Option<String>,
    /// Optional replacement game executable (e.g. a Proton-tuned build)
    #[serde(default)]
    pub game_exe_override: Option<String>,
}

fn default_mode() -> String {
    MODE_VPNGATE.to_string()
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            mode: default_mode(),
            game_path: None,
            game_type: None,
            installed_version: None,
            auto_start: false,
            close_after_launch: false,
            proton_path: None,
            proton_prefix: None,
            game_exe_override: None,
        }
    }
}

#[derive(Serialize, Clone, Debug)]
pub struct Status {
    pub logged_in: bool,
    /// 가져온 VPN 설정 파일 이름
    pub vpn_file: Option<String>,
    /// VPN 설정 파일이 아이디·비밀번호를 요구하는지 / 저장돼 있는지
    pub vpn_needs_auth: bool,
    pub vpn_has_auth: bool,
    pub game_path: Option<String>,
    pub game_found: bool,
    pub installed_version: Option<String>,
    pub mode: String,
    pub auto_start: bool,
    pub close_after_launch: bool,
    pub game_exe_override: Option<String>,
}

pub const VPN_OPENVPN: &str = "openvpn";
pub const VPN_WIREGUARD: &str = "wireguard";

/// 사용자가 가져온 VPN 설정 파일
#[derive(Serialize, Deserialize, Clone)]
pub struct VpnFile {
    pub name: String,
    /// "openvpn" 또는 "wireguard"
    pub kind: String,
    /// 설정 내용 (외부 인증서 파일은 안에 넣어 둠)
    pub text: String,
    pub needs_auth: bool,
}

/// What the launcher last installed from Localify, and its last update check.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct LocalifyRecord {
    /// Release tag of the installed `version.dll`.
    #[serde(default)]
    pub tag: Option<String>,
    /// SHA-256 (lowercase hex) of the installed `version.dll`.
    #[serde(default)]
    pub dll_sha256: Option<String>,
    /// Newest release tag seen by the last successful update check.
    #[serde(default)]
    pub latest_tag: Option<String>,
    /// Unix time in seconds of the last successful update check.
    #[serde(default)]
    pub checked_at: Option<u64>,
}

/// 프로그램 데이터 (설정, 암호화된 로그인 토큰, 기기 ID, VPN Gate 목록 캐시, VPN 설정 파일)
pub struct Store {
    dir: PathBuf,
}
// Rotation reopens the same directory through a second Store. Both writers
// must serialize access to the shared vpngate.csv.tmp file.
static VPNGATE_CACHE_LOCK: Mutex<()> = Mutex::new(());
// The install and the background update check both rewrite localify.json.
static LOCALIFY_LOCK: Mutex<()> = Mutex::new(());

fn file_age(p: &Path) -> Option<Duration> {
    fs::metadata(p).ok()?.modified().ok()?.elapsed().ok()
}

/// Write protected data with owner-only permissions where supported.
#[cfg(unix)]
fn write_private(path: &Path, data: &[u8]) -> Result<(), String> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("Failed to write {}: {e}", path.display()))?;
    f.write_all(data)
        .map_err(|e| format!("Failed to write {}: {e}", path.display()))
}

#[cfg(not(unix))]
fn write_private(path: &Path, data: &[u8]) -> Result<(), String> {
    fs::write(path, data).map_err(|e| format!("Failed to write {}: {e}", path.display()))
}

impl Store {
    pub fn new(dir: PathBuf) -> Result<Self, String> {
        fs::create_dir_all(&dir).map_err(|e| format!("Failed to create the data folder: {e}"))?;
        Ok(Self { dir })
    }

    /// 저장해 둔 VPN Gate 서버 목록 (없으면 None)
    pub fn cached_vpngate_list(&self) -> Option<String> {
        fs::read_to_string(self.file("vpngate.csv")).ok()
    }

    /// VPN Gate 서버 목록을 새로 받아 저장. `max_age` 보다 최근 목록이 있으면 그것을 씀.
    /// 동시에 불리면(시작할 때 받는 중에 연결 시도 등) 먼저 받는 쪽이 끝날 때까지 기다림
    pub fn refresh_vpngate_list(&self, max_age: Duration) -> Result<String, String> {
        self.refresh_vpngate_list_with(max_age, || {
            vpngate::fetch_server_list_raw().map_err(|e| e.to_string())
        })
    }

    fn refresh_vpngate_list_with(
        &self,
        max_age: Duration,
        fetch: impl FnOnce() -> Result<String, String>,
    ) -> Result<String, String> {
        let _guard = VPNGATE_CACHE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let cache = self.file("vpngate.csv");
        if file_age(&cache).is_some_and(|age| age < max_age) {
            if let Ok(body) = fs::read_to_string(&cache) {
                return Ok(body);
            }
        }
        let body = fetch().map_err(|e| format!("Failed to fetch the VPN Gate server list: {e}"))?;
        let tmp = self.file("vpngate.csv.tmp");
        fs::write(&tmp, &body).map_err(|e| e.to_string())?;
        fs::rename(&tmp, &cache).map_err(|e| e.to_string())?;
        Ok(body)
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn file(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    /// 설정. 게임 폴더를 모르면 DMM 플레이어 설정에서 한 번 가져옴
    pub fn settings(&self) -> Settings {
        let path = self.file("settings.json");
        let mut s: Settings = match fs::read_to_string(&path) {
            Ok(t) => match serde_json::from_str(t.trim_start_matches('\u{feff}')) {
                Ok(s) => s,
                Err(_) => {
                    // 깨진 설정은 덮어쓰기 전에 옆에 남겨 둠
                    let _ = fs::rename(&path, self.file("settings.json.bad"));
                    Settings::default()
                }
            },
            Err(_) => Settings::default(),
        };
        if s.game_path.is_none() {
            if let Some((path, version, game_type)) = dmm_player_install() {
                s.game_path = Some(path);
                s.installed_version = s.installed_version.or(version);
                s.game_type = game_type;
                let _ = self.save_settings(&s);
            }
        }
        s
    }

    pub fn save_settings(&self, s: &Settings) -> Result<(), String> {
        let text = serde_json::to_string_pretty(s).map_err(|e| e.to_string())?;
        let tmp = self.file("settings.json.tmp");
        fs::write(&tmp, text).map_err(|e| format!("Failed to save settings: {e}"))?;
        fs::rename(&tmp, self.file("settings.json")).map_err(|e| format!("Failed to save settings: {e}"))?;
        invalidate_route(self, |mode| mode != s.mode);
        Ok(())
    }

    /// The saved Localify record, or an empty one if none was saved or it is unreadable.
    pub fn localify(&self) -> LocalifyRecord {
        fs::read(self.file("localify.json"))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    /// Change the saved Localify record in place and return the result.
    pub fn update_localify(&self, change: impl FnOnce(&mut LocalifyRecord)) -> Result<LocalifyRecord, String> {
        let _guard = LOCALIFY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut record = self.localify();
        change(&mut record);
        let text = serde_json::to_string_pretty(&record).map_err(|e| e.to_string())?;
        let tmp = self.file("localify.json.tmp");
        fs::write(&tmp, text).map_err(|e| format!("Failed to save the Localify record: {e}"))?;
        fs::rename(&tmp, self.file("localify.json"))
            .map_err(|e| format!("Failed to save the Localify record: {e}"))?;
        Ok(record)
    }

    pub fn token(&self) -> Option<String> {
        let blob = fs::read(self.file("login.dat")).ok()?;
        String::from_utf8(platform::unprotect(&blob).ok()?).ok()
    }

    pub fn save_token(&self, token: &str) -> Result<(), String> {
        let blob = platform::protect(token.as_bytes())?;
        let saved = write_private(&self.file("login.dat"), &blob);
        TOKEN_CHECKS.forget();
        saved
    }

    /// 가져온 VPN 설정 파일 (개인 키가 들어 있어 DPAPI 로 암호화해 둠)
    pub fn vpn_file(&self) -> Option<VpnFile> {
        let blob = fs::read(self.file("vpn_file.dat")).ok()?;
        serde_json::from_slice(&platform::unprotect(&blob).ok()?).ok()
    }

    /// VPN 설정 파일을 읽어 확인하고 저장. 같은 폴더의 인증서·키 파일을 가리키면 내용을 넣어 하나로 만듦
    pub fn import_vpn_file(&self, path: &Path) -> Result<VpnFile, String> {
        let meta = fs::metadata(path).map_err(|e| format!("Failed to read the file: {e}"))?;
        if meta.len() > 1024 * 1024 {
            return Err("The VPN config file is too large".into());
        }
        let text = fs::read_to_string(path).map_err(|e| format!("Failed to read the file: {e}"))?;
        let text = text.trim_start_matches('\u{feff}');
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let file = if text.contains("[Interface]") {
            WgConfig::parse(text)?;
            VpnFile {
                name,
                kind: VPN_WIREGUARD.into(),
                text: text.to_string(),
                needs_auth: false,
            }
        } else {
            let dir = path.parent().unwrap_or(Path::new("."));
            let (inlined, creds) = openvpn::inline_external_files(text, dir)?;
            let cfg = OvpnConfig::parse(&inlined)?;
            if let Some((u, p)) = creds {
                self.save_vpn_auth(&u, &p)?;
            }
            VpnFile {
                name,
                kind: VPN_OPENVPN.into(),
                text: inlined,
                needs_auth: cfg.auth_user_pass,
            }
        };
        let json = serde_json::to_vec(&file).map_err(|e| e.to_string())?;
        write_private(&self.file("vpn_file.dat"), &platform::protect(&json)?)?;
        invalidate_route(self, |mode| mode == MODE_FILE);
        Ok(file)
    }

    /// VPN 아이디·비밀번호 (OpenVPN auth-user-pass)
    pub fn vpn_auth(&self) -> Option<(String, String)> {
        let blob = fs::read(self.file("vpn_auth.dat")).ok()?;
        let v: Value = serde_json::from_slice(&platform::unprotect(&blob).ok()?).ok()?;
        Some((
            v["username"].as_str()?.to_string(),
            v["password"].as_str()?.to_string(),
        ))
    }

    pub fn save_vpn_auth(&self, username: &str, password: &str) -> Result<(), String> {
        let json = json!({ "username": username, "password": password }).to_string();
        write_private(&self.file("vpn_auth.dat"), &platform::protect(json.as_bytes())?)?;
        invalidate_route(self, |mode| mode == MODE_FILE);
        Ok(())
    }

    /// 저장된 토큰이 아직 `token` 일 때만 삭제 (그사이 새로 로그인했으면 그대로 둠)
    pub fn clear_token_if(&self, token: &str) -> Result<(), String> {
        if self.token().as_deref() == Some(token) {
            self.clear_token()
        } else {
            Ok(())
        }
    }

    /// 저장된 로그인 토큰 삭제. 백신 검사 등으로 잠깐 잠겨 있을 수 있어 몇 번 다시 시도
    pub fn clear_token(&self) -> Result<(), String> {
        TOKEN_CHECKS.forget();
        let path = self.file("login.dat");
        let mut last = None;
        for _ in 0..10 {
            match fs::remove_file(&path) {
                Ok(()) => return Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(e) => last = Some(e),
            }
            std::thread::sleep(Duration::from_millis(150));
        }
        if !path.exists() {
            return Ok(());
        }
        Err(format!(
            "Failed to clear the login data: {}",
            last.map(|e| e.to_string()).unwrap_or_default()
        ))
    }

    /// DMM 에 보내는 기기 식별값. 실제 하드웨어 정보 대신 처음 한 번 만든 임의 값을 계속 씀
    pub fn device(&self) -> Value {
        if let Some(v) = fs::read_to_string(self.file("device.json"))
            .ok()
            .and_then(|t| serde_json::from_str::<Value>(&t).ok())
        {
            if v["mac_address"].is_string() {
                return v;
            }
        }
        let mut b = [0u8; 70];
        getrandom::getrandom(&mut b).expect("OS random generator");
        let hex = |s: &[u8]| s.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let mac = b[..6]
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect::<Vec<_>>()
            .join(":");
        let v = json!({ "mac_address": mac, "hdd_serial": hex(&b[6..38]), "motherboard": hex(&b[38..70]) });
        let _ = fs::write(self.file("device.json"), v.to_string());
        v
    }

    pub fn status(&self) -> Status {
        let s = self.settings();
        let vpn = self.vpn_file();
        // An empty folder is valid: the game files are downloaded on first
        // start. The executable is checked again right before launch.
        let game_found = s
            .game_path
            .as_ref()
            .map(|p| Path::new(p).is_dir())
            .unwrap_or(false);
        Status {
            logged_in: self.token().is_some(),
            vpn_file: vpn.as_ref().map(|v| v.name.clone()),
            vpn_needs_auth: vpn.as_ref().is_some_and(|v| v.needs_auth),
            vpn_has_auth: self.vpn_auth().is_some(),
            game_path: s.game_path,
            game_found,
            installed_version: s.installed_version,
            mode: s.mode,
            auto_start: s.auto_start,
            close_after_launch: s.close_after_launch,
            game_exe_override: s.game_exe_override,
        }
    }
}

/// DMM 플레이어 설정 파일에서 게임 설치 정보 (경로, 버전, 종류)
fn dmm_player_install() -> Option<(String, Option<String>, Option<String>)> {
    let p = platform::appdata_dir()?
        .join("dmmgameplayer5")
        .join("dmmgame.cnf");
    let text = fs::read_to_string(p).ok()?;
    let v: Value = serde_json::from_str(text.trim_start_matches('\u{feff}')).ok()?;
    let g = v["contents"]
        .as_array()?
        .iter()
        .find(|c| c["productId"] == PRODUCT_ID)?;
    Some((
        g["detail"]["path"].as_str()?.to_string(),
        g["detail"]["version"].as_str().map(String::from),
        g["gameType"].as_str().map(String::from),
    ))
}

// ---------------------------------------------------------------------------
// DMM API
// ---------------------------------------------------------------------------

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(15))
        .timeout_read(Duration::from_secs(60))
        .timeout_write(Duration::from_secs(30))
        .build()
}

/// ureq 오류를 짧게 설명. ureq 의 기본 메시지에는 요청 주소 전체가 들어가는데,
/// 게임 파일 주소에는 다운로드 서명이 붙어 있어 화면·기록에 남기지 않음
fn describe(e: &ureq::Error) -> String {
    match e {
        ureq::Error::Status(code, _) => format!("HTTP {code}"),
        ureq::Error::Transport(t) => format!("{:?}", t.kind()),
    }
}

/// 문자열에 섞인 서명된 주소의 쿼리 부분(?Policy=...)을 지움
fn redact(s: String) -> String {
    match s.find("?Policy=") {
        Some(i) => {
            let end = s[i..].find(char::is_whitespace).map_or(s.len(), |j| i + j);
            format!("{}{}", &s[..i], &s[end..])
        }
        None => s,
    }
}

/// 일반 회선으로 DMM API 호출 (로그인 관련 API 는 한국 IP 로도 됨)
fn direct_post(path: &str, body: &Value, token: Option<&str>) -> Result<Value, String> {
    let mut req = agent()
        .post(&format!("https://{DMM_HOST}{path}"))
        .set("User-Agent", USER_AGENT)
        .set("Client-App", "DMMGamePlayer5")
        .set("Client-version", CLIENT_VERSION)
        .set("Accept-Language", "ja")
        .set("Content-Type", "application/json");
    if let Some(t) = token {
        req = req.set("actauth", t);
    }
    let resp = req
        .send_string(&body.to_string())
        .map_err(|e| format!("Failed to connect to the DMM server ({})", describe(&e)))?;
    let text = resp
        .into_string()
        .map_err(|e| format!("Failed to receive the DMM response: {e}"))?;
    serde_json::from_str(&text).map_err(|e| format!("Failed to parse the DMM response: {e}"))
}

fn fetch_manifest_page(
    agent: &ureq::Agent,
    url: &tauri::Url,
    page: u64,
) -> Result<ManifestPageData, String> {
    let resp = agent
        .get(url.as_str())
        .set("User-Agent", USER_AGENT)
        .set("Client-App", "DMMGamePlayer5")
        .set("Client-version", CLIENT_VERSION)
        .call()
        .map_err(|e| format!("Failed to fetch game update manifest page {page} ({})", describe(&e)))?;
    if resp.status() != 200 {
        return Err(format!("Game update manifest page {page} returned HTTP {}", resp.status()));
    }
    let text = resp
        .into_string()
        .map_err(|e| format!("Failed to read game update manifest page {page}: {e}"))?;
    let response: ManifestPage = serde_json::from_str(&text)
        .map_err(|e| format!("Invalid game update manifest page {page}: {e}"))?;
    if let Some(code) = response.result_code.filter(|&code| code != 100) {
        return Err(format!("Game update manifest page {page} failed (result_code {code})"));
    }
    Ok(response.data)
}

/// Timestamped network log so all tunnel/DNS/proxy activity is visible.
pub fn netlog(msg: &str) {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() % 86400)
        .unwrap_or(0);
    let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    eprintln!("[{h:02}:{m:02}:{s:02}] {msg}");
}

/// One VPN tunnel shared by the launcher, My Games calls and the browser proxy.
struct SharedTunnel {
    stack: Arc<Mutex<TunnelStack>>,
    /// Server host names already used — rotation skips these.
    tried: HashSet<String>,
    /// The server this tunnel is connected to.
    server: Option<String>,
}

// Each route has its own setup lock. Its Arc also serves as the generation
// token: a slow handshake cannot publish after the user replaced the route.
struct Route {
    setup: Arc<Mutex<()>>,
    dir: PathBuf,
    mode: String,
    active: Option<SharedTunnel>,
    last_error: Option<(Instant, String)>,
}
static ROUTE: Mutex<Option<Route>> = Mutex::new(None);

fn invalidate_route(store: &Store, matches: impl FnOnce(&str) -> bool) {
    let mut route = ROUTE.lock().unwrap_or_else(|e| e.into_inner());
    if route.as_ref().is_some_and(|r| r.dir == store.dir && matches(&r.mode)) {
        *route = None;
    }
}

fn with_route<T>(setup: &Arc<Mutex<()>>, f: impl FnOnce(&mut Route) -> T) -> Result<T, String> {
    let mut guard = ROUTE.lock().map_err(|e| e.to_string())?;
    guard.as_mut().filter(|r| Arc::ptr_eq(&r.setup, setup)).map(f)
        .ok_or_else(|| "VPN route changed during connection setup".to_string())
}

fn open_tunnel(store: &Store, mode: &str, tried: &mut HashSet<String>, progress: ProgressFn)
    -> Result<(TunnelStack, Option<String>), String>
{
    if mode == MODE_FILE {
        netlog("Opening VPN file tunnel");
        return Ok((open_vpn_file(store, progress)?, None));
    }
    let (stack, host) = open_vpngate(store, progress, tried)?;
    netlog(&format!("VPN tunnel connected via {host}"));
    Ok((stack, Some(host)))
}

/// Called only under this generation's setup lock. Share failed attempts for a
/// short interval too, so queued connections don't each start a server search.
fn dial_route(
    setup: &Arc<Mutex<()>>, store: &Store, mode: &str, mut tried: HashSet<String>, progress: ProgressFn,
) -> Result<Arc<Mutex<TunnelStack>>, String> {
    if let Some(error) = with_route(setup, |r| r.last_error.as_ref()
        .filter(|(at, _)| at.elapsed() < Duration::from_secs(3)).map(|(_, e)| e.clone()))? {
        return Err(error);
    }
    match open_tunnel(store, mode, &mut tried, progress) {
        Ok((stack, server)) => {
            let stack = Arc::new(Mutex::new(stack));
            with_route(setup, |r| {
                r.active = Some(SharedTunnel { stack: stack.clone(), tried, server });
                r.last_error = None;
            })?;
            Ok(stack)
        }
        Err(error) => {
            with_route(setup, |r| {
                r.last_error = Some((Instant::now(), error.clone()));
                // A long-lived session may have exhausted every candidate.
                // On the next search, exclude only the currently failed exit.
                if let Some(active) = r.active.as_mut() {
                    active.tried = active.server.iter().cloned().collect();
                }
            })?;
            Err(error)
        }
    }
}

pub fn shared_tunnel(
    store: &Store,
    mode: &str,
    progress: ProgressFn,
) -> Result<Arc<Mutex<TunnelStack>>, String> {
    let mut guard = ROUTE.lock().map_err(|e| e.to_string())?;
    // A window or launch task may still carry a mode captured before the
    // settings change. Don't let it reinstall that route after invalidation.
    if fs::read(store.file("settings.json")).ok()
        .and_then(|b| serde_json::from_slice::<Settings>(&b).ok())
        .is_some_and(|s| s.mode != mode) {
        return Err("VPN mode changed; retry using the current settings".into());
    }
    if mode == MODE_DIRECT {
        *guard = None;
        return Err("Direct mode does not use a launcher tunnel".to_string());
    }
    if !guard.as_ref().is_some_and(|r| r.mode == mode && r.dir == store.dir) {
        *guard = Some(Route {
            setup: Arc::default(), dir: store.dir.clone(), mode: mode.into(), active: None, last_error: None,
        });
    }
    let setup = guard.as_ref().unwrap().setup.clone();
    drop(guard);
    let _opening = setup.lock().map_err(|e| e.to_string())?;
    if let Some(stack) = with_route(&setup, |r| r.active.as_ref().map(|s| s.stack.clone()))? {
        return Ok(stack);
    }
    netlog(&format!("Opening shared tunnel (mode={mode})"));
    dial_route(&setup, store, mode, HashSet::new(), progress)
}

pub(crate) struct TunnelRoute(Arc<Mutex<()>>);

impl TunnelRoute {
    pub(crate) fn for_stack(stack: &Arc<Mutex<TunnelStack>>) -> Result<Self, String> {
        let guard = ROUTE.lock().map_err(|e| e.to_string())?;
        guard.as_ref().filter(|r| r.active.as_ref().is_some_and(|s| Arc::ptr_eq(&s.stack, stack)))
            .map(|r| Self(r.setup.clone())).ok_or_else(|| "VPN route changed; try again".into())
    }

    pub(crate) fn stack(&self) -> Option<Arc<Mutex<TunnelStack>>> {
        with_route(&self.0, |r| r.active.as_ref().map(|s| s.stack.clone())).ok().flatten()
    }
}

/// Rotate only the stack that actually failed, coalescing concurrent reports.
pub fn rotate_tunnel_if(failed: &Arc<Mutex<TunnelStack>>) -> Result<Arc<Mutex<TunnelStack>>, String> {
    let (setup, dir, mode) = {
        let guard = ROUTE.lock().map_err(|e| e.to_string())?;
        let r = guard.as_ref().filter(|r| r.active.as_ref().is_some_and(|s| Arc::ptr_eq(&s.stack, failed)))
            .ok_or("Failed VPN tunnel is no longer current")?;
        (r.setup.clone(), r.dir.clone(), r.mode.clone())
    };
    let _opening = setup.lock().map_err(|e| e.to_string())?;
    let (stack, tried, server) = with_route(&setup, |r| {
        r.active.as_ref().map(|s| (s.stack.clone(), s.tried.clone(), s.server.clone()))
    })?.ok_or("No tunnel to rotate")?;
    if !Arc::ptr_eq(&stack, failed) {
        return Ok(stack);
    }
    if let Some(server) = server {
        netlog(&format!("Rotating away from failed server {server}"));
    }
    let stack = dial_route(&setup, &Store { dir }, &mode, tried, &|m, _| netlog(m))?;
    netlog("VPN tunnel rotated successfully");
    Ok(stack)
}

/// Discard the shared tunnel so the next call opens a fresh session.
pub fn reset_shared_tunnel() {
    *ROUTE.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

/// 일본 IP 가 필요한 API 를 부르는 경로
enum JapanLink {
    Direct,
    Tunnel(Arc<Mutex<TunnelStack>>),
}

impl JapanLink {
    fn rotate_failed_server(&self) -> Result<(), String> {
        if let JapanLink::Tunnel(stack) = self {
            rotate_tunnel_if(stack)?;
        }
        Ok(())
    }

    fn post(&mut self, path: &str, body: &Value, token: &str) -> Result<Value, String> {
        match self {
            JapanLink::Direct => direct_post(path, body, Some(token)),
            JapanLink::Tunnel(shared) => {
                let req = http::dmm_post(path, &body.to_string(), Some(token));
                let raw = TunnelStack::request_shared(
                    shared, DMM_HOST, 443, Some(http::dmm_tls_config()), &req, Duration::from_secs(30),
                )?;
                let (status, b) = http::parse_response(&raw)?;
                match serde_json::from_slice(&b) {
                    Ok(v) => Ok(v),
                    Err(_) if status != 200 => Err(format!("DMM server error (HTTP {status})")),
                    Err(e) => Err(format!("Failed to parse the DMM response: {e}")),
                }
            }
        }
    }
}

pub const PROFILE_REGISTRATION_REQUIRED: &str = "DMM GAMES profile registration is required. Open the Browser and register this account, then try again.";

fn require_dmm_success(response: &Value, operation: &str) -> Result<(), String> {
    match response["result_code"].as_i64() {
        Some(100) => Ok(()),
        Some(code) => Err(format!("Failed to {operation} (DMM result_code {code})")),
        None => Err(format!("Failed to {operation}: DMM response had no valid result_code")),
    }
}

fn check_mygames_response(response: &Value, operation: &str) -> Result<(), String> {
    if response["result_code"].as_i64() == Some(313) {
        return Err(PROFILE_REGISTRATION_REQUIRED.into());
    }
    require_dmm_success(response, operation)
}

fn mygames_contains_game(response: &Value) -> Result<bool, String> {
    check_mygames_response(response, "read My Games")?;
    let games = response["data"].as_array().ok_or("DMM returned an invalid My Games list")?;
    Ok(games.iter().any(|g| g["product_id"].as_str() == Some(PRODUCT_ID)))
}

/// Whether the game is already in the account's My Games list.
pub fn is_in_mygames(store: &Store, mode: &str, token: &str) -> Result<bool, String> {
    open_japan_link(store, mode, &|_, _| {})?.is_in_mygames(token)
}

enum MyGamesAdd {
    Added,
    AlreadyPresent,
}

/// Add the game to My Games over the selected connection mode.
pub fn add_to_mygames(store: &Store, mode: &str, token: &str) -> Result<String, String> {
    Ok(match open_japan_link(store, mode, &|_, _| {})?.add_to_mygames(token)? {
        MyGamesAdd::Added => "Game added to My Games".into(),
        MyGamesAdd::AlreadyPresent => "Game is already in My Games".into(),
    })
}

impl JapanLink {
    fn is_in_mygames(&mut self, token: &str) -> Result<bool, String> {
        let response = self.post("/v5/mygames", &json!({ "user_os": "win" }), token)?;
        mygames_contains_game(&response)
    }

    fn add_to_mygames(&mut self, token: &str) -> Result<MyGamesAdd, String> {
        if self.is_in_mygames(token)? {
            return Ok(MyGamesAdd::AlreadyPresent);
        }
        let response = self.post(
            "/v5/detail/mygame/add",
            &json!({ "product_id": PRODUCT_ID, "game_type": "cl", "game_os": "win" }),
            token,
        )?;
        check_mygames_response(&response, "add the game to My Games")?;
        Ok(MyGamesAdd::Added)
    }
}

fn confirm_terms_once(
    attempted: &mut bool,
    confirm: impl FnOnce() -> Result<Value, String>,
) -> Result<(), String> {
    if std::mem::replace(attempted, true) {
        return Err("DMM still requires the game terms after confirmation. Accept them in DMM and try again.".into());
    }
    require_dmm_success(&confirm()?, "confirm the game terms")
}

/// 일본 연결을 엶. VPN Gate 면 `tried` 에 없는 서버 중에서 고르고, 고른 서버 이름을 함께 돌려줌
fn open_japan_link(
    store: &Store,
    mode: &str,
    progress: ProgressFn,
) -> Result<JapanLink, String> {
    if mode == MODE_DIRECT {
        return Ok(JapanLink::Direct);
    }
    Ok(JapanLink::Tunnel(shared_tunnel(store, mode, progress)?))
}

fn try_servers(
    list: &[(vpngate::Server, vpngate::OvpnConfig)],
    tried: &mut HashSet<String>,
    progress: ProgressFn,
) -> Option<(TunnelStack, String)> {
    for (server, cfg) in list {
        if !tried.insert(server.host_name.clone()) {
            continue;
        }
        progress(&format!("Connecting to VPN · {}", server.host_name), None);
        match connect_tunnel(cfg, &server.tls_name(), progress) {
            Ok(stack) => return Some((stack, server.host_name.clone())),
            Err(e) => progress(&format!("{} connection failed: {e}", server.host_name), None),
        }
    }
    None
}

/// 터널을 열고 DMM 주소를 터널 안에서(일본 쪽 DNS 로) 찾아 둠.
/// 한국 등에서 받은 CDN 주소는 VPN Gate 쪽에서 연결되지 않을 수 있음. 못 찾으면 시스템 DNS 그대로 씀
fn connect_tunnel(
    cfg: &vpngate::OvpnConfig,
    tls_name: &str,
    progress: ProgressFn,
) -> Result<TunnelStack, String> {
    let tun = Tunnel::connect(cfg, tls_name, &mut |_| {})?;
    stack_with_japan_dns(tun, progress)
}

/// 터널 위에 TCP/IP 스택을 올리고 DMM 주소를 터널 안에서 찾아 둠
fn stack_with_japan_dns<T: IpTunnel + 'static>(
    tun: T,
    progress: ProgressFn,
) -> Result<TunnelStack, String> {
    let mut stack = TunnelStack::new(tun)?;
    if let Err(e) = stack.resolve_in_tunnel(DMM_HOST) {
        progress(&format!("Japan DNS lookup failed, using the default DNS ({e})"), None);
    }
    Ok(stack)
}

/// 사용자가 가져온 VPN 설정 파일로 연결
fn open_vpn_file(store: &Store, progress: ProgressFn) -> Result<TunnelStack, String> {
    let file = store.vpn_file().ok_or("Please select a VPN config file")?;
    if file.kind == VPN_WIREGUARD {
        let cfg = WgConfig::parse(&file.text)?;
        progress(&format!("Connecting to VPN · {}", file.name), None);
        let tun = WgTunnel::connect(&cfg, &mut |_| {})?;
        return stack_with_japan_dns(tun, progress);
    }
    let cfg = OvpnConfig::parse(&file.text)?;
    let creds = if cfg.auth_user_pass {
        Some(
            store
                .vpn_auth()
                .ok_or("Please enter the VPN username and password")?,
        )
    } else {
        None
    };
    let mut last = String::from("Failed to connect to the VPN server");
    for remote in cfg.remote_order().iter().take(VPN_FILE_TRIES) {
        progress(&format!("Connecting to VPN · {}", remote.host), None);
        let opts = ConnectOptions {
            remote,
            tls_name: &remote.host,
            strict_verify: true,
            credentials: creds.as_ref().map(|(u, p)| (u.as_str(), p.as_str())),
        };
        match Tunnel::connect_with(&cfg, &opts, &mut |_| {}) {
            Ok(tun) => return stack_with_japan_dns(tun, progress),
            Err(e) if e.contains("AUTH_FAILED") => {
                return Err("The VPN username or password is incorrect".into())
            }
            Err(e) => {
                progress(&format!("{} connection failed: {e}", remote.host), None);
                last = format!("Failed to connect to the VPN server ({e})");
            }
        }
    }
    Err(last)
}

/// 프로그램에 내장된 쓰쿠바대 서버로 시도 (서버 목록을 받을 수 없는 네트워크용).
/// 마지막으로 확인한 IP 로 먼저 시도하고, 안 되면 DNS 로 찾은 IP 로 한 번 더
fn try_builtin(tried: &mut HashSet<String>, progress: ProgressFn) -> Option<(TunnelStack, String)> {
    let mut count = 0;
    for (server, mut cfg) in vpngate::builtin_official_servers() {
        if count >= VPNGATE_OFFICIAL_TRIES {
            break;
        }
        if !tried.insert(server.host_name.clone()) {
            continue;
        }
        count += 1;
        progress(&format!("Connecting to VPN · {}", server.host_name), None);
        let connect = |cfg: &vpngate::OvpnConfig| connect_tunnel(cfg, &server.tls_name(), progress);
        let mut result = connect(&cfg);
        if result.is_err() {
            let known = vpngate::remote_ip(&cfg).to_string();
            vpngate::refresh_builtin_ip(&server, &mut cfg);
            if vpngate::remote_ip(&cfg) != known {
                result = connect(&cfg);
            }
        }
        match result {
            Ok(stack) => return Some((stack, server.host_name)),
            Err(e) => progress(&format!("{} connection failed: {e}", server.host_name), None),
        }
    }
    None
}

/// 목록에서 아직 시도하지 않은 일본 서버 (쓰쿠바대 서버 먼저, 그다음 점수 순)
fn untried(
    body: &str,
    tried: &HashSet<String>,
    official_only: bool,
    take: usize,
) -> Vec<(vpngate::Server, vpngate::OvpnConfig)> {
    vpngate::japan_tcp_candidates(body)
        .into_iter()
        .filter(|(s, _)| (!official_only || s.is_official()) && !tried.contains(&s.host_name))
        .take(take)
        .collect()
}

/// VPN Gate 일본 서버에 터널을 염. `tried` 에 든 서버(이미 실패했거나 DMM 이 거부한 서버)는 건너뜀.
/// 1. 저장된 목록의 쓰쿠바대 서버  2. 목록을 갱신해 나머지 서버
/// 3. 목록을 받지 못하면 저장된 목록(오래됐어도)의 나머지 서버  4. 프로그램에 내장된 쓰쿠바대 서버
fn open_vpngate(
    store: &Store,
    progress: ProgressFn,
    tried: &mut HashSet<String>,
) -> Result<(TunnelStack, String), String> {
    let cached = store.cached_vpngate_list();
    if let Some(body) = &cached {
        let official = untried(body, tried, true, VPNGATE_OFFICIAL_TRIES);
        if let Some(found) = try_servers(&official, tried, progress) {
            return Ok(found);
        }
    }
    progress("Refreshing the server list", None);
    let list_ok = match store.refresh_vpngate_list(VPNGATE_RECENT) {
        Ok(body) => {
            let all = untried(&body, tried, false, VPNGATE_MORE_TRIES);
            if let Some(found) = try_servers(&all, tried, progress) {
                return Ok(found);
            }
            true
        }
        Err(e) => {
            progress(&e, None);
            if let Some(body) = &cached {
                let rest = untried(body, tried, false, VPNGATE_MORE_TRIES);
                if let Some(found) = try_servers(&rest, tried, progress) {
                    return Ok(found);
                }
            }
            false
        }
    };
    if let Some(found) = try_builtin(tried, progress) {
        return Ok(found);
    }
    Err(if list_ok {
        "Failed to connect to a VPN Gate server. Please try again in a moment.".to_string()
    } else {
        "Failed to connect to VPN Gate. It may be blocked on this network. \
         Please enable a Japanese VPN yourself and switch the connection mode to 'Direct'."
            .to_string()
    })
}

// ---------------------------------------------------------------------------
// 로그인
// ---------------------------------------------------------------------------

/// DMM 로그인. 로그인 창은 `get_code` 가 담당 (비밀번호는 이 코드가 다루지 않음)
pub fn login(
    store: &Store,
    get_code: CodeFn,
    progress: ProgressFn,
    sign_in: SignIn,
) -> Result<String, String> {
    progress("Opening DMM sign-in…", None);
    let r = direct_post("/v5/auth/login/url", &json!({ "prompt": "" }), None)?;
    let url = r["data"]["url"]
        .as_str()
        .ok_or_else(|| {
            format!(
                "Failed to get the login URL (result_code {})",
                r["result_code"]
            )
        })?
        .to_string();
    let code = get_code(&url, sign_in)?;
    let r = direct_post("/v5/auth/accesstoken/issue", &json!({ "code": code }), None)?;
    if r["result_code"] != 100 {
        return Err(format!(
            "Failed to issue the login token (result_code {})",
            r["result_code"]
        ));
    }
    let token = r["data"]["access_token"]
        .as_str()
        .ok_or("No login token in the response")?
        .to_string();
    store.save_token(&token)?;
    progress("Logged in", None);
    Ok(token)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenCheck {
    Valid,
    Expired,
    /// 연결 실패 등으로 확인하지 못함
    Unknown,
}

/// How long a successful token check also answers later checks of the same token.
const TOKEN_CHECK_REUSE: Duration = Duration::from_secs(60);

/// Shares DMM token checks between the startup verification and Start.
///
/// Callers checking a token while a check of that same token is in flight wait
/// for its result, and a `Valid` result is reused for `TOKEN_CHECK_REUSE`.
/// Results are keyed by the token itself, and `forget` (called whenever the
/// saved token changes) stops an in-flight check from publishing, so a result
/// for an old token never answers for its replacement.
struct TokenChecks {
    state: Mutex<TokenCheckState>,
    done: Condvar,
}

struct TokenCheckState {
    next_id: u64,
    entry: Option<TokenCheckEntry>,
}

struct TokenCheckEntry {
    id: u64,
    token: String,
    /// `None` while the check is in flight.
    result: Option<(TokenCheck, Instant)>,
}

/// Publishes the check's result when the checking caller finishes, or
/// withdraws the in-flight entry if it unwinds without one.
struct InFlightCheck<'a> {
    checks: &'a TokenChecks,
    id: u64,
    result: Option<TokenCheck>,
}

impl Drop for InFlightCheck<'_> {
    fn drop(&mut self) {
        let mut st = self.checks.state.lock().unwrap_or_else(|e| e.into_inner());
        if st.entry.as_ref().is_some_and(|e| e.id == self.id) {
            match self.result {
                Some(r) => st.entry.as_mut().unwrap().result = Some((r, Instant::now())),
                None => st.entry = None,
            }
        }
        drop(st);
        self.checks.done.notify_all();
    }
}

impl TokenChecks {
    const fn new() -> Self {
        Self {
            state: Mutex::new(TokenCheckState { next_id: 0, entry: None }),
            done: Condvar::new(),
        }
    }

    fn check(&self, token: &str, reuse: Duration, verify: impl FnOnce(&str) -> TokenCheck) -> TokenCheck {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        // Set once this caller has waited on an in-flight check of its token:
        // it then takes that check's result whatever it is.
        let mut joined = None;
        loop {
            match st.entry.as_ref().filter(|e| e.token == token) {
                Some(e) if e.result.is_none() => {
                    joined = Some(e.id);
                    st = self.done.wait(st).unwrap_or_else(|e| e.into_inner());
                }
                Some(TokenCheckEntry { id, result: Some((r, at)), .. })
                    if joined == Some(*id) || (*r == TokenCheck::Valid && at.elapsed() < reuse) =>
                {
                    return *r;
                }
                _ => break,
            }
        }
        let id = st.next_id;
        st.next_id += 1;
        st.entry = Some(TokenCheckEntry { id, token: token.to_string(), result: None });
        drop(st);
        let mut in_flight = InFlightCheck { checks: self, id, result: None };
        let r = verify(token);
        in_flight.result = Some(r);
        r
    }

    /// Drop any in-flight or reusable result (the saved token changed).
    fn forget(&self) {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).entry = None;
        self.done.notify_all();
    }
}

static TOKEN_CHECKS: TokenChecks = TokenChecks::new();

/// 토큰이 아직 유효한지 DMM 에 확인 (같은 토큰의 진행 중인 확인 결과와 직전의 성공 결과를 함께 씀)
pub fn check_token(token: &str) -> TokenCheck {
    TOKEN_CHECKS.check(token, TOKEN_CHECK_REUSE, request_token_check)
}

/// 토큰이 아직 유효한지 DMM 에 확인. DMM 은 지역보다 인증을 먼저 보므로 VPN 없이 일반 회선으로 됨
/// (만료·무효: 203 / 유효: 100, 일본 밖이면 지역 차단 801·803)
fn request_token_check(token: &str) -> TokenCheck {
    match direct_post("/v5/userinfo", &json!({}), Some(token)) {
        Ok(r) => match r["result_code"].as_i64() {
            Some(203) => TokenCheck::Expired,
            Some(100 | 801 | 803) => TokenCheck::Valid,
            _ => TokenCheck::Unknown,
        },
        Err(_) => TokenCheck::Unknown,
    }
}

/// 저장된 토큰을 검사해 만료됐으면 지움. 확인하지 못하면 그대로 둠
pub fn verify_saved_token(store: &Store) -> Result<TokenCheck, String> {
    let Some(token) = store.token() else {
        return Ok(TokenCheck::Expired);
    };
    let c = check_token(&token);
    if c == TokenCheck::Expired {
        store.clear_token_if(&token)?;
    }
    Ok(c)
}

// ---------------------------------------------------------------------------
// 실행
// ---------------------------------------------------------------------------

fn region_error(mode: &str) -> String {
    if mode == MODE_DIRECT {
        "No Japanese VPN is connected".into()
    } else if mode == MODE_FILE {
        "DMM rejected this VPN server. Check that the config is for a Japanese server, or try a different server file."
            .into()
    } else {
        "DMM rejected the VPN server. Please try again in a moment.".into()
    }
}

/// 실행 토큰을 받아 (필요하면 업데이트 후) 게임 실행. launch 가 false 면 실행 직전까지만
pub fn start_game(
    store: &Store,
    get_code: CodeFn,
    progress: ProgressFn,
    launch: bool,
) -> Result<String, String> {
    start_game_with_profile_setup(store, get_code, progress, launch, None)
}

pub fn start_game_with_profile_setup(
    store: &Store,
    get_code: CodeFn,
    progress: ProgressFn,
    launch: bool,
    profile_setup: Option<ProfileSetupFn>,
) -> Result<String, String> {
    let mut settings = store.settings();
    let game_dir = PathBuf::from(
        settings
            .game_path
            .clone()
            .ok_or("Please select the game folder")?,
    );
    if !game_dir.is_dir() {
        return Err(format!(
            "Game folder not found: {}",
            game_dir.display()
        ));
    }
    let game_type = settings.game_type.clone().unwrap_or_else(|| "GCL".into());

    // 저장된 토큰이 유효하면 그대로 쓰고, 만료됐으면 VPN 을 열기 전에 다시 로그인
    let mut token = match store.token() {
        Some(t) => {
            progress("Checking login", None);
            if check_token(&t) == TokenCheck::Expired {
                progress("Login expired, signing in again", None);
                store.clear_token_if(&t)?;
                // The DMM browser session often outlives the token, so try it silently first.
                login(store, get_code, progress, SignIn::ReuseSession)?
            } else {
                t
            }
        }
        None => login(store, get_code, progress, SignIn::Interactive)?,
    };

    let device = store.device();
    let body = json!({
        "product_id": PRODUCT_ID, "game_type": game_type, "game_os": "win", "launch_type": "LIB",
        "mac_address": device["mac_address"], "hdd_serial": device["hdd_serial"],
        "motherboard": device["motherboard"], "user_os": "win"
    });

    let mut relogged = false;
    let mut tried_terms_confirmation = false;
    let mut added_mygame = false;
    let mut tried_profile_setup = false;
    let mut profile_launch_retries = 0;
    let mut attempts = 0;
    let data = loop {
        attempts += 1;
        // VPN Gate 서버가 DMM 에 거부당하거나 연결이 끊기면 다른 서버로 다시 시도
        let can_retry = settings.mode == MODE_VPNGATE && attempts < VPNGATE_LAUNCH_ATTEMPTS;
        let mut link = open_japan_link(store, &settings.mode, progress)?;
        progress("Preparing to launch", None);
        let result = link.post("/v5/r2/launch/cl", &body, &token);
        let r = match result {
            Ok(r) => r,
            Err(e) if can_retry => {
                progress(&format!("{e} · trying another server"), None);
                link.rotate_failed_server()?;
                continue;
            }
            Err(e) => return Err(e),
        };
        match r["result_code"].as_i64().unwrap_or(-1) {
            100 => {
                if tried_profile_setup {
                    netlog("[profile] DMM accepted launch after windowless setup");
                }
                break r["data"].clone();
            }
            203 if !relogged => {
                progress("A new login is required", None);
                store.clear_token()?;
                token = login(store, get_code, progress, SignIn::ReuseSession)?;
                relogged = true;
            }
            801 | 803 if can_retry => {
                progress("DMM rejected the VPN server; trying another server", None);
                link.rotate_failed_server()?;
            }
            801 | 803 => return Err(region_error(&settings.mode)),
            308 => {
                confirm_terms_once(&mut tried_terms_confirmation, || {
                    progress("Game terms not accepted; confirming...", None);
                    link.post(
                        "/v5/agreement/confirm/client",
                        &json!({ "product_id": PRODUCT_ID, "is_notification": false }),
                        &token,
                    )
                })?;
            }
            // 314 (NOT_PURCHASED_FAILURE) means DMM does not see the title in
            // this account's My Games, so the same My Games add can clear it.
            code @ (313 | 314) => {
                if !added_mygame {
                    match link.add_to_mygames(&token) {
                        Ok(MyGamesAdd::Added) => {
                            progress("Game added to My Games", None);
                            added_mygame = true;
                            continue;
                        }
                        Ok(MyGamesAdd::AlreadyPresent) => added_mygame = true,
                        Err(e) if e == PROFILE_REGISTRATION_REQUIRED && code == 314 => return Err(e),
                        Err(e) if e == PROFILE_REGISTRATION_REQUIRED => (),
                        Err(e) => return Err(e),
                    }
                }
                if code == 314 {
                    return Err("DMM reports this account does not have the game (result_code 314). Add Gakumas from its DMM GAMES page in the Browser, then try again.".into());
                }
                if let Some(setup) = profile_setup.filter(|_| launch && !tried_profile_setup) {
                    tried_profile_setup = true;
                    if let Err(e) = setup(&settings.mode, &token) {
                        netlog(&format!("[profile] background setup unavailable: {e}"));
                        return Err(format!("Windowless DMM profile setup failed: {e}"));
                    }
                    // The launch endpoint is authoritative for 313. A separate
                    // userinfo response may omit the flag or lag behind setup.
                    profile_launch_retries = 2;
                    progress("Checking DMM GAMES profile registration…", None);
                    continue;
                }
                if profile_launch_retries > 0 {
                    profile_launch_retries -= 1;
                    netlog("[profile] launch still returned 313; waiting before retry");
                    std::thread::sleep(Duration::from_secs(2));
                    continue;
                }
                if tried_profile_setup {
                    return Err("DMM still reports profile registration required (313) after windowless setup. No setup window was opened.".into());
                }
                return Err(PROFILE_REGISTRATION_REQUIRED.into());
            }
            c => return Err(format!("Failed to prepare launch (result_code {c}, {})", r["error"])),
        }
    };

    let latest = data["latest_version"].as_str().unwrap_or("").to_string();
    if !latest.is_empty() && settings.installed_version.as_deref() != Some(latest.as_str()) {
        update_game(&game_dir, &data, progress, !launch)?;
        if launch {
            settings.installed_version = Some(latest.clone());
            store.save_settings(&settings)?;
        }
    }

    // DMM 플레이어와 같이, DRM 인증 정보가 오면 정해진 위치에 저장
    if let (Some(drm), true) = (data["drm_auth_token"].as_str(), launch) {
        // On Linux the profile is inside the Proton prefix. If no prefix is
        // configured there is nowhere to write, so skip it instead of failing.
        if let Some(profile) = platform::user_profile_dir() {
            let dir = profile.join(".DMMGamePlayer");
            fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
            use base64::Engine;
            let name = base64::engine::general_purpose::STANDARD.encode(PRODUCT_ID);
            fs::write(dir.join(name), drm).map_err(|e| e.to_string())?;
        }
    }

    let exe_name = data["exec_file_name"]
        .as_str()
        .ok_or("No executable name in the response")?;
    // Optional user-supplied executable (e.g. a Proton-tuned build with
    // protection checks disabled). Relative paths are resolved inside the
    // game folder; absolute paths are used as-is.
    let exe = match settings.game_exe_override.as_deref() {
        Some(path) if !path.trim().is_empty() => {
            let override_path = Path::new(path.trim());
            let resolved = if override_path.is_absolute() {
                override_path.to_path_buf()
            } else {
                game_dir.join(override_path)
            };
            progress(
                &format!("Using custom executable: {}", resolved.display()),
                None,
            );
            resolved
        }
        _ => game_dir.join(exe_name),
    };
    if !exe.is_file() {
        return Err(format!(
            "Game executable not found: {}",
            exe.display()
        ));
    }
    let args = data["execute_args"]
        .as_str()
        .ok_or("No launch arguments in the response")?;
    if !launch {
        return Ok(format!(
            "[Dry run] Checked up to just before launch ({})",
            exe.display()
        ));
    }
    let elevated = data["is_administrator"].as_bool().unwrap_or(true);
    progress("Launching the game", None);
    platform::launch(&exe, args, &game_dir, elevated, Duration::from_secs(8))?;
    Ok("Game launched".into())
}

// ---------------------------------------------------------------------------
// 업데이트 (DMM 플레이어와 같은 방식: 파일 목록의 MD5 와 다른 파일만 받음)
// ---------------------------------------------------------------------------

/// DMM's file list uses Windows separators. On Linux those backslashes are
/// ordinary filename characters, so split on both separators and rebuild the
/// path with native components instead of replacing '/' with '\\'.
fn resolve_game_path(game_dir: &Path, local_path: &str) -> Option<PathBuf> {
    let mut rel = PathBuf::new();
    for part in local_path.split(['/', '\\']) {
        if !part.is_empty() {
            rel.push(part);
        }
    }
    if rel.as_os_str().is_empty() || rel.components().any(|c| !matches!(c, Component::Normal(_))) {
        return None;
    }
    Some(game_dir.join(rel))
}

/// 받는 중인 파일의 임시 확장자
const TMP_EXT: &str = "dmmtmp";

/// 게임 폴더 아래의 임시 파일(*.dmmtmp)을 지움 (깊이 제한)
fn remove_stale_tmp(dir: &Path, depth: u32) {
    if depth > 8 {
        return;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        match entry.file_type() {
            Ok(t) if t.is_dir() => remove_stale_tmp(&path, depth + 1),
            Ok(t) if t.is_file() && path.extension().and_then(|e| e.to_str()) == Some(TMP_EXT) => {
                let _ = fs::remove_file(&path);
            }
            _ => {}
        }
    }
}

fn md5_file(path: &Path, buf: &mut [u8]) -> Result<String, String> {
    let mut f = fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut h = Md5::new();
    loop {
        let n = f
            .read(buf)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(format!("{:x}", h.finalize()))
}

fn percent_encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

#[derive(Deserialize)]
struct ManifestPage {
    result_code: Option<i64>,
    data: ManifestPageData,
}

#[derive(Deserialize)]
struct ManifestPageData {
    domain: Option<String>,
    page: Option<NonZeroU64>,
    file_list: Vec<ManifestFile>,
}

#[derive(Deserialize)]
struct ManifestFile {
    local_path: String,
    path: Option<String>,
    size: Option<u64>,
    hash: Option<String>,
    #[serde(default)]
    force_delete_flg: bool,
    #[serde(default)]
    check_hash_flg: bool,
    #[serde(default)]
    protected_flg: bool,
}

fn load_manifest(
    agent: &ureq::Agent,
    url: &tauri::Url,
    game_dir: &Path,
) -> Result<(String, Vec<(ManifestFile, PathBuf)>), String> {
    let mut first = fetch_manifest_page(agent, url, 1)?;
    let pages = first
        .page
        .ok_or("Missing page count in game update manifest")?
        .get();
    let domain = first
        .domain
        .ok_or("Missing download server in game update manifest")?;
    let server = tauri::Url::parse(&domain).map_err(|_| "Invalid game update download server")?;
    if !matches!(server.scheme(), "http" | "https")
        || server.host_str().is_none()
        || server.query().is_some()
        || server.fragment().is_some()
        || !server.username().is_empty()
        || server.password().is_some()
    {
        return Err("Invalid game update download server".into());
    }

    let mut files = Vec::new();
    for number in 1..=pages {
        let page_files = if number == 1 {
            std::mem::take(&mut first.file_list)
        } else {
            let mut page_url = url.clone();
            page_url
                .query_pairs_mut()
                .append_pair("page", &number.to_string());
            fetch_manifest_page(agent, &page_url, number)?.file_list
        };
        for (index, file) in page_files.into_iter().enumerate() {
            let invalid = |field| {
                format!("Invalid {field} in game update manifest page {number}, entry {}", index + 1)
            };
            let full =
                resolve_game_path(game_dir, &file.local_path).ok_or_else(|| invalid("local_path"))?;
            if !file.force_delete_flg {
                if !file.protected_flg
                    && !file
                        .path
                        .as_deref()
                        .is_some_and(|path| !path.trim_matches('/').trim().is_empty())
                {
                    return Err(invalid("path"));
                }
                if file.check_hash_flg
                    && !file.hash.as_deref().is_some_and(|hash| {
                        hash.len() == 32 && hash.bytes().all(|b| b.is_ascii_hexdigit())
                    })
                {
                    return Err(invalid("hash"));
                }
            }
            files.push((file, full));
        }
    }
    Ok((server.to_string(), files))
}

#[derive(Debug, PartialEq, Eq)]
enum FileAction {
    Keep,
    Download,
    Delete,
}

/// Decide what the update does with one manifest entry. A hash-checked file
/// whose size already differs from the manifest is queued without reading it;
/// otherwise `md5` hashes it.
fn file_action(
    f: &ManifestFile,
    full: &Path,
    md5: impl FnOnce(&Path) -> Result<String, String>,
) -> Result<FileAction, String> {
    let meta = fs::metadata(full).ok().filter(|m| m.is_file());
    if f.force_delete_flg {
        return Ok(if meta.is_some() { FileAction::Delete } else { FileAction::Keep });
    }
    let Some(meta) = meta else {
        return Ok(FileAction::Download);
    };
    if !f.check_hash_flg {
        return Ok(FileAction::Keep);
    }
    if f.size.is_some_and(|size| size != meta.len()) {
        return Ok(FileAction::Download);
    }
    Ok(if md5(full)?.eq_ignore_ascii_case(f.hash.as_deref().unwrap_or_default()) {
        FileAction::Keep
    } else {
        FileAction::Download
    })
}

fn update_game(
    game_dir: &Path,
    data: &Value,
    progress: ProgressFn,
    dry_run: bool,
) -> Result<(), String> {
    let list_url = data["file_list_url"]
        .as_str()
        .filter(|url| url.starts_with('/'))
        .ok_or("No update information in the response")?;
    let sign = data["sign"]
        .as_str()
        .ok_or("No download signature in the response")?;
    progress("Checking files for updates", None);
    let list_url = tauri::Url::parse(&format!("https://{DMM_HOST}{list_url}"))
        .map_err(|_| "Invalid game update manifest URL")?;
    let agent = agent();
    let (domain, files) = load_manifest(&agent, &list_url, game_dir)?;

    let mut todo = Vec::new();
    let mut delete = Vec::new();
    let mut buf = Vec::new();
    for (i, (f, full)) in files.iter().enumerate() {
        if i % 10 == 0 {
            progress(
                &format!("Checking files {}/{}", i, files.len()),
                Some(i as f32 * 100.0 / files.len().max(1) as f32),
            );
        }
        let action = file_action(f, full, |path| {
            buf.resize(1 << 20, 0);
            md5_file(path, &mut buf)
        })?;
        match action {
            FileAction::Keep => {}
            FileAction::Download => todo.push((f, full)),
            FileAction::Delete => delete.push(full),
        }
    }
    if todo.is_empty() && delete.is_empty() {
        progress("Updating: already up to date", Some(100.0));
        return Ok(());
    }
    if todo.iter().any(|(f, _)| f.protected_flg) {
        return Err("This update contains protected files that this launcher cannot download. Please update with DMM GAME PLAYER.".into());
    }
    let total = todo.iter().try_fold(0u64, |total, (f, _)| {
        total
            .checked_add(f.size.unwrap_or(0))
            .ok_or("Invalid total game update size")
    })?;
    progress(
        &format!(
            "Updating: {} files, {:.0} MB",
            todo.len(),
            total as f64 / 1_048_576.0
        ),
        None,
    );
    if dry_run {
        for (f, _) in &todo {
            progress(
                &format!("Updating: file to download: {}", f.local_path),
                None,
            );
        }
        return Ok(());
    }

    // 이전에 중간에 끊긴 업데이트가 남긴 임시 파일 정리
    remove_stale_tmp(game_dir, 0);

    // CloudFront 서명: "CloudFront-Policy=..;CloudFront-Signature=..;CloudFront-Key-Pair-Id=.."
    let mut policy = "";
    let mut signature = "";
    let mut key_pair = "";
    for kv in sign.split(';') {
        if let Some((k, v)) = kv.trim().split_once('=') {
            match k {
                "CloudFront-Policy" => policy = v,
                "CloudFront-Signature" => signature = v,
                "CloudFront-Key-Pair-Id" => key_pair = v,
                _ => {}
            }
        }
    }
    let query = format!(
        "Policy={}&Signature={}&Key-Pair-Id={}",
        percent_encode(policy),
        percent_encode(signature),
        percent_encode(key_pair)
    );

    let mut done: u64 = 0;
    buf.resize(256 * 1024, 0);
    for (n, &(f, full)) in todo.iter().enumerate() {
        let local = &f.local_path;
        let url = format!(
            "{}/{}?{}",
            domain.trim_end_matches('/'),
            f.path.as_deref().unwrap_or_default().trim_start_matches('/'),
            query
        );
        if let Some(parent) = full.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
        }
        let tmp = full.with_extension(format!(
            "{}.{TMP_EXT}",
            full.extension().and_then(|e| e.to_str()).unwrap_or("")
        ));
        let mut fetch = || -> Result<(), String> {
            let resp = agent
                .get(&url)
                .set("User-Agent", USER_AGENT)
                .call()
                .map_err(|e| format!("Failed to download {local} ({})", describe(&e)))?;
            let mut reader = resp.into_reader();
            let mut out = fs::File::create(&tmp).map_err(|e| format!("{}: {e}", tmp.display()))?;
            let mut hash = f.check_hash_flg.then(Md5::new);
            let mut last_report = 0u64;
            loop {
                let k = reader
                    .read(&mut buf)
                    .map_err(|e| redact(format!("Failed to download {local}: {e}")))?;
                if k == 0 {
                    break;
                }
                let chunk = &buf[..k];
                out.write_all(chunk)
                    .map_err(|e| format!("{}: {e}", tmp.display()))?;
                if let Some(hash) = &mut hash {
                    hash.update(chunk);
                }
                done += k as u64;
                if done - last_report >= 2 * 1_048_576 {
                    last_report = done;
                    progress(
                        &format!("Updating {}/{}", n + 1, todo.len()),
                        Some(done as f32 * 100.0 / total.max(1) as f32),
                    );
                }
            }
            drop(out);
            if hash.is_some_and(|hash| {
                !format!("{:x}", hash.finalize())
                    .eq_ignore_ascii_case(f.hash.as_deref().unwrap_or_default())
            }) {
                return Err(format!("{local}: downloaded file hash mismatch"));
            }
            fs::rename(&tmp, full)
                .map_err(|e| format!("{local}: failed to replace the file (is the game running?): {e}"))
        };
        if let Err(e) = fetch() {
            let _ = fs::remove_file(&tmp); // 받다 만 파일을 남기지 않음
            return Err(e);
        }
        progress(
            &format!("Updating {}/{}", n + 1, todo.len()),
            Some(done as f32 * 100.0 / total.max(1) as f32),
        );
    }
    for d in delete {
        fs::remove_file(d).map_err(|e| format!("{}: {e}", d.display()))?;
    }
    progress("Updating: complete", Some(100.0));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;

    /// A verifier that counts its calls and takes `delay` to answer.
    fn counted(calls: &AtomicUsize, delay: Duration, result: TokenCheck) -> impl FnOnce(&str) -> TokenCheck + '_ {
        move |_: &str| {
            calls.fetch_add(1, Ordering::SeqCst);
            thread::sleep(delay);
            result
        }
    }

    #[test]
    fn concurrent_and_recent_token_checks_share_one_request() {
        let checks = TokenChecks::new();
        let calls = AtomicUsize::new(0);
        let delay = Duration::from_millis(300);
        thread::scope(|s| {
            let startup = s.spawn(|| checks.check("t", TOKEN_CHECK_REUSE, counted(&calls, delay, TokenCheck::Valid)));
            thread::sleep(Duration::from_millis(50));
            let start = checks.check("t", TOKEN_CHECK_REUSE, counted(&calls, delay, TokenCheck::Valid));
            assert_eq!(start, TokenCheck::Valid);
            assert_eq!(startup.join().unwrap(), TokenCheck::Valid);
        });
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // Right after a successful check, the result is reused.
        assert_eq!(checks.check("t", TOKEN_CHECK_REUSE, |_| panic!("not reused")), TokenCheck::Valid);
        // A different token is checked on its own.
        assert_eq!(checks.check("other", TOKEN_CHECK_REUSE, counted(&calls, Duration::ZERO, TokenCheck::Valid)), TokenCheck::Valid);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        // Once the reuse window has passed, the token is checked again.
        assert_eq!(checks.check("other", Duration::ZERO, counted(&calls, Duration::ZERO, TokenCheck::Valid)), TokenCheck::Valid);
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn only_valid_token_checks_are_reused() {
        let checks = TokenChecks::new();
        let calls = AtomicUsize::new(0);
        for result in [TokenCheck::Expired, TokenCheck::Unknown] {
            assert_eq!(checks.check("t", TOKEN_CHECK_REUSE, counted(&calls, Duration::ZERO, result)), result);
        }
        assert_eq!(checks.check("t", TOKEN_CHECK_REUSE, counted(&calls, Duration::ZERO, TokenCheck::Valid)), TokenCheck::Valid);
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn waiters_share_an_unsuccessful_in_flight_result() {
        let checks = TokenChecks::new();
        let calls = AtomicUsize::new(0);
        thread::scope(|s| {
            let first = s.spawn(|| checks.check("t", TOKEN_CHECK_REUSE, counted(&calls, Duration::from_millis(300), TokenCheck::Unknown)));
            thread::sleep(Duration::from_millis(50));
            assert_eq!(checks.check("t", TOKEN_CHECK_REUSE, |_| panic!("joined check repeated")), TokenCheck::Unknown);
            assert_eq!(first.join().unwrap(), TokenCheck::Unknown);
        });
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn replaced_token_is_not_answered_by_the_old_check() {
        let checks = TokenChecks::new();
        let calls = AtomicUsize::new(0);
        thread::scope(|s| {
            let old = s.spawn(|| checks.check("old", TOKEN_CHECK_REUSE, counted(&calls, Duration::from_millis(300), TokenCheck::Valid)));
            thread::sleep(Duration::from_millis(50));
            // The saved token is replaced while the old check is in flight.
            checks.forget();
            assert_eq!(checks.check("new", TOKEN_CHECK_REUSE, counted(&calls, Duration::ZERO, TokenCheck::Expired)), TokenCheck::Expired);
            assert_eq!(old.join().unwrap(), TokenCheck::Valid);
        });
        // The old token's late Valid result was not published for later callers.
        assert_eq!(checks.check("old", TOKEN_CHECK_REUSE, counted(&calls, Duration::ZERO, TokenCheck::Expired)), TokenCheck::Expired);
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn forgetting_releases_waiters_to_check_again() {
        let checks = TokenChecks::new();
        let calls = AtomicUsize::new(0);
        thread::scope(|s| {
            let first = s.spawn(|| checks.check("t", TOKEN_CHECK_REUSE, counted(&calls, Duration::from_millis(400), TokenCheck::Valid)));
            let waiter = s.spawn(|| {
                thread::sleep(Duration::from_millis(50));
                checks.check("t", TOKEN_CHECK_REUSE, counted(&calls, Duration::ZERO, TokenCheck::Expired))
            });
            thread::sleep(Duration::from_millis(150));
            checks.forget();
            assert_eq!(waiter.join().unwrap(), TokenCheck::Expired);
            assert_eq!(first.join().unwrap(), TokenCheck::Valid);
        });
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    fn manifest_file(size: Option<u64>, hash: &str, check_hash: bool, force_delete: bool) -> ManifestFile {
        ManifestFile {
            local_path: "f.bin".into(),
            path: Some("/f.bin".into()),
            size,
            hash: Some(hash.into()),
            force_delete_flg: force_delete,
            check_hash_flg: check_hash,
            protected_flg: false,
        }
    }

    #[test]
    fn update_scan_queues_size_mismatches_without_hashing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f.bin");
        fs::write(&path, b"0123456789").unwrap();
        let mut buf = vec![0; 64];
        let hash = md5_file(&path, &mut buf).unwrap();
        let md5 = |p: &Path| md5_file(p, &mut vec![0; 64]);
        let no_read = |_: &Path| -> Result<String, String> { panic!("file was read") };

        // Truncated: the size differs, so it is queued without reading.
        assert_eq!(file_action(&manifest_file(Some(20), &hash, true, false), &path, no_read), Ok(FileAction::Download));
        // Intact.
        assert_eq!(file_action(&manifest_file(Some(10), &hash, true, false), &path, md5), Ok(FileAction::Keep));
        // Same size but corrupt: found by hashing.
        let hashed = AtomicUsize::new(0);
        let counted_md5 = |p: &Path| { hashed.fetch_add(1, Ordering::SeqCst); md5(p) };
        let other = "0".repeat(32);
        assert_eq!(file_action(&manifest_file(Some(10), &other, true, false), &path, counted_md5), Ok(FileAction::Download));
        assert_eq!(hashed.load(Ordering::SeqCst), 1);
        // No size in the manifest: still hashed.
        assert_eq!(file_action(&manifest_file(None, &hash, true, false), &path, md5), Ok(FileAction::Keep));
        assert_eq!(file_action(&manifest_file(None, &other, true, false), &path, md5), Ok(FileAction::Download));
        // Not hash-checked: kept as before, even with a different size.
        assert_eq!(file_action(&manifest_file(Some(20), &other, false, false), &path, no_read), Ok(FileAction::Keep));
        // Force delete.
        assert_eq!(file_action(&manifest_file(Some(10), &hash, true, true), &path, no_read), Ok(FileAction::Delete));
        let missing = dir.path().join("missing.bin");
        assert_eq!(file_action(&manifest_file(Some(10), &hash, true, true), &missing, no_read), Ok(FileAction::Keep));
        assert_eq!(file_action(&manifest_file(Some(10), &hash, true, false), &missing, no_read), Ok(FileAction::Download));
    }

    #[test]
    fn vpngate_list_refresh_honors_cache_age() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path().to_path_buf()).unwrap();
        let downloads = AtomicUsize::new(0);
        let fetch = |body: &'static str| {
            let downloads = &downloads;
            move || {
                downloads.fetch_add(1, Ordering::SeqCst);
                Ok(body.to_string())
            }
        };

        // Missing cache: downloaded once, then fresh for the next refreshes (a quick restart).
        assert_eq!(store.refresh_vpngate_list_with(VPNGATE_RECENT, fetch("first")), Ok("first".into()));
        assert_eq!(store.refresh_vpngate_list_with(VPNGATE_RECENT, fetch("second")), Ok("first".into()));
        assert_eq!(store.refresh_vpngate_list_with(VPNGATE_RECENT, fetch("second")), Ok("first".into()));
        assert_eq!(downloads.load(Ordering::SeqCst), 1);

        // Expired cache whose refresh fails: the error is reported and the stale list is kept for fallback.
        let failed = store.refresh_vpngate_list_with(Duration::ZERO, || Err("offline".into()));
        assert!(failed.unwrap_err().contains("offline"));
        assert_eq!(store.cached_vpngate_list().as_deref(), Some("first"));

        // Expired cache: downloaded again.
        assert_eq!(store.refresh_vpngate_list_with(Duration::ZERO, fetch("second")), Ok("second".into()));
        assert_eq!(downloads.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn overlapping_vpngate_refreshes_share_one_download() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path().to_path_buf()).unwrap();
        let downloads = AtomicUsize::new(0);
        let fetch = || {
            downloads.fetch_add(1, Ordering::SeqCst);
            thread::sleep(Duration::from_millis(200));
            Ok("list".to_string())
        };
        thread::scope(|s| {
            let startup = s.spawn(|| store.refresh_vpngate_list_with(VPNGATE_RECENT, fetch));
            thread::sleep(Duration::from_millis(50));
            assert_eq!(store.refresh_vpngate_list_with(VPNGATE_RECENT, fetch), Ok("list".into()));
            assert_eq!(startup.join().unwrap(), Ok("list".into()));
        });
        assert_eq!(downloads.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn terms_confirmation_is_checked_and_not_repeated() {
        let mut attempted = false;
        assert!(confirm_terms_once(&mut attempted, || Ok(json!({ "result_code": 100 }))).is_ok());
        assert!(confirm_terms_once(&mut attempted, || panic!("repeated confirmation")).is_err());

        let mut attempted = false;
        let error = confirm_terms_once(&mut attempted, || Ok(json!({ "result_code": 308 }))).unwrap_err();
        assert!(error.contains("result_code 308"));
        assert!(attempted);
    }

    #[test]
    fn mygames_distinguishes_empty_lists_and_profile_errors() {
        assert_eq!(mygames_contains_game(&json!({ "result_code": 100, "data": [] })), Ok(false));
        assert_eq!(mygames_contains_game(&json!({
            "result_code": 100, "data": [{ "product_id": PRODUCT_ID }],
        })), Ok(true));
        assert_eq!(mygames_contains_game(&json!({ "result_code": 313 })), Err(PROFILE_REGISTRATION_REQUIRED.into()));
        assert!(mygames_contains_game(&json!({ "result_code": 100 })).is_err());
        assert!(mygames_contains_game(&json!({ "result_code": 203, "data": [] })).is_err());
    }

    #[test]
    fn resolves_windows_style_paths_into_nested_paths() {
        let root = Path::new("/gameras");
        let p = resolve_game_path(root, r"gakumas_Data\Octo\1\4131323131").unwrap();
        assert_eq!(
            p,
            root.join("gakumas_Data").join("Octo").join("1").join("4131323131")
        );
        // Forward slashes and leading separators work too.
        assert_eq!(
            resolve_game_path(root, "/gakumas_Data/Octo/file.bin").unwrap(),
            root.join("gakumas_Data").join("Octo").join("file.bin")
        );
        // Parent-directory escapes are still rejected.
        assert!(resolve_game_path(root, r"..\outside").is_none());
    }

    fn manifest_server(
        pages: Vec<(&'static str, Value)>,
    ) -> (tauri::Url, std::thread::JoinHandle<()>) {
        use std::io::{BufRead, BufReader};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/manifest?revision=1", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        let server = std::thread::spawn(move || {
            // Every page must use the same HTTP/1.1 connection.
            let (stream, _) = listener.accept().unwrap();
            drop(listener);
            stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            let mut stream = BufReader::new(stream);
            for (target, response) in pages {
                let mut line = String::new();
                stream.read_line(&mut line).unwrap();
                assert_eq!(line, format!("GET {target} HTTP/1.1\r\n"));
                loop {
                    line.clear();
                    assert_ne!(stream.read_line(&mut line).unwrap(), 0);
                    if line == "\r\n" {
                        break;
                    }
                }
                let response = response.to_string();
                write!(
                    stream.get_mut(),
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{response}",
                    response.len()
                ).unwrap();
            }
        });
        (url, server)
    }

    #[test]
    fn manifest_loads_all_pages_over_one_connection() {
        let (url, server) = manifest_server(vec![
            ("/manifest?revision=1", json!({"result_code": 100, "data": {
                "domain": "https://cdn.example/", "page": 2,
                "file_list": [{"local_path": "new.bin", "path": "/new.bin"}]
            }})),
            ("/manifest?revision=1&page=2", json!({"data": {
                "file_list": [{"local_path": "old.bin", "force_delete_flg": true}]
            }})),
        ]);
        let agent = ureq::AgentBuilder::new().try_proxy_from_env(false).build();
        let root = Path::new("game");
        let (domain, files) = load_manifest(&agent, &url, root).unwrap();
        server.join().unwrap();
        assert_eq!(domain, "https://cdn.example/");
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].1, root.join("new.bin"));
        assert!(files[1].0.force_delete_flg);
    }

    #[test]
    fn manifest_rejects_a_missing_list_or_invalid_file_on_a_later_page() {
        for data in [
            json!({}),
            json!({"file_list": [{"local_path": "new.bin", "path": "new.bin", "check_hash_flg": true}]}),
        ] {
            let (url, server) = manifest_server(vec![
                ("/manifest?revision=1", json!({"data": {
                    "domain": "https://cdn.example/", "page": 2, "file_list": []
                }})),
                ("/manifest?revision=1&page=2", json!({"data": data})),
            ]);
            let agent = ureq::AgentBuilder::new().try_proxy_from_env(false).build();
            let result = load_manifest(&agent, &url, Path::new("game"));
            server.join().unwrap();
            assert!(matches!(result, Err(message) if message.contains("manifest page 2")));
        }
    }
}
