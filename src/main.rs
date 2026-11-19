//! 학원 아이돌마스터 런처 (UI)
//!
//! 로그인은 프로그램 안의 WebView2 창에서 사용자가 직접 합니다. 로그인 상태와(사용자가 저장을 고르면)
//! 비밀번호는 WebView2 가 이 프로그램 전용 데이터 폴더에 보관하므로, 보통은 창 없이 자동으로 지나갑니다.
//! 이 코드는 비밀번호를 읽거나 대신 입력·제출하지 않습니다.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Mutex};
use std::time::Duration;

use gakumas_launcher::launcher::{self, Status, Store};
use serde::Serialize;
use serde_json::{json, Value};
use tauri::{AppHandle, Emitter, Manager, WebviewUrl, WebviewWindowBuilder};
use tauri_plugin_dialog::DialogExt;

/// Register a desktop entry and icon so Wayland compositors show the app icon
/// instead of a generic one. The GTK app id comes from `enableGTKAppId` in
/// tauri.conf.json and must match this desktop file's name/StartupWMClass.
#[cfg(not(windows))]
fn install_desktop_entry() {
    const APP_ID: &str = "local.gakumas.launcher";
    let Some(home) = std::env::var_os("HOME") else {
        return;
    };
    let home = PathBuf::from(home);
    let applications = home.join(".local/share/applications");
    let icons_root = home.join(".local/share/icons/hicolor");
    if std::fs::create_dir_all(&applications).is_err()
        || std::fs::create_dir_all(&icons_root).is_err()
    {
        return;
    }
    let mut changed = false;

    // A user-level hicolor tree needs its own index.theme to be discoverable.
    let index = icons_root.join("index.theme");
    if !index.exists() {
        changed = true;
        let _ = std::fs::write(
            &index,
            "[Icon Theme]\nName=Hicolor\nComment=Fallback icon theme\nDirectories=16x16/apps,32x32/apps,48x48/apps,64x64/apps,128x128/apps,256x256/apps,512x512/apps\n\n[16x16/apps]\nSize=16\nType=Application\n\n[32x32/apps]\nSize=32\nType=Application\n\n[48x48/apps]\nSize=48\nType=Application\n\n[64x64/apps]\nSize=64\nType=Application\n\n[128x128/apps]\nSize=128\nType=Application\n\n[256x256/apps]\nSize=256\nType=Application\n\n[512x512/apps]\nSize=512\nType=Application\n",
        );
    }

    // Taskbars request small icons; a single 512px entry can fall back to the
    // generic icon, so install the standard sizes from the embedded PNG.
    for size in [16, 32, 48, 64, 128, 256, 512] {
        let dir = icons_root.join(format!("{size}x{size}/apps"));
        if std::fs::create_dir_all(&dir).is_err() {
            continue;
        }
        let path = dir.join(format!("{APP_ID}.png"));
        if path.exists() {
            continue;
        }
        // GTK scales the source image to the size declared in index.theme.
        let _ = std::fs::write(&path, include_bytes!("../icons/icon.png"));
    }

    let desktop = applications.join(format!("{APP_ID}.desktop"));
    if let Ok(exe) = std::env::current_exe() {
        let exec = exe.to_string_lossy().replace('\\', "\\\\").replace('"', "\\\"");
        let contents = format!(
            "[Desktop Entry]\nType=Application\nName=Gakumas Launcher\nExec=\"{exec}\"\nIcon={APP_ID}\nStartupWMClass={APP_ID}\nTerminal=false\nCategories=Game;\n"
        );
        let same = std::fs::read_to_string(&desktop)
            .map(|s| s == contents)
            .unwrap_or(false);
        if !same {
            changed = true;
            let _ = std::fs::write(&desktop, contents);
        }
    }

    if changed {
        let _ = std::process::Command::new("gtk-update-icon-cache")
            .arg("-f")
            .arg("-t")
            .arg(&icons_root)
            .status();
        let _ = std::process::Command::new("update-desktop-database")
            .arg(&applications)
            .status();
    }
}

#[cfg(windows)]
fn install_desktop_entry() {}

/// Status returned on platforms without Proton support, with the same keys.
fn proton_unavailable() -> Value {
    json!({
        "available": false,
        "proton": "",
        "prefix": "",
        "prefix_exists": false,
        "deps_installed": false,
        "candidates": [],
    })
}

struct AppState {
    store: Store,
    busy: Mutex<bool>,
    /// 이번 실행에서 아직 자동 시작을 하지 않았는지 (프로그램을 켤 때 한 번만)
    auto_start_pending: Mutex<bool>,
    /// 진행 중에도 닫겠다고 확인했는지
    force_close: AtomicBool,
}

#[derive(Clone, Serialize)]
struct ProgressEvent {
    message: String,
    percent: Option<f32>,
}

fn emit_progress(app: &AppHandle, message: &str, percent: Option<f32>) {
    let _ = app.emit(
        "progress",
        ProgressEvent {
            message: message.to_string(),
            percent,
        },
    );
}

static LOGIN_SEQ: AtomicUsize = AtomicUsize::new(0);
/// 로그인이 끝나면 이 주소로 넘어가며 code 를 넘겨줌 (원래는 DMM 플레이어를 여는 페이지)
const LOGIN_SUCCESS_HOST: &str = "webdgp-gameplayer.games.dmm.com";

/// 로그인 창을 띄워 로그인 완료 주소의 code 를 받아 옴.
/// 저장된 로그인 상태로 바로 지나가면 창을 보이지 않은 채로 끝남
fn login_window(app: &AppHandle, url: &str) -> Result<String, String> {
    let target: tauri::Url = url.parse().map_err(|e| format!("Invalid login URL: {e}"))?;
    let (tx, rx) = mpsc::channel::<Option<String>>();
    let tx_nav = tx.clone();
    let label = format!("login{}", LOGIN_SEQ.fetch_add(1, Ordering::SeqCst));
    let win = WebviewWindowBuilder::new(app, &label, WebviewUrl::External(target))
        .title("DMM Login")
        .inner_size(480.0, 760.0)
        .center()
        .visible(false)
        .initialization_script(include_str!("keep_login.js"))
        .on_navigation(move |u| {
            if u.host_str() == Some(LOGIN_SUCCESS_HOST) && u.path().starts_with("/login/success") {
                let code = u
                    .query_pairs()
                    .find(|(k, _)| k == "code")
                    .map(|(_, v)| v.into_owned());
                let _ = tx_nav.send(code);
                return false; // 완료 페이지는 열지 않음 (DMM 플레이어 호출 방지)
            }
            true
        })
        .build()
        .map_err(|e| format!("Failed to open the login window: {e}"))?;
    enable_password_autosave(&win);
    let tx_close = tx.clone();
    win.on_window_event(move |e| {
        if let tauri::WindowEvent::Destroyed = e {
            let _ = tx_close.send(None);
        }
    });
    drop(tx);

    let code = match rx.recv_timeout(Duration::from_secs(6)) {
        Ok(c) => c,
        Err(mpsc::RecvTimeoutError::Timeout) => {
            emit_progress(app, "Please sign in in the login window", None);
            let _ = win.show();
            let _ = win.set_focus();
            rx.recv_timeout(Duration::from_secs(900)).ok().flatten()
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => None,
    };
    let _ = win.close();
    code.ok_or_else(|| "Login was cancelled".to_string())
}

/// Enable the browser's own password save / autofill in the login window (WebView2 default is off).
/// On Linux WebView2 is not used, so this is a no-op.
#[cfg(windows)]
fn enable_password_autosave(win: &tauri::WebviewWindow) {
    use webview2_com::Microsoft::Web::WebView2::Win32::ICoreWebView2Settings4;
    use windows_core::Interface;
    let _ = win.with_webview(|wv| unsafe {
        let Ok(core) = wv.controller().CoreWebView2() else {
            return;
        };
        let Ok(settings) = core.Settings() else {
            return;
        };
        if let Ok(s4) = settings.cast::<ICoreWebView2Settings4>() {
            let _ = s4.SetIsPasswordAutosaveEnabled(true);
            let _ = s4.SetIsGeneralAutofillEnabled(true);
        }
    });
}

#[cfg(not(windows))]
fn enable_password_autosave(_win: &tauri::WebviewWindow) {}

async fn run_busy<F>(app: AppHandle, f: F) -> Result<String, String>
where
    F: FnOnce(&AppHandle, &Store) -> Result<String, String> + Send + 'static,
{
    {
        let state = app.state::<AppState>();
        let mut busy = state.busy.lock().unwrap();
        if *busy {
            return Err("An operation is already in progress".into());
        }
        *busy = true;
    }
    let worker = app.clone();
    let result = tauri::async_runtime::spawn_blocking(move || {
        let state = worker.state::<AppState>();
        f(&worker, &state.store)
    })
    .await
    .map_err(|e| e.to_string())
    .and_then(|r| r);
    *app.state::<AppState>().busy.lock().unwrap() = false;
    result
}

#[tauri::command]
fn get_status(state: tauri::State<'_, AppState>) -> Status {
    state.store.status()
}

#[tauri::command]
fn set_mode(state: tauri::State<'_, AppState>, mode: String) -> Result<Status, String> {
    if ![
        launcher::MODE_VPNGATE,
        launcher::MODE_DIRECT,
        launcher::MODE_FILE,
    ]
    .contains(&mode.as_str())
    {
        return Err("Unknown connection mode".into());
    }
    let mut s = state.store.settings();
    s.mode = mode;
    state.store.save_settings(&s)?;
    Ok(state.store.status())
}

#[tauri::command]
fn set_auto_start(state: tauri::State<'_, AppState>, enabled: bool) -> Result<Status, String> {
    let mut s = state.store.settings();
    s.auto_start = enabled;
    state.store.save_settings(&s)?;
    Ok(state.store.status())
}

#[tauri::command]
fn set_close_after_launch(
    state: tauri::State<'_, AppState>,
    enabled: bool,
) -> Result<Status, String> {
    let mut s = state.store.settings();
    s.close_after_launch = enabled;
    state.store.save_settings(&s)?;
    Ok(state.store.status())
}

/// 자동 시작을 해야 하면 true (프로그램을 켠 뒤 첫 호출에서만)
#[tauri::command]
fn take_auto_start(state: tauri::State<'_, AppState>) -> bool {
    std::mem::take(&mut *state.auto_start_pending.lock().unwrap())
}

/// Windows 폴더 선택 창으로 게임 폴더 지정
#[tauri::command]
async fn pick_game_folder(app: AppHandle, window: tauri::Window) -> Result<Status, String> {
    let current = app.state::<AppState>().store.settings().game_path;
    let dialog_app = app.clone();
    let picked = tauri::async_runtime::spawn_blocking(move || {
        let mut d = dialog_app
            .dialog()
            .file()
            .set_title("Select game folder")
            .set_parent(&window);
        if let Some(p) = current {
            d = d.set_directory(p);
        }
        d.blocking_pick_folder()
    })
    .await
    .map_err(|e| e.to_string())?;

    let state = app.state::<AppState>();
    let Some(picked) = picked else {
        return Ok(state.store.status());
    };
    let path: PathBuf = picked.into_path().map_err(|e| e.to_string())?;
    // An empty folder is valid: the launcher downloads the game files on
    // first start, so no executable needs to exist here yet.
    let mut s = state.store.settings();
    let path = path.to_string_lossy().into_owned();
    if s.game_path.as_deref() != Some(path.as_str()) {
        s.game_path = Some(path);
        s.installed_version = None; // 새 폴더는 버전을 모르므로 다음 실행 때 파일 전체 검사
        state.store.save_settings(&s)?;
    }
    Ok(state.store.status())
}

/// Choose a replacement game executable (e.g. a Proton-tuned build).
#[tauri::command]
async fn pick_game_exe(app: AppHandle, window: tauri::Window) -> Result<Status, String> {
    let current = app.state::<AppState>().store.settings().game_exe_override;
    let dialog_app = app.clone();
    let picked = tauri::async_runtime::spawn_blocking(move || {
        let mut d = dialog_app
            .dialog()
            .file()
            .set_title("Select game executable")
            .set_parent(&window);
        if let Some(p) = current {
            if let Some(parent) = PathBuf::from(&p).parent() {
                d = d.set_directory(parent);
            }
        }
        d.blocking_pick_file()
    })
    .await
    .map_err(|e| e.to_string())?;

    let state = app.state::<AppState>();
    let Some(picked) = picked else {
        return Ok(state.store.status());
    };
    let path: PathBuf = picked.into_path().map_err(|e| e.to_string())?;
    if !path.is_file() {
        return Err(format!("File not found: {}", path.display()));
    }
    let mut s = state.store.settings();
    s.game_exe_override = Some(path.to_string_lossy().into_owned());
    state.store.save_settings(&s)?;
    Ok(state.store.status())
}

/// Go back to the executable named in the DMM launch response.
#[tauri::command]
fn clear_game_exe(state: tauri::State<'_, AppState>) -> Result<Status, String> {
    let mut s = state.store.settings();
    s.game_exe_override = None;
    state.store.save_settings(&s)?;
    Ok(state.store.status())
}

/// VPN 설정 파일(.ovpn / WireGuard .conf) 선택
#[tauri::command]
async fn pick_vpn_file(app: AppHandle, window: tauri::Window) -> Result<Status, String> {
    let dialog_app = app.clone();
    let picked = tauri::async_runtime::spawn_blocking(move || {
        dialog_app
            .dialog()
            .file()
            .set_title("Select VPN config file")
            .add_filter("VPN config files", &["ovpn", "conf"])
            .set_parent(&window)
            .blocking_pick_file()
    })
    .await
    .map_err(|e| e.to_string())?;
    let state = app.state::<AppState>();
    let Some(picked) = picked else {
        return Ok(state.store.status());
    };
    let path: PathBuf = picked.into_path().map_err(|e| e.to_string())?;
    state.store.import_vpn_file(&path)?;
    Ok(state.store.status())
}

/// VPN 아이디·비밀번호 저장 (사용자가 화면에 직접 입력한 값, DPAPI 로 암호화)
#[tauri::command]
fn set_vpn_auth(
    state: tauri::State<'_, AppState>,
    username: String,
    password: String,
) -> Result<Status, String> {
    if username.trim().is_empty() || password.is_empty() {
        return Err("Please enter both a username and password".into());
    }
    state.store.save_vpn_auth(username.trim(), &password)?;
    Ok(state.store.status())
}

#[tauri::command]
async fn start_game(app: AppHandle) -> Result<String, String> {
    let result = run_busy(app.clone(), |app, store| {
        let progress = |m: &str, p: Option<f32>| emit_progress(app, m, p);
        let get_code = |url: &str| login_window(app, url);
        launcher::start_game(store, &get_code, &progress, true)
    })
    .await;
    // 게임이 실행됐고 '게임 실행 후 런처 종료'가 켜져 있으면 런처를 닫음
    if result.is_ok() && app.state::<AppState>().store.settings().close_after_launch {
        app.exit(0);
    }
    result
}

#[tauri::command]
async fn login(app: AppHandle) -> Result<String, String> {
    run_busy(app, |app, store| {
        let progress = |m: &str, p: Option<f32>| emit_progress(app, m, p);
        let get_code = |url: &str| login_window(app, url);
        launcher::login(store, &get_code, &progress).map(|_| "Logged in".to_string())
    })
    .await
}

#[tauri::command]
fn logout(app: AppHandle, state: tauri::State<'_, AppState>) -> Result<Status, String> {
    if *state.busy.lock().unwrap() {
        return Err("Cannot log out while an operation is in progress".into());
    }
    state.store.clear_token()?;
    if let Some(w) = app.get_webview_window("main") {
        // 로그인 창과 같은 저장소를 쓰므로 DMM 로그인 상태와 저장된 비밀번호도 함께 지워짐
        w.clear_all_browsing_data()
            .map_err(|e| format!("Failed to clear the login data: {e}"))?;
    }
    Ok(state.store.status())
}

/// 저장된 로그인이 아직 유효한지 확인하고 상태를 돌려줌 (만료됐으면 로그아웃 상태로)
#[tauri::command]
async fn verify_login(app: AppHandle) -> Result<Status, String> {
    if *app.state::<AppState>().busy.lock().unwrap() {
        return Ok(app.state::<AppState>().store.status());
    }
    let worker = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let state = worker.state::<AppState>();
        launcher::verify_saved_token(&state.store)?;
        Ok(state.store.status())
    })
    .await
    .map_err(|e| e.to_string())?
}

/// 진행 중 닫기 확인 후 종료
#[tauri::command]
fn force_close(app: AppHandle, state: tauri::State<'_, AppState>) {
    state.force_close.store(true, Ordering::SeqCst);
    app.exit(0);
}

// ---------------------------------------------------------------------------
// Proton (Linux only). The commands exist on every platform so the UI can call
// them unconditionally; Windows returns an "unavailable" status / a clear error.
// ---------------------------------------------------------------------------

#[tauri::command]
fn get_proton_status(app: AppHandle) -> Value {
    #[cfg(not(windows))]
    {
        match app.path().app_local_data_dir() {
            Ok(base) => gakumas_launcher::proton::status(&base),
            Err(_) => proton_unavailable(),
        }
    }
    #[cfg(windows)]
    {
        let _ = app;
        proton_unavailable()
    }
}

#[tauri::command]
fn set_proton_path(app: AppHandle, path: String) -> Result<Value, String> {
    #[cfg(not(windows))]
    {
        let base = app.path().app_local_data_dir().map_err(|e| e.to_string())?;
        let state = app.state::<AppState>();
        gakumas_launcher::proton::set_path(&base, &state.store, &path)
    }
    #[cfg(windows)]
    {
        let _ = (app, path);
        Err("Proton settings are only available on Linux".into())
    }
}

#[tauri::command]
fn set_proton_prefix(app: AppHandle, path: String) -> Result<Value, String> {
    #[cfg(not(windows))]
    {
        let base = app.path().app_local_data_dir().map_err(|e| e.to_string())?;
        let state = app.state::<AppState>();
        gakumas_launcher::proton::set_prefix(&base, &state.store, &path)
    }
    #[cfg(windows)]
    {
        let _ = (app, path);
        Err("Proton settings are only available on Linux".into())
    }
}

#[tauri::command]
async fn proton_setup(app: AppHandle) -> Result<String, String> {
    #[cfg(not(windows))]
    {
        run_busy(app.clone(), |app, store| {
            let base = app.path().app_local_data_dir().map_err(|e| e.to_string())?;
            let progress = |m: &str, p: Option<f32>| emit_progress(app, m, p);
            gakumas_launcher::proton::setup(&base, store, &progress)
        })
        .await
    }
    #[cfg(windows)]
    {
        let _ = app;
        Err("Proton setup is only available on Linux".into())
    }
}

#[tauri::command]
async fn proton_install_dw(app: AppHandle) -> Result<String, String> {
    #[cfg(not(windows))]
    {
        run_busy(app.clone(), |app, store| {
            let base = app.path().app_local_data_dir().map_err(|e| e.to_string())?;
            let progress = |m: &str, p: Option<f32>| emit_progress(app, m, p);
            gakumas_launcher::proton::install_dw_proton(&base, store, &progress)
                .map(|v| v.to_string())
        })
        .await
    }
    #[cfg(windows)]
    {
        let _ = app;
        Err("Proton settings are only available on Linux".into())
    }
}

#[tauri::command]
async fn localify_install(app: AppHandle) -> Result<String, String> {
    #[cfg(not(windows))]
    {
        run_busy(app.clone(), |app, store| {
            let base = app.path().app_local_data_dir().map_err(|e| e.to_string())?;
            let progress = |m: &str, p: Option<f32>| emit_progress(app, m, p);
            gakumas_launcher::proton::install_localify(&base, store, &progress)
        })
        .await
    }
    #[cfg(windows)]
    {
        let _ = app;
        Err("Localify install is only available on Linux".into())
    }
}

/// 화면(작업 표시줄 제외)보다 창이 크면 높이를 줄여 화면 안에 들어오게 함.
/// 이때만 내용이 길면 스크롤이 생기고, 보통 화면에서는 기본 높이(스크롤 없음)를 그대로 씀
fn fit_to_screen(win: &tauri::WebviewWindow) {
    let Ok(Some(monitor)) = win.current_monitor() else {
        return;
    };
    let scale = monitor.scale_factor();
    let max_h = monitor.work_area().size.height as f64 / scale - 16.0;
    let Ok(size) = win.outer_size() else {
        return;
    };
    let (w, h) = (size.width as f64 / scale, size.height as f64 / scale);
    if h > max_h {
        let _ = win.set_size(tauri::LogicalSize::new(w, max_h.max(600.0)));
        let _ = win.center();
    }
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .on_window_event(|window, event| {
            // 업데이트 등이 진행 중이면 바로 닫지 않고 화면에서 확인을 받음
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                if window.label() == "main" {
                    if let Some(state) = window.try_state::<AppState>() {
                        if *state.busy.lock().unwrap() && !state.force_close.load(Ordering::SeqCst)
                        {
                            api.prevent_close();
                            let _ = window.emit("close-blocked", ());
                        }
                    }
                }
            }
        })
        .setup(|app| {
            install_desktop_entry();
            if let Some(win) = app.get_webview_window("main") {
                fit_to_screen(&win);
            }
            let dir = app.path().app_local_data_dir()?;
            // Share the real data dir with the platform layer, which has no AppHandle.
            std::env::set_var("GAKUMAS_BASE_DIR", &dir);
            let store = Store::new(dir.join("data"))?;
            let settings = store.settings();
            let vpngate_mode = settings.mode == launcher::MODE_VPNGATE;
            app.manage(AppState {
                store,
                busy: Mutex::new(false),
                auto_start_pending: Mutex::new(settings.auto_start),
                force_close: AtomicBool::new(false),
            });
            // 시작하자마자 VPN Gate 서버 목록을 새로 받아 둠 (게임 시작은 받는 동안에도 쓰쿠바대 서버로 먼저 시도)
            if vpngate_mode {
                let handle = app.handle().clone();
                std::thread::spawn(move || {
                    let _ = handle
                        .state::<AppState>()
                        .store
                        .refresh_vpngate_list(Duration::ZERO);
                });
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_status,
            set_mode,
            set_auto_start,
            set_close_after_launch,
            take_auto_start,
            pick_game_folder,
            pick_game_exe,
            clear_game_exe,
            pick_vpn_file,
            set_vpn_auth,
            start_game,
            login,
            logout,
            verify_login,
            force_close,
            get_proton_status,
            set_proton_path,
            set_proton_prefix,
            proton_setup,
            proton_install_dw,
            localify_install
        ])
        .run(tauri::generate_context!())
        .expect("error while running application");
}
