//! Local HTTP CONNECT proxy forwarding WebView traffic through the in-app VPN tunnel.
//! Each operation fetches the current shared tunnel, so a dead session can be
//! rotated to a different VPN Gate server without restarting the proxy.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::launcher;
use crate::netstack::TunnelStack;

pub struct BrowserProxy {
    pub port: u16,
}

impl BrowserProxy {
    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }
}

/// Rate-limited error logging: the browser opens dozens of connections and a
/// dead tunnel would otherwise produce hundreds of identical lines.
static LAST_ERROR: OnceLock<Mutex<(String, Instant)>> = OnceLock::new();

fn log_error(msg: &str) {
    let cell = LAST_ERROR.get_or_init(|| Mutex::new((String::new(), Instant::now())));
    let mut guard = cell.lock().unwrap();
    let now = Instant::now();
    if guard.0 != msg || now.duration_since(guard.1) > Duration::from_secs(3) {
        launcher::netlog(&format!("[proxy] {msg}"));
        guard.0 = msg.to_string();
        guard.1 = now;
    }
}

fn is_dead(e: &str) -> bool {
    e.contains("VPN server closed the connection")
        || e.contains("Broken pipe")
        || e.contains("no A record")
        || e.contains("DNS error code")
        || e.contains("TCP connect timed out")
        || e.contains("VPN send")
}

/// Run an operation on the current shared tunnel; on a dead-session error,
/// rotate to a different VPN server and retry once.
fn with_tunnel<T>(mut op: impl FnMut(&Mutex<TunnelStack>) -> Result<T, String>) -> Result<T, String> {
    let stack = launcher::current_tunnel().ok_or("No VPN tunnel available")?;
    match op(&stack) {
        Ok(v) => Ok(v),
        Err(e) if is_dead(&e) => {
            log_error(&e);
            launcher::netlog("Reconnecting to a different VPN server...");
            let stack = launcher::rotate_tunnel()?;
            op(&stack)
        }
        Err(e) => Err(e),
    }
}

pub fn start(store: &launcher::Store, mode: &str) -> Result<BrowserProxy, String> {
    launcher::shared_tunnel(store, mode, &|m, _| launcher::netlog(m))?;
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    launcher::netlog(&format!("Browser proxy listening on 127.0.0.1:{port}"));

    std::thread::spawn(move || loop {
        if let Some(stack) = launcher::current_tunnel() {
            if let Ok(mut guard) = stack.lock() {
                if let Err(e) = guard.keepalive() {
                    if is_dead(&e) {
                        log_error(&e);
                        let _ = launcher::rotate_tunnel();
                    }
                }
            }
        }
        std::thread::sleep(Duration::from_millis(500));
    });

    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || {
                if let Err(e) = handle(stream) {
                    log_error(&e);
                }
            });
        }
    });
    Ok(BrowserProxy { port })
}

fn handle(mut client: TcpStream) -> Result<(), String> {
    let _ = client.set_read_timeout(Some(Duration::from_millis(10)));
    let _ = client.set_write_timeout(Some(Duration::from_secs(10)));

    let mut request = Vec::new();
    let mut b = [0u8; 1];
    while request.len() < 8192 {
        match client.read(&mut b) {
            Ok(0) => return Err("client closed".into()),
            Ok(_) => {
                request.push(b[0]);
                if request.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut || e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e.to_string()),
        }
    }
    let first = String::from_utf8_lossy(&request);
    let first = first.lines().next().unwrap_or("");
    let mut it = first.split_whitespace();
    if it.next() != Some("CONNECT") {
        client.write_all(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n").ok();
        return Ok(());
    }
    let target = it.next().unwrap_or("");
    let (host, port) = target.rsplit_once(':').ok_or("bad CONNECT target")?;
    let port: u16 = port.parse::<u16>().map_err(|e| e.to_string())?;

    launcher::netlog(&format!("CONNECT {host}:{port}"));

    let handle = with_tunnel(|s| {
        let mut guard = s.lock().map_err(|e| e.to_string())?;
        guard.tcp_open(host, port, Duration::from_secs(30))
    })?;

    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .map_err(|e| e.to_string())?;

    let mut buf = [0u8; 65536];
    let result = loop {
        // Drain client -> tunnel without blocking for long.
        match client.read(&mut buf) {
            Ok(0) => break Ok(()),
            Ok(n) => {
                let mut sent = 0;
                while sent < n {
                    let written = with_tunnel(|s| {
                        let mut guard = s.lock().map_err(|e| e.to_string())?;
                        guard.tcp_send(handle, &buf[sent..n])
                    })?;
                    if written == 0 {
                        std::thread::sleep(Duration::from_millis(1));
                    } else {
                        sent += written;
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut || e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => break Err(e.to_string()),
        }

        // Drain ALL available tunnel data before waiting on the client again.
        // One recv per loopiteration with a 100 ms client timeout is what made
        // page loads crawl when many resources were fetched in parallel.
        loop {
            let got = with_tunnel(|s| {
                let mut guard = s.lock().map_err(|e| e.to_string())?;
                guard.tcp_recv(handle, &mut buf)
            })?;
            if got == 0 {
                break;
            }
            if client.write_all(&buf[..got]).is_err() {
                break;
            }
        }
    };

    if let Some(stack) = launcher::current_tunnel() {
        if let Ok(mut guard) = stack.lock() {
            guard.tcp_close(handle);
        }
    }
    result
}
