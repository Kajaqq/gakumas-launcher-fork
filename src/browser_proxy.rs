//! Local HTTP CONNECT proxy forwarding WebView traffic through the in-app VPN tunnel.
//! The tunnel mutex is held only for each short smoltcp operation, so the
//! keepalive thread can run between them and keep the VPN session alive.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

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

pub fn start(store: &launcher::Store, mode: &str) -> Result<BrowserProxy, String> {
    let stack = Arc::new(Mutex::new(launcher::open_tunnel_stack(store, mode)?));
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();

    let keepalive_stack = Arc::clone(&stack);
    std::thread::spawn(move || loop {
        if let Ok(mut guard) = keepalive_stack.lock() {
            let _ = guard.keepalive();
        }
        std::thread::sleep(Duration::from_millis(500));
    });

    let shared = Arc::clone(&stack);
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let stack = Arc::clone(&shared);
            std::thread::spawn(move || {
                if let Err(e) = handle(stream, stack) {
                    eprintln!("[proxy] {e}");
                }
            });
        }
    });
    Ok(BrowserProxy { port })
}

fn handle(mut client: TcpStream, stack: Arc<Mutex<TunnelStack>>) -> Result<(), String> {
    let _ = client.set_read_timeout(Some(Duration::from_millis(100)));
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

    let handle = {
        let mut guard = stack.lock().map_err(|e| e.to_string())?;
        guard.tcp_open(host, port, Duration::from_secs(30))?
    };

    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .map_err(|e| e.to_string())?;

    let mut buf = [0u8; 16384];
    let result = loop {
        match client.read(&mut buf) {
            Ok(0) => break Ok(()),
            Ok(n) => {
                let mut sent = 0;
                while sent < n {
                    let written = {
                        let mut guard = stack.lock().map_err(|e| e.to_string())?;
                        guard.tcp_send(handle, &buf[sent..n])?
                    };
                    if written == 0 {
                        std::thread::sleep(Duration::from_millis(2));
                    } else {
                        sent += written;
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut || e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => break Err(e.to_string()),
        }

        let got = {
            let mut guard = stack.lock().map_err(|e| e.to_string())?;
            guard.tcp_recv(handle, &mut buf)?
        };
        if got > 0 {
            if let Err(e) = client.write_all(&buf[..got]) {
                break Err(e.to_string());
            }
        } else {
            std::thread::sleep(Duration::from_millis(2));
        }
    };

    if let Ok(mut guard) = stack.lock() {
        guard.tcp_close(handle);
    }
    result
}
