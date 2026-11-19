//! Loopback HTTPS CONNECT proxy. Header reads and DNS run outside the tunnel;
//! a single pump multiplexes every handshake and established stream on one stack.

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::launcher;
use crate::netstack::{resolve_v4, ProxyHandle, TunnelStack};

const MAX_CLIENTS: usize = 128;
const HEADER_LIMIT: usize = 16 * 1024;
const CHUNK: usize = 32 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(45);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const RETRY_DELAY: Duration = Duration::from_secs(3);
const ESTABLISHED: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";
const BAD: &str = "400 Bad Request";
const LARGE: &str = "431 Request Header Fields Too Large";
const GATEWAY: &str = "502 Bad Gateway";
const TIMEOUT: &str = "504 Gateway Timeout";
type Stack = Arc<Mutex<TunnelStack>>;

pub struct BrowserProxy {
    pub port: u16,
    stopped: Arc<AtomicBool>,
}

impl BrowserProxy {
    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }
}

impl Drop for BrowserProxy {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Release);
    }
}

fn log(msg: &str) {
    launcher::netlog(&format!("[proxy] {msg}"));
}

fn reject(client: &mut TcpStream, status: &str) {
    let allow = if status.starts_with("405") { "Allow: CONNECT\r\n" } else { "" };
    let _ = client.write_all(format!("HTTP/1.1 {status}\r\n{allow}Connection: close\r\nContent-Length: 0\r\n\r\n").as_bytes());
}

struct Request {
    host: String,
    port: u16,
    early: Vec<u8>,
}

fn parse(data: &[u8]) -> Result<Option<Request>, &'static str> {
    let mut headers = [httparse::EMPTY_HEADER; 96];
    let mut req = httparse::Request::new(&mut headers);
    let end = match req.parse(data) {
        Ok(httparse::Status::Complete(n)) if n <= HEADER_LIMIT => n,
        Ok(httparse::Status::Partial) if data.len() < HEADER_LIMIT => return Ok(None),
        Ok(_) | Err(httparse::Error::TooManyHeaders) => return Err(LARGE),
        Err(_) => return Err(BAD),
    };
    if req.method != Some("CONNECT") { return Err("405 Method Not Allowed"); }
    let (host, port) = req.path.and_then(|p| p.rsplit_once(':')).ok_or(BAD)?;
    // The user-space IP stack is IPv4. Accept DNS names and literal IPv4,
    // never URLs, userinfo or an implicit/default port.
    if host.is_empty() || host.len() > 253 || !host.bytes().all(|b| b.is_ascii_alphanumeric() || b".-_".contains(&b)) || !port.bytes().all(|b| b.is_ascii_digit()) { return Err(BAD); }
    let port = port.parse::<u16>().ok().filter(|p| *p != 0).ok_or(BAD)?;
    Ok(Some(Request { host: host.to_ascii_lowercase(), port, early: data[end..].to_vec() }))
}

fn read_request(client: &mut TcpStream, stopped: &AtomicBool) -> Result<Request, &'static str> {
    let mut data = Vec::new();
    let mut chunk = [0; 4096];
    let start = Instant::now();
    client.set_read_timeout(Some(Duration::from_millis(300))).map_err(|_| BAD)?;
    loop {
        if start.elapsed() >= Duration::from_secs(10) || stopped.load(Ordering::Acquire) { return Err("408 Request Timeout"); }
        match client.read(&mut chunk) {
            Ok(0) => return Err(BAD),
            Ok(n) => { data.extend_from_slice(&chunk[..n]); if let Some(req) = parse(&data)? { return Ok(req); } }
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted) => (),
            Err(_) => return Err(BAD),
        }
    }
}

struct Slot(Arc<AtomicUsize>);
impl Drop for Slot { fn drop(&mut self) { self.0.fetch_sub(1, Ordering::Relaxed); } }

struct Ready {
    client: TcpStream,
    request: Request,
    ip: Ipv4Addr,
    deadline: Instant,
    _slot: Slot,
}

impl Ready {
    fn expired(&self) -> bool { Instant::now() >= self.deadline }

    fn client_gone(&self) -> bool {
        match self.client.peek(&mut [0]) {
            Ok(0) => true,
            Ok(_) => false,
            Err(e) => !matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted),
        }
    }
}

fn prepare(mut client: TcpStream, stack: Stack, stopped: Arc<AtomicBool>, slot: Slot, tx: mpsc::Sender<Ready>) {
    let _ = client.set_write_timeout(Some(Duration::from_secs(1)));
    let request = match read_request(&mut client, &stopped) {
        Ok(r) => r, Err(status) => { reject(&mut client, status); return; }
    };
    let started = Instant::now();
    let cached = stack.try_lock().ok().and_then(|s| s.cached_ip(&request.host));
    let ip = match cached.map(Ok).unwrap_or_else(|| resolve_v4(&request.host)) {
        Ok(ip) => ip, Err(e) => { log(&format!("DNS failed: {e}")); reject(&mut client, GATEWAY); return; }
    };
    log(&format!("CONNECT {}:{} ({ip}; DNS {} ms)",request.host, request.port, started.elapsed().as_millis()));
    if client.set_nonblocking(true).is_ok() && !stopped.load(Ordering::Acquire) {
        let _ = client.set_nodelay(true);
        let _ = tx.send(Ready { client, request, ip, deadline: started + REQUEST_TIMEOUT, _slot: slot });
    }
}

#[derive(Default)]
struct Pending { bytes: Vec<u8>, offset: usize }
impl Pending {
    fn remaining(&self) -> &[u8] { &self.bytes[self.offset..] }
    fn advance(&mut self, n: usize) { self.offset += n; if self.offset == self.bytes.len() { self.bytes.clear(); self.offset = 0; } }
}

struct Flow {
    peer: Ready, handle: ProxyHandle, connected: bool,
    up: Pending, down: Pending, client_fin: bool, remote_fin: bool,
    started: Instant, progress: Instant, sent: usize, received: usize,
    established: Option<Instant>, first_down: Option<Duration>,
}

fn nonblocking(r: io::Result<usize>) -> Result<Option<usize>, String> {
    match r { Ok(n) => Ok(Some(n)), Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted) => Ok(None), Err(e) => Err(e.to_string()) }
}

impl Flow {
    fn new(mut peer: Ready, handle: ProxyHandle) -> Self {
        let early = std::mem::take(&mut peer.request.early);
        let now = Instant::now();
        Self { peer, handle, connected:false, up: Pending { bytes: early, offset: 0 }, down: Pending::default(), client_fin:false,remote_fin:false, started:now,progress:now,sent:0,received:0, established: None, first_down: None }
    }

    /// At most one chunk in each direction per turn. A slow reader can't hold
    /// the stack lock, grow a queue, or starve a different TLS handshake.
    fn tick(&mut self, stack: &mut TunnelStack, scratch: &mut [u8]) -> Result<bool, String> {
        if !self.connected {
            if self.peer.expired() || self.started.elapsed() >= CONNECT_TIMEOUT { return Err(TIMEOUT.into()); }
            if self.peer.client_gone() { return Err("browser canceled CONNECT".into()); }
            if !stack.tcp_connected(self.handle)? { return Ok(false); }
            self.connected = true;
            self.established = Some(Instant::now());
            self.down.bytes.extend_from_slice(ESTABLISHED);
            log(&format!("connected {}:{} in {} ms", self.peer.request.host, self.peer.request.port, self.started.elapsed().as_millis()));
        }
        if self.progress.elapsed() >= Duration::from_secs(300) { return Err("idle timeout".into()); }
        let client = &mut self.peer.client;
        if self.up.remaining().is_empty() && !self.client_fin {
            match nonblocking(client.read(scratch)).map_err(|e| format!("browser socket read: {e}"))? {
                Some(0) => { self.client_fin = true; stack.tcp_shutdown_write(self.handle)?; }
                Some(n) => self.up.bytes.extend_from_slice(&scratch[..n]), None => (),
            }
        }
        if !self.up.remaining().is_empty() {
            let n = stack.tcp_send(self.handle,self.up.remaining())?;
            self.up.advance(n); self.sent += n; if n > 0 { self.progress = Instant::now(); }
        }
        if self.down.remaining().is_empty() && !self.remote_fin {
            match stack.tcp_recv(self.handle,scratch)? {
                Some(0) => { self.remote_fin = true; client.shutdown(Shutdown::Write).map_err(|e| format!("browser socket shutdown: {e}"))?; }
                Some(n) => {
                    if self.first_down.is_none() { self.first_down = self.established.map(|at| at.elapsed()); }
                    self.down.bytes.extend_from_slice(&scratch[..n]);
                    self.received += n;
                }
                None => (),
            }
        }
        if !self.down.remaining().is_empty() {
            match nonblocking(client.write(self.down.remaining())).map_err(|e| format!("browser socket write: {e}"))? {
                Some(0) => return Err("client write closed".into()), Some(n) => { self.down.advance(n); self.progress = Instant::now(); }, None => (),
            }
        }
        Ok(self.client_fin && self.remote_fin)
    }

    fn finish(&mut self, stack: &mut TunnelStack, reason: &str) {
        stack.tcp_close(self.handle);
        if !self.connected { reject(&mut self.peer.client, if reason == TIMEOUT {TIMEOUT} else {GATEWAY}); }
        let first_down = self.first_down.map_or("n/a".into(), |d| format!("{} ms", d.as_millis()));
        log(&format!("{}:{} closed: {reason}; up={} down={} first_tunnel_byte={first_down} idle_at_close={} ms lifetime={} ms", self.peer.request.host, self.peer.request.port, self.sent, self.received, self.progress.elapsed().as_millis(), self.started.elapsed().as_millis()));
    }

    // Never move a flow after committing its CONNECT response. It may have
    // already carried a form submission; the browser owns any retry then.
    fn on_vpn_loss(mut self, stack: &mut TunnelStack, reason: &str, pending: &mut VecDeque<Ready>) {
        if self.connected {
            self.finish(stack, reason);
        } else {
            stack.tcp_close(self.handle);
            log(&format!("{}:{} waiting for a new VPN connection", self.peer.request.host, self.peer.request.port));
            self.peer.request.early = self.up.bytes;
            pending.push_back(self.peer);
        }
    }
}

pub fn start(store: &launcher::Store, mode: &str) -> Result<BrowserProxy, String> {
    let stack = launcher::shared_tunnel(store, mode, &|m, _| launcher::netlog(m))?;
    let route = launcher::TunnelRoute::for_stack(&stack)?;
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    let stopped = Arc::new(AtomicBool::new(false));
    let stop = stopped.clone();
    thread::Builder::new().name("browser-proxy".into()).spawn(move || run(listener, route, stack, stop)).map_err(|e|e.to_string())?;
    log(&format!("listening on 127.0.0.1:{port}"));
    Ok(BrowserProxy { port, stopped })
}

fn run(listener: TcpListener, route: launcher::TunnelRoute, mut stack: Stack, stop: Arc<AtomicBool>) {
    let slots = Arc::new(AtomicUsize::new(0));
    let (tx, rx) = mpsc::channel::<Ready>();
    let mut pending = VecDeque::new();
    let mut flows: Vec<Flow> = Vec::new();
    let mut scratch = [0; CHUNK];
    let mut pumped = None;
    let mut failed = false;
    let mut reconnect: Option<mpsc::Receiver<Result<(), String>>> = None;
    let mut retry_at = Instant::now();
    while !stop.load(Ordering::Acquire) {
        let mut moved_data = false;
        let Some(current) = route.stack() else { break };
        if !Arc::ptr_eq(&stack, &current) {
            if let Ok(mut s) = stack.lock() {
                for flow in flows.drain(..) {
                    flow.on_vpn_loss(&mut s, "VPN exit changed", &mut pending);
                }
            }
            stack = current;
            failed = false;
            pumped = None;
            reconnect = None;
        }
        for _ in 0..16 {
            let mut client = match listener.accept() { Ok((s,_))=>s, Err(e) if e.kind()==io::ErrorKind::WouldBlock => break, Err(e)=>{log(&format!("accept: {e}")); break;} };
            if slots.load(Ordering::Relaxed) >= MAX_CLIENTS { let _=client.set_nonblocking(true); reject(&mut client,"503 Service Unavailable"); continue; }
            slots.fetch_add(1, Ordering::Relaxed);
            let (s, t, stop, slot) = (stack.clone(), tx.clone(), stop.clone(), Slot(slots.clone()));
            // Accepted sockets may inherit nonblocking mode on some platforms.
            if client.set_nonblocking(false).is_err() { continue; }
            if let Err(e)=thread::Builder::new().name("proxy-headers".into()).spawn(move || prepare(client,s,stop,slot,t)) { log(&format!("header worker: {e}")); }
        }
        pending.extend(rx.try_iter());
        pending.retain_mut(|ready| {
            if ready.client_gone() { return false; }
            if ready.expired() { reject(&mut ready.client, TIMEOUT); return false; }
            true
        });

        if failed {
            if let Some(rx) = &reconnect {
                let error = match rx.try_recv() {
                    Ok(Err(e)) => Some(e),
                    Err(mpsc::TryRecvError::Disconnected) => Some("reconnect worker exited".into()),
                    Ok(Ok(())) => continue, // The route publishes the new stack before sending success.
                    Err(mpsc::TryRecvError::Empty) => None,
                };
                if let Some(e) = error {
                    log(&format!("reconnect failed: {e}"));
                    retry_at = Instant::now() + RETRY_DELAY;
                    reconnect = None;
                }
            }
            if reconnect.is_none() && Instant::now() >= retry_at {
                let failed_stack = stack.clone();
                let (tx, rx) = mpsc::channel();
                match thread::Builder::new().name("browser-vpn-reconnect".into()).spawn(move || {
                    let _ = tx.send(launcher::rotate_tunnel_if(&failed_stack).map(|_| ()));
                }) {
                    Ok(_) => reconnect = Some(rx),
                    Err(e) => {
                        log(&format!("could not start reconnect worker: {e}"));
                        retry_at = Instant::now() + RETRY_DELAY;
                    }
                }
            }
        } else if let Ok(mut s) = stack.try_lock() {
            while let Some(mut ready) = pending.pop_front() {
                match s.tcp_start(ready.ip,ready.request.port) {
                    Ok(handle) => flows.push(Flow::new(ready,handle)),
                    Err(e) => {log(&format!("TCP start {}: {e}",ready.request.host));reject(&mut ready.client,GATEWAY);}
                }
            }
            let err = if !flows.is_empty() || pumped.is_none_or(|at: Instant| at.elapsed() >= Duration::from_millis(500)) {
                let start = Instant::now();
                pumped = Some(start);
                let result = s.keepalive().err();
                let elapsed = start.elapsed();
                if elapsed >= Duration::from_millis(100) {
                    log(&format!("slow tunnel pump: {} ms ({} browser flows)", elapsed.as_millis(), flows.len()));
                }
                result
            } else { None };
            if let Some(e) = err {
                log(&format!("VPN transport failed: {e}; reconnecting"));
                for flow in flows.drain(..) {
                    flow.on_vpn_loss(&mut s, &e, &mut pending);
                }
                failed = true;
                retry_at = Instant::now();
            } else {
                flows.retain_mut(|flow| {
                    let before = flow.progress;
                    let result = flow.tick(&mut s, &mut scratch);
                    moved_data |= before != flow.progress;
                    match result {
                        Ok(false) => return true,
                        Ok(true) => flow.finish(&mut s, "finished"),
                        Err(e) => flow.finish(&mut s, &e),
                    }
                    false
                });
            }
        }
        // The transport pump already waits briefly for packets.
        if flows.is_empty() {
            thread::sleep(Duration::from_millis(8));
        } else if !moved_data {
            thread::sleep(Duration::from_millis(1));
        }
    }
    close_flows(&stack, &mut flows, "proxy stopped");
    log("stopped");
}

fn close_flows(stack: &Stack, flows: &mut Vec<Flow>, reason: &str) {
    if let Ok(mut s) = stack.lock() {
        for mut flow in flows.drain(..) { flow.finish(&mut s, reason); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netstack::{IpTunnel, TunnelAddr};

    struct OfflineTunnel;

    impl IpTunnel for OfflineTunnel {
        fn address(&self) -> TunnelAddr {
            TunnelAddr { local_ip: [10, 0, 0, 1], prefix_len: 24, gateway: None, mtu: 1300, dns: vec![] }
        }

        fn send_ip(&mut self, _: &[u8]) -> Result<(), String> { Ok(()) }
        fn pump(&mut self, _: Duration) -> Result<(), String> { Err("VPN server closed the connection".into()) }
        fn take_inbound(&mut self) -> Option<Vec<u8>> { None }
    }

    #[test]
    fn vpn_loss_requeues_only_uncommitted_connects() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut stack = TunnelStack::new(OfflineTunnel).unwrap();
        let mut pending = VecDeque::new();
        let deadline = Instant::now() + REQUEST_TIMEOUT;
        let ip = Ipv4Addr::new(10, 0, 0, 2);
        let slots = Arc::new(AtomicUsize::new(2));
        let mut browsers = Vec::new();
        for committed in [false, true] {
            browsers.push(TcpStream::connect(addr).unwrap());
            let (client, _) = listener.accept().unwrap();
            client.set_nonblocking(true).unwrap();
            let handle = stack.tcp_start(ip, 443).unwrap();
            let mut flow = Flow::new(Ready {
                client, request: Request { host: "example.test".into(), port: 443, early: vec![0x16, 3, 1] },
                ip, deadline, _slot: Slot(slots.clone()),
            }, handle);
            flow.connected = committed;
            let error = stack.keepalive().unwrap_err();
            flow.on_vpn_loss(&mut stack, &error, &mut pending);
            assert!(stack.tcp_connected(handle).is_err());
        }
        assert_eq!(pending.len(), 1);
        assert_eq!(slots.load(Ordering::Relaxed), 1);
        assert_eq!(pending[0].deadline, deadline);
        assert_eq!(pending[0].request.early, [0x16, 3, 1]);
        browsers[0].set_nonblocking(true).unwrap();
        assert_eq!(browsers[0].peek(&mut [0]).unwrap_err().kind(), io::ErrorKind::WouldBlock);
        assert_eq!(browsers[1].peek(&mut [0]).unwrap(), 0);
    }
    #[test]
    fn fragmented_connect_preserves_early_tls() {
        let head=b"CONNECT static.example:443 HTTP/1.1\r\nHost: static.example:443\r\n\r\n";
        for n in 0..head.len() { assert!(parse(&head[..n]).unwrap().is_none()); }
        let tls = [0x16,3,1,0,0xff];
        let req=parse(&[head.as_slice(), &tls].concat()).unwrap().unwrap();
        assert_eq!((req.host.as_str(),req.port,req.early.as_slice()),("static.example",443,tls.as_slice()));
    }
    #[test]
    fn bad_and_oversized_requests_are_never_tunneled() {
        for target in ["host",":443","host:0","host:+443","host:65536","user@host:443","https://host:443"] {
            assert_eq!(parse(format!("CONNECT {target} HTTP/1.1\r\n\r\n").as_bytes()).err(),Some(BAD));
        }
        assert_eq!(parse(b"GET / HTTP/1.1\r\n\r\n").err(),Some("405 Method Not Allowed"));
        assert_eq!(parse(format!("CONNECT host:443 HTTP/1.1\r\nX: {}", "a".repeat(HEADER_LIMIT)).as_bytes()).err(),Some(LARGE));
    }
}
