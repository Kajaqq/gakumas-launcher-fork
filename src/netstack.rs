//! 터널 위에서 도는 사용자 공간 TCP/IP 스택 (smoltcp)
//!
//! Windows 네트워크 설정을 건드리지 않고, 이 프로그램이 여는 TCP 연결만 VPN 터널을 탑니다.

use std::collections::{HashMap, VecDeque};
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{self, Device, DeviceCapabilities, Medium};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, Ipv4Address};

use crate::http;
/// 사용자 공간 TCP/IP 스택 아래에 놓이는 VPN 터널 (OpenVPN, WireGuard)
pub trait IpTunnel: Send {
    fn address(&self) -> TunnelAddr;
    /// IP 패킷 하나를 암호화해 보냄
    fn send_ip(&mut self, ip: &[u8]) -> Result<(), String>;
    /// 서버에서 온 패킷을 최대 `wait` 동안 기다려 처리
    fn pump(&mut self, wait: Duration) -> Result<(), String>;
    /// 복호화된 IP 패킷 하나를 꺼냄
    fn take_inbound(&mut self) -> Option<Vec<u8>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    type Packets = Arc<Mutex<VecDeque<Vec<u8>>>>;
    struct Pipe { addr: [u8; 4], rx: Packets, tx: Packets }
    impl IpTunnel for Pipe {
        fn address(&self) -> TunnelAddr {
            TunnelAddr { local_ip: self.addr, prefix_len: 24, gateway: None, mtu: 1300, dns: vec![] }
        }
        fn send_ip(&mut self, ip: &[u8]) -> Result<(), String> {
            self.tx.lock().unwrap().push_back(ip.to_vec()); Ok(())
        }
        fn pump(&mut self, _: Duration) -> Result<(), String> { Ok(()) }
        fn take_inbound(&mut self) -> Option<Vec<u8>> { self.rx.lock().unwrap().pop_front() }
    }
    fn pair() -> (TunnelStack, TunnelStack) {
        let (a, b) = (Packets::default(), Packets::default());
        (TunnelStack::new(Pipe { addr: [10,0,0,1], rx: a.clone(), tx: b.clone() }).unwrap(),
         TunnelStack::new(Pipe { addr: [10,0,0,2], rx: b, tx: a }).unwrap())
    }

    #[test]
    fn slow_handshake_does_not_block_other_stream_or_its_eof() {
        let (mut client, mut server) = pair();
        let mut listener = tcp::Socket::new(tcp::SocketBuffer::new(vec![0; 8192]), tcp::SocketBuffer::new(vec![0; 8192]));
        listener.listen(443).unwrap();
        let peer = server.sockets.add(listener);
        let slow = client.tcp_start(Ipv4Addr::new(10,0,0,3), 443).unwrap();
        let ready = client.tcp_start(Ipv4Addr::new(10,0,0,2), 443).unwrap();
        for _ in 0..4 { client.keepalive().unwrap(); server.keepalive().unwrap(); }
        assert!(!client.tcp_connected(slow).unwrap());
        assert!(client.tcp_connected(ready).unwrap());
        let mut buf = [0; 16];
        assert_eq!(client.tcp_recv(ready, &mut buf).unwrap(), None);
        assert_eq!(client.tcp_send(ready, b"hello").unwrap(), 5);
        client.tcp_shutdown_write(ready).unwrap();
        for _ in 0..4 { client.keepalive().unwrap(); server.keepalive().unwrap(); }
        let sock = server.sockets.get_mut::<tcp::Socket>(peer);
        assert_eq!(sock.recv_slice(&mut buf).unwrap(), 5);
        assert_eq!(&buf[..5], b"hello");
        assert!(!sock.may_recv());
        sock.send_slice(b"world").unwrap();
        sock.close();
        for _ in 0..4 { server.keepalive().unwrap(); client.keepalive().unwrap(); }
        assert_eq!(client.tcp_recv(ready, &mut buf).unwrap(), Some(5));
        assert_eq!(&buf[..5], b"world");
        assert_eq!(client.tcp_recv(ready, &mut buf).unwrap(), Some(0));
        assert!(!client.tcp_connected(slow).unwrap());
    }

    #[test]
    fn shared_api_wait_does_not_block_browser_data() {
        let (client, mut server) = pair();
        let client = Arc::new(Mutex::new(client));
        let mut listen = |port| {
            let buf = || tcp::SocketBuffer::new(vec![0; 8192]);
            let mut sock = tcp::Socket::new(buf(), buf());
            sock.listen(port).unwrap();
            server.sockets.add(sock)
        };
        let api_peer = listen(80);
        let browser_peer = listen(443);
        let api = {
            let client = client.clone();
            std::thread::spawn(move || {
                TunnelStack::request_shared(
                    &client, "10.0.0.2", 80, None, b"GET / HTTP/1.1\r\n\r\n", Duration::from_secs(5),
                )
            })
        };
        let until = Instant::now() + Duration::from_secs(3);
        let mut browser = None;
        let mut sent = false;
        let mut replied = false;
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        while Instant::now() < until && !api.is_finished() {
            server.keepalive().unwrap();
            let waiting_for_response = server.sockets.get::<tcp::Socket>(api_peer).can_recv();
            if let Ok(mut stack) = client.try_lock() {
                if waiting_for_response && browser.is_none() {
                    browser = Some(stack.tcp_start(Ipv4Addr::new(10, 0, 0, 2), 443).unwrap());
                }
                stack.keepalive().unwrap();
                if let Some(handle) = browser {
                    let mut buf = [0; 16];
                    if stack.tcp_connected(handle).unwrap() && !replied {
                        let peer = server.sockets.get_mut::<tcp::Socket>(browser_peer);
                        if peer.can_send() && !sent {
                            peer.send_slice(b"browser data").unwrap();
                            sent = true;
                        }
                        if let Some(n) = stack.tcp_recv(handle, &mut buf).unwrap() {
                            assert_eq!(&buf[..n], b"browser data");
                            server.sockets.get_mut::<tcp::Socket>(api_peer).send_slice(response).unwrap();
                            replied = true;
                        }
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(replied, "browser must receive data before the API is allowed to finish");
        assert_eq!(api.join().unwrap().unwrap(), response);
    }

    #[test]
    fn old_handle_never_aliases_a_reused_slot() {
        let (mut old, mut rotated) = pair();
        let ip = Ipv4Addr::new(10, 0, 0, 3);
        let stale = old.tcp_start(ip, 443).unwrap();
        old.tcp_close(stale);
        old.keepalive().unwrap();
        for stack in [&mut old, &mut rotated] {
            let current = stack.tcp_start(ip, 443).unwrap();
            stack.tcp_close(stale);
            assert!(stack.tcp_connected(stale).is_err());
            assert_eq!(stack.tcp_connected(current), Ok(false));
        }
    }
}

/// 터널 안에서 이 프로그램이 쓰는 주소
#[derive(Clone, Debug)]
pub struct TunnelAddr {
    pub local_ip: [u8; 4],
    pub prefix_len: u8,
    pub gateway: Option<[u8; 4]>,
    /// 터널 안 IP 패킷 최대 크기. 작게 잡아 TCP 세그먼트가 터널에서 잘리지 않게 함
    pub mtu: usize,
    /// 터널이 알려 준 DNS 서버 (OpenVPN dhcp-option DNS, WireGuard DNS)
    pub dns: Vec<[u8; 4]>,
}

struct QueueDevice {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
    mtu: usize,
}

struct RxTok(Vec<u8>);
struct TxTok<'a>(&'a mut VecDeque<Vec<u8>>);

impl phy::RxToken for RxTok {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        f(&mut self.0)
    }
}

impl<'a> phy::TxToken for TxTok<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut b = vec![0u8; len];
        let r = f(&mut b);
        self.0.push_back(b);
        r
    }
}

impl Device for QueueDevice {
    type RxToken<'a>
        = RxTok
    where
        Self: 'a;
    type TxToken<'a>
        = TxTok<'a>
    where
        Self: 'a;

    fn receive(&mut self, _t: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let p = self.rx.pop_front()?;
        Some((RxTok(p), TxTok(&mut self.tx)))
    }

    fn transmit(&mut self, _t: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(TxTok(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        c.medium = Medium::Ip;
        c.max_transmission_unit = self.mtu;
        c
    }
}

// smoltcp recycles slot indices, including immediately after a tunnel rotation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ProxyHandle(u64);
static NEXT_PROXY_HANDLE: AtomicU64 = AtomicU64::new(1);

pub struct TunnelStack {
    tun: Box<dyn IpTunnel>,
    dev: QueueDevice,
    iface: Interface,
    sockets: SocketSet<'static>,
    epoch: Instant,
    /// 터널 안에서 찾은 주소 (일본 쪽에서 본 주소)
    hosts: HashMap<String, Ipv4Addr>,
    dns: Vec<[u8; 4]>,
    /// Handles created for the browser proxy (invalidated on rotation).
    proxy_handles: HashMap<ProxyHandle, SocketHandle>,
    retired: Vec<(SocketHandle, Instant)>,
    next_port: u16,
}

/// DNS-over-TCP 질의 (2바이트 길이 + DNS 메시지, A 레코드)
fn dns_query(host: &str, id: [u8; 2]) -> Vec<u8> {
    let mut m = vec![id[0], id[1], 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in host.trim_end_matches('.').split('.') {
        m.push(label.len() as u8);
        m.extend_from_slice(label.as_bytes());
    }
    m.extend_from_slice(&[0, 0, 1, 0, 1]);
    [(m.len() as u16).to_be_bytes().to_vec(), m].concat()
}

fn dns_tcp_complete(r: &[u8]) -> bool {
    r.len() >= 2 && r.len() >= 2 + u16::from_be_bytes([r[0], r[1]]) as usize
}

/// DNS 응답 이름 건너뛰기 (압축 포인터 포함)
fn dns_skip_name(m: &[u8], mut off: usize) -> Option<usize> {
    loop {
        let len = *m.get(off)? as usize;
        if len == 0 {
            return Some(off + 1);
        }
        if len & 0xC0 == 0xC0 {
            return Some(off + 2);
        }
        off += 1 + len;
    }
}

/// DNS-over-TCP 응답에서 첫 A 레코드
fn dns_answer(raw: &[u8], id: [u8; 2]) -> Result<Ipv4Addr, String> {
    let m = raw.get(2..).ok_or("short DNS response")?;
    if m.len() < 12 || m[0..2] != id {
        return Err("bad DNS response".into());
    }
    if m[3] & 0x0F != 0 {
        return Err(format!("DNS error code {}", m[3] & 0x0F));
    }
    let qd = u16::from_be_bytes([m[4], m[5]]);
    let an = u16::from_be_bytes([m[6], m[7]]);
    let mut off = 12;
    for _ in 0..qd {
        off = dns_skip_name(m, off).ok_or("bad DNS response")? + 4;
    }
    for _ in 0..an {
        off = dns_skip_name(m, off).ok_or("bad DNS response")?;
        let h = m.get(off..off + 10).ok_or("bad DNS response")?;
        let (rtype, rdlen) = (
            u16::from_be_bytes([h[0], h[1]]),
            u16::from_be_bytes([h[8], h[9]]) as usize,
        );
        off += 10;
        if rtype == 1 && rdlen == 4 {
            let a = m.get(off..off + 4).ok_or("bad DNS response")?;
            return Ok(Ipv4Addr::new(a[0], a[1], a[2], a[3]));
        }
        off += rdlen;
    }
    Err("no A record".into())
}

/// 터널 안에서 쓰는 DNS-over-HTTPS (주소, TLS 이름, 경로). 시스템 DNS 를 거치지 않도록 IP 로 접속
const DOH_SERVERS: &[([u8; 4], &str, &str)] = &[
    ([8, 8, 8, 8], "dns.google", "/resolve"),
    ([1, 1, 1, 1], "cloudflare-dns.com", "/dns-query"),
];

pub fn resolve_v4(host: &str) -> Result<Ipv4Addr, String> {
    (host, 0)
        .to_socket_addrs()
        .map_err(|e| format!("DNS {host}: {e}"))?
        .find_map(|a| match a.ip() {
            std::net::IpAddr::V4(v4) => Some(v4),
            _ => None,
        })
        .ok_or(format!("no IPv4 address for {host}"))
}

impl TunnelStack {
    pub fn new<T: IpTunnel + 'static>(tun: T) -> Result<Self, String> {
        let push = tun.address();
        let ip = push.local_ip;
        let mut dev = QueueDevice {
            rx: VecDeque::new(),
            tx: VecDeque::new(),
            mtu: push.mtu,
        };
        let mut cfg = Config::new(HardwareAddress::Ip);
        let mut seed = [0u8; 8];
        getrandom::getrandom(&mut seed).map_err(|e| e.to_string())?;
        cfg.random_seed = u64::from_le_bytes(seed);
        let mut iface = Interface::new(cfg, &mut dev, SmolInstant::from_millis(0));
        iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::new(
                IpAddress::v4(ip[0], ip[1], ip[2], ip[3]),
                push.prefix_len,
            ));
        });
        // WireGuard 처럼 게이트웨이가 없는 터널은 같은 대역의 .1 을 씀 (IP 장치라 실제로 쓰이지는 않음)
        let gw = push
            .gateway
            .unwrap_or([ip[0], ip[1], ip[2], if ip[3] == 1 { 2 } else { 1 }]);
        iface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Address::new(gw[0], gw[1], gw[2], gw[3]))
            .map_err(|e| format!("route: {e:?}"))?;
        Ok(Self {
            tun: Box::new(tun),
            dev,
            iface,
            sockets: SocketSet::new(Vec::new()),
            epoch: Instant::now(),
            hosts: HashMap::new(),
            dns: push.dns.clone(),
            proxy_handles: HashMap::new(),
            retired: Vec::new(),
            next_port: 49152 + u16::from_le_bytes([seed[0], seed[1]]) % 16384,
        })
    }

    pub fn cached_ip(&self, host: &str) -> Option<Ipv4Addr> {
        self.hosts.get(host).copied()
    }

    /// `host` 의 주소를 터널 안에서(일본 쪽 DNS 로) 찾아 이후 요청에 씀.
    /// CDN 은 묻는 쪽 위치에 따라 다른 서버를 알려 주는데, 한국 쪽 서버는 VPN Gate 에서 연결되지 않을 수 있음
    pub fn resolve_in_tunnel(&mut self, host: &str) -> Result<Ipv4Addr, String> {
        let mut errors = Vec::new();
        for &(ip, name, path) in DOH_SERVERS {
            let req = format!(
                "GET {path}?name={host}&type=A HTTP/1.1\r\nHost: {name}\r\n\
                 Accept: application/dns-json\r\nConnection: close\r\n\r\n"
            );
            let answer = self
                .request_ip(
                    Ipv4Addr::from(ip),
                    name,
                    443,
                    Some(http::dmm_tls_config()),
                    req.as_bytes(),
                    Duration::from_secs(6),
                )
                .and_then(|raw| http::parse_response(&raw))
                .and_then(|(_, body)| {
                    let v: serde_json::Value =
                        serde_json::from_slice(&body).map_err(|e| e.to_string())?;
                    v["Answer"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter(|a| a["type"] == 1)
                        .find_map(|a| a["data"].as_str()?.parse::<Ipv4Addr>().ok())
                        .ok_or_else(|| "no A record".to_string())
                });
            match answer {
                Ok(addr) => {
                    self.hosts.insert(host.to_string(), addr);
                    return Ok(addr);
                }
                Err(e) => errors.push(format!("{name}: {e}")),
            }
        }
        // DoH 가 막힌 VPN(광고 차단 기능 등)도 있어, 터널이 알려 준 DNS 와 공개 DNS 에 TCP 로 직접 물어봄
        let mut servers = self.dns.clone();
        for s in [[8, 8, 8, 8], [1, 1, 1, 1]] {
            if !servers.contains(&s) {
                servers.push(s);
            }
        }
        for s in servers {
            let server = Ipv4Addr::from(s);
            let id: [u8; 2] = {
                let mut b = [0u8; 2];
                getrandom::getrandom(&mut b).map_err(|e| e.to_string())?;
                b
            };
            let query = dns_query(host, id);
            let answer = self
                .request_ip_until(
                    server,
                    "",
                    53,
                    None,
                    &query,
                    Duration::from_secs(6),
                    Completion::Custom(dns_tcp_complete),
                )
                .and_then(|raw| dns_answer(&raw, id));
            match answer {
                Ok(addr) => {
                    self.hosts.insert(host.to_string(), addr);
                    return Ok(addr);
                }
                Err(e) => errors.push(format!("DNS {server}: {e}")),
            }
        }
        Err(errors.join(" / "))
    }

    fn now(&self) -> SmolInstant {
        SmolInstant::from_millis(self.epoch.elapsed().as_millis() as i64)
    }

    fn start_socket(&mut self, ip: Ipv4Addr, port: u16) -> Result<SocketHandle, String> {
        let ip = ip.octets();
        let mut sock = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; 65535]),
            tcp::SocketBuffer::new(vec![0u8; 65535]),
        );
        let local_port = (0..16384).find_map(|_| {
            let p = self.next_port;
            self.next_port = p.checked_add(1).unwrap_or(49152);
            let used = self.sockets.iter().any(|(h, _)| self.sockets.get::<tcp::Socket>(h).local_endpoint().is_some_and(|ep| ep.port == p));
            (!used).then_some(p)
        }).ok_or("all tunnel TCP ports are in use")?;
        sock.connect(
            self.iface.context(),
            (IpAddress::v4(ip[0], ip[1], ip[2], ip[3]), port),
            local_port,
        )
        .map_err(|e| format!("TCP connect: {e:?}"))?;
        Ok(self.sockets.add(sock))
    }

    /// Enqueue the handshake. Only the shared keepalive/poll loop performs I/O.
    pub fn tcp_start(&mut self, ip: Ipv4Addr, port: u16) -> Result<ProxyHandle, String> {
        let h = self.start_socket(ip, port)?;
        let id = ProxyHandle(NEXT_PROXY_HANDLE.fetch_add(1, Ordering::Relaxed));
        self.proxy_handles.insert(id, h);
        Ok(id)
    }

    fn socket(&mut self, id: ProxyHandle) -> Result<&mut tcp::Socket<'static>, String> {
        let h = *self.proxy_handles.get(&id).ok_or("connection reset after close or VPN rotation")?;
        Ok(self.sockets.get_mut::<tcp::Socket>(h))
    }

    pub fn tcp_connected(&mut self, id: ProxyHandle) -> Result<bool, String> {
        match self.socket(id)?.state() {
            tcp::State::SynSent | tcp::State::SynReceived => Ok(false),
            tcp::State::Established | tcp::State::CloseWait => Ok(true),
            _ => Err("TCP connection refused or closed".into()),
        }
    }

    pub fn tcp_send(&mut self, id: ProxyHandle, data: &[u8]) -> Result<usize, String> {
        self.socket(id)?.send_slice(data).map_err(|e| format!("TCP send: {e:?}"))
    }

    /// None means would-block; Some(0) means the remote has closed its write half.
    pub fn tcp_recv(&mut self, id: ProxyHandle, buf: &mut [u8]) -> Result<Option<usize>, String> {
        let sock = self.socket(id)?;
        if sock.can_recv() {
            sock.recv_slice(buf).map(Some).map_err(|e| format!("TCP recv: {e:?}"))
        } else if sock.may_recv() {
            Ok(None)
        } else {
            Ok(Some(0))
        }
    }

    pub fn tcp_shutdown_write(&mut self, id: ProxyHandle) -> Result<(), String> {
        self.socket(id)?.close();
        Ok(())
    }

    pub fn tcp_close(&mut self, id: ProxyHandle) {
        if let Some(h) = self.proxy_handles.remove(&id) {
            let sock = self.sockets.get_mut::<tcp::Socket>(h);
            // A graceful half-close can still have unacknowledged data. Let it
            // drain, but bound the lifetime of a socket abandoned by both ends.
            if matches!(sock.state(), tcp::State::LastAck | tcp::State::Closing | tcp::State::TimeWait | tcp::State::FinWait1 | tcp::State::FinWait2) {
                self.retired.push((h, Instant::now() + Duration::from_secs(30)));
            } else {
                sock.abort();
                self.retired.push((h, Instant::now()));
            }
        }
    }

    pub fn keepalive(&mut self) -> Result<(), String> {
        self.step()
    }

    fn step(&mut self) -> Result<(), String> {
        let now = self.now();
        self.poll_and_flush()?;
        let delay = self
            .iface
            .poll_delay(now, &self.sockets)
            .map(|d| Duration::from_millis(d.total_millis()))
            .unwrap_or(Duration::from_millis(20));
        self.tun
            .pump(delay.clamp(Duration::from_millis(1), Duration::from_millis(4)))?;
        while let Some(p) = self.tun.take_inbound() {
            self.dev.rx.push_back(p);
        }
        if !self.dev.rx.is_empty() {
            self.poll_and_flush()?;
        }
        Ok(())
    }

    fn poll_and_flush(&mut self) -> Result<(), String> {
        let now = Instant::now();
        for &(h, deadline) in &self.retired {
            if now >= deadline {
                self.sockets.get_mut::<tcp::Socket>(h).abort();
            }
        }
        self.iface.poll(self.now(), &mut self.dev, &mut self.sockets);
        self.retired.retain(|&(h, _)| {
            if self.sockets.get::<tcp::Socket>(h).state() == tcp::State::Closed {
                self.sockets.remove(h);
                false
            } else { true }
        });
        while let Some(p) = self.dev.tx.pop_front() {
            self.tun.send_ip(&p)?;
        }
        Ok(())
    }

    /// 터널을 통해 HTTP(S) 요청을 보내고 응답 전체를 돌려줌. `tls` 가 None 이면 평문 HTTP
    pub fn request(
        &mut self,
        host: &str,
        port: u16,
        tls: Option<Arc<ClientConfig>>,
        req: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, String> {
        let ip = match self.hosts.get(host) {
            Some(ip) => *ip,
            None => resolve_v4(host)?,
        };
        self.request_ip(ip, host, port, tls, req, timeout)
    }

    /// Drive a launcher request on the same VPN as the browser without holding
    /// the stack lock across DNS resolution or the entire TCP/TLS exchange.
    pub(crate) fn request_shared(
        shared: &Mutex<Self>,
        host: &str,
        port: u16,
        tls: Option<Arc<ClientConfig>>,
        req: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, String> {
        let lock = || shared.lock().map_err(|e| e.to_string());
        let cached = lock()?.cached_ip(host);
        let ip = match cached {
            Some(ip) => ip,
            None => resolve_v4(host)?,
        };
        let mut exchange = Exchange::new(host, tls, req, timeout, Completion::http())?;
        let handle = lock()?.start_socket(ip, port)?;
        let result = loop {
            let tick = {
                let mut stack = lock()?;
                stack.advance_exchange(handle, &mut exchange)
            };
            match tick {
                Ok(false) => std::thread::sleep(Duration::from_millis(2)),
                Ok(true) => break Ok(exchange.response),
                Err(e) => break Err(e),
            }
        };
        lock()?.retire_exchange(handle);
        result
    }

    /// `ip` 로 접속해 `host` 이름으로 HTTP(S) 요청
    fn request_ip(
        &mut self,
        ip: Ipv4Addr,
        host: &str,
        port: u16,
        tls: Option<Arc<ClientConfig>>,
        req: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, String> {
        self.request_ip_until(ip, host, port, tls, req, timeout, Completion::http())
    }

    /// `ip` 로 접속해 요청을 보내고, `complete` 가 참이 되거나 연결이 닫힐 때까지 응답을 받음
    #[allow(clippy::too_many_arguments)]
    fn request_ip_until(
        &mut self,
        ip: Ipv4Addr,
        host: &str,
        port: u16,
        tls: Option<Arc<ClientConfig>>,
        req: &[u8],
        timeout: Duration,
        complete: Completion,
    ) -> Result<Vec<u8>, String> {
        let mut exchange = Exchange::new(host, tls, req, timeout, complete)?;
        let h = self.start_socket(ip, port)?;
        let result = loop {
            match self.advance_exchange(h, &mut exchange) {
                Ok(false) => (),
                Ok(true) => break Ok(exchange.response),
                Err(e) => break Err(e),
            }
        };
        self.retire_exchange(h);
        result
    }

    fn retire_exchange(&mut self, h: SocketHandle) {
        self.sockets.get_mut::<tcp::Socket>(h).abort();
        // Let the next pump flush the reset before recycling the handle.
        self.retired.push((h, Instant::now()));
    }

    fn advance_exchange(&mut self, h: SocketHandle, exchange: &mut Exchange) -> Result<bool, String> {
        if Instant::now() >= exchange.deadline {
            return Err(if exchange.connected { "response timed out" } else { "TCP connect timed out" }.into());
        }
        self.step()?;
        exchange.advance(self.sockets.get_mut::<tcp::Socket>(h))
    }
}

/// Decides when an exchange has received its whole response.
enum Completion {
    /// HTTP framing, tracked incrementally across reads.
    Http(http::ResponseFraming),
    /// A stateless check of the whole buffer (used for small, non-HTTP replies).
    Custom(fn(&[u8]) -> bool),
}

impl Completion {
    fn http() -> Self {
        Self::Http(http::ResponseFraming::default())
    }

    fn check(&mut self, resp: &[u8]) -> bool {
        match self {
            Self::Http(framing) => framing.is_complete(resp),
            Self::Custom(complete) => complete(resp),
        }
    }
}

struct Exchange {
    deadline: Instant,
    conn: Option<ClientConnection>,
    outgoing: Vec<u8>,
    response: Vec<u8>,
    connected: bool,
    complete: Completion,
}

impl Exchange {
    fn new(
        host: &str,
        tls: Option<Arc<ClientConfig>>,
        req: &[u8],
        timeout: Duration,
        complete: Completion,
    ) -> Result<Self, String> {
        let conn = match tls {
            Some(cfg) => {
                let name = ServerName::try_from(host.to_string())
                    .map_err(|e| format!("server name: {e}"))?;
                let mut c =
                    ClientConnection::new(cfg, name).map_err(|e| format!("TLS init: {e}"))?;
                c.writer()
                    .write_all(req)
                    .map_err(|e| format!("TLS write: {e}"))?;
                Some(c)
            }
            None => None,
        };
        Ok(Self {
            deadline: Instant::now() + timeout,
            outgoing: if conn.is_none() { req.to_vec() } else { Vec::new() },
            conn,
            response: Vec::new(),
            connected: false,
            complete,
        })
    }

    fn advance(&mut self, sock: &mut tcp::Socket<'_>) -> Result<bool, String> {
        if matches!(sock.state(), tcp::State::Established | tcp::State::CloseWait) {
            self.connected = true;
        }
        if let Some(c) = self.conn.as_mut() {
            while c.wants_write() {
                c.write_tls(&mut self.outgoing)
                    .map_err(|e| format!("TLS write: {e}"))?;
            }
        }
        if sock.can_send() && !self.outgoing.is_empty() {
            let n = sock.send_slice(&self.outgoing).map_err(|e| format!("TCP send: {e:?}"))?;
            self.outgoing.drain(..n);
        }
        let mut tls_closed = false;
        if sock.can_recv() {
            // Read at most one chunk per turn to give other sockets lock time.
            let mut buf = [0; 16384];
            let n = sock.recv_slice(&mut buf).map_err(|e| format!("TCP recv: {e:?}"))?;
            if let Some(c) = self.conn.as_mut() {
                let mut rd = &buf[..n];
                while !rd.is_empty() {
                    c.read_tls(&mut rd).map_err(|e| format!("TLS read: {e}"))?;
                    c.process_new_packets().map_err(|e| format!("TLS: {e}"))?;
                    let mut plain = [0; 16384];
                    loop {
                        match c.reader().read(&mut plain) {
                            Ok(0) => { tls_closed = true; break; }
                            Ok(k) => self.response.extend_from_slice(&plain[..k]),
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                            Err(e) => return Err(format!("TLS plaintext: {e}")),
                        }
                    }
                }
            } else {
                self.response.extend_from_slice(&buf[..n]);
            }
            if self.complete.check(&self.response) || tls_closed {
                return Ok(true);
            }
        }
        let remote_closed = matches!(sock.state(), tcp::State::CloseWait | tcp::State::LastAck
            | tcp::State::Closing | tcp::State::TimeWait | tcp::State::Closed);
        if remote_closed && !sock.can_recv() {
            return if !self.response.is_empty() {
                Ok(true)
            } else if self.connected {
                Err("connection closed without a response".into())
            } else {
                Err("connection refused".into())
            };
        }
        Ok(false)
    }
}
