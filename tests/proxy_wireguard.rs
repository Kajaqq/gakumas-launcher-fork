//! Offline end-to-end check: `cargo test --offline --test proxy_wireguard`.
//! The only OS listeners are the launcher's CONNECT proxy and our loopback UDP peer.
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use boringtun::{noise::{Tunn, TunnResult}, x25519::{PublicKey, StaticSecret}};
use gakumas_launcher::{browser_proxy, launcher::{Store, MODE_FILE}};
use rustls::{pki_types::{CertificateDer, PrivatePkcs8KeyDer}, ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned};
use smoltcp::{iface::{Config, Interface, SocketSet}, phy::{Device, DeviceCapabilities, Loopback, Medium, RxToken, TxToken}, socket::tcp, time::Instant as Tick, wire::{HardwareAddress, IpCidr, Ipv4Address}};
use std::{io::{ErrorKind, Read, Write}, net::{TcpStream,UdpSocket}, sync::{Arc, mpsc}, thread, time::{Duration,Instant}};

const CLIENTS: usize = 3;
const SIZE: usize = 24 * 1024 + 73;
// Self-signed echo.test identity, generated solely for this test (2020–2099).
const CERT: &str = "MIIBPjCB5aADAgECAgEHMAoGCCqGSM49BAMCMBQxEjAQBgNVBAMMCWVjaG8udGVzdDAgFw0yMDAxMDEwMDAwMDBaGA8yMDk5MDEwMTAwMDAwMFowFDESMBAGA1UEAwwJZWNoby50ZXN0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAElhIv/rg9CNfBv9YaxPdxAbuI3/vxWMj7k4CMsm0/JnyqMCTvIOHKSGpkpOEXgXA24xaJ5tBuVQA2swlthSh5KaMmMCQwFAYDVR0RBA0wC4IJZWNoby50ZXN0MAwGA1UdEwEB/wQCMAAwCgYIKoZIzj0EAwIDSAAwRQIhAIUJx79W+HInNXdclbUrU2iBUeKSuN2nJBkf6zxTMkVoAiAEE3P0hjLegyAx+lAR4WcKFK0NSmzE7Ms6hlbHrJyPXg==";
const KEY: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgrInjgMYQKglN4pq75U8fmqavfi08+LdhTZ8HzKgA3W6hRANCAASWEi/+uD0I18G/1hrE93EBu4jf+/FYyPuTgIyybT8mfKowJO8g4cpIamSk4ReBcDbjFonm0G5VADazCW2FKHkp";
fn cert() -> CertificateDer<'static> { B64.decode(CERT).unwrap().into() }

// One packet queue in each direction between WireGuard and the server stack.
struct Link { rx: Loopback, tx: Loopback }
impl Device for Link {
    type RxToken<'a> = <Loopback as Device>::RxToken<'a>;
    type TxToken<'a> = <Loopback as Device>::TxToken<'a>;
    fn receive(&mut self, t: Tick) -> Option<(Self::RxToken<'_>,Self::TxToken<'_>)> { Some((self.rx.receive(t)?.0,self.tx.transmit(t)?)) }
    fn transmit(&mut self, t: Tick) -> Option<Self::TxToken<'_>> { self.tx.transmit(t) }
    fn capabilities(&self) -> DeviceCapabilities { let mut c=self.rx.capabilities(); c.max_transmission_unit=1380; c }
}
fn listener(port:u16) -> tcp::Socket<'static> {
    let buf=|| tcp::SocketBuffer::new(vec![0;65536]);
    let mut s=tcp::Socket::new(buf(),buf()); s.listen((Ipv4Address::new(10,44,0,1),port)).unwrap(); s
}

// Return a single A record for each DNS-over-TCP question, including any
// startup DNS warmup. Preserve its transaction ID and original question.
fn dns(s:&mut tcp::Socket<'_>, pending:&mut Vec<u8>) {
    if !s.is_open() { s.listen((Ipv4Address::new(10,44,0,1),53)).unwrap(); pending.clear(); }
    if !s.can_recv(){ return; }
    s.recv(|b| { pending.extend_from_slice(b); (b.len(),()) }).unwrap();
    if pending.len()<2 || pending.len()<2+u16::from_be_bytes([pending[0],pending[1]]) as usize {return;}
    let mut ans=pending[2..].to_vec(); ans[2..4].copy_from_slice(&[0x81,0x80]); ans[6..8].copy_from_slice(&[0,1]);
    ans.extend_from_slice(&[0xc0,12,0,1,0,1,0,0,0,60,0,4,10,44,0,1]);
    let reply=[&(ans.len() as u16).to_be_bytes()[..],&ans].concat();
    assert_eq!(s.send_slice(&reply).unwrap(),reply.len()); pending.clear(); s.close();
}
fn peer(udp:UdpSocket, mut wg:Tunn, stop:mpsc::Receiver<()>) {
    udp.set_nonblocking(true).unwrap();
    let mut link=Link {rx:Loopback::new(Medium::Ip),tx:Loopback::new(Medium::Ip)};
    let mut iface=Interface::new(Config::new(HardwareAddress::Ip),&mut link,Tick::from_millis(0));
    iface.update_ip_addrs(|ips| {
        // Refuse optional DoH warmup probes immediately on the virtual network.
        for (ip,bits) in [([10,44,0,1],24),([1,1,1,1],32)] {ips.push(IpCidr::new(Ipv4Address(ip).into(),bits)).unwrap();}
    });
    let mut sockets=SocketSet::new(vec![]);
    let dns_handle=sockets.add(listener(53)); let mut question=Vec::new();
    let cfg=Arc::new(ServerConfig::builder().with_no_client_auth().with_single_cert(vec![cert()],PrivatePkcs8KeyDer::from(B64.decode(KEY).unwrap()).into()).unwrap());
    let mut conns:Vec<_>=(0..CLIENTS).map(|_|(sockets.add(listener(443)),ServerConnection::new(cfg.clone()).unwrap(),Vec::new(),Vec::new())).collect();
    let mut pkt=vec![0;65536]; let mut out=vec![0;65536]; let mut remote=None; let start=Instant::now(); let mut echoed=false;
    while stop.try_recv()==Err(mpsc::TryRecvError::Empty) {
        assert!(start.elapsed()<Duration::from_secs(60),"peer timed out");
        let t=Tick::from_millis(start.elapsed().as_millis() as i64);
        loop {
            let (n,addr)=match udp.recv_from(&mut pkt) {Ok(v)=>v,Err(e) if e.kind()==ErrorKind::WouldBlock=>break,Err(e)=>panic!("UDP: {e}")};
            remote=Some(addr); let mut src=&pkt[..n];
            loop {match wg.decapsulate(Some(addr.ip()),src,&mut out){
                TunnResult::WriteToNetwork(p)=>{udp.send_to(p,addr).unwrap();src=&[];},
                TunnResult::WriteToTunnelV4(p,_)=>{link.rx.transmit(t).unwrap().consume(p.len(),|dst|dst.copy_from_slice(p));break;},
                TunnResult::Done=>break, other=>panic!("unexpected WG result: {other:?}"),
            }}
        }
        iface.poll(t,&mut link,&mut sockets);
        dns(sockets.get_mut(dns_handle),&mut question);
        for (h,tls,plain,wire) in &mut conns {
            let s=sockets.get_mut::<tcp::Socket>(*h);
            while s.can_recv() {
                s.recv(|b| { let n=tls.read_tls(&mut &b[..]).unwrap(); (n,()) }).unwrap();
                let state=tls.process_new_packets().unwrap(); let old=plain.len(); plain.resize(old+state.plaintext_bytes_to_read(),0); tls.reader().read_exact(&mut plain[old..]).unwrap();
            }
            while tls.wants_write(){tls.write_tls(wire).unwrap();}
            if s.can_send() && !wire.is_empty(){let n=s.send_slice(wire).unwrap(); wire.drain(..n);}
        }
        if !echoed && conns.iter().all(|(_,_,p,_)|p.len()==SIZE) {
            for (_,tls,p,_) in &mut conns {tls.writer().write_all(p).unwrap();}
            echoed=true;
        }
        while let Some((rx,_))=link.tx.receive(t) {rx.consume(|p| match wg.encapsulate(p,&mut out){
            TunnResult::WriteToNetwork(msg)=>{udp.send_to(msg,remote.unwrap()).unwrap();},other=>panic!("WG send: {other:?}"),
        });}
        thread::sleep(Duration::from_millis(1));
    }
    assert!(echoed,"clients did not exchange data concurrently");
}

fn client(port:u16,id:usize) {
    let mut sock=TcpStream::connect(("127.0.0.1",port)).unwrap(); let limit=Some(Duration::from_secs(20)); sock.set_read_timeout(limit).unwrap(); sock.set_write_timeout(limit).unwrap();
    sock.write_all(b"CONNECT 10.44.0.1:443 HTTP/1.1\r\nHost: 10.44.0.1:443\r\n\r\n").unwrap();
    let mut hdr=Vec::new(); while !hdr.ends_with(b"\r\n\r\n"){assert!(hdr.len()<8192); let mut b=[0];sock.read_exact(&mut b).unwrap();hdr.push(b[0]);}
    assert!(hdr.starts_with(b"HTTP/1.1 200 "),"{}",String::from_utf8_lossy(&hdr));
    let mut roots=RootCertStore::empty(); roots.add(cert()).unwrap();
    let cfg=ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    let mut tls=StreamOwned::new(ClientConnection::new(Arc::new(cfg),"echo.test".try_into().unwrap()).unwrap(),sock);
    let payload:Vec<_>=(0..SIZE).map(|n|((n+57*id)%251) as u8).collect(); tls.write_all(&payload).unwrap(); tls.flush().unwrap();
    let mut reply=vec![0;SIZE];tls.read_exact(&mut reply).unwrap(); assert!(reply==payload,"wrong echo on client {id}");
}

#[test]
fn configured_wireguard_proxy_carries_concurrent_tls_streams() {
    let udp=UdpSocket::bind("127.0.0.1:0").unwrap(); let addr=udp.local_addr().unwrap();
    let sk=StaticSecret::from([23;32]); let ck=StaticSecret::from([67;32]);
    let profile=format!("[Interface]\nPrivateKey={}\nAddress=10.44.0.2/24\nDNS=10.44.0.1\n[Peer]\nPublicKey={}\nEndpoint={addr}\n",B64.encode(ck.to_bytes()),B64.encode(PublicKey::from(&sk).as_bytes()));
    let wg=Tunn::new(sk,PublicKey::from(&ck),None,None,7,None);
    let (stop,rx)=mpsc::channel(); let worker=thread::spawn(move||peer(udp,wg,rx));
    let dir=std::env::temp_dir().join(format!("gakumas-offline-wg-{}-{}",std::process::id(),addr.port()));
    let store=Store::new(dir.clone()).unwrap(); let path=dir.join("loopback.conf"); std::fs::write(&path,profile).unwrap(); store.import_vpn_file(&path).unwrap();
    let proxy=browser_proxy::start(&store,MODE_FILE).unwrap(); let port=proxy.port;
    let clients:Vec<_>=(0..CLIENTS).map(|id|thread::spawn(move||client(port,id))).collect();
    let success=clients.into_iter().map(|h|h.join()).collect::<Vec<_>>(); drop(proxy); drop(stop); worker.join().unwrap(); assert!(success.into_iter().all(|r|r.is_ok()));
}
