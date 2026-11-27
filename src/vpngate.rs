//! VPN Gate (University of Tsukuba) public server list and OpenVPN config handling.

use std::io::Read;
use std::net::{Ipv4Addr, ToSocketAddrs};
use std::time::Duration;

use base64::Engine;

const MAX_LIST_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct Server {
    pub host_name: String,
    pub ip: String,
    pub score: u64,
    pub ping_ms: Option<u32>,
    pub speed_bps: u64,
    pub sessions: u32,
    pub uptime_ms: u64,
    pub country: String,
    pub config_text: String,
}

impl Server {
    /// University of Tsukuba official server (`public-vpn-*`).
    pub fn is_official(&self) -> bool {
        self.host_name.starts_with("public-vpn-")
    }

    /// TLS server name (VPN Gate servers use `*.opengw.net` certificates).
    pub fn tls_name(&self) -> String {
        format!("{}.opengw.net", self.host_name)
    }

    /// IPv4 `/24` prefix (e.g. `"219.100.37"`), used to diversify candidates across subnets.
    pub fn subnet24(&self) -> Option<String> {
        subnet24_of(&self.ip)
    }

    /// Heuristic quality score combining VPN Gate's score, throughput, ping, uptime and load.
    /// Higher is better. Unlike the old official-first wall, this lets fast, healthy volunteer
    /// servers compete directly with Tsukuba servers while batch selection enforces `/24` diversity.
    pub fn quality_score(&self) -> u64 {
        self.quality_score_with_sessions(self.sessions)
    }

    /// Quality score using an explicit effective session count (e.g. aggregated across
    /// multiple hostnames sharing the same IP address).
    pub fn quality_score_with_sessions(&self, effective_sessions: u32) -> u64 {
        // VPN Gate's score is typically 100k..30M; scale into a moderate baseline.
        let mut q: u64 = (self.score / 10_000).min(1_500);

        // Speed bonus: capped at 500 (250+ Mbps). The tunnel only carries small API/webview
        // traffic (game downloads use the direct connection), so chasing ultra-high-bandwidth
        // relays over less-loaded ones hurts reliability.
        let mbps = self.speed_bps / 1_000_000;
        q += (mbps * 2).min(500);

        // Ping bonus/penalty (lower ping => faster handshake & TLS).
        match self.ping_ms {
            Some(p) if p <= 25 => q += 300,
            Some(p) if p <= 60 => q += 200,
            Some(p) if p <= 120 => q += 100,
            Some(p) if p > 250 => q = q.saturating_sub(250),
            _ => {}
        }

        // Uptime stability: reward servers up for >= 1h, penalize brand-new (<10m) relays.
        let uptime_mins = self.uptime_ms / 60_000;
        if uptime_mins >= 60 {
            q += 150;
        } else if uptime_mins > 0 && uptime_mins < 10 {
            q = q.saturating_sub(200);
        }

        // Congestion penalty: SoftEther's OpenVPN L3 mode (SecureNAT virtual DHCP + net30)
        // frequently rejects new clients with AUTH_FAILED once a relay is heavily loaded.
        // Start penalizing above 40 sessions and ramp steeply past 80/140.
        let load_penalty: u64 = if effective_sessions <= 40 {
            0
        } else if effective_sessions <= 80 {
            (effective_sessions - 40) as u64 * 3
        } else if effective_sessions <= 140 {
            120 + (effective_sessions - 80) as u64 * 5
        } else {
            (420 + (effective_sessions - 140) as u64 * 6).min(750)
        };
        q = q.saturating_sub(load_penalty);

        // Modest preference for Tsukuba official relays without blocking volunteers.
        if self.is_official() {
            q += 150;
        }

        q
    }
}

/// Extract the IPv4 `/24` prefix `"a.b.c"` from an IP string.
pub fn subnet24_of(ip: &str) -> Option<String> {
    let addr: Ipv4Addr = ip.trim().parse().ok()?;
    let [a, b, c, _] = addr.octets();
    Some(format!("{a}.{b}.{c}"))
}

pub use crate::openvpn::OvpnConfig;

/// Whether the config's primary remote uses TCP.
pub fn is_tcp(c: &OvpnConfig) -> bool {
    c.remotes.first().is_some_and(|r| !r.udp)
}

/// Replace the primary remote host/IP in an OpenVPN config.
pub fn set_remote_ip(c: &mut OvpnConfig, ip: &str) {
    if let Some(r) = c.remotes.first_mut() {
        r.host = ip.to_string();
    }
}

/// Primary remote host/IP of an OpenVPN config.
pub fn remote_ip(c: &OvpnConfig) -> &str {
    c.remotes.first().map_or("", |r| r.host.as_str())
}

/// Fetch and parse the VPN Gate CSV server list.
pub fn fetch_server_list() -> Result<Vec<Server>, String> {
    Ok(parse_server_list(&fetch_server_list_raw()?))
}

/// Japanese VPN Gate candidates (both TCP and UDP), ranked by quality score with a slight
/// tie-break preference for TCP (more likely to traverse restrictive firewalls).
/// Session load is aggregated per IP so multi-instance hosts sharing one IP are scored by
/// their combined load.
pub fn japan_candidates(body: &str) -> Vec<(Server, OvpnConfig)> {
    let mut v: Vec<(Server, OvpnConfig)> = parse_server_list(body)
        .into_iter()
        .filter(|s| s.country == "JP")
        .filter_map(|s| parse_config(&s.config_text).ok().map(|c| (s, c)))
        .collect();
    let mut sessions_by_ip: std::collections::HashMap<String, u32> =
        std::collections::HashMap::new();
    for (s, _) in &v {
        *sessions_by_ip.entry(s.ip.clone()).or_insert(0) += s.sessions;
    }
    v.sort_by(|a, b| {
        let sa = sessions_by_ip.get(&a.0.ip).copied().unwrap_or(a.0.sessions);
        let sb = sessions_by_ip.get(&b.0.ip).copied().unwrap_or(b.0.sessions);
        let qa = a.0.quality_score_with_sessions(sa) + if is_tcp(&a.1) { 50 } else { 0 };
        let qb = b.0.quality_score_with_sessions(sb) + if is_tcp(&b.1) { 50 } else { 0 };
        qb.cmp(&qa).then(b.0.score.cmp(&a.0.score))
    });
    v
}

/// Japanese TCP-only VPN Gate candidates, ranked by quality score.
pub fn japan_tcp_candidates(body: &str) -> Vec<(Server, OvpnConfig)> {
    japan_candidates(body)
        .into_iter()
        .filter(|(_, c)| is_tcp(c))
        .collect()
}

/// Raw CSV server list (saved to cache for reuse).
/// Tries HTTPS first (supports gzip cleanly and avoids HTTP throttling), falling back to HTTP.
pub fn fetch_server_list_raw() -> Result<String, String> {
    let https_err = match fetch_https() {
        Ok(body) => return Ok(body),
        Err(e) => e,
    };
    fetch_http().map_err(|e| format!("HTTPS: {https_err} / HTTP: {e}"))
}

/// Debug-only failure injection (`GAKUMAS_TEST_LIST_FAIL=http|https|all`).
fn simulated_failure(kind: &str) -> Result<(), String> {
    if cfg!(debug_assertions)
        && std::env::var("GAKUMAS_TEST_LIST_FAIL").is_ok_and(|v| v == kind || v == "all")
    {
        return Err("simulated failure".into());
    }
    Ok(())
}

fn check_list(body: String) -> Result<String, String> {
    if !body.contains("*vpn_servers") && !body.contains("#HostName") {
        return Err("unexpected server list response".into());
    }
    Ok(body)
}

fn fetch_list_url(
    url: &str,
    tls: Option<native_tls::TlsConnector>,
    connect_timeout: Duration,
    read_timeout: Duration,
) -> Result<String, String> {
    let mut builder = ureq::AgentBuilder::new()
        .timeout_connect(connect_timeout)
        .timeout_read(read_timeout);
    if let Some(tls) = tls {
        builder = builder.tls_connector(std::sync::Arc::new(tls));
    }
    let resp = builder
        .build()
        .get(url)
        .set("User-Agent", "Mozilla/5.0")
        .call()
        .map_err(|e| match e {
            ureq::Error::Status(code, _) => format!("HTTP {code}"),
            ureq::Error::Transport(t) => t.to_string(),
        })?;
    let mut body = String::new();
    resp.into_reader()
        .take(MAX_LIST_BYTES)
        .read_to_string(&mut body)
        .map_err(|e| format!("receive: {e}"))?;
    check_list(body)
}

/// `www.vpngate.net` only offers TLS 1.2 CBC cipher suites that rustls does not support,
/// so HTTPS uses `native_tls` (schannel on Windows, OpenSSL on Linux).
fn fetch_https() -> Result<String, String> {
    simulated_failure("https")?;
    let tls = native_tls::TlsConnector::new().map_err(|e| format!("TLS: {e}"))?;
    fetch_list_url(
        "https://www.vpngate.net/api/iphone/",
        Some(tls),
        Duration::from_secs(8),
        Duration::from_secs(20),
    )
}

/// Built-in University of Tsukuba servers (host name, last known IP).
/// Used only when the server list cannot be fetched. IPs are refreshed via DNS before dialing.
const BUILTIN_OFFICIAL: &[(&str, &str)] = &[
    ("public-vpn-162", "219.100.37.125"),
    ("public-vpn-42", "219.100.37.6"),
    ("public-vpn-127", "219.100.37.63"),
    ("public-vpn-150", "219.100.37.108"),
    ("public-vpn-214", "219.100.37.204"),
    ("public-vpn-210", "219.100.37.198"),
    ("public-vpn-61", "219.100.37.51"),
    ("public-vpn-81", "219.100.37.28"),
    ("public-vpn-142", "219.100.37.114"),
];

/// Shared VPN Gate client profile (CA, client cert, client key). Only the remote address varies.
const BUILTIN_PROFILE: &str = include_str!("vpngate_builtin.ovpn");

/// Built-in Tsukuba servers usable even if the CSV list cannot be downloaded.
pub fn builtin_official_servers() -> Vec<(Server, OvpnConfig)> {
    let Ok(base) = parse_config(BUILTIN_PROFILE) else {
        return Vec::new();
    };
    BUILTIN_OFFICIAL
        .iter()
        .map(|&(host, known_ip)| {
            let server = Server {
                host_name: host.to_string(),
                ip: known_ip.to_string(),
                score: 0,
                ping_ms: None,
                speed_bps: 0,
                sessions: 0,
                uptime_ms: 0,
                country: "JP".into(),
                config_text: String::new(),
            };
            let mut cfg = base.clone();
            set_remote_ip(&mut cfg, known_ip);
            (server, cfg)
        })
        .collect()
}

/// Refresh a built-in server's current IP via DNS (`<host>.opengw.net`).
pub fn refresh_builtin_ip(server: &Server, cfg: &mut OvpnConfig) {
    if let Ok(mut addrs) = (server.tls_name().as_str(), 443).to_socket_addrs() {
        if let Some(a) = addrs.find(|a| a.is_ipv4()) {
            set_remote_ip(cfg, &a.ip().to_string());
        }
    }
}

fn fetch_http() -> Result<String, String> {
    simulated_failure("http")?;
    fetch_list_url(
        "http://www.vpngate.net/api/iphone/",
        None,
        Duration::from_secs(5),
        Duration::from_secs(20),
    )
}

pub fn parse_server_list(body: &str) -> Vec<Server> {
    let mut out = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('*') || line.starts_with('#') {
            continue;
        }
        let cols: Vec<&str> = line.split(',').collect();
        if cols.len() < 15 {
            continue;
        }
        let Ok(raw) = base64::engine::general_purpose::STANDARD.decode(cols[cols.len() - 1].trim())
        else {
            continue;
        };
        out.push(Server {
            host_name: cols[0].to_string(),
            ip: cols[1].to_string(),
            score: cols[2].parse().unwrap_or(0),
            ping_ms: cols[3].parse().ok(),
            speed_bps: cols[4].parse().unwrap_or(0),
            sessions: cols[7].parse().unwrap_or(0),
            uptime_ms: cols[8].parse().unwrap_or(0),
            country: cols[6].to_string(),
            config_text: String::from_utf8_lossy(&raw).into_owned(),
        });
    }
    out
}

/// Parse an OpenVPN configuration file.
pub fn parse_config(text: &str) -> Result<OvpnConfig, String> {
    OvpnConfig::parse(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_ovpn(proto: &str, ip: &str, port: u16) -> String {
        let ovpn = format!(
            "client\ndev tun\nproto {proto}\nremote {ip} {port}\ncipher AES-128-CBC\nauth SHA1\n<ca>\n-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n</ca>\n"
        );
        base64::engine::general_purpose::STANDARD.encode(ovpn)
    }

    #[test]
    fn parses_metrics_and_ranks_fast_volunteer_ahead_of_slow_official() {
        let csv = format!(
            "*vpn_servers\n\
             #HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64\n\
             public-vpn-1,219.100.37.1,200000,280,5000000,Japan,JP,450,300000,100,1000,2weeks,tsukuba,,{}\n\
             fast-vol,133.242.10.5,5000000,18,500000000,Japan,JP,25,86400000,500,9000,2weeks,vol,,{}\n\
             udp-vol,153.120.5.9,4000000,22,400000000,Japan,JP,10,86400000,200,5000,2weeks,vol,,{}\n\
             us-server,1.2.3.4,9999999,10,900000000,United States,US,1,86400000,1,1,2weeks,us,,{}\n",
            sample_ovpn("tcp", "219.100.37.1", 443),
            sample_ovpn("tcp", "133.242.10.5", 1194),
            sample_ovpn("udp", "153.120.5.9", 1194),
            sample_ovpn("tcp", "1.2.3.4", 443),
        );
        let all = japan_candidates(&csv);
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].0.host_name, "fast-vol");
        assert_eq!(all[0].0.ping_ms, Some(18));
        assert_eq!(all[0].0.speed_bps, 500_000_000);
        assert_eq!(all[0].0.sessions, 25);
        assert_eq!(all[0].0.subnet24().as_deref(), Some("133.242.10"));
        assert_eq!(all[1].0.host_name, "udp-vol");
        assert!(!is_tcp(&all[1].1));
        assert_eq!(all[2].0.host_name, "public-vpn-1");

        let tcp_only = japan_tcp_candidates(&csv);
        assert_eq!(tcp_only.len(), 2);
        assert!(tcp_only.iter().all(|(_, c)| is_tcp(c)));
    }

    #[test]
    fn subnet24_extracts_prefix_only_for_valid_ipv4() {
        assert_eq!(subnet24_of("219.100.37.125").as_deref(), Some("219.100.37"));
        assert_eq!(subnet24_of("not-an-ip"), None);
    }

    #[test]
    fn scoring_caps_speed_at_500_penalizes_high_sessions_and_aggregates_shared_ips() {
        let csv = format!(
            "*vpn_servers\n\
             #HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64\n\
             saturated-official,219.100.37.1,2200000,15,1100000000,Japan,JP,210,86400000,500,9000,2weeks,tsukuba,,{}\n\
             split-a,123.48.124.169,1600000,9,800000000,Japan,JP,95,86400000,500,9000,2weeks,vol,,{}\n\
             split-b,123.48.124.169,1550000,8,820000000,Japan,JP,90,86400000,500,9000,2weeks,vol,,{}\n\
             clean-vol,115.38.22.45,1100000,12,260000000,Japan,JP,25,86400000,500,9000,2weeks,vol,,{}\n\
             ultra-fast-vol,126.206.11.243,1100000,12,2000000000,Japan,JP,25,86400000,500,9000,2weeks,vol,,{}\n",
            sample_ovpn("tcp", "219.100.37.1", 443),
            sample_ovpn("tcp", "123.48.124.169", 1534),
            sample_ovpn("tcp", "123.48.124.169", 1558),
            sample_ovpn("tcp", "115.38.22.45", 1194),
            sample_ovpn("tcp", "126.206.11.243", 1194),
        );
        let ranked = japan_candidates(&csv);
        // 260 Mbps and 2000 Mbps both hit the 500-point speed cap, so equal score/ping/sessions tie.
        let clean = ranked.iter().find(|(s, _)| s.host_name == "clean-vol").unwrap();
        let ultra = ranked.iter().find(|(s, _)| s.host_name == "ultra-fast-vol").unwrap();
        assert_eq!(clean.0.quality_score(), ultra.0.quality_score());

        // Low-load volunteer outranks both the 210-session official relay and the 95+90=185 shared-IP host.
        let pos = |name: &str| ranked.iter().position(|(s, _)| s.host_name == name).unwrap();
        assert!(pos("clean-vol") < pos("saturated-official"));
        assert!(pos("clean-vol") < pos("split-a"));
        assert!(pos("clean-vol") < pos("split-b"));
    }
}
