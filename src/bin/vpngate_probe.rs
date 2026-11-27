//! VPN Gate 연결 시험 프로그램
//!
//! Windows 네트워크 설정을 바꾸지 않고, 프로그램 안의 OpenVPN + TCP/IP 스택으로
//! VPN Gate 일본 서버에 붙어 DMM API 를 호출해 봅니다.
//!
//! 사용법: vpngate_probe [--data-dir <PowerShell 판 폴더>] [--server <호스트 이름>] [--tries <N>]
//! data-dir 에 dmm_login.dat / dmm_device.json 이 있으면 DMM API 까지 시험합니다. 토큰 값은 출력하지 않습니다.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use gakumas_launcher::{http, netstack::TunnelStack, openvpn::Tunnel, platform, vpngate};

fn main() {
    if let Err(e) = run() {
        println!("\nError: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut data_dir = PathBuf::from("..");
    let mut only: Option<String> = None;
    let mut tries = 4usize;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--data-dir" => {
                data_dir = PathBuf::from(args.next().ok_or("--data-dir needs a value")?)
            }
            "--server" => only = Some(args.next().ok_or("--server needs a value")?),
            "--tries" => {
                tries = args
                    .next()
                    .and_then(|v| v.parse().ok())
                    .ok_or("--tries needs a number")?
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }

    let token = std::fs::read_to_string(data_dir.join("dmm_login.dat"))
        .ok()
        .and_then(|t| platform::unprotect_powershell_secure_string(&t).ok());
    let device: serde_json::Value = std::fs::read_to_string(data_dir.join("dmm_device.json"))
        .ok()
        .and_then(|t| serde_json::from_str(t.trim_start_matches('\u{feff}')).ok())
        .unwrap_or(serde_json::Value::Null);
    println!(
        "Login token: {} / device info: {}",
        if token.is_some() {
            "present (value not shown)"
        } else {
            "missing - skipping the DMM API test"
        },
        if device.is_object() {
            "present"
        } else {
            "missing"
        }
    );

    println!("\n[1] Fetching the VPN Gate server list...");
    let t0 = Instant::now();
    let raw = vpngate::fetch_server_list_raw()?;
    let mut candidates = vpngate::japan_candidates(&raw);
    if let Some(name) = &only {
        candidates.retain(|(s, _)| &s.host_name == name);
    }
    println!(
        "    {} Japanese servers ({} ms)",
        candidates.len(),
        t0.elapsed().as_millis()
    );

    for (server, cfg) in candidates.iter().take(tries) {
        println!(
            "\n[2] Trying {} ({}) {}:{}",
            server.host_name,
            if server.is_official() {
                "University of Tsukuba"
            } else {
                "volunteer"
            },
            vpngate::remote_ip(cfg),
            cfg.remotes[0].port
        );
        let t0 = Instant::now();
        let mut log = |m: String| println!("    {:>6} ms  {m}", t0.elapsed().as_millis());
        let tun = match Tunnel::connect(cfg, &server.tls_name(), &mut log) {
            Ok(t) => t,
            Err(e) => {
                println!("    Failed: {e}");
                continue;
            }
        };
        let mut stack = TunnelStack::new(tun)?;
        let t_dns = Instant::now();
        match stack.resolve_in_tunnel(http::DMM_HOST) {
            Ok(ip) => println!(
                "    DMM address (DNS in tunnel): {ip} ({} ms)",
                t_dns.elapsed().as_millis()
            ),
            Err(e) => println!("    DNS in tunnel failed, using system DNS: {e}"),
        }

        println!("\n[3] Check the connected country inside the tunnel (ipinfo.io, plain HTTP)");
        let t1 = Instant::now();
        let req = b"GET /country HTTP/1.1\r\nHost: ipinfo.io\r\nUser-Agent: curl/8.0\r\nConnection: close\r\n\r\n";
        match stack.request("ipinfo.io", 80, None, req, Duration::from_secs(20)) {
            Ok(r) => {
                let (status, body) = http::parse_response(&r)?;
                println!(
                    "    HTTP {status}, country: {} ({} ms)",
                    String::from_utf8_lossy(&body).trim(),
                    t1.elapsed().as_millis()
                );
            }
            Err(e) => println!("    Failed: {e}"),
        }

        if let Some(tok) = &token {
            println!("\n[4] DMM API call (HTTPS inside the tunnel, DMM certificate verified)");
            let launch_body = serde_json::json!({
                "product_id": "gakumas", "game_type": "GCL", "game_os": "win", "launch_type": "LIB",
                "mac_address": device["mac_address"], "hdd_serial": device["hdd_serial"],
                "motherboard": device["motherboard"], "user_os": "win"
            })
            .to_string();
            let calls = [
                ("userinfo", "/v5/userinfo", "{}".to_string()),
                ("launch/cl", "/v5/r2/launch/cl", launch_body),
            ];
            let tls = http::dmm_tls_config();
            for (name, path, body) in calls {
                let t1 = Instant::now();
                let req = http::dmm_post(path, &body, Some(tok));
                match stack.request(
                    http::DMM_HOST,
                    443,
                    Some(tls.clone()),
                    &req,
                    Duration::from_secs(30),
                ) {
                    Ok(r) => {
                        let (status, body) = http::parse_response(&r)?;
                        let v: serde_json::Value =
                            serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
                        let mut line = format!(
                            "    {name}: HTTP {status}, result_code={}",
                            v["result_code"]
                        );
                        if name == "launch/cl" && v["result_code"] == 100 {
                            let args = v["data"]["execute_args"].as_str().unwrap_or("");
                            let names: Vec<&str> = args
                                .split_whitespace()
                                .filter_map(|a| {
                                    a.strip_prefix('/').and_then(|a| a.split('=').next())
                                })
                                .collect();
                            line.push_str(&format!(
                                " (launch argument entries: {}, latest version {})",
                                names.join(", "),
                                v["data"]["latest_version"].as_str().unwrap_or("?")
                            ));
                        }
                        println!("{line} ({} ms)", t1.elapsed().as_millis());
                    }
                    Err(e) => println!("    {name}: failed: {e}"),
                }
            }
        }
        return Ok(());
    }
    Err("All attempted servers failed to connect".into())
}
