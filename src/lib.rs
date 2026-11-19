//! 학원 아이돌마스터 런처 (Rust 판)
//!
//! - `vpngate`  : VPN Gate 공개 서버 목록과 OpenVPN 설정 파일 해석
//! - `openvpn`  : OpenVPN 클라이언트 (TCP/UDP, tls-auth/tls-crypt, CBC/GCM). 가상 네트워크 장치를 만들지 않음
//! - `wireguard`: WireGuard 클라이언트 (boringtun). 가상 네트워크 장치를 만들지 않음
//! - `netstack` : 터널 위에서 도는 사용자 공간 TCP/IP 스택 (smoltcp) 과 HTTP(S) 요청
//! - `http`     : HTTP 요청/응답 처리와 DMM API 요청 형식
//! - `platform` : Windows/Linux 공통 실행·암호화·경로 계층
//! - `proton`   : Linux 에서 Proton/Wine 실행 (Windows 를 에뮬레이션하는 DMM 클라이언트)

pub mod platform;
#[cfg(not(windows))]
pub mod proton;

pub mod http;
pub mod launcher;
pub mod netstack;
pub mod openvpn;
pub mod vpngate;
pub mod wireguard;

#[cfg(windows)]
pub mod dpapi;
#[cfg(windows)]
pub mod winutil;
