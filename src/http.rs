//! HTTP 요청/응답 처리와 DMM API 요청 형식

use std::fs::{self, File};
use std::io::{self, Seek};
use std::path::Path;
use std::sync::Arc;

use rustls::ClientConfig;

pub const DMM_HOST: &str = "apidgp-gameplayer.games.dmm.com";
pub const CLIENT_VERSION: &str = "5.5.22";

pub(crate) fn cached_file_has_size(path: &Path, expected_size: u64) -> bool {
    fs::metadata(path).is_ok_and(|meta| meta.is_file() && meta.len() == expected_size)
}

/// Validate a download before replacing its cache entry on the same filesystem.
pub(crate) fn download_file(
    agent: &ureq::Agent,
    url: &str,
    path: &Path,
    expected_size: Option<u64>,
    validate: impl FnOnce(&mut File) -> Result<(), String>,
) -> Result<(), String> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut staged = tempfile::NamedTempFile::new_in(parent)
        .map_err(|e| format!("Could not stage {}: {e}", path.display()))?;
    let response = agent
        .get(url)
        .call()
        .map_err(|e| format!("Failed to download {}: {e}", path.display()))?;
    if response.status() != 200 {
        return Err(format!("Unexpected HTTP {} for {}", response.status(), path.display()));
    }
    let content_length = response
        .header("Content-Length")
        .and_then(|len| len.parse::<u64>().ok());
    let copied = io::copy(&mut response.into_reader(), &mut staged)
        .map_err(|e| format!("Failed to download {}: {e}", path.display()))?;
    if copied == 0 || expected_size.or(content_length).is_some_and(|size| size != copied) {
        return Err(format!("Unexpected download size for {}", path.display()));
    }
    staged
        .as_file_mut()
        .rewind()
        .map_err(|e| format!("Could not read {}: {e}", path.display()))?;
    validate(staged.as_file_mut())?;
    staged
        .persist(path)
        .map_err(|e| format!("Could not save {}: {e}", path.display()))?;
    Ok(())
}

/// DMM 서버 인증서를 검증하는 TLS 설정 (일반 웹 루트 인증서 사용)
pub fn dmm_tls_config() -> Arc<ClientConfig> {
    static CFG: std::sync::OnceLock<Arc<ClientConfig>> = std::sync::OnceLock::new();
    CFG.get_or_init(|| {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        Arc::new(
            ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .expect("TLS versions")
                .with_root_certificates(roots)
                .with_no_client_auth(),
        )
    })
    .clone()
}

/// DMM 플레이어와 같은 형식의 POST 요청
pub fn dmm_post(path: &str, body: &str, token: Option<&str>) -> Vec<u8> {
    let mut r = format!(
        "POST {path} HTTP/1.1\r\nHost: {DMM_HOST}\r\nUser-Agent: DMMGamePlayer5-Win/{CLIENT_VERSION} Electron/34.3.0\r\n\
         Client-App: DMMGamePlayer5\r\nClient-version: {CLIENT_VERSION}\r\nAccept-Language: ja\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    if let Some(t) = token {
        r.push_str("actauth: ");
        r.push_str(t);
        r.push_str("\r\n");
    }
    r.push_str("\r\n");
    r.push_str(body);
    r.into_bytes()
}

pub fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}

/// 응답을 끝까지 받았는지 (Content-Length 또는 chunked 끝 표시 기준)
pub fn is_complete(resp: &[u8]) -> bool {
    let Some(he) = find(resp, b"\r\n\r\n") else {
        return false;
    };
    let head = String::from_utf8_lossy(&resp[..he]).to_ascii_lowercase();
    let body = &resp[he + 4..];
    if head.contains("transfer-encoding: chunked") {
        return dechunk(body).is_some();
    }
    for line in head.lines() {
        if let Some(v) = line.strip_prefix("content-length:") {
            if let Ok(n) = v.trim().parse::<usize>() {
                return body.len() >= n;
            }
        }
    }
    false
}

/// (상태 코드, 본문)
pub fn parse_response(resp: &[u8]) -> Result<(u16, Vec<u8>), String> {
    let he = find(resp, b"\r\n\r\n").ok_or("incomplete HTTP response")?;
    let head = String::from_utf8_lossy(&resp[..he]);
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or("bad HTTP status line")?;
    let body = &resp[he + 4..];
    let body = if head
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        dechunk(body).ok_or("incomplete chunked body")?
    } else {
        body.to_vec()
    };
    Ok((status, body))
}

fn dechunk(mut b: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let le = find(b, b"\r\n")?;
        let size_str = std::str::from_utf8(&b[..le])
            .ok()?
            .split(';')
            .next()?
            .trim();
        let size = usize::from_str_radix(size_str, 16).ok()?;
        b = &b[le + 2..];
        if size == 0 {
            return Some(out);
        }
        if b.len() < size + 2 {
            return None;
        }
        out.extend_from_slice(&b[..size]);
        b = &b[size + 2..];
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::time::Duration;

    #[test]
    fn failed_download_can_be_retried_without_publishing_partial_data() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            for body in [b"short".as_slice(), b"bad-data", b"complete"] {
                let (stream, _) = listener.accept().unwrap();
                stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
                let mut stream = BufReader::new(stream);
                let mut line = String::new();
                loop {
                    line.clear();
                    assert_ne!(stream.read_line(&mut line).unwrap(), 0);
                    if line == "\r\n" {
                        break;
                    }
                }
                stream.get_mut().write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\n").unwrap();
                stream.get_mut().write_all(body).unwrap();
            }
        });
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("release.zip");
        fs::write(&path, b"partial").unwrap();
        assert!(!cached_file_has_size(&path, 8));

        let agent = ureq::AgentBuilder::new().try_proxy_from_env(false).build();
        assert!(download_file(&agent, &url, &path, Some(8), |_| {
            panic!("an interrupted download must fail before validation")
        }).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"partial");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);

        let rejected = download_file(&agent, &url, &path, Some(8), |_| Err("invalid archive".into()));
        assert_eq!(rejected, Err("invalid archive".into()));
        assert_eq!(fs::read(&path).unwrap(), b"partial");

        download_file(&agent, &url, &path, Some(8), |file| {
            let mut data = Vec::new();
            file.read_to_end(&mut data).unwrap();
            assert_eq!(data, b"complete");
            Ok(())
        }).unwrap();
        assert!(cached_file_has_size(&path, 8));
        assert_eq!(fs::read(&path).unwrap(), b"complete");
        server.join().unwrap();
    }
}
