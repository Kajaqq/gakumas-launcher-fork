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
// Only the Linux Proton setup downloads without reporting progress.
#[cfg_attr(windows, allow(dead_code))]
pub(crate) fn download_file(
    agent: &ureq::Agent,
    url: &str,
    path: &Path,
    expected_size: Option<u64>,
    validate: impl FnOnce(&mut File) -> Result<(), String>,
) -> Result<(), String> {
    download_file_with_progress(agent, url, path, expected_size, &|_, _| {}, validate)
}

/// Report download progress at most this often (in bytes).
const PROGRESS_STEP: u64 = 256 * 1024;

/// Counts bytes read and reports them with the expected total.
struct ProgressReader<'a, R> {
    inner: R,
    done: u64,
    reported: u64,
    total: Option<u64>,
    progress: &'a dyn Fn(u64, Option<u64>),
}

impl<R: io::Read> io::Read for ProgressReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.done += n as u64;
        if n == 0 || self.done - self.reported >= PROGRESS_STEP {
            self.reported = self.done;
            (self.progress)(self.done, self.total);
        }
        Ok(n)
    }
}

/// [`download_file`] that reports `(bytes received, expected total)` as it goes.
/// With a known size it stops reading one byte past it, so an oversized
/// response fails without being downloaded in full.
pub(crate) fn download_file_with_progress(
    agent: &ureq::Agent,
    url: &str,
    path: &Path,
    expected_size: Option<u64>,
    progress: &dyn Fn(u64, Option<u64>),
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
        .set("Accept-Encoding", "identity")
        .call()
        .map_err(|e| format!("Failed to download {}: {e}", path.display()))?;
    if response.status() != 200 {
        return Err(format!("Unexpected HTTP {} for {}", response.status(), path.display()));
    }
    let content_length = response
        .header("Content-Length")
        .and_then(|len| len.parse::<u64>().ok());
    let total = expected_size.or(content_length);
    let mut reader = ProgressReader {
        inner: io::Read::take(response.into_reader(), total.map_or(u64::MAX, |size| size + 1)),
        done: 0,
        reported: 0,
        total,
        progress,
    };
    let copied = io::copy(&mut reader, &mut staged)
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
    ResponseFraming::default().is_complete(resp)
}

/// Tracks HTTP response framing across reads of a growing buffer, so each
/// completion check only looks at bytes it has not seen yet and never copies
/// the body. It agrees with `parse_response`: a chunked response is complete
/// once its zero-size chunk line has arrived.
#[derive(Debug, Default)]
pub struct ResponseFraming {
    /// How far the search for the end of the headers has got.
    head_scan: usize,
    body: Option<BodyFraming>,
    /// Bytes examined so far (for checking that the work stays linear).
    #[cfg(test)]
    examined: usize,
}

#[derive(Debug)]
enum BodyFraming {
    Length(usize),
    Chunked(ChunkProgress),
    /// No length and not chunked: the response ends when the connection closes.
    UntilClose,
}

#[derive(Debug)]
enum ChunkProgress {
    /// The next chunk-size line starts at `start`; no CRLF before `scan`.
    SizeLine { start: usize, scan: usize },
    /// The chunk starting at `start` ends, with its CRLF, at `end`.
    Data { end: usize },
    Done,
    /// A malformed size line: like `dechunk`, never complete.
    Invalid,
}

impl ResponseFraming {
    /// `resp` must be the same buffer as in earlier calls, possibly with more bytes appended.
    pub fn is_complete(&mut self, resp: &[u8]) -> bool {
        if self.body.is_none() {
            // Resume a few bytes back in case the terminator straddles two reads.
            let from = self.head_scan.saturating_sub(3);
            let Some(he) = find(&resp[from..], b"\r\n\r\n").map(|i| from + i) else {
                self.note_examined(resp.len() - from);
                self.head_scan = resp.len();
                return false;
            };
            self.note_examined(he + 4 - from);
            self.body = Some(body_framing(&resp[..he], he + 4));
        }
        let mut examined = 0;
        let complete = match self.body.as_mut().unwrap() {
            BodyFraming::Length(end) => resp.len() >= *end,
            BodyFraming::UntilClose => false,
            BodyFraming::Chunked(progress) => advance_chunks(progress, resp, &mut examined),
        };
        self.note_examined(examined);
        complete
    }

    #[cfg(test)]
    fn note_examined(&mut self, n: usize) {
        self.examined += n;
    }

    #[cfg(not(test))]
    fn note_examined(&mut self, _n: usize) {}
}

fn body_framing(head: &[u8], body_start: usize) -> BodyFraming {
    let head = String::from_utf8_lossy(head).to_ascii_lowercase();
    if head.contains("transfer-encoding: chunked") {
        return BodyFraming::Chunked(ChunkProgress::SizeLine { start: body_start, scan: body_start });
    }
    for line in head.lines() {
        if let Some(v) = line.strip_prefix("content-length:") {
            if let Ok(n) = v.trim().parse::<usize>() {
                return BodyFraming::Length(body_start.saturating_add(n));
            }
        }
    }
    BodyFraming::UntilClose
}

/// Move chunk framing forward over newly received bytes, mirroring `dechunk`.
fn advance_chunks(progress: &mut ChunkProgress, resp: &[u8], examined: &mut usize) -> bool {
    loop {
        match *progress {
            ChunkProgress::Done => return true,
            ChunkProgress::Invalid => return false,
            ChunkProgress::Data { end } => {
                if resp.len() < end {
                    return false;
                }
                *progress = ChunkProgress::SizeLine { start: end, scan: end };
            }
            ChunkProgress::SizeLine { start, scan } => {
                // Resume one byte back in case the CRLF straddles two reads.
                let from = scan.saturating_sub(1).max(start);
                let Some(le) = find(&resp[from..], b"\r\n").map(|i| from + i) else {
                    *examined += resp.len() - from;
                    *progress = ChunkProgress::SizeLine { start, scan: resp.len() };
                    return false;
                };
                *examined += le + 2 - from;
                let size = std::str::from_utf8(&resp[start..le])
                    .ok()
                    .and_then(|line| line.split(';').next())
                    .and_then(|s| usize::from_str_radix(s.trim(), 16).ok());
                *progress = match size {
                    None => ChunkProgress::Invalid,
                    Some(0) => ChunkProgress::Done,
                    Some(size) => match (le + 2).checked_add(size).and_then(|n| n.checked_add(2)) {
                        Some(end) => ChunkProgress::Data { end },
                        None => ChunkProgress::Invalid,
                    },
                };
            }
        }
    }
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

    fn chunked_response(chunks: &[&[u8]]) -> Vec<u8> {
        let mut r = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        for (i, c) in chunks.iter().enumerate() {
            // Mix in a chunk extension to exercise the size-line parser.
            let ext = if i % 2 == 1 { ";name=value" } else { "" };
            r.extend_from_slice(format!("{:x}{ext}\r\n", c.len()).as_bytes());
            r.extend_from_slice(c);
            r.extend_from_slice(b"\r\n");
        }
        r.extend_from_slice(b"0\r\n\r\n");
        r
    }

    /// The original whole-buffer predicate, as an independent reference.
    fn reference_complete(resp: &[u8]) -> bool {
        let Some(he) = find(resp, b"\r\n\r\n") else { return false };
        dechunk(&resp[he + 4..]).is_some()
    }

    #[test]
    fn chunked_framing_agrees_with_dechunk_for_every_split() {
        let resp = chunked_response(&[
            b"hello".as_slice(),
            b"0123456789abcdef0123",
            b"\r\n inside \r\n",
            b"x",
        ]);
        let expected = parse_response(&resp).unwrap();
        assert_eq!(expected.1, b"hello0123456789abcdef0123\r\n inside \r\nx");

        // Whole.
        assert!(ResponseFraming::default().is_complete(&resp));

        // One byte at a time: pending exactly until the reference says complete.
        let mut framing = ResponseFraming::default();
        for end in 1..=resp.len() {
            assert_eq!(framing.is_complete(&resp[..end]), reference_complete(&resp[..end]), "prefix {end}");
        }

        // Every two-piece split, including inside size lines, payloads and terminators.
        for split in 0..=resp.len() {
            let mut framing = ResponseFraming::default();
            assert_eq!(framing.is_complete(&resp[..split]), reference_complete(&resp[..split]), "split {split}");
            assert!(framing.is_complete(&resp), "split {split}");
        }
        assert_eq!(parse_response(&resp).unwrap(), expected);
    }

    #[test]
    fn malformed_chunk_size_stays_pending() {
        let resp = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nabc\r\n0\r\n\r\n";
        let mut framing = ResponseFraming::default();
        for end in 1..=resp.len() {
            assert!(!framing.is_complete(&resp[..end]));
        }
    }

    #[test]
    fn content_length_and_close_delimited_framing_are_unchanged() {
        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let mut framing = ResponseFraming::default();
        for end in 1..resp.len() {
            assert!(!framing.is_complete(&resp[..end]), "prefix {end}");
        }
        assert!(framing.is_complete(resp));
        assert!(is_complete(resp));

        let resp = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nuntil close";
        let mut framing = ResponseFraming::default();
        for end in 1..=resp.len() {
            assert!(!framing.is_complete(&resp[..end]));
        }
    }

    #[test]
    fn chunked_framing_work_is_linear_in_response_size() {
        for chunks in [100usize, 1000, 4000] {
            let payload = vec![b'a'; 7];
            let resp = chunked_response(&vec![payload.as_slice(); chunks]);
            let mut framing = ResponseFraming::default();
            let mut done = false;
            for end in 1..=resp.len() {
                done = framing.is_complete(&resp[..end]);
            }
            assert!(done);
            // Each byte is examined a bounded number of times, however many chunks there are.
            assert!(framing.examined <= 4 * resp.len(), "{chunks} chunks: {} of {}", framing.examined, resp.len());
        }
    }

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

    #[test]
    fn download_reports_progress_and_rejects_an_oversized_body() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let big = vec![b'x'; 3 * PROGRESS_STEP as usize];
        let bodies = [big.clone(), big.clone()];
        let server = std::thread::spawn(move || {
            for body in bodies {
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
                // No Content-Length: the body ends when the connection closes.
                stream.get_mut().write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n").unwrap();
                let _ = stream.get_mut().write_all(&body);
            }
        });
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big.bin");
        let agent = ureq::AgentBuilder::new().try_proxy_from_env(false).build();
        let size = big.len() as u64;

        let seen = std::cell::RefCell::new(Vec::new());
        let report = |done: u64, total: Option<u64>| seen.borrow_mut().push((done, total));
        download_file_with_progress(&agent, &url, &path, Some(size), &report, |_| Ok(())).unwrap();
        let seen = seen.into_inner();
        assert!(seen.len() >= 3, "{seen:?}");
        assert_eq!(seen.last(), Some(&(size, Some(size))));
        assert!(seen.windows(2).all(|w| w[0].0 <= w[1].0));

        // A body longer than the expected size fails without publishing anything.
        let other = dir.path().join("small.bin");
        assert!(download_file(&agent, &url, &other, Some(size / 2), |_| Ok(())).is_err());
        assert!(!other.exists());
        server.join().unwrap();
    }
}
