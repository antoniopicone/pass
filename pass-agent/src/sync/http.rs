//! A very small HTTP/1.1 client and server, for the five sync endpoints.
//!
//! ## Why hand-rolled rather than axum plus reqwest
//!
//! Those two would pull in an async runtime and something like fifty
//! crates. For a project whose case against a Bitwarden server is "no
//! remote attack surface and nothing to keep running", growing the
//! dependency tree by an order of magnitude to serve five fixed JSON
//! endpoints is a bad trade — and the rest of this agent is already
//! blocking sockets and threads, so an async runtime would be a second
//! concurrency model living alongside the first.
//!
//! ## Why HTTP at all, given the control socket speaks NDJSON
//!
//! Because the peers are not all Rust. An iOS or Android client gets
//! `URLSession`/`OkHttp` for free and a browser extension gets `fetch`;
//! asking each of them to reimplement a bespoke framing is how a protocol
//! ends up with four subtly different implementations.
//!
//! ## What is deliberately not here
//!
//! Keep-alive, chunked encoding, compression, redirects, TLS. A round of
//! anti-entropy is a handful of requests every few seconds between machines
//! on a private network; connection reuse would save nothing measurable.
//! Confidentiality does not come from the transport here — every payload is
//! sealed and every op is signed before it reaches this module (see
//! [`passlib::sync::crypto`]) — which is what lets the transport stay this
//! small.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Longest request line or header line accepted.
const MAX_LINE: u64 = 8 * 1024;
/// Most headers accepted before a request is treated as hostile.
const MAX_HEADERS: usize = 64;
/// Largest body accepted, in either direction. An op-log transfer for a
/// personal vault is kilobytes; anything at this size is a bug or an
/// attempt to exhaust memory.
pub const MAX_BODY: usize = 8 * 1024 * 1024;
/// How long a peer has to finish talking before it is dropped.
const IO_TIMEOUT: Duration = Duration::from_secs(10);
/// How often the accept loop wakes up to notice a shutdown.
const POLL_INTERVAL: Duration = Duration::from_millis(200);

/// A parsed request: only what the five endpoints actually need.
#[derive(Debug)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub body: Vec<u8>,
}

/// A response to send back.
#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}

impl Response {
    /// A JSON body, or a 500 if it somehow cannot be encoded.
    pub fn json<T: serde::Serialize>(value: &T) -> Self {
        match serde_json::to_vec(value) {
            Ok(body) => Self { status: 200, body },
            Err(e) => Self::error(500, &format!("failed to encode response: {e}")),
        }
    }

    pub fn error(status: u16, message: &str) -> Self {
        Self {
            status,
            body: serde_json::json!({ "error": message }).to_string().into_bytes(),
        }
    }
}

/// Serve until `shutdown` is set, one thread per connection.
///
/// Mirrors the control socket's accept loop: non-blocking accept plus a
/// short sleep, because there is no portable way to interrupt a blocked
/// `accept` and polling costs nothing for a process that spends its life
/// idle.
pub fn serve<F>(listener: TcpListener, shutdown: Arc<AtomicBool>, handler: F)
where
    F: Fn(Request) -> Response + Send + Sync + 'static,
{
    let handler = Arc::new(handler);
    let _ = listener.set_nonblocking(true);

    while !shutdown.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                let handler = Arc::clone(&handler);
                std::thread::spawn(move || {
                    let _ = stream.set_nonblocking(false);
                    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
                    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
                    let _ = handle_connection(stream, handler.as_ref());
                });
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => std::thread::sleep(POLL_INTERVAL),
            Err(_) => std::thread::sleep(POLL_INTERVAL),
        }
    }
}

fn handle_connection<F>(stream: TcpStream, handler: &F) -> io::Result<()>
where
    F: Fn(Request) -> Response,
{
    let mut writer = stream.try_clone()?;
    let mut reader = BufReader::new(stream);

    // A malformed request gets an answer rather than a dropped connection:
    // a peer running an older protocol should see "400" and say so, not
    // "connection reset" and guess.
    let response = match read_request(&mut reader) {
        Ok(request) => handler(request),
        Err(e) => Response::error(400, &e.to_string()),
    };

    write_response(&mut writer, &response)
}

fn read_request(reader: &mut BufReader<TcpStream>) -> io::Result<Request> {
    let request_line = read_line(reader)?;

    // `METHOD /path HTTP/1.1`, all three parts, checked. Taking the first
    // two whitespace-separated tokens and hoping is not enough: a line of
    // prose has two tokens too, and would be dispatched as a request rather
    // than rejected as garbage.
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    let [method, path, version] = parts.as_slice() else {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "malformed request line"));
    };
    if !version.starts_with("HTTP/") || !path.starts_with('/') {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "malformed request line"));
    }
    let (method, path) = (method.to_string(), path.to_string());

    let mut content_length = 0usize;
    for _ in 0..MAX_HEADERS {
        let line = read_line(reader)?;
        if line.is_empty() {
            let mut body = vec![0u8; content_length];
            reader.read_exact(&mut body)?;
            return Ok(Request { method, path, body });
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-length") {
                content_length = value
                    .trim()
                    .parse()
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad content-length"))?;
                if content_length > MAX_BODY {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "request body too large"));
                }
            }
        }
    }

    Err(io::Error::new(io::ErrorKind::InvalidData, "too many headers"))
}

fn read_line(reader: &mut BufReader<TcpStream>) -> io::Result<String> {
    let mut line = String::new();
    // Bounded, so a peer that never sends a newline cannot make this
    // allocate until the process dies.
    reader.take(MAX_LINE).read_line(&mut line)?;
    if line.is_empty() {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "connection closed"));
    }
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

fn write_response(writer: &mut TcpStream, response: &Response) -> io::Result<()> {
    let reason = match response.status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        503 => "Service Unavailable",
        _ => "Error",
    };

    write!(
        writer,
        "HTTP/1.1 {} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response.status,
        response.body.len()
    )?;
    writer.write_all(&response.body)?;
    writer.flush()
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// A request to a peer that did not produce a usable answer.
#[derive(Debug)]
pub enum HttpError {
    /// Could not connect, or the connection broke.
    Unreachable(String),
    /// Answered, but not with what was asked for.
    Status { code: u16, message: String },
    /// Answered with a body that is not the expected JSON.
    Malformed(String),
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpError::Unreachable(e) => write!(f, "unreachable ({e})"),
            HttpError::Status { code, message } => write!(f, "answered {code}: {message}"),
            HttpError::Malformed(e) => write!(f, "malformed answer ({e})"),
        }
    }
}

impl std::error::Error for HttpError {}

pub type HttpResult<T> = std::result::Result<T, HttpError>;

/// `GET addr/path`, decoding the JSON answer.
pub fn get_json<T: serde::de::DeserializeOwned>(addr: &str, path: &str, timeout: Duration) -> HttpResult<T> {
    request(addr, "GET", path, None, timeout)
}

/// `POST addr/path` with a JSON body, decoding the JSON answer.
pub fn post_json<B: serde::Serialize, T: serde::de::DeserializeOwned>(
    addr: &str,
    path: &str,
    body: &B,
    timeout: Duration,
) -> HttpResult<T> {
    let encoded = serde_json::to_vec(body).map_err(|e| HttpError::Malformed(e.to_string()))?;
    request(addr, "POST", path, Some(encoded), timeout)
}

fn request<T: serde::de::DeserializeOwned>(
    addr: &str,
    method: &str,
    path: &str,
    body: Option<Vec<u8>>,
    timeout: Duration,
) -> HttpResult<T> {
    let mut stream = connect(addr, timeout)?;
    stream.set_read_timeout(Some(timeout)).ok();
    stream.set_write_timeout(Some(timeout)).ok();

    let body = body.unwrap_or_default();
    let head = format!(
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );

    stream
        .write_all(head.as_bytes())
        .and_then(|()| stream.write_all(&body))
        .and_then(|()| stream.flush())
        .map_err(|e| HttpError::Unreachable(e.to_string()))?;

    read_response(stream)
}

/// Connect with a timeout, resolving `host:port`.
///
/// `TcpStream::connect` applies no timeout of its own, which on an
/// unreachable peer means waiting out the OS's SYN retries — well over a
/// minute, during which the whole anti-entropy round is stalled behind one
/// device that happens to be asleep.
fn connect(addr: &str, timeout: Duration) -> HttpResult<TcpStream> {
    use std::net::ToSocketAddrs;

    let mut last = HttpError::Unreachable(format!("no address found for {addr}"));
    let resolved = addr
        .to_socket_addrs()
        .map_err(|e| HttpError::Unreachable(format!("cannot resolve {addr}: {e}")))?;

    for socket_addr in resolved {
        match TcpStream::connect_timeout(&socket_addr, timeout) {
            Ok(stream) => return Ok(stream),
            Err(e) => last = HttpError::Unreachable(e.to_string()),
        }
    }
    Err(last)
}

fn read_response<T: serde::de::DeserializeOwned>(stream: TcpStream) -> HttpResult<T> {
    let mut reader = BufReader::new(stream);

    let status_line = read_line(&mut reader).map_err(|e| HttpError::Unreachable(e.to_string()))?;
    let code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| HttpError::Malformed(format!("bad status line: {status_line}")))?;

    let mut content_length = None;
    for _ in 0..MAX_HEADERS {
        let line = read_line(&mut reader).map_err(|e| HttpError::Unreachable(e.to_string()))?;
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse::<usize>().ok();
            }
        }
    }

    // Read to the declared length, or to end-of-stream: the peer closes the
    // connection after answering, so EOF is a valid terminator.
    let mut body = Vec::new();
    match content_length {
        Some(length) if length > MAX_BODY => {
            return Err(HttpError::Malformed("response body too large".to_string()))
        }
        Some(length) => {
            body.resize(length, 0);
            reader.read_exact(&mut body).map_err(|e| HttpError::Unreachable(e.to_string()))?;
        }
        None => {
            reader
                .take(MAX_BODY as u64)
                .read_to_end(&mut body)
                .map_err(|e| HttpError::Unreachable(e.to_string()))?;
        }
    }

    if code != 200 {
        let message = serde_json::from_slice::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(String::from))
            .unwrap_or_else(|| String::from_utf8_lossy(&body).to_string());
        return Err(HttpError::Status { code, message });
    }

    serde_json::from_slice(&body).map_err(|e| HttpError::Malformed(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct Echo {
        value: String,
    }

    /// A server on an ephemeral port, shut down when the guard drops.
    struct TestServer {
        addr: String,
        shutdown: Arc<AtomicBool>,
    }

    impl Drop for TestServer {
        fn drop(&mut self) {
            self.shutdown.store(true, Ordering::SeqCst);
        }
    }

    fn spawn<F>(handler: F) -> TestServer
    where
        F: Fn(Request) -> Response + Send + Sync + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let shutdown = Arc::new(AtomicBool::new(false));

        let handle = Arc::clone(&shutdown);
        std::thread::spawn(move || serve(listener, handle, handler));

        TestServer { addr, shutdown }
    }

    fn timeout() -> Duration {
        Duration::from_secs(5)
    }

    #[test]
    fn a_get_round_trips() {
        let server = spawn(|req| {
            assert_eq!(req.method, "GET");
            Response::json(&Echo { value: req.path })
        });

        let got: Echo = get_json(&server.addr, "/v1/vv", timeout()).unwrap();
        assert_eq!(got.value, "/v1/vv");
    }

    #[test]
    fn a_post_body_arrives_intact() {
        let server = spawn(|req| {
            let echo: Echo = serde_json::from_slice(&req.body).unwrap();
            Response::json(&echo)
        });

        let sent = Echo { value: "a".repeat(10_000) };
        let got: Echo = post_json(&server.addr, "/v1/ops", &sent, timeout()).unwrap();
        assert_eq!(got, sent);
    }

    #[test]
    fn an_error_status_carries_its_message_back() {
        let server = spawn(|_| Response::error(403, "device not trusted"));

        let err = get_json::<Echo>(&server.addr, "/v1/vv", timeout()).unwrap_err();
        match err {
            HttpError::Status { code, message } => {
                assert_eq!(code, 403);
                assert_eq!(message, "device not trusted");
            }
            other => panic!("expected a status error, got {other:?}"),
        }
    }

    #[test]
    fn an_unreachable_peer_fails_fast_rather_than_hanging() {
        // Bound and immediately dropped: nothing is listening on that port.
        let port = {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap().port()
        };

        let started = std::time::Instant::now();
        let err = get_json::<Echo>(&format!("127.0.0.1:{port}"), "/v1/vv", Duration::from_millis(500));
        assert!(matches!(err, Err(HttpError::Unreachable(_))));
        assert!(started.elapsed() < Duration::from_secs(5), "connect ignored its timeout");
    }

    #[test]
    fn a_non_json_answer_is_reported_as_malformed() {
        let server = spawn(|_| Response { status: 200, body: b"not json".to_vec() });

        let err = get_json::<Echo>(&server.addr, "/v1/vv", timeout()).unwrap_err();
        assert!(matches!(err, HttpError::Malformed(_)));
    }

    #[test]
    fn garbage_gets_a_400_instead_of_killing_the_server() {
        let server = spawn(|_| Response::json(&Echo { value: "ok".into() }));

        let mut stream = TcpStream::connect(&server.addr).unwrap();
        stream.write_all(b"this is not http\r\n\r\n").unwrap();
        let mut answer = String::new();
        stream.read_to_string(&mut answer).unwrap();
        assert!(answer.starts_with("HTTP/1.1 400"), "got: {answer}");

        // Still serving.
        let got: Echo = get_json(&server.addr, "/v1/vv", timeout()).unwrap();
        assert_eq!(got.value, "ok");
    }

    #[test]
    fn a_request_line_missing_a_part_is_refused() {
        let server = spawn(|_| Response::json(&Echo { value: "ok".into() }));

        for line in ["GET /v1/vv\r\n\r\n", "GET v1/vv HTTP/1.1\r\n\r\n", "\r\n"] {
            let mut stream = TcpStream::connect(&server.addr).unwrap();
            stream.write_all(line.as_bytes()).unwrap();
            let mut answer = String::new();
            let _ = stream.read_to_string(&mut answer);
            assert!(answer.starts_with("HTTP/1.1 400"), "accepted {line:?}, answered: {answer}");
        }
    }

    #[test]
    fn an_oversized_body_is_refused_before_it_is_allocated() {
        let server = spawn(|_| Response::json(&Echo { value: "ok".into() }));

        let mut stream = TcpStream::connect(&server.addr).unwrap();
        write!(
            stream,
            "POST /v1/ops HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            MAX_BODY + 1
        )
        .unwrap();
        let mut answer = String::new();
        stream.read_to_string(&mut answer).unwrap();
        assert!(answer.starts_with("HTTP/1.1 400"), "got: {answer}");
    }

    #[test]
    fn a_header_flood_is_refused() {
        let server = spawn(|_| Response::json(&Echo { value: "ok".into() }));

        let mut stream = TcpStream::connect(&server.addr).unwrap();
        stream.write_all(b"GET /v1/vv HTTP/1.1\r\n").unwrap();
        for i in 0..MAX_HEADERS + 10 {
            let _ = write!(stream, "X-Pad-{i}: x\r\n");
        }
        let _ = stream.write_all(b"\r\n");

        let mut answer = String::new();
        let _ = stream.read_to_string(&mut answer);
        assert!(answer.starts_with("HTTP/1.1 400"), "got: {answer}");
    }
}
