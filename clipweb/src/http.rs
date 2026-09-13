//! One HTTP request in, one HTTP response out.
//!
//! The bridge answers a phone, not a browser, so this reads the one shape the
//! Shortcuts app sends: a request with a `Content-Length` body, or none at all.
//! It refuses a chunked body rather than guess at one.
//!
//! `httparse` reads the head. It is the parser that `hyper` uses, and the
//! `tailscaled` client in `clipto-host` already depends on it.
//!
//! The bridge closes the connection after each answer. There is no keep-alive,
//! so a request never has to be told apart from the one behind it.

use std::io::{Read, Write};

use anyhow::{bail, Context, Result};
use zeroize::Zeroize;

/// The largest head to read. A request from the phone sends a handful of
/// headers.
const MAX_HEAD: usize = 8 * 1024;

/// The largest body to read. The clipboard holds text, and a phone sends far
/// less than this.
const MAX_BODY: usize = 16 * 1024 * 1024;

/// Room for the headers a client sends.
const MAX_HEADERS: usize = 32;

/// The header that marks a copy as a password, a key, or other secret content.
const SENSITIVE_HEADER: &str = "x-clipto-sensitive";

/// One request from the phone.
pub struct Request {
    pub method: String,
    /// The path, with any query string cut off.
    pub path: String,
    /// The client set `X-Clipto-Sensitive`.
    pub sensitive: bool,
    pub body: Vec<u8>,
}

impl Drop for Request {
    fn drop(&mut self) {
        self.body.zeroize();
    }
}

/// The body holds clipboard plaintext, so this prints its size and never its
/// bytes. A panic message and a log line both go through here.
impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Request")
            .field("method", &self.method)
            .field("path", &self.path)
            .field("sensitive", &self.sensitive)
            .field("body_bytes", &self.body.len())
            .finish()
    }
}

/// Read one request. The body holds clipboard plaintext, so the caller must
/// erase it, which `Drop` does.
pub fn read(stream: &mut impl Read) -> Result<Request> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];

    // Read until the head is complete. A client that sends a head and then
    // goes quiet hits the socket read timeout.
    let (head_len, method, path, length, chunked, sensitive) = loop {
        let read = stream
            .read(&mut chunk)
            .context("failed to read the request")?;
        if read == 0 {
            bail!("the client closed the connection inside the head");
        }
        buffer.extend_from_slice(&chunk[..read]);

        if buffer.len() > MAX_HEAD {
            bail!("the request head is larger than {MAX_HEAD} bytes");
        }

        let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
        let mut request = httparse::Request::new(&mut headers);

        if let httparse::Status::Complete(head_len) =
            request.parse(&buffer).context("the request is not HTTP")?
        {
            let method = request
                .method
                .context("the request has no method")?
                .to_string();
            let target = request.path.context("the request has no path")?;
            let path = target.split('?').next().unwrap_or(target).to_string();

            let mut length = 0usize;
            let mut chunked = false;
            let mut sensitive = false;

            for header in request.headers.iter() {
                if header.name.eq_ignore_ascii_case("content-length") {
                    length = std::str::from_utf8(header.value)
                        .ok()
                        .and_then(|v| v.trim().parse().ok())
                        .context("the request has a Content-Length that is not a number")?;
                } else if header.name.eq_ignore_ascii_case("transfer-encoding") {
                    chunked = true;
                } else if header.name.eq_ignore_ascii_case(SENSITIVE_HEADER) {
                    sensitive = truthy(header.value);
                }
            }

            break (head_len, method, path, length, chunked, sensitive);
        }
    };

    // The last read of the head may have carried body bytes with it.
    chunk.zeroize();

    // A chunked body needs a second parser, and nothing the phone sends uses
    // one. Say so, rather than read the chunk sizes as content.
    if chunked {
        bail!("the bridge reads a Content-Length body only, not a chunked one");
    }
    if length > MAX_BODY {
        bail!("the body is larger than {MAX_BODY} bytes");
    }

    // The first read already took part of the body.
    let mut body = buffer.split_off(head_len);
    buffer.zeroize();
    body.reserve_exact(length.saturating_sub(body.len()));

    while body.len() < length {
        let read = stream.read(&mut chunk).context("failed to read the body")?;
        if read == 0 {
            bail!("the client closed the connection inside the body");
        }
        body.extend_from_slice(&chunk[..read]);
        chunk.zeroize();
    }
    body.truncate(length);

    Ok(Request {
        method,
        path,
        sensitive,
        body,
    })
}

/// Read a header value that means yes.
fn truthy(value: &[u8]) -> bool {
    let value = std::str::from_utf8(value).unwrap_or("").trim();
    value.eq_ignore_ascii_case("1")
        || value.eq_ignore_ascii_case("true")
        || value.eq_ignore_ascii_case("yes")
}

/// Write one answer and close.
///
/// `body` may hold clipboard plaintext. The caller owns it and erases it.
pub fn write(stream: &mut impl Write, status: u16, content_type: &str, body: &[u8]) -> Result<()> {
    let mut head = format!(
        "HTTP/1.1 {status} {}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         Cache-Control: no-store\r\n",
        reason(status),
        body.len()
    );
    if !body.is_empty() {
        head.push_str(&format!("Content-Type: {content_type}\r\n"));
    }
    head.push_str("\r\n");

    stream
        .write_all(head.as_bytes())
        .context("failed to write the answer")?;
    stream
        .write_all(body)
        .context("failed to write the answer body")?;
    stream.flush().context("failed to flush the answer")?;
    Ok(())
}

/// Write an answer that carries a message for the person holding the phone.
pub fn write_text(stream: &mut impl Write, status: u16, message: &str) -> Result<()> {
    let mut body = format!("{message}\n");
    let result = write(stream, status, "text/plain; charset=utf-8", body.as_bytes());
    body.zeroize();
    result
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        503 => "Service Unavailable",
        _ => "Internal Server Error",
    }
}

// ─── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// A reader that gives a few bytes at a time, the way a socket does. The
    /// head, the headers and the body all arrive split.
    struct Trickle {
        bytes: Vec<u8>,
        at: usize,
        each: usize,
    }

    impl Read for Trickle {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            let left = self.bytes.len() - self.at;
            let take = left.min(self.each).min(out.len());
            out[..take].copy_from_slice(&self.bytes[self.at..self.at + take]);
            self.at += take;
            Ok(take)
        }
    }

    fn parse(raw: &str) -> Result<Request> {
        read(&mut std::io::Cursor::new(raw.as_bytes().to_vec()))
    }

    #[test]
    fn reads_a_get() {
        let request = parse("GET /v1/clipboard HTTP/1.1\r\nHost: omen\r\n\r\n").unwrap();
        assert_eq!(request.method, "GET");
        assert_eq!(request.path, "/v1/clipboard");
        assert!(request.body.is_empty());
        assert!(!request.sensitive);
    }

    #[test]
    fn reads_a_post_with_its_body() {
        let request =
            parse("POST /v1/clipboard HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello").unwrap();
        assert_eq!(request.method, "POST");
        assert_eq!(request.body, b"hello");
    }

    /// A socket hands over what has arrived, not what was sent. The body must
    /// survive arriving in pieces.
    #[test]
    fn reads_a_body_that_arrives_in_pieces() {
        let raw = "POST /v1/clipboard HTTP/1.1\r\nContent-Length: 11\r\n\r\nhello world";
        let mut trickle = Trickle {
            bytes: raw.as_bytes().to_vec(),
            at: 0,
            each: 3,
        };
        let request = read(&mut trickle).unwrap();
        assert_eq!(request.body, b"hello world");
    }

    /// The query string belongs to no route here. Cut it off, so a path with
    /// one still reaches the handler.
    #[test]
    fn cuts_the_query_string_off_the_path() {
        let request = parse("GET /v1/clipboard?t=1 HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(request.path, "/v1/clipboard");
    }

    #[test]
    fn reads_the_sensitive_header() {
        let request = parse(
            "POST /v1/clipboard HTTP/1.1\r\nX-Clipto-Sensitive: 1\r\nContent-Length: 2\r\n\r\nhi",
        )
        .unwrap();
        assert!(request.sensitive);
    }

    /// A chunked body needs a second parser. Refuse it, rather than read the
    /// chunk sizes as clipboard content.
    #[test]
    fn refuses_a_chunked_body() {
        let error = parse(
            "POST /v1/clipboard HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\n\r\n",
        )
        .unwrap_err();
        assert!(format!("{error}").contains("chunked"));
    }

    #[test]
    fn refuses_a_head_that_is_too_large() {
        let padding = "x".repeat(MAX_HEAD + 1);
        let error = parse(&format!(
            "GET /v1/clipboard HTTP/1.1\r\nPad: {padding}\r\n\r\n"
        ))
        .unwrap_err();
        assert!(format!("{error}").contains("head"));
    }

    #[test]
    fn refuses_a_body_that_is_too_large() {
        let error = parse(&format!(
            "POST /v1/clipboard HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            MAX_BODY + 1
        ))
        .unwrap_err();
        assert!(format!("{error}").contains("body"));
    }

    #[test]
    fn refuses_a_content_length_that_is_not_a_number() {
        assert!(parse("POST /v1/clipboard HTTP/1.1\r\nContent-Length: soon\r\n\r\n").is_err());
    }

    /// A client that stops in the middle must be an error, not a request with
    /// a body cut short.
    #[test]
    fn refuses_a_body_that_stops_early() {
        let error =
            parse("POST /v1/clipboard HTTP/1.1\r\nContent-Length: 10\r\n\r\nshort").unwrap_err();
        assert!(format!("{error}").contains("body"));
    }

    #[test]
    fn writes_a_head_the_client_can_read() {
        let mut out = Vec::new();
        write(&mut out, 200, "text/plain; charset=utf-8", b"hello").unwrap();
        let answer = String::from_utf8(out).unwrap();

        assert!(answer.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(answer.contains("Content-Length: 5\r\n"));
        assert!(answer.contains("Content-Type: text/plain; charset=utf-8\r\n"));
        assert!(answer.contains("Connection: close\r\n"));
        assert!(answer.contains("Cache-Control: no-store\r\n"));
        assert!(answer.ends_with("\r\n\r\nhello"));
    }

    /// An answer with no body carries no content type either.
    #[test]
    fn writes_an_empty_answer() {
        let mut out = Vec::new();
        write(&mut out, 204, "", b"").unwrap();
        let answer = String::from_utf8(out).unwrap();

        assert!(answer.starts_with("HTTP/1.1 204 No Content\r\n"));
        assert!(answer.contains("Content-Length: 0\r\n"));
        assert!(!answer.contains("Content-Type"));
    }

    #[test]
    fn reads_a_header_that_means_yes() {
        assert!(truthy(b"1"));
        assert!(truthy(b"true"));
        assert!(truthy(b" Yes "));
        assert!(!truthy(b"0"));
        assert!(!truthy(b""));
        assert!(!truthy(b"no"));
    }

    #[test]
    fn names_each_status_it_sends() {
        assert_eq!(reason(200), "OK");
        assert_eq!(reason(403), "Forbidden");
        assert_eq!(reason(429), "Too Many Requests");
        assert_eq!(reason(999), "Internal Server Error");
    }
}
