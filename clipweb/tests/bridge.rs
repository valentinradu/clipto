//! The bridge answers a phone, and it refuses everything else.
//!
//! The test starts a real `clipweb`. A small server on a Unix socket plays
//! `tailscaled`, and a second one plays `clipd`, so the whole path runs: the
//! node identity gate, the routing, and the requests the bridge sends to the
//! daemon.
//!
//! Each request comes from its own source address, because that address is
//! what the gate reads.

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use clipto_ipc::{PasteTarget, Request, Response};

/// How long a test waits for the bridge to open its port.
const DEADLINE: Duration = Duration::from_secs(30);

/// The node that carries `tag:clipto`. The phone.
const PHONE: &str = "127.0.0.41";

/// A node on the tailnet with no `tag:clipto`.
const STRANGER: &str = "127.0.0.42";

/// An address the netmap does not hold at all.
const UNKNOWN: &str = "127.0.0.43";

/// What the fake daemon holds, and what it saw.
struct Daemon {
    clipboard: Vec<u8>,
    seen: Arc<Mutex<Vec<String>>>,
}

// ─── the fake daemon ──────────────────────────────────────────────────────────

/// Answer the requests `clipweb` sends, and record each one.
fn fake_clipd(path: &Path, daemon: Daemon) {
    let listener = UnixListener::bind(path).unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };

            let Ok(request) = clipto_ipc::read_frame::<Request>(&mut stream) else {
                continue;
            };

            let answer = match &request {
                Request::Sync => {
                    daemon.seen.lock().unwrap().push("sync".to_string());
                    Response::Peers { peers: Vec::new() }
                }
                Request::Paste { target } => {
                    daemon
                        .seen
                        .lock()
                        .unwrap()
                        .push(format!("paste {target:?}"));
                    Response::Payload {
                        data: daemon.clipboard.clone(),
                    }
                }
                Request::Copy {
                    payload, sensitive, ..
                } => {
                    daemon.seen.lock().unwrap().push(format!(
                        "copy {} sensitive={sensitive}",
                        String::from_utf8_lossy(payload)
                    ));
                    Response::Ok
                }
                Request::Peers => Response::Peers { peers: Vec::new() },
            };

            let _ = clipto_ipc::write_frame(&mut stream, &answer);
        }
    });
}

// ─── the fake tailnet ─────────────────────────────────────────────────────────

/// Answer `status` with this machine, and `whois` with the node behind one
/// address. `PHONE` carries the tag, `STRANGER` carries none, and the netmap
/// holds no record for anything else.
fn fake_tailscaled(path: &Path, own: String) {
    let listener = UnixListener::bind(path).unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };

            // Read the whole head before answering. A socket hands over what
            // has arrived, so one read can hold part of the request line, and
            // closing with the rest unread would reset the connection and
            // throw the answer away.
            let Some(head) = read_head(&mut stream) else {
                continue;
            };

            let body = if head.contains("/localapi/v0/whois") {
                whois(&head)
            } else {
                serde_json::json!({ "Self": { "TailscaleIPs": [own] }, "Peer": {} }).to_string()
            };

            let answer = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(answer.as_bytes());
            let _ = stream.shutdown(Shutdown::Write);
        }
    });
}

/// Read an HTTP head, up to and including the blank line that ends it.
fn read_head(stream: &mut UnixStream) -> Option<String> {
    let mut head = Vec::new();
    let mut chunk = [0u8; 256];

    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
        let read = stream.read(&mut chunk).ok()?;
        if read == 0 {
            return None;
        }
        head.extend_from_slice(&chunk[..read]);
        if head.len() > 8192 {
            return None;
        }
    }

    Some(String::from_utf8_lossy(&head).to_string())
}

/// The node behind the address in a whois request line.
///
/// The port is percent-encoded, so the address itself stays literal and a
/// substring match finds it.
fn whois(head: &str) -> String {
    if head.contains(&format!("{PHONE}%3A")) {
        serde_json::json!({
            "Node": { "Name": "iphone.example.ts.", "Tags": ["tag:admin", "tag:clipto"] },
        })
        .to_string()
    } else if head.contains(&format!("{STRANGER}%3A")) {
        serde_json::json!({ "Node": { "Name": "stranger.example.ts." } }).to_string()
    } else {
        // What `tailscaled` sends for an address the netmap does not hold.
        "{}".to_string()
    }
}

// ─── starting the bridge ──────────────────────────────────────────────────────

struct Bridge {
    child: Child,
    target: SocketAddr,
    seen: Arc<Mutex<Vec<String>>>,
    /// Held so the temporary directory outlives the bridge.
    _root: tempfile::TempDir,
}

impl Drop for Bridge {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Bridge {
    fn start(address: &str, port: u16, clipboard: &[u8]) -> Bridge {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().to_path_buf();
        let runtime = home.join("run");
        let config = home.join("config");
        std::fs::create_dir_all(&runtime).unwrap();
        std::fs::create_dir_all(config.join("clipto")).unwrap();

        // `web_device` is empty, because the test binds a loopback address and
        // there is no `tailscale0` here to bind.
        std::fs::write(
            config.join("clipto").join("config.toml"),
            format!("web_port = {port}\nweb_device = \"\"\npeer_refresh = 1\n"),
        )
        .unwrap();

        let seen = Arc::new(Mutex::new(Vec::new()));
        fake_clipd(
            &runtime.join("clipto.sock"),
            Daemon {
                clipboard: clipboard.to_vec(),
                seen: Arc::clone(&seen),
            },
        );

        let tailscaled = home.join("tailscaled.sock");
        fake_tailscaled(&tailscaled, address.to_string());

        let child = Command::new(env!("CARGO_BIN_EXE_clipweb"))
            .env_clear()
            .env("HOME", &home)
            .env("XDG_RUNTIME_DIR", &runtime)
            .env("XDG_CONFIG_HOME", &config)
            .env("CLIPTO_TAILSCALED_SOCK", &tailscaled)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("failed to start clipweb");

        let target: SocketAddr = format!("{address}:{port}").parse().unwrap();
        wait_until_open(target);

        Bridge {
            child,
            target,
            seen,
            _root: root,
        }
    }

    /// Send one raw request from a source address, and read the whole answer.
    fn ask(&self, source: &str, raw: &str) -> String {
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )
        .unwrap();

        let from: SocketAddr = format!("{source}:0").parse().unwrap();
        socket.bind(&from.into()).unwrap();
        socket.connect(&self.target.into()).unwrap();

        let mut stream: TcpStream = socket.into();
        stream
            .set_read_timeout(Some(Duration::from_secs(20)))
            .unwrap();
        stream.write_all(raw.as_bytes()).unwrap();

        let mut answer = Vec::new();
        stream.read_to_end(&mut answer).unwrap();
        String::from_utf8_lossy(&answer).to_string()
    }

    /// What the fake daemon was asked to do.
    fn seen(&self) -> Vec<String> {
        self.seen.lock().unwrap().clone()
    }
}

fn wait_until_open(target: SocketAddr) {
    let deadline = Instant::now() + DEADLINE;
    loop {
        match TcpStream::connect(target) {
            Ok(_) => return,
            Err(e) => assert!(Instant::now() < deadline, "{target} never opened: {e}"),
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

// ─── the tests ────────────────────────────────────────────────────────────────

/// The phone carries the tag, so it gets the clipboard. The bridge syncs
/// first, so the machine it reached holds the newest copy before it answers.
#[test]
fn the_phone_gets_the_clipboard() {
    let bridge = Bridge::start("127.0.0.40", 17870, b"what omen copied");

    let answer = bridge.ask(
        PHONE,
        "GET /v1/clipboard HTTP/1.1\r\nHost: clipto.example.ts\r\n\r\n",
    );

    assert!(answer.starts_with("HTTP/1.1 200 OK\r\n"), "{answer}");
    assert!(answer.ends_with("what omen copied"), "{answer}");

    assert_eq!(
        bridge.seen(),
        vec!["sync".to_string(), format!("paste {:?}", PasteTarget::Web)],
        "the bridge must sync before it pastes, and paste for the web target"
    );
}

/// A node with no `tag:clipto` gets nothing, and the daemon is never asked.
/// The gate runs before the bridge reads a request.
#[test]
fn a_node_without_the_tag_is_refused() {
    let bridge = Bridge::start("127.0.0.44", 17871, b"not for you");

    let answer = bridge.ask(STRANGER, "GET /v1/clipboard HTTP/1.1\r\n\r\n");

    assert!(answer.starts_with("HTTP/1.1 403 Forbidden\r\n"), "{answer}");
    assert!(answer.contains("tag:clipto"), "{answer}");
    assert!(!answer.contains("not for you"), "{answer}");
    assert!(
        bridge.seen().is_empty(),
        "the bridge asked the daemon for a node it refused: {:?}",
        bridge.seen()
    );
}

/// An address the netmap does not hold is refused too. `tailscaled` answers
/// such a request with an empty object, not an error.
#[test]
fn an_address_the_netmap_does_not_hold_is_refused() {
    let bridge = Bridge::start("127.0.0.45", 17872, b"not for you");

    let answer = bridge.ask(UNKNOWN, "GET /v1/clipboard HTTP/1.1\r\n\r\n");

    assert!(answer.starts_with("HTTP/1.1 403 Forbidden\r\n"), "{answer}");
    assert!(bridge.seen().is_empty());
}

/// A copy from the phone reaches the daemon as an ordinary user copy, so the
/// daemon raises the generation and announces it to every machine.
#[test]
fn the_phone_copies() {
    let bridge = Bridge::start("127.0.0.46", 17873, b"");

    let answer = bridge.ask(
        PHONE,
        "POST /v1/clipboard HTTP/1.1\r\nContent-Length: 14\r\n\r\nfrom the phone",
    );

    assert!(answer.starts_with("HTTP/1.1 204 No Content\r\n"), "{answer}");
    assert_eq!(bridge.seen(), vec!["copy from the phone sensitive=false"]);
}

/// The header marks a copy sensitive, and the daemon decides what that means.
#[test]
fn the_phone_marks_a_copy_sensitive() {
    let bridge = Bridge::start("127.0.0.47", 17874, b"");

    let answer = bridge.ask(
        PHONE,
        "POST /v1/clipboard HTTP/1.1\r\nX-Clipto-Sensitive: 1\r\nContent-Length: 8\r\n\r\na secret",
    );

    assert!(answer.starts_with("HTTP/1.1 204 No Content\r\n"), "{answer}");
    assert_eq!(bridge.seen(), vec!["copy a secret sensitive=true"]);
}

/// The bridge serves one path. Anything else is a mistake worth naming.
#[test]
fn another_path_is_not_found() {
    let bridge = Bridge::start("127.0.0.48", 17875, b"");

    let answer = bridge.ask(PHONE, "GET / HTTP/1.1\r\n\r\n");

    assert!(answer.starts_with("HTTP/1.1 404 Not Found\r\n"), "{answer}");
    assert!(answer.contains("/v1/clipboard"), "{answer}");
    assert!(bridge.seen().is_empty());
}

#[test]
fn another_method_is_refused() {
    let bridge = Bridge::start("127.0.0.49", 17876, b"");

    let answer = bridge.ask(PHONE, "DELETE /v1/clipboard HTTP/1.1\r\n\r\n");

    assert!(
        answer.starts_with("HTTP/1.1 405 Method Not Allowed\r\n"),
        "{answer}"
    );
    assert!(bridge.seen().is_empty());
}

/// A copy with no body is a mistake in the shortcut, not a reason to clear the
/// clipboard on every machine.
#[test]
fn a_copy_with_no_body_is_refused() {
    let bridge = Bridge::start("127.0.0.50", 17877, b"");

    let answer = bridge.ask(PHONE, "POST /v1/clipboard HTTP/1.1\r\nContent-Length: 0\r\n\r\n");

    assert!(answer.starts_with("HTTP/1.1 400 Bad Request\r\n"), "{answer}");
    assert!(bridge.seen().is_empty());
}
