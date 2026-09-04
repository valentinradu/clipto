//! Two daemons share one clipboard.
//!
//! The test starts a real `clipd` for each machine. A small server on a Unix
//! socket plays `tailscaled`, and each daemon binds its own loopback address,
//! so the whole path runs: discovery, the Noise handshake, the announcement,
//! the fetch and the last writer wins rule.

use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use clipto_ipc::{CopySource, PeerInfo, Request, Response};

/// How long a test waits for a payload to cross.
const DEADLINE: Duration = Duration::from_secs(45);

// ─── one machine ──────────────────────────────────────────────────────────────

struct Machine {
    name: String,
    child: Child,
    socket: PathBuf,
    log: PathBuf,
}

impl Drop for Machine {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Machine {
    fn ask(&self, request: &Request) -> Response {
        let mut stream = UnixStream::connect(&self.socket)
            .unwrap_or_else(|e| panic!("cannot reach {}: {e}", self.name));

        // Not `clipto_ipc::set_timeouts`. That timeout is 5 seconds, which fits
        // a release build: the 5 MB test then takes about 100 ms. A test build
        // has no optimization, and ChaCha20-Poly1305 costs about 1.2 seconds
        // for each 5 MB pass. The paste path makes five passes, so the answer
        // arrives at about the 5 second mark. Give the test room, so it
        // measures the daemon and not the build profile.
        let patience = Some(Duration::from_secs(60));
        stream.set_read_timeout(patience).unwrap();
        stream.set_write_timeout(patience).unwrap();

        clipto_ipc::write_frame(&mut stream, request).unwrap();
        clipto_ipc::read_frame(&mut stream).unwrap()
    }

    fn copy(&self, payload: &[u8], sensitive: bool) {
        let answer = self.ask(&Request::Copy {
            payload: payload.to_vec(),
            source: CopySource::User,
            sensitive,
        });
        assert!(
            matches!(answer, Response::Ok),
            "{} refused the copy: {answer:?}",
            self.name
        );
    }

    fn paste(&self) -> Result<Vec<u8>, String> {
        match self.ask(&Request::Paste) {
            Response::Payload { data } => Ok(data),
            Response::Error { message } => Err(message),
            other => panic!("{} answered a paste with {other:?}", self.name),
        }
    }

    /// Everything the daemon wrote to its log so far.
    fn log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    fn peers(&self) -> Vec<PeerInfo> {
        match self.ask(&Request::Peers) {
            Response::Peers { peers } => peers,
            other => panic!("{} answered a peer list with {other:?}", self.name),
        }
    }

    /// Block until this machine has shaken hands with `hostname`.
    fn wait_for(&self, hostname: &str) {
        let deadline = Instant::now() + DEADLINE;
        while Instant::now() < deadline {
            if self
                .peers()
                .iter()
                .any(|p| p.hostname == hostname && p.state == "joined")
            {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!("{} never joined {hostname}: {:?}", self.name, self.peers());
    }

    /// Block until a paste on this machine gives `expected`.
    fn wait_for_payload(&self, expected: &[u8]) {
        let deadline = Instant::now() + DEADLINE;
        let mut last = String::new();
        while Instant::now() < deadline {
            match self.paste() {
                Ok(data) if data == expected => return,
                Ok(data) => last = format!("{} bytes that do not match", data.len()),
                Err(message) => last = message,
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        panic!("{} never got the payload: {last}", self.name);
    }
}

// ─── the fake tailnet ─────────────────────────────────────────────────────────

/// Answer every request with the same tailnet status.
fn fake_tailscaled(path: &Path, body: String) {
    let listener = UnixListener::bind(path).unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut request = [0u8; 1024];
            let _ = stream.read(&mut request);

            let answer = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(answer.as_bytes());
            let _ = stream.shutdown(Shutdown::Both);
        }
    });
}

/// The status one machine reads: itself, and every other machine as a peer.
fn status(own: &str, peers: &[(&str, &str)]) -> String {
    let peers: serde_json::Map<String, serde_json::Value> = peers
        .iter()
        .map(|(hostname, address)| {
            (
                format!("nodekey:{hostname}"),
                serde_json::json!({
                    "HostName": hostname,
                    "TailscaleIPs": [address],
                    "Online": true,
                }),
            )
        })
        .collect();

    serde_json::json!({
        "Self": { "TailscaleIPs": [own] },
        "Peer": peers,
    })
    .to_string()
}

// ─── starting a machine ───────────────────────────────────────────────────────

struct Tailnet {
    root: tempfile::TempDir,
    port: u16,
    /// The shared credential. Every machine that holds it joins.
    credential: PathBuf,
}

impl Tailnet {
    fn new(port: u16) -> Self {
        let root = tempfile::tempdir().unwrap();
        let credential = root.path().join("clipto-psk");
        std::fs::write(&credential, [42u8; 32]).unwrap();

        Tailnet {
            root,
            port,
            credential,
        }
    }

    /// Start one daemon. `peers` is what its `tailscaled` reports.
    fn start(&self, name: &str, address: &str, peers: &[(&str, &str)]) -> Machine {
        self.start_with(name, address, peers, &self.credential)
    }

    fn start_with(
        &self,
        name: &str,
        address: &str,
        peers: &[(&str, &str)],
        credential: &Path,
    ) -> Machine {
        let home = self.root.path().join(name);
        let runtime = home.join("run");
        let state = home.join("state");
        let config = home.join("config");
        std::fs::create_dir_all(&runtime).unwrap();
        std::fs::create_dir_all(&state).unwrap();
        std::fs::create_dir_all(config.join("clipto")).unwrap();

        std::fs::write(
            config.join("clipto").join("config.toml"),
            format!(
                "port = {}\npeer_refresh = 1\nfetch_timeout = 10\n",
                self.port
            ),
        )
        .unwrap();

        // The encryption key differs per machine, exactly as the TPM makes it.
        let key = home.join("clipto-key");
        std::fs::write(&key, [name.as_bytes()[0]; 32]).unwrap();

        let tailscaled = home.join("tailscaled.sock");
        fake_tailscaled(&tailscaled, status(address, peers));

        // Keep the log, so a test can read what the daemon reported.
        let log = home.join("clipd.log");
        let child = Command::new(env!("CARGO_BIN_EXE_clipd"))
            .env_clear()
            .env("HOME", &home)
            .env("XDG_RUNTIME_DIR", &runtime)
            .env("XDG_STATE_HOME", &state)
            .env("XDG_CONFIG_HOME", &config)
            .env("CLIPTO_KEY_FILE", &key)
            .env("CLIPTO_PSK_FILE", credential)
            .env("CLIPTO_TAILSCALED_SOCK", &tailscaled)
            .stdout(Stdio::null())
            .stderr(Stdio::from(std::fs::File::create(&log).unwrap()))
            .spawn()
            .expect("failed to start clipd");

        let socket = runtime.join("clipto.sock");
        let deadline = Instant::now() + DEADLINE;
        while !socket.exists() {
            assert!(Instant::now() < deadline, "{name} never opened its socket");
            std::thread::sleep(Duration::from_millis(50));
        }

        Machine {
            name: name.to_string(),
            child,
            socket,
            log,
        }
    }
}

/// Block until the daemon binds its port, then connect.
fn connect_when_open(address: &str, port: u16) -> TcpStream {
    let deadline = Instant::now() + DEADLINE;
    loop {
        match TcpStream::connect((address, port)) {
            Ok(stream) => return stream,
            Err(e) => assert!(
                Instant::now() < deadline,
                "{address}:{port} never opened: {e}"
            ),
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

// ─── the tests ────────────────────────────────────────────────────────────────

/// A copy on one machine becomes a paste on the other machine, both ways.
///
/// The `iphone` node runs nothing. It must not break the discovery.
#[test]
fn a_copy_crosses_in_both_directions() {
    let net = Tailnet::new(17851);
    let omen = net.start(
        "omen",
        "127.0.0.2",
        &[("edge", "127.0.0.3"), ("iphone", "127.0.0.9")],
    );
    let edge = net.start(
        "edge",
        "127.0.0.3",
        &[("omen", "127.0.0.2"), ("iphone", "127.0.0.9")],
    );

    omen.wait_for("edge");
    edge.wait_for("omen");

    omen.copy(b"from omen", false);
    edge.wait_for_payload(b"from omen");

    edge.copy(b"from edge", false);
    omen.wait_for_payload(b"from edge");
}

/// A payload larger than `inline_limit` travels as a promise. The far machine
/// fetches the bytes when a client pastes.
#[test]
fn a_large_payload_crosses() {
    let net = Tailnet::new(17852);
    let omen = net.start("omen", "127.0.0.4", &[("edge", "127.0.0.5")]);
    let edge = net.start("edge", "127.0.0.5", &[("omen", "127.0.0.4")]);

    omen.wait_for("edge");
    edge.wait_for("omen");

    let payload: Vec<u8> = (0..5 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
    omen.copy(&payload, false);
    edge.wait_for_payload(&payload);
}

/// A machine that holds the wrong credential must not get the clipboard, and
/// the machine that owns the payload must send nothing.
#[test]
fn a_wrong_credential_gets_nothing() {
    let net = Tailnet::new(17853);
    let wrong = net.root.path().join("wrong-psk");
    std::fs::write(&wrong, [7u8; 32]).unwrap();

    let omen = net.start("omen", "127.0.0.6", &[("edge", "127.0.0.7")]);
    let edge = net.start_with("edge", "127.0.0.7", &[("omen", "127.0.0.6")], &wrong);

    omen.copy(b"a secret plan", false);

    // Give the announcement more than enough time to arrive.
    std::thread::sleep(Duration::from_secs(3));

    assert!(
        edge.paste().is_err(),
        "the machine with the wrong credential took the payload"
    );
    assert!(edge.peers().iter().all(|p| p.state != "joined"));
}

/// The origin stops. The paste must fail with a clear message, and it must not
/// serve the older content.
#[test]
fn a_paste_fails_when_the_origin_is_gone() {
    let net = Tailnet::new(17854);
    let omen = net.start("omen", "127.0.0.8", &[("edge", "127.0.0.10")]);
    let edge = net.start("edge", "127.0.0.10", &[("omen", "127.0.0.8")]);

    omen.wait_for("edge");
    edge.wait_for("omen");

    // A small copy travels with the announcement, so `edge` holds these bytes.
    omen.copy(b"the older content", false);
    edge.wait_for_payload(b"the older content");

    // A large copy travels as a promise. `edge` fetches it only when a client
    // pastes, and nothing pastes here.
    let payload: Vec<u8> = (0..2 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
    omen.copy(&payload, false);
    std::thread::sleep(Duration::from_secs(2));

    drop(omen);

    let message = edge
        .paste()
        .expect_err("edge served the older content instead of failing");
    assert!(
        message.contains("omen"),
        "the message must name the machine it cannot reach: {message}"
    );
}

/// A small payload travels WITH the announcement, so the far machine holds the
/// bytes and never needs a fetch.
///
/// Nothing pastes before the origin stops: a paste would fetch the bytes and
/// hide the very fault this test looks for. Every session opens with a hello
/// naming the same copy, so the promise lands first and the announcement's
/// bytes arrive as "not newer" — they must still fill that promise.
#[test]
fn a_small_payload_needs_no_fetch() {
    let net = Tailnet::new(17859);
    let omen = net.start("omen", "127.0.0.18", &[("edge", "127.0.0.19")]);
    let edge = net.start("edge", "127.0.0.19", &[("omen", "127.0.0.18")]);

    omen.wait_for("edge");
    edge.wait_for("omen");

    omen.copy(b"small enough to ride along", false);
    std::thread::sleep(Duration::from_secs(2));
    drop(omen);

    assert_eq!(
        edge.paste().expect("edge kept only a promise it can no longer fetch"),
        b"small enough to ride along"
    );
}

/// A sensitive payload never travels with the announcement. The far machine
/// therefore holds nothing once the origin stops.
#[test]
fn a_sensitive_payload_never_travels_with_the_announcement() {
    let net = Tailnet::new(17855);
    let omen = net.start("omen", "127.0.0.11", &[("edge", "127.0.0.12")]);
    let edge = net.start("edge", "127.0.0.12", &[("omen", "127.0.0.11")]);

    omen.wait_for("edge");
    edge.wait_for("omen");

    // Small enough to travel with the announcement, if it were allowed to.
    omen.copy(b"a password", true);
    std::thread::sleep(Duration::from_secs(2));

    // While the origin runs, the far machine fetches the bytes.
    edge.wait_for_payload(b"a password");

    // A second copy, and this time nothing pastes it before the origin stops.
    omen.copy(b"another password", true);
    std::thread::sleep(Duration::from_secs(2));
    drop(omen);

    assert!(
        edge.paste().is_err(),
        "the announcement carried the sensitive payload"
    );
}

/// Two machines copy at nearly the same moment. Both must agree which copy
/// wins, whichever machine the user asks.
#[test]
fn two_machines_agree_on_the_winner() {
    let net = Tailnet::new(17857);
    let omen = net.start("omen", "127.0.0.15", &[("edge", "127.0.0.16")]);
    let edge = net.start("edge", "127.0.0.16", &[("omen", "127.0.0.15")]);

    omen.wait_for("edge");
    edge.wait_for("omen");

    std::thread::scope(|scope| {
        scope.spawn(|| omen.copy(b"from omen", false));
        scope.spawn(|| edge.copy(b"from edge", false));
    });

    // Both machines settle on one payload. Which one depends on the machine
    // identifiers, so the test only asks that the two agree.
    let deadline = Instant::now() + DEADLINE;
    loop {
        let here = omen.paste();
        let there = edge.paste();
        if let (Ok(here), Ok(there)) = (&here, &there) {
            if here == there {
                assert!(here == b"from omen" || here == b"from edge");
                return;
            }
        }
        assert!(
            Instant::now() < deadline,
            "the machines never agreed: {here:?} against {there:?}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// A node on the tailnet that holds no credential reaches the port, because
/// the tailnet is the transport and not the identity. The daemon must reject
/// it, log the address, send it nothing, and keep working.
#[test]
fn a_probe_with_no_credential_is_rejected_and_logged() {
    let net = Tailnet::new(17858);
    let omen = net.start("omen", "127.0.0.17", &[]);
    omen.copy(b"not for you", false);

    // The listener comes up after the discovery thread reads the tailnet, so
    // it is later than the Unix socket that `start` waits for.
    let mut probe = connect_when_open("127.0.0.17", 17858);
    probe
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();

    // Anything that is not a Noise handshake message. The daemon must not
    // answer it with a version, a generation number or a size.
    probe.write_all(b"\x00\x08probe!!!").unwrap();

    let mut answer = Vec::new();
    probe.read_to_end(&mut answer).unwrap();
    assert!(
        answer.is_empty(),
        "the daemon sent {} bytes to a peer that proved nothing",
        answer.len()
    );

    let deadline = Instant::now() + DEADLINE;
    while !omen.log().contains("rejected 127.0.0.") {
        assert!(
            Instant::now() < deadline,
            "the daemon did not log the address: {}",
            omen.log()
        );
        std::thread::sleep(Duration::from_millis(100));
    }

    // The daemon keeps working.
    assert_eq!(omen.paste().unwrap(), b"not for you");
}

/// A machine that sleeps misses the announcements. It greets every machine at
/// start, and takes the highest generation from the answers.
#[test]
fn a_machine_catches_up_when_it_comes_back() {
    let net = Tailnet::new(17856);
    let omen = net.start("omen", "127.0.0.13", &[("edge", "127.0.0.14")]);

    // `edge` is not running yet, so it misses this copy.
    omen.copy(b"while edge slept", false);
    std::thread::sleep(Duration::from_secs(2));

    let edge = net.start("edge", "127.0.0.14", &[("omen", "127.0.0.13")]);
    edge.wait_for_payload(b"while edge slept");
}
