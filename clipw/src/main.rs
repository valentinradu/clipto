//! The bridge between a phone and the clipboard.
//!
//! A phone cannot run `clipd`. It holds no `clipto-key`, it cannot run the
//! Noise handshake, and iOS lets nothing listen on a port in the background. So
//! it stays a client of the machines, never a machine.
//!
//! The gate is the node identity, not a token. A packet reaches this listener
//! only out of a WireGuard tunnel, and only the holder of that node's private
//! key can put one there. `tailscaled` names the node behind the source
//! address, and the node must carry `web_tag`. Copying a string gets an
//! attacker nothing, and one record on the control server takes a phone away.
//!
//! The bridge answers for the whole mesh, not for this machine. It asks the
//! daemon to greet every machine first, so the machine a phone happens to
//! reach gives the same answer as any other. That is why the phone can hold one
//! DNS name with every machine behind it, and name no machine at all.
//!
//! It runs beside `clipd`, not inside it. The daemon holds the key, and it
//! never has to parse a request from the network.

use std::collections::HashSet;
use std::io::Read;
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use zeroize::Zeroize;

use clipto_host::config::Config;
use clipto_host::limit::Limiter;
use clipto_host::tailscale::{self, Who};
use clipto_ipc::{CopySource, PasteTarget, Request, Response};

mod http;

/// The one path the bridge serves.
const CLIPBOARD_PATH: &str = "/v1/clipboard";

/// How long one read or write with the phone may stall. A phone on a mobile
/// network is slower than a machine on the tailnet.
const IO_TIMEOUT: Duration = Duration::from_secs(10);

/// How many connections wait while the bridge answers the ones before them.
const BACKLOG: i32 = 32;

/// The most the bridge reads from a request it already refused.
const MAX_DRAIN: usize = 64 * 1024;

/// What every connection handler needs.
struct Bridge {
    config: Config,
    limiter: Mutex<Limiter>,
    /// The addresses the listener already binds.
    bound: Mutex<HashSet<IpAddr>>,
}

// ─── main ─────────────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let config = clipto_host::config::load()?;

    eprintln!(
        "clipw: port {}, tag {}, sensitive payload {}",
        config.web_port,
        config.web_tag,
        if config.web_sensitive {
            "served"
        } else {
            "refused"
        }
    );

    let bridge = Arc::new(Bridge {
        config,
        limiter: Mutex::new(Limiter::default()),
        bound: Mutex::new(HashSet::new()),
    });

    // The Tailscale addresses appear after `tailscaled` comes up, and they can
    // change. Read them again on every turn, and bind what is new.
    loop {
        match tailscale::status() {
            Ok(status) => listen(&bridge, &status.own_addresses),
            Err(e) => eprintln!("clipw: cannot read the tailnet status: {e:#}"),
        }
        std::thread::sleep(bridge.config.peer_refresh());
    }
}

// ─── the listener ─────────────────────────────────────────────────────────────

/// Bind every Tailscale address the bridge does not listen on yet.
fn listen(bridge: &Arc<Bridge>, addresses: &[IpAddr]) {
    for address in addresses {
        if !bridge.bound.lock().unwrap().insert(*address) {
            continue;
        }

        let target = SocketAddr::new(*address, bridge.config.web_port);
        let listener = match bind(target, &bridge.config.web_device) {
            Ok(listener) => listener,
            Err(e) => {
                eprintln!("clipw: failed to listen on {target}: {e:#}");
                bridge.bound.lock().unwrap().remove(address);
                continue;
            }
        };

        eprintln!("clipw: listening on {target}");
        let bridge = Arc::clone(bridge);
        let address = *address;
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                match stream {
                    Ok(stream) => {
                        let bridge = Arc::clone(&bridge);
                        std::thread::spawn(move || serve(&bridge, stream));
                    }
                    Err(e) => eprintln!("clipw: accept error on {address}: {e}"),
                }
            }
            bridge.bound.lock().unwrap().remove(&address);
        });
    }
}

/// Bind one address, on one network device.
///
/// The address alone is not enough. Linux hands a packet to a socket bound to
/// an address even when the packet arrived on a different device, so a machine
/// on the LAN could otherwise reach a socket bound to a Tailscale address.
/// `SO_BINDTODEVICE` closes that before anything is parsed.
///
/// An empty `device` turns this off. Then the node identity check is the only
/// gate, which is a deliberate choice and not a default.
fn bind(target: SocketAddr, device: &str) -> Result<TcpListener> {
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(target),
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )
    .context("failed to make the socket")?;

    socket
        .set_reuse_address(true)
        .context("failed to set SO_REUSEADDR")?;

    if !device.is_empty() {
        socket
            .bind_device(Some(device.as_bytes()))
            .with_context(|| {
                format!(
                    "failed to bind the socket to {device}; set web_device to an empty string to \
                 serve on the address alone"
                )
            })?;
    }

    socket
        .bind(&target.into())
        .with_context(|| format!("failed to bind {target}"))?;
    socket.listen(BACKLOG).context("failed to listen")?;

    Ok(socket.into())
}

// ─── one connection ───────────────────────────────────────────────────────────

fn serve(bridge: &Arc<Bridge>, mut stream: TcpStream) {
    let Ok(remote) = stream.peer_addr() else {
        return;
    };
    let address = remote.ip();

    // Over the limit gets no answer at all. That is what the limit is for.
    if !bridge.limiter.lock().unwrap().allow(address) {
        eprintln!("clipw: refused {address}, too many failed requests");
        return;
    }

    let result = (|| -> Result<bool> {
        stream.set_read_timeout(Some(IO_TIMEOUT))?;
        stream.set_write_timeout(Some(IO_TIMEOUT))?;

        // The node must pass before the bridge reads a request from it.
        let who = match gate(bridge, remote) {
            Ok(who) => who,
            Err(e) => {
                eprintln!("clipw: refused {address}: {e:#}");
                http::write_text(&mut stream, 403, &format!("{e:#}"))?;
                drain(&mut stream);
                return Ok(false);
            }
        };

        let request = http::read(&mut stream)?;
        handle(&mut stream, &request, &who)?;
        Ok(true)
    })();

    match result {
        Ok(true) => bridge.limiter.lock().unwrap().passed(address),
        Ok(false) => bridge.limiter.lock().unwrap().failed(address),
        Err(e) => {
            bridge.limiter.lock().unwrap().failed(address);
            eprintln!("clipw: the request from {address} failed: {e:#}");
        }
    }
}

/// Read what the client already sent, and throw it away.
///
/// The gate answers before the bridge reads the request, so the refused
/// request is still in the receive buffer. Linux resets a connection that
/// closes with unread bytes there, and the reset throws away the answer the
/// client has not read yet. The refused node would then see a connection error
/// instead of the reason it was refused.
///
/// Bounded, because a client that keeps sending is owed no clean close.
fn drain(stream: &mut TcpStream) {
    let _ = stream.shutdown(std::net::Shutdown::Write);

    let mut sink = [0u8; 4096];
    let mut left = MAX_DRAIN;
    while left > 0 {
        match stream.read(&mut sink) {
            Ok(0) | Err(_) => break,
            Ok(read) => left = left.saturating_sub(read),
        }
    }
}

/// Decide whether this node may use the bridge.
///
/// `whois` reads the netmap that `tailscaled` already holds, so this keeps
/// working while the control server is unreachable.
fn gate(bridge: &Arc<Bridge>, remote: SocketAddr) -> Result<Who> {
    let who = tailscale::whois(remote)
        .with_context(|| format!("{} is not a node on this tailnet", remote.ip()))?;

    if !who.has_tag(&bridge.config.web_tag) {
        bail!(
            "the node {} does not carry {}",
            who.name,
            bridge.config.web_tag
        );
    }

    Ok(who)
}

/// Route one request.
fn handle(stream: &mut TcpStream, request: &http::Request, who: &Who) -> Result<()> {
    if request.path != CLIPBOARD_PATH {
        return http::write_text(
            stream,
            404,
            &format!("the bridge serves {CLIPBOARD_PATH} only"),
        );
    }

    match request.method.as_str() {
        "GET" => get(stream, who),
        "POST" => post(stream, request, who),
        _ => http::write_text(stream, 405, "the bridge takes GET and POST"),
    }
}

/// Answer a paste.
///
/// The sync comes first, so the machine this phone reached holds the newest
/// copy before it reads its own buffer. A sync that fails is not fatal: the
/// only failure the daemon reports here is a machine with no `clipto-psk`,
/// which shares the clipboard with nobody, and whose own buffer is therefore
/// the whole truth.
fn get(stream: &mut TcpStream, who: &Who) -> Result<()> {
    if let Response::Error { message } = ask(&Request::Sync)? {
        eprintln!(
            "clipw: {} asked for a paste, and the sync said: {message}",
            who.name
        );
    }

    match ask(&Request::Paste {
        target: PasteTarget::Web,
    })? {
        Response::Payload { mut data } => {
            eprintln!("clipw: {} took {} bytes", who.name, data.len());
            let result = http::write(stream, 200, "text/plain; charset=utf-8", &data);
            data.zeroize();
            result
        }
        Response::Error { message } => {
            eprintln!("clipw: {} got no paste: {message}", who.name);
            http::write_text(stream, 503, &message)
        }
        _ => http::write_text(
            stream,
            503,
            "the daemon answered a paste with the wrong message",
        ),
    }
}

/// Take a copy.
///
/// The daemon raises the generation and announces it to every machine, so one
/// POST to any machine reaches all of them. The bridge sends to one machine
/// only, and it must not fan out: a second copy of the same text would race the
/// first one for the same generation.
fn post(stream: &mut TcpStream, request: &http::Request, who: &Who) -> Result<()> {
    if request.body.is_empty() {
        return http::write_text(stream, 400, "a copy needs a body");
    }

    // The request owns one copy of the plaintext and erases it on drop. This
    // is a second copy, so erase it here as soon as the daemon has it.
    let mut copy = Request::Copy {
        payload: request.body.clone(),
        source: CopySource::User,
        sensitive: request.sensitive,
    };
    let answer = ask(&copy);
    if let Request::Copy { payload, .. } = &mut copy {
        payload.zeroize();
    }

    match answer? {
        Response::Ok => {
            eprintln!(
                "clipw: {} copied {} bytes{}",
                who.name,
                request.body.len(),
                if request.sensitive { ", sensitive" } else { "" }
            );
            http::write(stream, 204, "", &[])
        }
        Response::Error { message } => {
            eprintln!("clipw: {} could not copy: {message}", who.name);
            http::write_text(stream, 503, &message)
        }
        _ => http::write_text(
            stream,
            503,
            "the daemon answered a copy with the wrong message",
        ),
    }
}

// ─── the daemon ───────────────────────────────────────────────────────────────

/// Send one request to `clipd` and read its answer.
fn ask(request: &Request) -> Result<Response> {
    let path = clipto_ipc::socket_path()?;
    let mut stream = UnixStream::connect(&path).with_context(|| {
        format!(
            "failed to connect to clipd at {} — is clipd running?",
            path.display()
        )
    })?;

    clipto_ipc::set_timeouts(&stream)?;
    // A sync greets every machine before the daemon answers, so it outlasts the
    // ordinary timeout.
    if matches!(request, Request::Sync) {
        clipto_ipc::set_sync_timeout(&stream)?;
    }

    clipto_ipc::write_frame(&mut stream, request)?;
    clipto_ipc::read_frame::<Response>(&mut stream)
}
