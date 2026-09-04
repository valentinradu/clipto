//! The clipboard across machines.
//!
//! The tailnet is the transport, not the identity. Any node on the tailnet may
//! reach the port, so the handshake is the only gate. Three rules follow:
//!
//! 1. The daemon sends nothing before the handshake completes. A peer that
//!    fails learns no version, no generation number and no size.
//! 2. The daemon limits the handshake attempts for each source address.
//! 3. The daemon writes a log line for each failure with the source address.

use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use zeroize::{Zeroize, Zeroizing};

use clipto_ipc::{Meta, PeerInfo, PeerMessage, PROTOCOL_VERSION};

use crate::config::Config;
use crate::discovery::{self, Node};
use crate::identity::{format_id, Identity};
use crate::noise::{self, NoiseIo};
use crate::peers::Registry;
use crate::state::{Content, State};
use crate::wayland;

/// Failed handshakes one address may make inside `FAILURE_WINDOW`.
const MAX_FAILURES: u32 = 10;

/// The window the failure count applies to.
const FAILURE_WINDOW: Duration = Duration::from_secs(60);

/// How long a connection for an announcement or a hello may take. A machine on
/// the same tailnet answers in well under this. The announcement waits for
/// every machine before it starts the next one, so a generous value here is a
/// delay on the NEXT copy, not just this one.
const DIAL_TIMEOUT: Duration = Duration::from_secs(3);

// ─── the handle the daemon holds ──────────────────────────────────────────────

pub struct Net {
    id: Identity,
    config: Config,
    state: Arc<Mutex<State>>,
    link: Arc<wayland::Link>,
    registry: Registry,
    limiter: Mutex<Limiter>,
    /// The addresses the listener already binds.
    bound: Mutex<HashSet<IpAddr>>,
    announcements: Sender<Announcement>,
    /// Wakes the discovery thread before its next turn.
    refresh: Arc<(Mutex<bool>, Condvar)>,
}

/// One local copy, on its way to the other machines.
struct Announcement {
    generation: u64,
    meta: Meta,
    /// The bytes, for a small payload that is not sensitive.
    inline: Option<Vec<u8>>,
}

impl Drop for Announcement {
    fn drop(&mut self) {
        if let Some(inline) = &mut self.inline {
            inline.zeroize();
        }
    }
}

/// Start the network. The listener, the discovery thread and the announcement
/// thread all run in the background.
pub fn start(
    id: Identity,
    config: Config,
    state: Arc<Mutex<State>>,
    link: Arc<wayland::Link>,
) -> Arc<Net> {
    let (announcements, queue) = mpsc::channel();

    let net = Arc::new(Net {
        id,
        config,
        state,
        link,
        registry: Registry::open(),
        limiter: Mutex::new(Limiter::default()),
        bound: Mutex::new(HashSet::new()),
        announcements,
        refresh: Arc::new((Mutex::new(false), Condvar::new())),
    });

    {
        let net = Arc::clone(&net);
        std::thread::spawn(move || announce_loop(&net, queue));
    }
    {
        let net = Arc::clone(&net);
        std::thread::spawn(move || discover_loop(&net));
    }

    net
}

impl Net {
    /// The list `clipto peers` prints.
    pub fn peers(&self) -> Vec<PeerInfo> {
        self.registry.report()
    }

    /// Tell the other machines about a local copy. Returns at once: the
    /// announcement thread does the work.
    pub fn announce(&self, generation: u64, meta: Meta, plaintext: &[u8]) {
        // A sensitive payload never travels with the announcement, and it does
        // not travel at all when the user turned that off.
        if meta.sensitive && !self.config.sync_sensitive {
            return;
        }
        let inline = (!meta.sensitive && plaintext.len() <= self.config.inline_limit)
            .then(|| plaintext.to_vec());

        let _ = self.announcements.send(Announcement {
            generation,
            meta,
            inline,
        });
    }

    /// Fetch the bytes behind a promise from the machine that holds them.
    ///
    /// The deadline is shorter than the Wayland paste timeout, so a paste never
    /// appears to hang. On failure the caller writes nothing: a silent stale
    /// paste is worse than an empty one.
    pub fn fetch(
        &self,
        generation: u64,
        origin: [u8; 8],
        meta: Meta,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let name = self.registry.name_for(origin);
        let node = self
            .registry
            .node_for(origin)
            .with_context(|| format!("the machine {name} is not on the tailnet"))?;

        // The answer to the hello says nothing this fetch needs. Taking a newer
        // copy here would turn a paste that can still work into a failure.
        let (mut io, _) = self
            .dial(&node, self.config.fetch_timeout())
            .with_context(|| format!("cannot reach {name}"))?;

        clipto_ipc::write_frame(&mut io, &PeerMessage::Fetch { generation })?;

        match clipto_ipc::read_frame::<PeerMessage>(&mut io)? {
            PeerMessage::Payload { mut data } => {
                let plaintext = Zeroizing::new(std::mem::take(&mut data));
                let got = crate::state::meta_of(&plaintext, meta.sensitive);
                if got.digest != meta.digest {
                    bail!("{name} sent bytes that do not match the digest it announced");
                }
                self.state.lock().unwrap().fulfill(generation, &plaintext)?;
                Ok(plaintext)
            }
            PeerMessage::Gone => {
                bail!("{name} no longer holds that clipboard content")
            }
            _ => bail!("{name} answered a fetch with the wrong message"),
        }
    }

    /// Connect to one machine, complete the handshake, and exchange the hello.
    ///
    /// The hello is what proves the session. `Noise_XXpsk3` mixes the credential
    /// into the third message, so the machine that connects learns nothing about
    /// the credential from the handshake itself: only a message it can read
    /// tells it that the other machine holds the same bytes.
    ///
    /// Returns the session and the hello the other machine sent.
    fn dial(&self, node: &Node, timeout: Duration) -> Result<(NoiseIo<TcpStream>, PeerMessage)> {
        let mut last: Option<anyhow::Error> = None;

        for address in &node.addresses {
            let target = SocketAddr::new(*address, self.config.port);
            match self.dial_one(node, target, timeout) {
                Ok((io, hello)) => {
                    self.registry.reached(&node.hostname, io.remote_id());
                    return Ok((io, hello));
                }
                Err(e) => last = Some(e),
            }
        }

        let error = last.unwrap_or_else(|| anyhow::anyhow!("the machine has no address"));
        self.registry.failed(&node.hostname, &format!("{error}"));
        self.nudge();
        Err(error)
    }

    fn dial_one(
        &self,
        node: &Node,
        target: SocketAddr,
        timeout: Duration,
    ) -> Result<(NoiseIo<TcpStream>, PeerMessage)> {
        let stream = TcpStream::connect_timeout(&target, timeout)
            .with_context(|| format!("failed to connect to {target}"))?;
        clipto_ipc::set_tcp_timeouts(&stream, timeout)?;

        let mut io = noise::connect(stream, &self.id).context("the handshake failed")?;
        self.registry
            .admit(io.remote_id(), io.remote_static(), &node.hostname)?;

        clipto_ipc::write_frame(&mut io, &self.hello())?;
        let hello = clipto_ipc::read_frame::<PeerMessage>(&mut io)
            .context("the machine did not answer the hello, so it holds another credential")?;

        let PeerMessage::Hello {
            protocol_version, ..
        } = &hello
        else {
            bail!("the machine answered the hello with the wrong message");
        };
        if *protocol_version != PROTOCOL_VERSION {
            bail!(
                "the machine speaks protocol {protocol_version}, this build speaks \
                 {PROTOCOL_VERSION}"
            );
        }

        Ok((io, hello))
    }

    /// Ask the discovery thread to read the peer list again.
    fn nudge(&self) {
        let (lock, condvar) = &*self.refresh;
        *lock.lock().unwrap() = true;
        condvar.notify_all();
    }

    /// Take what another machine reports, when it beats what this machine has.
    fn apply(&self, generation: u64, origin: [u8; 8], meta: Meta, inline: Option<&[u8]>) {
        if meta.sensitive && !self.config.sync_sensitive {
            return;
        }

        {
            let mut state = self.state.lock().unwrap();
            state.observe(generation);

            if !state.accepts(generation, origin) {
                // Every session opens with a hello, and that hello names the
                // same copy the announcement is about to carry. So the promise
                // usually lands first, and the bytes that follow are no longer
                // "newer" — but they are the bytes that promise is waiting for.
                if let Some(bytes) = inline {
                    if crate::state::meta_of(bytes, meta.sensitive).digest != meta.digest {
                        eprintln!("peers: an announcement carried bytes it did not match");
                        return;
                    }
                    match state.fulfill(generation, bytes) {
                        Ok(true) => eprintln!(
                            "clipboard: filled generation {generation} from {} ({} bytes)",
                            self.registry.name_for(origin),
                            meta.size
                        ),
                        Ok(false) => {}
                        Err(e) => eprintln!("peers: failed to store a remote copy: {e:#}"),
                    }
                    return;
                }

                eprintln!(
                    "clipboard: kept {} over generation {generation} from {}",
                    state.describe(),
                    self.registry.name_for(origin)
                );
                return;
            }

            if let Err(e) = state.adopt(generation, origin, meta, inline) {
                eprintln!("peers: failed to store a remote copy: {e:#}");
                return;
            }
            eprintln!(
                "clipboard: took generation {generation} from {} ({} bytes{})",
                self.registry.name_for(origin),
                meta.size,
                if inline.is_some() { "" } else { ", a promise" }
            );
        }

        // The daemon claims the local selection at once, even for a promise.
        // It announces nothing, which stops the echo between two machines.
        self.link.claim(meta.sensitive);
    }

    /// What this machine tells another machine about its clipboard.
    fn hello(&self) -> PeerMessage {
        let (generation, origin, state) = self.state.lock().unwrap().hello();
        PeerMessage::Hello {
            protocol_version: PROTOCOL_VERSION,
            machine_id: self.id.machine_id,
            generation,
            origin,
            state,
        }
    }
}

// ─── the announcement thread ──────────────────────────────────────────────────

/// Send each local copy to every machine that answers the port.
fn announce_loop(net: &Arc<Net>, queue: Receiver<Announcement>) {
    while let Ok(mut announcement) = queue.recv() {
        // A burst of copies only needs the last one.
        while let Ok(newer) = queue.try_recv() {
            announcement = newer;
        }

        // One thread for each machine. A machine that never answers the port
        // costs a full connection timeout for each of its addresses, and the
        // copy must not wait behind it to reach a machine that is up.
        let mut sending = Vec::new();
        for node in net.registry.candidates() {
            let net = Arc::clone(net);
            let message = PeerMessage::Announce {
                machine_id: net.id.machine_id,
                generation: announcement.generation,
                meta: announcement.meta,
                inline: announcement.inline.clone(),
            };

            sending.push(std::thread::spawn(move || {
                let sent = send_one(&net, &node, &message);

                // This thread's own copy of the plaintext. Erase it here: the
                // announcement itself lives until every machine has one.
                let mut message = message;
                if let PeerMessage::Announce {
                    inline: Some(inline),
                    ..
                } = &mut message
                {
                    inline.zeroize();
                }

                if let Err(e) = sent {
                    eprintln!("peers: {} did not take the copy: {e:#}", node.hostname);
                }
            }));
        }

        // Wait for them all, so a burst of copies cannot pile up threads and
        // the plaintext never outlives the announcement that carries it.
        for thread in sending {
            let _ = thread.join();
        }
    }
}

/// Open a session, send one message, and close.
fn send_one(net: &Arc<Net>, node: &Node, message: &PeerMessage) -> Result<()> {
    let (mut io, _) = net.dial(node, DIAL_TIMEOUT)?;
    clipto_ipc::write_frame(&mut io, message)?;
    Ok(())
}

// ─── the discovery thread ─────────────────────────────────────────────────────

/// Read the peer list, bind the listener, and greet the machines that came
/// back online.
fn discover_loop(net: &Arc<Net>) {
    let mut online_before: HashSet<String> = HashSet::new();

    loop {
        match discovery::status() {
            Ok(status) => {
                listen(net, &status.own_addresses);

                let online_now: HashSet<String> = status
                    .peers
                    .iter()
                    .filter(|node| node.online)
                    .map(|node| node.hostname.clone())
                    .collect();

                // A machine that returns to the online state starts again with
                // no failure behind it, so the daemon greets it at once.
                for hostname in online_now.difference(&online_before) {
                    net.registry.forget(hostname);
                }

                net.registry.set_nodes(status.peers);
                online_before = online_now;

                // A machine that slept missed the announcements. Greet every
                // machine this daemon has not talked to yet, and take the
                // highest generation from the answer.
                for node in net.registry.ungreeted() {
                    let net = Arc::clone(net);
                    std::thread::spawn(move || {
                        if let Err(e) = greet(&net, &node) {
                            eprintln!("peers: {} did not answer a hello: {e:#}", node.hostname);
                        }
                    });
                }
            }
            Err(e) => eprintln!("peers: cannot read the tailnet status: {e:#}"),
        }

        wait(net);
    }
}

/// Sleep until the next turn, or until a failed connection asks for an earlier
/// one.
fn wait(net: &Arc<Net>) {
    let (lock, condvar) = &*net.refresh;
    let mut asked = lock.lock().unwrap();
    if !*asked {
        let (guard, _) = condvar
            .wait_timeout(asked, net.config.peer_refresh())
            .unwrap();
        asked = guard;
    }
    *asked = false;
}

/// Exchange a hello and take what the other machine reports.
fn greet(net: &Arc<Net>, node: &Node) -> Result<()> {
    let (_, hello) = net.dial(node, DIAL_TIMEOUT)?;

    if let PeerMessage::Hello {
        generation,
        origin,
        state: Some(meta),
        ..
    } = hello
    {
        net.apply(generation, origin, meta, None);
    }
    Ok(())
}

// ─── the listener ─────────────────────────────────────────────────────────────

/// Bind every Tailscale address the daemon does not listen on yet.
///
/// The listener must not bind `0.0.0.0`, because the port must not appear on
/// the LAN.
fn listen(net: &Arc<Net>, addresses: &[IpAddr]) {
    for address in addresses {
        if !net.bound.lock().unwrap().insert(*address) {
            continue;
        }

        let target = SocketAddr::new(*address, net.config.port);
        let listener = match TcpListener::bind(target) {
            Ok(listener) => listener,
            Err(e) => {
                eprintln!("peers: failed to listen on {target}: {e}");
                net.bound.lock().unwrap().remove(address);
                continue;
            }
        };

        eprintln!("peers: listening on {target}");
        let net = Arc::clone(net);
        let address = *address;
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                match stream {
                    Ok(stream) => {
                        let net = Arc::clone(&net);
                        std::thread::spawn(move || serve(&net, stream));
                    }
                    Err(e) => eprintln!("peers: accept error on {address}: {e}"),
                }
            }
            net.bound.lock().unwrap().remove(&address);
        });
    }
}

/// Handle one connection from another machine.
fn serve(net: &Arc<Net>, stream: TcpStream) {
    let Ok(remote) = stream.peer_addr() else {
        return;
    };
    let address = remote.ip();

    if !net.limiter.lock().unwrap().allow(address) {
        eprintln!("peers: refused {address}, too many failed handshakes");
        return;
    }

    let result = (|| -> Result<()> {
        clipto_ipc::set_tcp_timeouts(&stream, DIAL_TIMEOUT)?;
        let mut io = noise::accept(stream, &net.id).context("the handshake failed")?;

        let sender = io.remote_id();
        // The tailnet name is only a label here. An address that discovery does
        // not know still gets a session, because the credential is the gate.
        let hostname = net.registry.hostname_at(address);
        net.registry.admit(
            sender,
            io.remote_static(),
            hostname.as_deref().unwrap_or("unknown"),
        )?;
        if let Some(hostname) = &hostname {
            net.registry.reached(hostname, sender);
        }

        greeting(net, &mut io, sender)?;

        // The other machine may follow the hello with one announcement or one
        // fetch, or it may close. Any error here only ends the connection.
        if let Err(e) = dispatch(net, &mut io, sender) {
            eprintln!("peers: the session with {address} ended: {e:#}");
        }
        Ok(())
    })();

    if let Err(e) = result {
        net.limiter.lock().unwrap().failed(address);
        eprintln!("peers: rejected {address}: {e:#}");
    } else {
        net.limiter.lock().unwrap().passed(address);
    }
}

/// Read the hello the other machine must send first, and answer it.
///
/// This is the message that proves the other machine holds the same credential,
/// because only that machine can encrypt one this daemon can read.
fn greeting<S: Read + Write>(net: &Arc<Net>, io: &mut NoiseIo<S>, sender: [u8; 8]) -> Result<()> {
    let PeerMessage::Hello {
        protocol_version,
        generation,
        origin,
        state,
        ..
    } = clipto_ipc::read_frame::<PeerMessage>(io)?
    else {
        bail!(
            "the machine {} opened with something that is not a hello",
            format_id(&sender)
        );
    };

    if protocol_version != PROTOCOL_VERSION {
        bail!(
            "the machine {} speaks protocol {protocol_version}, this build speaks \
             {PROTOCOL_VERSION}",
            format_id(&sender)
        );
    }

    // Answer first, so the other machine catches up even when this one wins.
    clipto_ipc::write_frame(io, &net.hello())?;

    if let Some(meta) = state {
        net.apply(generation, origin, meta, None);
    }
    Ok(())
}

/// Read the message that follows the hello, and answer it.
fn dispatch<S: Read + Write>(net: &Arc<Net>, io: &mut NoiseIo<S>, sender: [u8; 8]) -> Result<()> {
    match clipto_ipc::read_frame::<PeerMessage>(io)? {
        // A second hello says nothing new. The exchange already happened.
        PeerMessage::Hello { .. } => {}

        // The sender is always the origin: a machine passes on nothing it took
        // from a third machine.
        PeerMessage::Announce {
            machine_id,
            generation,
            meta,
            mut inline,
        } => {
            net.apply(generation, machine_id, meta, inline.as_deref());
            if let Some(inline) = &mut inline {
                inline.zeroize();
            }
        }

        PeerMessage::Fetch { generation } => {
            let payload = net.state.lock().unwrap().serve(generation);
            let mut answer = match payload {
                Some(data) => PeerMessage::Payload {
                    data: data.to_vec(),
                },
                None => PeerMessage::Gone,
            };
            clipto_ipc::write_frame(io, &answer)?;

            // `serve` gives a Zeroizing buffer, but `to_vec` above made a plain
            // copy for the answer. Erase that copy too.
            if let PeerMessage::Payload { data } = &mut answer {
                data.zeroize();
            }
        }

        PeerMessage::Payload { mut data } => {
            data.zeroize();
            bail!(
                "the machine {} sent a payload nobody asked for",
                format_id(&sender)
            );
        }

        PeerMessage::Gone => {}
    }

    Ok(())
}

// ─── the rate limit ───────────────────────────────────────────────────────────

/// Counts the failed handshakes for each source address.
#[derive(Default)]
struct Limiter {
    failures: HashMap<IpAddr, (u32, Instant)>,
}

impl Limiter {
    fn allow(&mut self, address: IpAddr) -> bool {
        match self.failures.get(&address) {
            Some((count, since)) if *count >= MAX_FAILURES => {
                if since.elapsed() >= FAILURE_WINDOW {
                    self.failures.remove(&address);
                    true
                } else {
                    false
                }
            }
            _ => true,
        }
    }

    fn failed(&mut self, address: IpAddr) {
        let entry = self.failures.entry(address).or_insert((0, Instant::now()));
        if entry.1.elapsed() >= FAILURE_WINDOW {
            *entry = (0, Instant::now());
        }
        entry.0 += 1;
    }

    fn passed(&mut self, address: IpAddr) {
        self.failures.remove(&address);
    }
}

// ─── the paste path ───────────────────────────────────────────────────────────

/// Give the bytes for a paste, whichever machine holds them.
///
/// `net` is `None` when the daemon runs with no credential.
pub fn payload_for_paste(
    state: &Arc<Mutex<State>>,
    net: Option<&Arc<Net>>,
) -> Result<Zeroizing<Vec<u8>>> {
    let content = state.lock().unwrap().content();

    match content {
        Content::Empty => bail!("the clipboard is empty"),
        Content::Held => state.lock().unwrap().load(),
        Content::Promised {
            generation,
            origin,
            meta,
        } => {
            let net = net.context(
                "the clipboard is on another machine, and this daemon has no clipto-psk \
                 credential",
            )?;
            net.fetch(generation, origin, meta)
        }
    }
}
