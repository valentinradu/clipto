//! Wayland integration.
//!
//! `clipd` connects to the compositor itself and owns the selection through
//! `ext-data-control-v1`. It spawns no `wl-copy` and no `wl-paste`.
//!
//! The gain is the plaintext lifetime. The compositor stores only a promise,
//! so `clipd` decrypts the buffer when a client actually pastes, and erases it
//! again in the same function.

use std::collections::HashMap;
use std::io::Read;
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::fs::FileTypeExt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use wayland_client::backend::ObjectId;
use wayland_client::globals::{registry_queue_init, GlobalListContents};
use wayland_client::protocol::{wl_registry, wl_seat};
use wayland_client::{event_created_child, Connection, Dispatch, Proxy, QueueHandle};
use wayland_protocols::ext::data_control::v1::client::{
    ext_data_control_device_v1::{self, ExtDataControlDeviceV1},
    ext_data_control_manager_v1::ExtDataControlManagerV1,
    ext_data_control_offer_v1::{self, ExtDataControlOfferV1},
    ext_data_control_source_v1::{self, ExtDataControlSourceV1},
};
use zeroize::Zeroize;

use clipto_ipc::CopySource;

use crate::net::Net;
use crate::state::State;

/// The formats `clipd` offers, best first. The same list decides which format
/// `clipd` asks for when it reads another client's selection.
const TEXT_MIMES: [&str; 5] = [
    "text/plain;charset=utf-8",
    "text/plain",
    "UTF8_STRING",
    "STRING",
    "TEXT",
];

/// Marks a password. A clipboard history tool skips a payload that offers it.
const SENSITIVE_MIME: &str = "x-kde-passwordManagerHint";

/// How long one paste may take before the daemon drops it.
const PASTE_TIMEOUT: Duration = Duration::from_secs(10);

/// Shortest time between two connection attempts to the same compositor.
const RECONNECT_INTERVAL: Duration = Duration::from_secs(1);

// ─── the handle the daemon holds ──────────────────────────────────────────────

/// Lets the IPC threads reach the compositor. Empty while no compositor runs.
pub struct Link {
    session: Mutex<Option<Arc<Session>>>,
}

impl Link {
    pub fn new() -> Self {
        Link {
            session: Mutex::new(None),
        }
    }

    /// Take ownership of the selection. The payload stays encrypted until a
    /// client pastes. Does nothing when no compositor is reachable.
    pub fn claim(&self, sensitive: bool) {
        let session = self.session.lock().unwrap().clone();
        if let Some(session) = session {
            session.claim(sensitive);
        }
    }
}

/// One connection to one compositor.
struct Session {
    conn: Connection,
    qh: QueueHandle<Wayland>,
    manager: ExtDataControlManagerV1,
    device: ExtDataControlDeviceV1,
    /// Set while `clipd` owns the selection.
    source: Mutex<Option<ExtDataControlSourceV1>>,
}

impl Session {
    fn claim(&self, sensitive: bool) {
        let source = self.manager.create_data_source(&self.qh, ());
        for mime in TEXT_MIMES {
            source.offer(mime.to_string());
        }
        if sensitive {
            source.offer(SENSITIVE_MIME.to_string());
        }

        // Publish the source before the request goes out. The Wayland thread
        // reads this field to tell our own selection from another client's,
        // and it flushes this connection on every dispatch.
        let old = self.source.lock().unwrap().replace(source.clone());

        self.device.set_selection(Some(&source));

        // The compositor cancels the old source, but the event may arrive
        // after the next claim. Destroy it here, and the `Cancelled` handler
        // leaves a source it no longer holds alone.
        if let Some(old) = old {
            old.destroy();
        }

        if let Err(e) = self.conn.flush() {
            eprintln!("wayland: failed to claim the selection: {e}");
        }
    }
}

// ─── dispatch state ───────────────────────────────────────────────────────────

struct Wayland {
    clip: Arc<Mutex<State>>,
    session: Arc<Session>,
    /// Empty while the daemon runs with no credential.
    net: Option<Arc<Net>>,
    /// Formats announced for an offer, until its `selection` event arrives.
    offers: HashMap<ObjectId, Vec<String>>,
}

impl Wayland {
    /// Pull another client's selection into the daemon buffer.
    fn read_offer(&self, offer: &ExtDataControlOfferV1, mimes: &[String]) {
        let Some(mime) = TEXT_MIMES.iter().find(|m| mimes.iter().any(|o| o == *m)) else {
            return; // nothing we can represent, e.g. an image
        };
        let sensitive = mimes.iter().any(|m| m == SENSITIVE_MIME);

        let Ok((reader, writer)) = std::io::pipe() else { return };
        offer.receive(mime.to_string(), writer.as_fd());

        // The request must reach the owner before we close our end and read.
        let _ = self.session.conn.flush();
        drop(writer);

        let clip = Arc::clone(&self.clip);
        let net = self.net.clone();
        std::thread::spawn(move || {
            let mut payload = Vec::new();
            match std::io::BufReader::new(reader).read_to_end(&mut payload) {
                // An empty selection is not an update. Keep what we have.
                Ok(_) if payload.is_empty() => {}
                Ok(_) => {
                    let stored =
                        clip.lock()
                            .unwrap()
                            .store_local(&payload, sensitive, CopySource::Wayland);
                    match stored {
                        Ok((generation, meta)) => {
                            eprintln!(
                                "clipboard: the compositor's selection is generation                                  {generation} ({} bytes)",
                                meta.size
                            );
                            if let Some(net) = &net {
                                net.announce(generation, meta, &payload);
                            }
                        }
                        Err(e) => eprintln!("wayland: failed to store the selection: {e:#}"),
                    }
                }
                Err(e) => eprintln!("wayland: failed to read the selection: {e}"),
            }
            payload.zeroize();
        });
    }
}

/// Write the payload to the descriptor the compositor passed.
///
/// A pipe holds about 64 KiB. A client that asks for the clipboard and then
/// stops reading would block this thread — and keep the plaintext alive with
/// it. So the descriptor is non-blocking and the write has a deadline.
fn serve_paste(fd: std::os::fd::OwnedFd, data: &[u8]) {
    let raw = fd.as_raw_fd();
    if unsafe { libc::fcntl(raw, libc::F_SETFL, libc::O_NONBLOCK) } < 0 {
        return;
    }

    let deadline = Instant::now() + PASTE_TIMEOUT;
    let mut sent = 0;

    while sent < data.len() {
        let n = unsafe {
            libc::write(
                raw,
                data[sent..].as_ptr().cast::<libc::c_void>(),
                data.len() - sent,
            )
        };

        if n > 0 {
            sent += n as usize;
            continue;
        }

        let err = std::io::Error::last_os_error();
        match err.kind() {
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted => {}
            _ => return, // the reader closed the pipe, which is normal
        }

        let Some(left) = deadline.checked_duration_since(Instant::now()) else {
            eprintln!("wayland: a paste stalled, dropping it after {PASTE_TIMEOUT:?}");
            return;
        };

        let mut poll_fd = libc::pollfd {
            fd: raw,
            events: libc::POLLOUT,
            revents: 0,
        };
        if unsafe { libc::poll(&mut poll_fd, 1, left.as_millis() as libc::c_int) } < 0 {
            return;
        }
    }
}

// ─── protocol handlers ────────────────────────────────────────────────────────

impl Dispatch<wl_registry::WlRegistry, GlobalListContents> for Wayland {
    fn event(
        _: &mut Self,
        _: &wl_registry::WlRegistry,
        _: wl_registry::Event,
        _: &GlobalListContents,
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }
}

wayland_client::delegate_noop!(Wayland: ignore wl_seat::WlSeat);
wayland_client::delegate_noop!(Wayland: ignore ExtDataControlManagerV1);

impl Dispatch<ExtDataControlDeviceV1, ()> for Wayland {
    fn event(
        state: &mut Self,
        _: &ExtDataControlDeviceV1,
        event: ext_data_control_device_v1::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        use ext_data_control_device_v1::Event;

        match event {
            Event::DataOffer { id } => {
                state.offers.insert(id.id(), Vec::new());
            }

            Event::Selection { id: Some(offer) } => {
                let mimes = state.offers.remove(&offer.id()).unwrap_or_default();

                // Our own selection coming back. Reading it would deadlock:
                // the daemon would be both the reader and the writer.
                if state.session.source.lock().unwrap().is_none() {
                    state.read_offer(&offer, &mimes);
                }
                offer.destroy();
            }

            // The compositor clipboard is empty. Keep the buffer, so `clipto
            // paste` still works. Hyprland does not send this when the owning
            // app exits, so the two can differ until the next copy.
            Event::Selection { id: None } => {}

            // `clipd` does not handle the primary selection. Drop the offer,
            // otherwise its formats stay in the map for ever.
            Event::PrimarySelection { id: Some(offer) } => {
                state.offers.remove(&offer.id());
                offer.destroy();
            }

            _ => {}
        }
    }

    event_created_child!(Wayland, ExtDataControlDeviceV1, [
        ext_data_control_device_v1::EVT_DATA_OFFER_OPCODE => (ExtDataControlOfferV1, ()),
    ]);
}

impl Dispatch<ExtDataControlOfferV1, ()> for Wayland {
    fn event(
        state: &mut Self,
        offer: &ExtDataControlOfferV1,
        event: ext_data_control_offer_v1::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        if let ext_data_control_offer_v1::Event::Offer { mime_type } = event {
            state.offers.entry(offer.id()).or_default().push(mime_type);
        }
    }
}

impl Dispatch<ExtDataControlSourceV1, ()> for Wayland {
    fn event(
        state: &mut Self,
        source: &ExtDataControlSourceV1,
        event: ext_data_control_source_v1::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        use ext_data_control_source_v1::Event;

        match event {
            // Somebody pasted. This is the only place the plaintext exists.
            //
            // The bytes may sit on another machine, and then this thread
            // fetches them first. The chain runs from the compositor, to this
            // daemon, to the remote daemon.
            Event::Send { fd, .. } => {
                let clip = Arc::clone(&state.clip);
                let net = state.net.clone();
                std::thread::spawn(move || {
                    match crate::net::payload_for_paste(&clip, net.as_ref()) {
                        Ok(data) => serve_paste(fd, &data),
                        // Close the pipe and write nothing. Never serve the
                        // older content instead: a silent stale paste is worse
                        // than an empty one.
                        Err(e) => eprintln!("wayland: a paste found no bytes: {e:#}"),
                    }
                });
            }

            // Another client took the selection. Drop our source, so the next
            // `selection` event reads that client's payload instead of ours.
            Event::Cancelled => {
                let mut held = state.session.source.lock().unwrap();
                if held.as_ref() == Some(source) {
                    *held = None;
                    drop(held);
                    source.destroy();
                }
                // A source we no longer hold was already destroyed by `claim`.
            }

            _ => {}
        }
    }
}

// ─── connection lifecycle ─────────────────────────────────────────────────────

/// Start the Wayland thread. It connects when a compositor appears, and
/// reconnects when one restarts.
pub fn start(clip: Arc<Mutex<State>>, link: Arc<Link>, net: Option<Arc<Net>>) {
    let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") else {
        return; // nowhere to look for a compositor
    };

    let thread_link = link;
    std::thread::spawn(move || {
        // True after a failed setup: the socket that is there now is known
        // bad, so wait for a different one instead of retrying it.
        let mut socket_is_bad = false;

        loop {
            if crate::wayland_socket().is_some() && !socket_is_bad {
                let started = Instant::now();
                match run(&clip, &thread_link, net.clone()) {
                    // The connection ended. A new compositor may already be up.
                    Ok(()) => {
                        *thread_link.session.lock().unwrap() = None;
                        // A compositor that accepts us and then drops us at
                        // once would make this loop spin. Hold it to one try
                        // per interval.
                        if let Some(left) = RECONNECT_INTERVAL.checked_sub(started.elapsed()) {
                            std::thread::sleep(left);
                        }
                        continue;
                    }
                    // Setup failed. Only a new compositor changes the answer.
                    Err(e) => {
                        eprintln!("wayland: {e:#}");
                        *thread_link.session.lock().unwrap() = None;
                        socket_is_bad = true;
                    }
                }
            }

            if let Err(e) = wait_for_socket(&runtime_dir, socket_is_bad) {
                eprintln!("wayland: giving up, cannot watch for a compositor: {e:#}");
                return;
            }
            socket_is_bad = false;
        }
    });
}

/// Connect, claim the buffer, then dispatch until the connection ends.
fn run(clip: &Arc<Mutex<State>>, link: &Arc<Link>, net: Option<Arc<Net>>) -> Result<()> {
    // Connect by path rather than by environment, because $WAYLAND_DISPLAY may
    // be unset when the daemon starts before the graphical session.
    let path = crate::wayland_socket().context("no compositor socket")?;
    let stream = std::os::unix::net::UnixStream::connect(&path)
        .with_context(|| format!("failed to connect to {}", path.display()))?;
    let conn = Connection::from_socket(stream).context("the compositor refused the connection")?;
    let (globals, mut queue) =
        registry_queue_init::<Wayland>(&conn).context("failed to read the registry")?;
    let qh = queue.handle();

    let manager: ExtDataControlManagerV1 = globals
        .bind(&qh, 1..=1, ())
        .context("the compositor does not support ext-data-control-v1")?;
    let seat: wl_seat::WlSeat = globals.bind(&qh, 1..=9, ()).context("no wl_seat")?;
    let device = manager.get_data_device(&seat, &qh, ());

    let session = Arc::new(Session {
        conn,
        qh,
        manager,
        device,
        source: Mutex::new(None),
    });
    *link.session.lock().unwrap() = Some(Arc::clone(&session));

    let mut state = Wayland {
        clip: Arc::clone(clip),
        session: Arc::clone(&session),
        net,
        offers: HashMap::new(),
    };

    // A restarted compositor has an empty clipboard. Put ours back.
    if let Some(sensitive) = clip.lock().unwrap().sensitive() {
        session.claim(sensitive);
    }

    while queue.blocking_dispatch(&mut state).is_ok() {}
    Ok(())
}

/// Block until the Wayland socket appears in `$XDG_RUNTIME_DIR`. Uses inotify,
/// so an idle TTY session costs nothing.
/// `wait_for_new` skips the socket that is there now, which is what a failed
/// setup needs. Otherwise an existing socket returns at once.
fn wait_for_socket(runtime_dir: &str, wait_for_new: bool) -> Result<()> {
    use inotify::{EventMask, Inotify, WatchMask};

    // With $WAYLAND_DISPLAY set, watch the directory that holds that one
    // socket — an absolute value puts it outside $XDG_RUNTIME_DIR. Without
    // it, watch $XDG_RUNTIME_DIR for any compositor.
    let wanted = std::env::var("WAYLAND_DISPLAY")
        .ok()
        .map(|display| PathBuf::from(runtime_dir).join(display));

    let dir = match &wanted {
        Some(path) => path.parent().context("no parent directory")?.to_path_buf(),
        None => PathBuf::from(runtime_dir),
    };

    let mut inotify = Inotify::init().context("inotify init")?;
    inotify
        .watches()
        .add(&dir, WatchMask::CREATE)
        .with_context(|| format!("inotify watch on {}", dir.display()))?;

    // Watch first, then check, so a compositor that starts in between is not
    // lost. Skipped when the caller already knows this socket is bad.
    if !wait_for_new && crate::wayland_socket().is_some() {
        return Ok(());
    }

    let mut buf = [0u8; 1024];
    loop {
        let events = inotify
            .read_events_blocking(&mut buf)
            .context("inotify read")?;

        for event in events {
            let Some(created) = event.name else { continue };
            if !event.mask.contains(EventMask::CREATE) {
                continue;
            }

            let matches = match &wanted {
                Some(path) => Some(created) == path.file_name(),
                None => is_display_name(&created.to_string_lossy()),
            };
            if matches {
                return Ok(());
            }
        }
    }
}

/// Path to the Wayland socket, when the compositor is reachable.
///
/// `$WAYLAND_DISPLAY` decides it when set. The daemon may start before the
/// graphical session, and then the variable is missing, so fall back to the
/// lowest-numbered `wayland-N` socket in `$XDG_RUNTIME_DIR`.
pub fn socket() -> Option<PathBuf> {
    let runtime_dir = std::env::var("XDG_RUNTIME_DIR").ok()?;

    if let Ok(display) = std::env::var("WAYLAND_DISPLAY") {
        // An absolute $WAYLAND_DISPLAY replaces the base, which is what the
        // Wayland specification asks for.
        let path = PathBuf::from(&runtime_dir).join(display);
        return path.exists().then_some(path);
    }

    let mut found: Vec<PathBuf> = std::fs::read_dir(&runtime_dir)
        .ok()?
        .flatten()
        .filter(|entry| is_display_name(&entry.file_name().to_string_lossy()))
        .map(|entry| entry.path())
        // `metadata` follows a symlink; the entry's own file type does not.
        .filter(|path| std::fs::metadata(path).is_ok_and(|m| m.file_type().is_socket()))
        .collect();

    found.sort();
    found.into_iter().next()
}

/// True for `wayland-0`, `wayland-12` and so on. False for `wayland-1.lock`.
fn is_display_name(name: &str) -> bool {
    name.strip_prefix("wayland-")
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}
