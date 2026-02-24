use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::rngs::OsRng;
use zeroize::{Zeroize, Zeroizing};

use clipto_ipc::{CopySource, Request, Response};

// ─── encrypted in-memory buffer ──────────────────────────────────────────────

struct EncryptedBuffer {
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
}

impl Drop for EncryptedBuffer {
    fn drop(&mut self) {
        self.ciphertext.zeroize();
    }
}

// ─── daemon state ─────────────────────────────────────────────────────────────

struct State {
    cipher: ChaCha20Poly1305,
    buffer: Option<EncryptedBuffer>,
}

impl State {
    fn store(&mut self, plaintext: &[u8]) -> Result<()> {
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = self
            .cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| anyhow::anyhow!("encryption failed"))?;
        self.buffer = Some(EncryptedBuffer { nonce: nonce.into(), ciphertext });
        Ok(())
    }

    fn load(&self) -> Result<Zeroizing<Vec<u8>>> {
        let buf = self.buffer.as_ref().context("clipboard is empty")?;
        let nonce = Nonce::from_slice(&buf.nonce);
        let plaintext = self
            .cipher
            .decrypt(nonce, buf.ciphertext.as_slice())
            .map_err(|_| anyhow::anyhow!("decryption failed"))?;
        Ok(Zeroizing::new(plaintext))
    }
}

// ─── wayland socket detection ────────────────────────────────────────────────

/// Returns the Wayland socket path if the compositor is actually reachable.
fn wayland_socket() -> Option<PathBuf> {
    let runtime_dir = std::env::var("XDG_RUNTIME_DIR").ok()?;
    let display = std::env::var("WAYLAND_DISPLAY").ok()?;
    let path = PathBuf::from(runtime_dir).join(display);
    path.exists().then_some(path)
}

// ─── key loading ─────────────────────────────────────────────────────────────

fn load_key() -> Result<Zeroizing<Vec<u8>>> {
    if let Ok(creds) = std::env::var("CREDENTIALS_DIRECTORY") {
        let path = PathBuf::from(&creds).join("clipto-key");
        if path.exists() {
            let key = std::fs::read(&path)
                .with_context(|| format!("failed to read key from {}", path.display()))?;
            return Ok(Zeroizing::new(key));
        }
    }

    if let Ok(key_file) = std::env::var("CLIPTO_KEY_FILE") {
        let key = std::fs::read(&key_file)
            .with_context(|| format!("failed to read key from {key_file}"))?;
        return Ok(Zeroizing::new(key));
    }

    bail!(
        "no key found: run as a systemd service with LoadCredentialEncrypted=clipto-key:…, \
         or set CLIPTO_KEY_FILE for development"
    )
}

// ─── connection handler ───────────────────────────────────────────────────────

fn handle_connection(mut stream: UnixStream, state: Arc<Mutex<State>>) {
    let result = (|| -> Result<()> {
        let request: Request = clipto_ipc::read_frame(&mut stream)?;

        let response = match request {
            Request::Copy { payload, source } => {
                let mut st = state.lock().unwrap();
                match st.store(&payload) {
                    Ok(()) => {
                        let should_sync = source == CopySource::User;
                        drop(st);

                        if should_sync {
                            // Best-effort: silently skip if Wayland isn't up.
                            let _ = sync_to_wayland(&payload);
                        }

                        Response::Ok
                    }
                    Err(e) => Response::Error { message: e.to_string() },
                }
            }

            Request::Paste => {
                let st = state.lock().unwrap();
                match st.load() {
                    Ok(data) => Response::Payload { data: data.to_vec() },
                    Err(e) => Response::Error { message: e.to_string() },
                }
            }
        };

        clipto_ipc::write_frame(&mut stream, &response)?;
        Ok(())
    })();

    if let Err(e) = result {
        eprintln!("connection error: {e:#}");
    }
}

// ─── wayland sync ─────────────────────────────────────────────────────────────

/// Forward payload to the Wayland compositor. Returns Ok(()) silently if no
/// compositor is reachable — TTY sessions are expected to hit this path.
fn sync_to_wayland(payload: &[u8]) -> Result<()> {
    wayland_socket().context("no Wayland compositor")?;

    let mut child = Command::new("wl-copy")
        .stdin(Stdio::piped())
        .spawn()
        .context("failed to spawn wl-copy")?;

    if let Some(stdin) = child.stdin.as_mut() {
        stdin.write_all(payload).context("failed to write to wl-copy")?;
    }

    child.wait().context("wl-copy failed")?;
    Ok(())
}

/// Spawn a thread that uses inotify to watch for the Wayland socket to appear
/// in `$XDG_RUNTIME_DIR`. Starts `wl-paste --watch` when the socket is
/// created, kills it when the socket is deleted. Zero polling.
fn start_wayland_watcher(clipto_bin: PathBuf) {
    use inotify::{EventMask, Inotify, WatchMask};

    let runtime_dir = match std::env::var("XDG_RUNTIME_DIR") {
        Ok(d) => d,
        Err(_) => return, // no runtime dir, nothing to watch
    };
    let display = match std::env::var("WAYLAND_DISPLAY") {
        Ok(d) => d,
        Err(_) => return, // no display configured
    };

    std::thread::spawn(move || {
        let mut inotify = match Inotify::init() {
            Ok(i) => i,
            Err(e) => { eprintln!("inotify init: {e}"); return; }
        };

        if let Err(e) = inotify.watches().add(&runtime_dir, WatchMask::CREATE | WatchMask::DELETE) {
            eprintln!("inotify watch: {e}");
            return;
        }

        // If compositor is already up when the daemon starts, launch immediately.
        let mut child: Option<std::process::Child> = if wayland_socket().is_some() {
            spawn_wl_paste(&clipto_bin)
        } else {
            None
        };

        let mut buf = [0u8; 1024];
        loop {
            let events = match inotify.read_events_blocking(&mut buf) {
                Ok(e) => e,
                Err(e) => { eprintln!("inotify read: {e}"); break; }
            };

            for event in events {
                let name = match event.name {
                    Some(n) => n.to_string_lossy().into_owned(),
                    None => continue,
                };

                if name != display {
                    continue;
                }

                if event.mask.contains(EventMask::CREATE) {
                    child = spawn_wl_paste(&clipto_bin);
                } else if event.mask.contains(EventMask::DELETE) {
                    if let Some(mut c) = child.take() {
                        let _ = c.kill();
                        let _ = c.wait();
                    }
                }
            }
        }
    });
}

fn spawn_wl_paste(clipto_bin: &PathBuf) -> Option<std::process::Child> {
    match Command::new("wl-paste")
        .args(["--watch", "--"])
        .arg(clipto_bin)
        .args(["copy", "--source", "wayland"])
        .spawn()
    {
        Ok(child) => Some(child),
        Err(e) => { eprintln!("wl-paste --watch: {e}"); None }
    }
}

fn clipto_bin() -> PathBuf {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let candidate = dir.join("clipto");
            if candidate.exists() {
                return candidate;
            }
        }
    }
    PathBuf::from("clipto")
}

// ─── main ─────────────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let key = load_key()?;

    if key.len() != 32 {
        bail!("key must be exactly 32 bytes, got {}", key.len());
    }

    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| anyhow::anyhow!("failed to create cipher from key"))?;
    drop(key);

    let state = Arc::new(Mutex::new(State { cipher, buffer: None }));

    let socket_path = clipto_ipc::socket_path()?;
    let _ = std::fs::remove_file(&socket_path);

    let listener = UnixListener::bind(&socket_path)
        .with_context(|| format!("failed to bind to {}", socket_path.display()))?;

    std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))
        .context("failed to set socket permissions")?;

    {
        let path = socket_path.clone();
        ctrlc::set_handler(move || {
            let _ = std::fs::remove_file(&path);
            std::process::exit(0);
        })
        .context("failed to set signal handler")?;
    }

    // Always start the watcher thread — it polls silently until Wayland appears.
    start_wayland_watcher(clipto_bin());

    eprintln!("clipd listening on {}", socket_path.display());

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let state = Arc::clone(&state);
                std::thread::spawn(move || handle_connection(stream, state));
            }
            Err(e) => eprintln!("accept error: {e}"),
        }
    }

    Ok(())
}
