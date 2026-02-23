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
    wayland: bool,
}

impl State {
    fn store(&mut self, plaintext: &[u8]) -> Result<()> {
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = self
            .cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| anyhow::anyhow!("encryption failed"))?;
        self.buffer = Some(EncryptedBuffer {
            nonce: nonce.into(),
            ciphertext,
        });
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

// ─── key loading ─────────────────────────────────────────────────────────────

/// Load the 32-byte encryption key.
///
/// Production: reads from `$CREDENTIALS_DIRECTORY/clipto-key` (set by systemd
/// when the service uses `LoadCredentialEncrypted`).
///
/// Development fallback: reads from the path in `$CLIPTO_KEY_FILE`.
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
                        let should_sync = st.wayland && source == CopySource::User;
                        drop(st);

                        if should_sync {
                            sync_to_wayland(&payload)?;
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

fn sync_to_wayland(payload: &[u8]) -> Result<()> {
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

/// Spawn a thread that runs `wl-paste --watch clipto copy --source wayland`.
/// wl-paste feeds new compositor clipboard content to clipto's stdin on each
/// change. clipto sends it to the daemon with `source = Wayland` so the daemon
/// stores it without calling wl-copy again.
fn start_wayland_watcher(clipto_bin: PathBuf) {
    std::thread::spawn(move || loop {
        let status = Command::new("wl-paste")
            .args(["--watch", "--"])
            .arg(&clipto_bin)
            .args(["copy", "--source", "wayland"])
            .status();

        match status {
            Ok(s) if s.success() => {}
            Ok(s) => eprintln!("wl-paste --watch exited: {s}"),
            Err(e) => eprintln!("failed to start wl-paste --watch: {e}"),
        }

        // Brief pause before restarting to avoid tight loops on persistent errors.
        std::thread::sleep(std::time::Duration::from_secs(2));
    });
}

/// Resolve the path to the `clipto` binary: first look alongside the running
/// `clipd` executable, then fall back to searching PATH.
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

    let wayland = std::env::var("WAYLAND_DISPLAY").is_ok();

    let state = Arc::new(Mutex::new(State {
        cipher,
        buffer: None,
        wayland,
    }));

    let socket_path = clipto_ipc::socket_path()?;

    // Remove stale socket from a previous run.
    let _ = std::fs::remove_file(&socket_path);

    let listener = UnixListener::bind(&socket_path)
        .with_context(|| format!("failed to bind to {}", socket_path.display()))?;

    std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))
        .context("failed to set socket permissions")?;

    // Clean up socket on Ctrl-C / SIGTERM.
    {
        let path = socket_path.clone();
        ctrlc::set_handler(move || {
            let _ = std::fs::remove_file(&path);
            std::process::exit(0);
        })
        .context("failed to set signal handler")?;
    }

    if wayland {
        start_wayland_watcher(clipto_bin());
    }

    eprintln!(
        "clipd listening on {} (wayland={})",
        socket_path.display(),
        wayland
    );

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
