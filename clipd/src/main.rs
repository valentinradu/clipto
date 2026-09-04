use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::rngs::OsRng;
use zeroize::{Zeroize, Zeroizing};

use clipto_ipc::{CopySource, Request, Response};

mod wayland;

pub use wayland::socket as wayland_socket;

// ─── encrypted in-memory buffer ──────────────────────────────────────────────

struct EncryptedBuffer {
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
    sensitive: bool,
}

impl Drop for EncryptedBuffer {
    fn drop(&mut self) {
        self.ciphertext.zeroize();
    }
}

// ─── daemon state ─────────────────────────────────────────────────────────────

pub struct State {
    cipher: ChaCha20Poly1305,
    buffer: Option<EncryptedBuffer>,
}

impl State {
    fn store(&mut self, plaintext: &[u8], sensitive: bool) -> Result<()> {
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = self
            .cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| anyhow::anyhow!("encryption failed"))?;
        self.buffer = Some(EncryptedBuffer {
            nonce: nonce.into(),
            ciphertext,
            sensitive,
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

    /// Sensitivity of the stored payload, or None when the clipboard is empty.
    fn sensitive(&self) -> Option<bool> {
        self.buffer.as_ref().map(|b| b.sensitive)
    }
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

fn handle_connection(mut stream: UnixStream, state: Arc<Mutex<State>>, link: Arc<wayland::Link>) {
    let result = (|| -> Result<()> {
        clipto_ipc::set_timeouts(&stream)?;

        let request: Request = clipto_ipc::read_frame(&mut stream)?;

        let mut response = match request {
            Request::Copy {
                mut payload,
                source,
                sensitive,
            } => {
                let stored = state.lock().unwrap().store(&payload, sensitive);
                payload.zeroize();

                match stored {
                    Ok(()) => {
                        // A Wayland copy is already the selection. Claiming it
                        // again would take the richer formats away from its
                        // owner.
                        if source == CopySource::User {
                            link.claim(sensitive);
                        }
                        Response::Ok
                    }
                    Err(e) => Response::Error {
                        message: e.to_string(),
                    },
                }
            }

            Request::Paste => {
                let st = state.lock().unwrap();
                match st.load() {
                    Ok(data) => Response::Payload {
                        data: data.to_vec(),
                    },
                    Err(e) => Response::Error {
                        message: e.to_string(),
                    },
                }
            }
        };

        clipto_ipc::write_frame(&mut stream, &response)?;

        // `load` gives a Zeroizing buffer, but `to_vec` above made a plain
        // copy for the response. Erase that copy too.
        if let Response::Payload { data } = &mut response {
            data.zeroize();
        }

        Ok(())
    })();

    if let Err(e) = result {
        eprintln!("connection error: {e:#}");
    }
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

    let state = Arc::new(Mutex::new(State {
        cipher,
        buffer: None,
    }));

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

    let link = wayland::start(Arc::clone(&state));

    eprintln!("clipd listening on {}", socket_path.display());

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let state = Arc::clone(&state);
                let link = Arc::clone(&link);
                std::thread::spawn(move || handle_connection(stream, state, link));
            }
            Err(e) => eprintln!("accept error: {e}"),
        }
    }

    Ok(())
}
