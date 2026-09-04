use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use chacha20poly1305::{aead::KeyInit, ChaCha20Poly1305};
use zeroize::Zeroize;

use clipto_ipc::{CopySource, Request, Response};

mod config;
mod discovery;
mod identity;
mod keys;
mod net;
mod noise;
mod peers;
mod state;
mod wayland;

use state::State;

pub use wayland::socket as wayland_socket;

// ─── connection handler ───────────────────────────────────────────────────────

fn handle_connection(
    mut stream: UnixStream,
    state: Arc<Mutex<State>>,
    link: Arc<wayland::Link>,
    net: Option<Arc<net::Net>>,
) {
    let result = (|| -> Result<()> {
        clipto_ipc::set_timeouts(&stream)?;

        let request: Request = clipto_ipc::read_frame(&mut stream)?;

        let mut response = match request {
            Request::Copy {
                mut payload,
                source,
                sensitive,
            } => {
                let stored = state
                    .lock()
                    .unwrap()
                    .store_local(&payload, sensitive, source);

                let answer = match stored {
                    Ok((generation, meta)) => {
                        // A Wayland copy is already the selection. Claiming it
                        // again would take the richer formats away from its
                        // owner.
                        if source == CopySource::User {
                            link.claim(sensitive);
                        }
                        eprintln!(
                            "clipboard: a local copy is generation {generation} ({} bytes)",
                            meta.size
                        );
                        if let Some(net) = &net {
                            net.announce(generation, meta, &payload);
                        }
                        Response::Ok
                    }
                    Err(e) => Response::Error {
                        message: e.to_string(),
                    },
                };

                payload.zeroize();
                answer
            }

            Request::Paste => match net::payload_for_paste(&state, net.as_ref()) {
                Ok(data) => Response::Payload {
                    data: data.to_vec(),
                },
                Err(e) => Response::Error {
                    message: format!("{e:#}"),
                },
            },

            Request::Peers => match &net {
                Some(net) => Response::Peers { peers: net.peers() },
                None => Response::Error {
                    message: "this daemon has no clipto-psk credential, so it shares the \
                              clipboard with no other machine"
                        .to_string(),
                },
            },
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
    let config = config::load()?;
    let key = keys::load_key()?;

    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| anyhow::anyhow!("failed to create cipher from key"))?;

    // The daemon runs with no network when the credential is absent. The local
    // clipboard must keep working.
    let identity = match identity::load_psk()? {
        Some(psk) => Some(identity::derive(&key, psk)?),
        None => {
            eprintln!(
                "clipd: no clipto-psk credential, so this machine shares the clipboard with \
                 no other machine"
            );
            None
        }
    };
    drop(key);

    let machine_id = identity.as_ref().map_or([0u8; 8], |id| id.machine_id);
    let state = Arc::new(Mutex::new(State::new(cipher, machine_id)));
    let link = Arc::new(wayland::Link::new());

    let net = identity.map(|identity| {
        eprintln!(
            "clipd: machine {} on port {}",
            identity::format_id(&identity.machine_id),
            config.port
        );
        net::start(identity, config, Arc::clone(&state), Arc::clone(&link))
    });

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

    wayland::start(Arc::clone(&state), Arc::clone(&link), net.clone());

    eprintln!("clipd listening on {}", socket_path.display());

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let state = Arc::clone(&state);
                let link = Arc::clone(&link);
                let net = net.clone();
                std::thread::spawn(move || handle_connection(stream, state, link, net));
            }
            Err(e) => eprintln!("accept error: {e}"),
        }
    }

    Ok(())
}
