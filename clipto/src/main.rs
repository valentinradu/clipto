use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};

use clipto_ipc::{CopySource, PeerInfo, Request, Response};

// ─── CLI definition ───────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "clipto",
    about = "Clipboard client — copy stdin to clipd, or paste from clipd to stdout",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Read stdin and send it to the clipboard daemon.
    Copy {
        /// Where this copy originated. `wayland` means the compositor already
        /// holds the payload, so the daemon stores it without claiming the
        /// selection.
        #[arg(long, default_value = "user")]
        source: Source,
        /// Mark the payload as a password, a key, or other secret content. The
        /// daemon then asks a clipboard history tool not to keep it.
        #[arg(long)]
        sensitive: bool,
    },
    /// Fetch the current clipboard from the daemon and write it to stdout.
    Paste,
    /// Print the machines that share this clipboard.
    Peers,
}

#[derive(ValueEnum, Clone, Copy)]
enum Source {
    User,
    Wayland,
}

impl From<Source> for CopySource {
    fn from(s: Source) -> Self {
        match s {
            Source::User => CopySource::User,
            Source::Wayland => CopySource::Wayland,
        }
    }
}

/// Print one line for each machine, in columns.
fn print_peers(peers: &[PeerInfo]) {
    if peers.is_empty() {
        eprintln!("no other machine is on the tailnet");
        return;
    }

    let name_width = peers.iter().map(|p| p.hostname.len()).max().unwrap_or(0);
    let id_width = peers.iter().map(|p| p.machine_id.len()).max().unwrap_or(1);
    let address_width = peers.iter().map(|p| p.address.len()).max().unwrap_or(0);

    for peer in peers {
        let id = if peer.machine_id.is_empty() {
            "-"
        } else {
            &peer.machine_id
        };
        println!(
            "{:name_width$}  {:id_width$}  {:address_width$}  {}",
            peer.hostname, id, peer.address, peer.state
        );
    }
}

// ─── socket helpers ───────────────────────────────────────────────────────────

fn connect() -> Result<UnixStream> {
    let path = clipto_ipc::socket_path()?;
    let stream = UnixStream::connect(&path).with_context(|| {
        format!("failed to connect to clipd at {} — is clipd running?", path.display())
    })?;
    clipto_ipc::set_timeouts(&stream)?;
    Ok(stream)
}

// ─── main ─────────────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Cmd::Copy { source, sensitive } => {
            let mut payload = Vec::new();
            io::stdin()
                .read_to_end(&mut payload)
                .context("failed to read stdin")?;

            let mut stream = connect()?;
            clipto_ipc::write_frame(
                &mut stream,
                &Request::Copy { payload, source: source.into(), sensitive },
            )?;

            match clipto_ipc::read_frame::<Response>(&mut stream)? {
                Response::Ok => {}
                Response::Error { message } => {
                    eprintln!("clipd: {message}");
                    std::process::exit(1);
                }
                _ => {
                    eprintln!("clipd: unexpected response to Copy");
                    std::process::exit(1);
                }
            }
        }

        Cmd::Paste => {
            let mut stream = connect()?;
            clipto_ipc::write_frame(&mut stream, &Request::Paste)?;

            match clipto_ipc::read_frame::<Response>(&mut stream)? {
                Response::Payload { data } => {
                    io::stdout()
                        .write_all(&data)
                        .context("failed to write to stdout")?;
                }
                Response::Error { message } => {
                    eprintln!("clipd: {message}");
                    std::process::exit(1);
                }
                _ => {
                    eprintln!("clipd: unexpected response to Paste");
                    std::process::exit(1);
                }
            }
        }

        Cmd::Peers => {
            let mut stream = connect()?;
            clipto_ipc::write_frame(&mut stream, &Request::Peers)?;

            match clipto_ipc::read_frame::<Response>(&mut stream)? {
                Response::Peers { peers } => print_peers(&peers),
                Response::Error { message } => {
                    eprintln!("clipd: {message}");
                    std::process::exit(1);
                }
                _ => {
                    eprintln!("clipd: unexpected response to Peers");
                    std::process::exit(1);
                }
            }
        }
    }

    Ok(())
}
