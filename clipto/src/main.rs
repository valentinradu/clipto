use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};

use clipto_ipc::{CopySource, Request, Response};

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
        /// Where this copy originated. Use `wayland` only when called from
        /// `wl-paste --watch` to avoid a sync loop.
        #[arg(long, default_value = "user")]
        source: Source,
    },
    /// Fetch the current clipboard from the daemon and write it to stdout.
    Paste,
}

#[derive(ValueEnum, Clone)]
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

// ─── socket helpers ───────────────────────────────────────────────────────────

fn connect() -> Result<UnixStream> {
    let path = clipto_ipc::socket_path()?;
    UnixStream::connect(&path)
        .with_context(|| format!("failed to connect to clipd at {} — is clipd running?", path.display()))
}

// ─── main ─────────────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Cmd::Copy { source } => {
            let mut payload = Vec::new();
            io::stdin()
                .read_to_end(&mut payload)
                .context("failed to read stdin")?;

            let mut stream = connect()?;
            clipto_ipc::write_frame(
                &mut stream,
                &Request::Copy { payload, source: source.into() },
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
    }

    Ok(())
}
