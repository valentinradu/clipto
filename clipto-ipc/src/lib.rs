use std::io::{Read, Write};
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Where a copy request originated. Controls whether the daemon forwards the
/// payload to the Wayland compositor via `wl-copy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CopySource {
    /// Originated from the user (e.g. tmux `y`). The daemon will sync to the
    /// Wayland compositor if a Wayland session is active.
    User,
    /// Originated from the Wayland compositor (via `wl-paste --watch`). The
    /// daemon stores it without forwarding back to avoid an infinite loop.
    Wayland,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Request {
    Copy { payload: Vec<u8>, source: CopySource },
    Paste,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Response {
    Ok,
    Payload { data: Vec<u8> },
    Error { message: String },
}

/// Path to the daemon's Unix socket: `$XDG_RUNTIME_DIR/clipto.sock`.
pub fn socket_path() -> Result<PathBuf> {
    let dir = std::env::var("XDG_RUNTIME_DIR").context("XDG_RUNTIME_DIR not set")?;
    Ok(PathBuf::from(dir).join("clipto.sock"))
}

/// Write a length-prefixed bincode frame.
pub fn write_frame<T: Serialize>(writer: &mut impl Write, msg: &T) -> Result<()> {
    let bytes = bincode::serialize(msg).context("serialization failed")?;
    let len = u32::try_from(bytes.len())
        .context("frame too large")?
        .to_le_bytes();
    writer.write_all(&len)?;
    writer.write_all(&bytes)?;
    writer.flush()?;
    Ok(())
}

/// Read a length-prefixed bincode frame.
pub fn read_frame<T: for<'de> Deserialize<'de>>(reader: &mut impl Read) -> Result<T> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf)?;
    let len = u32::from_le_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;
    bincode::deserialize(&buf).context("deserialization failed")
}
