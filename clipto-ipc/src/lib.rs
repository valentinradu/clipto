use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Largest frame the protocol accepts, in bytes. The length prefix comes from
/// the peer, so a cap stops a bad peer from making us allocate 4 GiB.
pub const MAX_FRAME: usize = 64 * 1024 * 1024;

/// Marks the start of a frame. A peer that speaks something else is rejected
/// on the first three bytes instead of misreading a length.
const MAGIC: [u8; 2] = *b"CT";

/// Bump this whenever `Request` or `Response` changes shape. `bincode` writes
/// no field names, so two builds that disagree would otherwise read each
/// other's bytes as nonsense.
pub const PROTOCOL_VERSION: u8 = 1;

/// How long one read or write on the socket may stall. A peer that connects
/// and then goes quiet must not hold a thread for ever.
pub const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Apply `IO_TIMEOUT` to a connected socket. The timeout is per read and per
/// write, so a large payload that keeps moving still gets through.
pub fn set_timeouts(stream: &UnixStream) -> Result<()> {
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .context("failed to set the read timeout")?;
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .context("failed to set the write timeout")?;
    Ok(())
}

/// Where a copy request originated. Controls whether the daemon claims the
/// Wayland selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CopySource {
    /// Originated from the user, for example from tmux, a TTY or a script. The
    /// daemon stores the payload and claims the Wayland selection.
    User,
    /// The payload is already the Wayland selection. The daemon stores it and
    /// claims nothing, because it must not take the selection from its owner.
    Wayland,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Request {
    Copy {
        payload: Vec<u8>,
        source: CopySource,
        /// The payload holds a password, a key, or other secret content. The
        /// daemon then offers `x-kde-passwordManagerHint`, which asks a
        /// clipboard history tool not to keep the payload.
        sensitive: bool,
    },
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
///
/// The frame holds clipboard plaintext, so this erases the buffer before it
/// returns. Otherwise the plaintext stays in the heap until the allocator
/// reuses that memory.
pub fn write_frame<T: Serialize>(writer: &mut impl Write, msg: &T) -> Result<()> {
    let mut bytes = bincode::serialize(msg).context("serialization failed")?;

    let result = (|| -> Result<()> {
        if bytes.len() > MAX_FRAME {
            bail!(
                "frame of {} bytes is larger than the {MAX_FRAME} byte limit",
                bytes.len()
            );
        }
        let len = u32::try_from(bytes.len())
            .context("frame too large")?
            .to_le_bytes();
        writer.write_all(&[MAGIC[0], MAGIC[1], PROTOCOL_VERSION])?;
        writer.write_all(&len)?;
        writer.write_all(&bytes)?;
        writer.flush()?;
        Ok(())
    })();

    bytes.zeroize();
    result
}

/// Read a length-prefixed bincode frame.
///
/// The frame holds clipboard plaintext, so this erases the buffer before it
/// returns. See `write_frame`.
pub fn read_frame<T: for<'de> Deserialize<'de>>(reader: &mut impl Read) -> Result<T> {
    let mut header = [0u8; 3];
    reader
        .read_exact(&mut header)
        .context("the peer sent no frame header")?;

    if header[..2] != MAGIC {
        bail!("not a clipto frame");
    }
    if header[2] != PROTOCOL_VERSION {
        bail!(
            "protocol version mismatch: the peer speaks {}, this build speaks {PROTOCOL_VERSION}",
            header[2]
        );
    }

    let mut len_buf = [0u8; 4];
    reader
        .read_exact(&mut len_buf)
        .context("the peer sent no frame length")?;

    let len = u32::from_le_bytes(len_buf) as usize;
    if len > MAX_FRAME {
        bail!("frame of {len} bytes is larger than the {MAX_FRAME} byte limit");
    }

    let mut buf = vec![0u8; len];
    let result = reader
        .read_exact(&mut buf)
        .context("short frame")
        .and_then(|()| bincode::deserialize(&buf).context("deserialization failed"));

    buf.zeroize();
    result
}
