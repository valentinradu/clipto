//! The encrypted channel between two machines.
//!
//! The handshake is `Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s`. `XX` gives each
//! session fresh ephemeral keys, so a leaked credential exposes the later
//! copies but not the recorded traffic. `psk3` puts the shared credential in
//! the third message, which is the message that authenticates the initiator.
//!
//! After the handshake, `NoiseIo` looks like a stream to the caller. That lets
//! the frame reader and the frame writer in `clipto-ipc` work unchanged, so the
//! magic, the version byte and the size cap apply to a network message too.
//!
//! One limit of the `XX` pattern: the machine that listens puts its static
//! public key in the second message, which is before the third message proves
//! the credential. A node on the tailnet that opens a connection therefore
//! learns the machine identifier of this machine. It learns no version, no
//! generation number and no size, because those travel only in a frame inside
//! the session.

use std::io::{self, Read, Write};

use anyhow::{bail, Context, Result};
use snow::TransportState;
use zeroize::Zeroize;

use crate::identity::{Identity, NOISE_PATTERN};

/// A Noise message may not be larger than this. The u16 length prefix says the
/// same thing.
const MAX_NOISE_MESSAGE: usize = 65535;

/// Room for the 16 byte authentication tag inside one Noise message.
const MAX_CHUNK: usize = MAX_NOISE_MESSAGE - 16;

/// A handshake message of `Noise_XXpsk3_25519_...` is at most 96 bytes. The cap
/// stops a peer from making the daemon read more before it proves anything.
const MAX_HANDSHAKE_MESSAGE: usize = 4096;

// ─── the handshake ────────────────────────────────────────────────────────────

/// Start a session as the machine that connects.
pub fn connect<S: Read + Write>(mut stream: S, id: &Identity) -> Result<NoiseIo<S>> {
    let mut handshake = snow::Builder::new(NOISE_PATTERN.parse()?)
        .local_private_key(id.static_secret.as_slice())
        .context("the derived private key is not valid")?
        .psk(3, &id.psk)
        .context("the credential is not valid")?
        .build_initiator()
        .context("failed to start the handshake")?;

    let mut buf = [0u8; MAX_HANDSHAKE_MESSAGE];
    let mut payload = [0u8; MAX_HANDSHAKE_MESSAGE];

    // -> e
    let n = handshake.write_message(&[], &mut buf)?;
    write_message(&mut stream, &buf[..n])?;

    // <- e, ee, s, es
    let n = read_message(&mut stream, &mut buf)?;
    handshake.read_message(&buf[..n], &mut payload)?;

    // -> s, se, psk
    let n = handshake.write_message(&[], &mut buf)?;
    write_message(&mut stream, &buf[..n])?;

    finish(stream, handshake)
}

/// Start a session as the machine that listens.
pub fn accept<S: Read + Write>(mut stream: S, id: &Identity) -> Result<NoiseIo<S>> {
    let mut handshake = snow::Builder::new(NOISE_PATTERN.parse()?)
        .local_private_key(id.static_secret.as_slice())
        .context("the derived private key is not valid")?
        .psk(3, &id.psk)
        .context("the credential is not valid")?
        .build_responder()
        .context("failed to start the handshake")?;

    let mut buf = [0u8; MAX_HANDSHAKE_MESSAGE];
    let mut payload = [0u8; MAX_HANDSHAKE_MESSAGE];

    // <- e
    let n = read_message(&mut stream, &mut buf)?;
    handshake.read_message(&buf[..n], &mut payload)?;

    // -> e, ee, s, es
    let n = handshake.write_message(&[], &mut buf)?;
    write_message(&mut stream, &buf[..n])?;

    // <- s, se, psk. A peer with the wrong credential fails here.
    let n = read_message(&mut stream, &mut buf)?;
    handshake.read_message(&buf[..n], &mut payload)?;

    finish(stream, handshake)
}

fn finish<S: Read + Write>(stream: S, handshake: snow::HandshakeState) -> Result<NoiseIo<S>> {
    let remote_static: [u8; 32] = handshake
        .get_remote_static()
        .context("the peer sent no static key")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("the static key of the peer is not 32 bytes"))?;

    let session = handshake
        .into_transport_mode()
        .context("the handshake did not complete")?;

    Ok(NoiseIo {
        inner: stream,
        session,
        remote_static,
        rx: Vec::new(),
        rx_pos: 0,
        tx: Vec::new(),
    })
}

/// Write one length-prefixed Noise message.
fn write_message(stream: &mut impl Write, msg: &[u8]) -> Result<()> {
    let len = u16::try_from(msg.len()).context("a Noise message that is too large")?;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(msg)?;
    stream.flush()?;
    Ok(())
}

/// Read one length-prefixed Noise message into `buf`.
fn read_message(stream: &mut impl Read, buf: &mut [u8]) -> Result<usize> {
    let mut len = [0u8; 2];
    stream
        .read_exact(&mut len)
        .context("the peer sent no message length")?;
    let len = u16::from_be_bytes(len) as usize;

    if len > buf.len() {
        bail!(
            "the peer sent {len} bytes, more than the {} byte limit",
            buf.len()
        );
    }

    stream.read_exact(&mut buf[..len]).context("a short read")?;
    Ok(len)
}

// ─── the stream after the handshake ───────────────────────────────────────────

/// An encrypted stream. Every `read` and every `write` passes through the Noise
/// session, so the caller never sees the ciphertext.
pub struct NoiseIo<S: Read + Write> {
    inner: S,
    session: TransportState,
    remote_static: [u8; 32],
    /// Plaintext the peer sent that the caller has not read yet.
    rx: Vec<u8>,
    rx_pos: usize,
    /// Plaintext the caller wrote that `flush` has not sent yet.
    tx: Vec<u8>,
}

impl<S: Read + Write> NoiseIo<S> {
    /// The static public key of the peer. The daemon records it at the first
    /// successful handshake.
    pub fn remote_static(&self) -> [u8; 32] {
        self.remote_static
    }

    /// The first 8 bytes of the peer's static public key.
    pub fn remote_id(&self) -> [u8; 8] {
        let mut id = [0u8; 8];
        id.copy_from_slice(&self.remote_static[..8]);
        id
    }
}

impl<S: Read + Write> Read for NoiseIo<S> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        // A Noise message may decrypt to nothing. Read again, because a zero
        // here would tell the caller the stream ended.
        while self.rx_pos == self.rx.len() {
            self.rx.zeroize();
            self.rx.clear();
            self.rx_pos = 0;

            let mut cipher = vec![0u8; MAX_NOISE_MESSAGE];
            let n = read_message(&mut self.inner, &mut cipher)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e:#}")))?;

            let mut plain = vec![0u8; MAX_NOISE_MESSAGE];
            let len = self
                .session
                .read_message(&cipher[..n], &mut plain)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            cipher.zeroize();
            plain.truncate(len);
            self.rx = plain;
        }

        let take = out.len().min(self.rx.len() - self.rx_pos);
        out[..take].copy_from_slice(&self.rx[self.rx_pos..self.rx_pos + take]);
        self.rx_pos += take;
        Ok(take)
    }
}

impl<S: Read + Write> Write for NoiseIo<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.tx.extend_from_slice(buf);
        Ok(buf.len())
    }

    /// Cut the buffered plaintext into Noise messages and send them. The frame
    /// writer calls this once, at the end of a frame.
    fn flush(&mut self) -> io::Result<()> {
        let mut plain = std::mem::take(&mut self.tx);
        let mut cipher = vec![0u8; MAX_NOISE_MESSAGE];
        let mut result = Ok(());

        for chunk in plain.chunks(MAX_CHUNK) {
            result = self
                .session
                .write_message(chunk, &mut cipher)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
                .and_then(|n| {
                    write_message(&mut self.inner, &cipher[..n])
                        .map_err(|e| io::Error::other(format!("{e:#}")))
                });
            if result.is_err() {
                break;
            }
        }

        cipher.zeroize();
        plain.zeroize();
        result
    }
}

impl<S: Read + Write> Drop for NoiseIo<S> {
    fn drop(&mut self) {
        self.rx.zeroize();
        self.tx.zeroize();
    }
}

// ─── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::derive;
    use std::os::unix::net::UnixStream;

    fn identity(key: u8, psk: u8) -> Identity {
        derive(&[key; 32], [psk; 32]).unwrap()
    }

    /// Run a handshake over a socket pair, then give both ends back.
    fn pair(
        initiator: Identity,
        responder: Identity,
    ) -> (
        Result<NoiseIo<UnixStream>>,
        Result<NoiseIo<UnixStream>>,
    ) {
        let (a, b) = UnixStream::pair().unwrap();
        let server = std::thread::spawn(move || accept(b, &responder));
        let client = connect(a, &initiator);
        (client, server.join().unwrap())
    }

    #[test]
    fn the_same_credential_makes_a_session() {
        let (client, server) = pair(identity(1, 9), identity(2, 9));
        let client = client.unwrap();
        let server = server.unwrap();

        // Each side learns the other's machine identifier.
        assert_eq!(client.remote_id(), identity(2, 9).machine_id);
        assert_eq!(server.remote_id(), identity(1, 9).machine_id);
    }

    #[test]
    fn a_different_credential_fails() {
        let (client, server) = pair(identity(1, 9), identity(2, 8));
        assert!(client.is_err() || server.is_err());
    }

    /// The same key must always give the same machine identifier, otherwise a
    /// restart would look like a new machine.
    #[test]
    fn the_identity_is_stable() {
        assert_eq!(identity(1, 9).machine_id, identity(1, 9).machine_id);
        assert_ne!(identity(1, 9).machine_id, identity(2, 9).machine_id);
    }

    #[test]
    fn a_frame_crosses_the_session() {
        let (client, server) = pair(identity(1, 9), identity(2, 9));
        let mut client = client.unwrap();
        let mut server = server.unwrap();

        let sent = clipto_ipc::PeerMessage::Fetch { generation: 42 };
        clipto_ipc::write_frame(&mut client, &sent).unwrap();

        match clipto_ipc::read_frame::<clipto_ipc::PeerMessage>(&mut server).unwrap() {
            clipto_ipc::PeerMessage::Fetch { generation } => assert_eq!(generation, 42),
            other => panic!("the session gave the wrong message: {other:?}"),
        }
    }

    /// A payload larger than one Noise message must cross in several chunks.
    #[test]
    fn a_large_payload_crosses_the_session() {
        let (client, server) = pair(identity(1, 9), identity(2, 9));
        let mut client = client.unwrap();
        let mut server = server.unwrap();

        let data: Vec<u8> = (0..5 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
        let expected = data.clone();

        let writer = std::thread::spawn(move || {
            clipto_ipc::write_frame(&mut client, &clipto_ipc::PeerMessage::Payload { data })
                .unwrap();
        });

        match clipto_ipc::read_frame::<clipto_ipc::PeerMessage>(&mut server).unwrap() {
            clipto_ipc::PeerMessage::Payload { data } => assert_eq!(data, expected),
            other => panic!("the session gave the wrong message: {other:?}"),
        }
        writer.join().unwrap();
    }
}
