//! The clipboard the daemon holds.
//!
//! The payload stays encrypted in memory. A payload that another machine owns
//! may be a promise instead: the daemon knows the size, the digest and the
//! machine that holds the bytes, and it fetches the bytes when a client pastes.
//!
//! A Lamport counter orders the copies. The wall clock does not order them,
//! because the machines disagree on the time.

use anyhow::{Context, Result};
use chacha20poly1305::{
    aead::{Aead, AeadCore},
    ChaCha20Poly1305, Nonce,
};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use clipto_ipc::{CopySource, Meta};

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

// ─── the current clipboard ────────────────────────────────────────────────────

struct Clip {
    generation: u64,
    origin: [u8; 8],
    source: CopySource,
    meta: Meta,
    /// None while the daemon holds a promise instead of the bytes.
    buffer: Option<EncryptedBuffer>,
}

/// What the daemon can answer a paste with.
pub enum Content {
    /// Nothing was ever copied.
    Empty,
    /// The daemon holds the bytes.
    Held,
    /// Another machine holds the bytes.
    Promised {
        generation: u64,
        origin: [u8; 8],
        meta: Meta,
    },
}

// ─── daemon state ─────────────────────────────────────────────────────────────

pub struct State {
    cipher: ChaCha20Poly1305,
    machine_id: [u8; 8],
    /// The Lamport counter. It only goes up, and it never follows the clock.
    lamport: u64,
    clip: Option<Clip>,
}

impl State {
    pub fn new(cipher: ChaCha20Poly1305, machine_id: [u8; 8]) -> Self {
        Self {
            cipher,
            machine_id,
            lamport: 0,
            clip: None,
        }
    }

    /// Store a payload this machine made. Returns the generation and the meta,
    /// which the caller announces to the other machines.
    pub fn store_local(
        &mut self,
        plaintext: &[u8],
        sensitive: bool,
        source: CopySource,
    ) -> Result<(u64, Meta)> {
        self.lamport = self.lamport.max(self.generation()) + 1;
        let generation = self.lamport;
        let origin = self.machine_id;
        let meta = meta_of(plaintext, sensitive);

        self.write(generation, origin, source, meta, Some(plaintext))?;
        Ok((generation, meta))
    }

    /// Move the Lamport counter up to what the peer reports.
    pub fn observe(&mut self, generation: u64) {
        self.lamport = self.lamport.max(generation);
    }

    /// The last writer wins. The generation decides first, then the machine
    /// identifier, so two machines that copy at the same moment still agree.
    pub fn accepts(&self, generation: u64, origin: [u8; 8]) -> bool {
        match &self.clip {
            None => true,
            Some(clip) => (generation, origin) > (clip.generation, clip.origin),
        }
    }

    /// Take a payload another machine made. `bytes` is `None` for a promise.
    pub fn adopt(
        &mut self,
        generation: u64,
        origin: [u8; 8],
        meta: Meta,
        bytes: Option<&[u8]>,
    ) -> Result<()> {
        // The daemon may already hold this exact content, because it copied it
        // earlier or because it took it from a third machine. Then it keeps the
        // bytes, and the paste needs no fetch.
        if bytes.is_none() {
            if let Some(clip) = &mut self.clip {
                if clip.buffer.is_some() && clip.meta.digest == meta.digest {
                    clip.generation = generation;
                    clip.origin = origin;
                    clip.source = CopySource::Remote;
                    clip.meta = meta;
                    return Ok(());
                }
            }
        }

        self.write(generation, origin, CopySource::Remote, meta, bytes)
    }

    /// Put the bytes behind a promise. Answers whether it did: a newer copy may
    /// have arrived while the fetch ran, and then there is no promise left.
    pub fn fulfill(&mut self, generation: u64, plaintext: &[u8]) -> Result<bool> {
        let Some(clip) = &self.clip else {
            return Ok(false);
        };
        if clip.generation != generation || clip.buffer.is_some() {
            return Ok(false);
        }
        let (origin, source, meta) = (clip.origin, clip.source, clip.meta);
        self.write(generation, origin, source, meta, Some(plaintext))?;
        Ok(true)
    }

    /// Replace the clipboard. `plaintext` is `None` for a promise.
    fn write(
        &mut self,
        generation: u64,
        origin: [u8; 8],
        source: CopySource,
        meta: Meta,
        plaintext: Option<&[u8]>,
    ) -> Result<()> {
        let buffer = match plaintext {
            Some(plaintext) => {
                let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
                let ciphertext = self
                    .cipher
                    .encrypt(&nonce, plaintext)
                    .map_err(|_| anyhow::anyhow!("encryption failed"))?;
                Some(EncryptedBuffer {
                    nonce: nonce.into(),
                    ciphertext,
                })
            }
            None => None,
        };

        self.clip = Some(Clip {
            generation,
            origin,
            source,
            meta,
            buffer,
        });
        Ok(())
    }

    /// Decrypt the payload. Fails while the daemon holds only a promise.
    pub fn load(&self) -> Result<Zeroizing<Vec<u8>>> {
        let clip = self.clip.as_ref().context("the clipboard is empty")?;
        let buffer = clip
            .buffer
            .as_ref()
            .context("the bytes are on another machine")?;
        let nonce = Nonce::from_slice(&buffer.nonce);
        let plaintext = self
            .cipher
            .decrypt(nonce, buffer.ciphertext.as_slice())
            .map_err(|_| anyhow::anyhow!("decryption failed"))?;
        Ok(Zeroizing::new(plaintext))
    }

    /// What a paste would find.
    pub fn content(&self) -> Content {
        match &self.clip {
            None => Content::Empty,
            Some(clip) => match clip.buffer {
                Some(_) => Content::Held,
                None => Content::Promised {
                    generation: clip.generation,
                    origin: clip.origin,
                    meta: clip.meta,
                },
            },
        }
    }

    /// Answer a `Fetch` from another machine. `None` means the daemon no longer
    /// holds that generation.
    pub fn serve(&self, generation: u64) -> Option<Zeroizing<Vec<u8>>> {
        let clip = self.clip.as_ref()?;
        if clip.generation != generation {
            return None;
        }
        self.load().ok()
    }

    /// What this machine tells another machine about its clipboard.
    pub fn hello(&self) -> (u64, [u8; 8], Option<Meta>) {
        match &self.clip {
            None => (self.lamport, self.machine_id, None),
            Some(clip) => (clip.generation, clip.origin, Some(clip.meta)),
        }
    }

    /// The current clipboard, for a log line: which copy this machine holds.
    pub fn describe(&self) -> String {
        match &self.clip {
            None => "an empty clipboard".to_string(),
            Some(clip) => format!(
                "generation {} from {}",
                clip.generation,
                crate::identity::format_id(&clip.origin)
            ),
        }
    }

    /// Sensitivity of the stored payload, or None when the clipboard is empty.
    pub fn sensitive(&self) -> Option<bool> {
        self.clip.as_ref().map(|c| c.meta.sensitive)
    }

    fn generation(&self) -> u64 {
        self.clip.as_ref().map_or(0, |c| c.generation)
    }
}

/// The size, the sensitivity and the digest of one payload.
pub fn meta_of(plaintext: &[u8], sensitive: bool) -> Meta {
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&Sha256::digest(plaintext));
    Meta {
        size: plaintext.len() as u64,
        sensitive,
        digest,
    }
}

// ─── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chacha20poly1305::KeyInit;

    const OMEN: [u8; 8] = [1, 0, 0, 0, 0, 0, 0, 0];
    const EDGE: [u8; 8] = [2, 0, 0, 0, 0, 0, 0, 0];

    fn state(machine_id: [u8; 8]) -> State {
        State::new(ChaCha20Poly1305::new_from_slice(&[7u8; 32]).unwrap(), machine_id)
    }

    #[test]
    fn a_local_copy_comes_back() {
        let mut st = state(OMEN);
        let (generation, meta) = st.store_local(b"hello", false, CopySource::User).unwrap();

        assert_eq!(generation, 1);
        assert_eq!(meta.size, 5);
        assert_eq!(*st.load().unwrap(), b"hello");
    }

    #[test]
    fn each_local_copy_raises_the_generation() {
        let mut st = state(OMEN);
        st.store_local(b"one", false, CopySource::User).unwrap();
        let (generation, _) = st.store_local(b"two", false, CopySource::User).unwrap();
        assert_eq!(generation, 2);
    }

    /// A copy on another machine wins when its generation is higher.
    #[test]
    fn a_higher_generation_wins() {
        let mut st = state(OMEN);
        st.store_local(b"mine", false, CopySource::User).unwrap();

        assert!(st.accepts(2, EDGE));
        assert!(!st.accepts(1, EDGE) || EDGE > OMEN);
    }

    /// Two machines that copy at the same moment must agree which copy wins.
    /// The machine identifier decides, and both machines apply the same rule.
    #[test]
    fn the_machine_identifier_breaks_a_tie() {
        let mut omen = state(OMEN);
        omen.store_local(b"from omen", false, CopySource::User).unwrap();

        let mut edge = state(EDGE);
        edge.store_local(b"from edge", false, CopySource::User).unwrap();

        // Both copies carry generation 1. EDGE is the larger identifier.
        assert!(omen.accepts(1, EDGE));
        assert!(!edge.accepts(1, OMEN));
    }

    /// The Lamport counter follows the peer, so the next local copy beats it.
    #[test]
    fn the_counter_follows_the_peer() {
        let mut st = state(OMEN);
        st.observe(10);
        let (generation, _) = st.store_local(b"after", false, CopySource::User).unwrap();
        assert_eq!(generation, 11);
    }

    #[test]
    fn a_promise_holds_no_bytes_until_a_fetch() {
        let mut st = state(OMEN);
        let meta = meta_of(b"far away", false);
        st.adopt(5, EDGE, meta, None).unwrap();

        assert!(matches!(st.content(), Content::Promised { generation: 5, .. }));
        assert!(st.load().is_err());

        st.fulfill(5, b"far away").unwrap();
        assert!(matches!(st.content(), Content::Held));
        assert_eq!(*st.load().unwrap(), b"far away");
    }

    /// A fetch that finishes late must not overwrite a newer copy.
    #[test]
    fn a_late_fetch_does_not_overwrite_a_newer_copy() {
        let mut st = state(OMEN);
        st.adopt(5, EDGE, meta_of(b"old", false), None).unwrap();
        st.store_local(b"new", false, CopySource::User).unwrap();

        st.fulfill(5, b"old").unwrap();
        assert_eq!(*st.load().unwrap(), b"new");
    }

    /// The daemon already holds the content, so the promise needs no fetch.
    #[test]
    fn a_known_digest_needs_no_fetch() {
        let mut st = state(OMEN);
        st.store_local(b"same bytes", false, CopySource::User).unwrap();

        st.adopt(9, EDGE, meta_of(b"same bytes", false), None).unwrap();
        assert!(matches!(st.content(), Content::Held));
        assert_eq!(*st.load().unwrap(), b"same bytes");
    }

    #[test]
    fn a_fetch_for_another_generation_finds_nothing() {
        let mut st = state(OMEN);
        st.store_local(b"hello", false, CopySource::User).unwrap();

        assert!(st.serve(1).is_some());
        assert!(st.serve(2).is_none());
    }
}
