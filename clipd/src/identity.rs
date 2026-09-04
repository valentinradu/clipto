//! The machine identity and the shared credential.
//!
//! The daemon derives its identity from the key it already holds. It stores no
//! new file, and the user runs no new command.
//!
//! ```text
//! static_key = HKDF-SHA256(ikm = clipto-key, info = "clipto peer identity v1")
//! machine_id = first 8 bytes of the static public key
//! ```
//!
//! The `clipto-key` is sealed to the TPM of one machine, so the identity is per
//! machine and stable across a restart.

use anyhow::{bail, Result};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::keys;

/// Separates this use of the key from every other use of the same key.
const IDENTITY_INFO: &[u8] = b"clipto peer identity v1";

/// The Noise pattern. `XX` gives both sides a fresh ephemeral key, and `psk3`
/// puts the shared credential in the third message.
pub const NOISE_PATTERN: &str = "Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s";

/// What one machine needs to talk to another.
pub struct Identity {
    /// The Curve25519 private key, derived from `clipto-key`.
    pub static_secret: Zeroizing<[u8; 32]>,
    /// The first 8 bytes of the public key.
    pub machine_id: [u8; 8],
    /// The shared credential. The same bytes go to every machine.
    pub psk: Zeroizing<[u8; 32]>,
}

/// Derive the identity from the encryption key and the shared credential.
pub fn derive(key: &[u8], psk: [u8; 32]) -> Result<Identity> {
    let hk = Hkdf::<Sha256>::new(None, key);
    let mut secret = Zeroizing::new([0u8; 32]);
    hk.expand(IDENTITY_INFO, secret.as_mut_slice())
        .map_err(|_| anyhow::anyhow!("failed to derive the peer identity"))?;

    // Both `x25519-dalek` and `snow` clamp the scalar before they use it, so
    // the two agree on which public key belongs to these bytes.
    let static_public = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(*secret));
    let static_public = static_public.to_bytes();

    let mut machine_id = [0u8; 8];
    machine_id.copy_from_slice(&static_public[..8]);

    Ok(Identity {
        static_secret: secret,
        machine_id,
        psk: Zeroizing::new(psk),
    })
}

/// Read the shared credential, named `clipto-psk`.
///
/// Returns `None` when no credential exists. The daemon then runs with no
/// network, and the local clipboard keeps working.
pub fn load_psk() -> Result<Option<[u8; 32]>> {
    let Some(bytes) = keys::load_secret("clipto-psk", "CLIPTO_PSK_FILE")? else {
        return Ok(None);
    };

    if bytes.len() != 32 {
        bail!(
            "the clipto-psk credential must be exactly 32 bytes, got {}",
            bytes.len()
        );
    }

    let mut psk = [0u8; 32];
    psk.copy_from_slice(&bytes);
    Ok(Some(psk))
}

/// Print a machine identifier the way `clipto peers` shows it.
pub fn format_id(id: &[u8; 8]) -> String {
    hex::encode(id)
}
