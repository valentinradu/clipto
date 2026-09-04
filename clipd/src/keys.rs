//! Loads a secret from the systemd credentials directory.
//!
//! `systemd-creds` seals a credential to the TPM of this machine. systemd
//! unseals it and puts the plaintext in `$CREDENTIALS_DIRECTORY`, which only
//! this service can read. A file path in an environment variable is the
//! development fallback.

use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use zeroize::Zeroizing;

/// Read one credential by name.
///
/// `env_var` names the development fallback, for example `CLIPTO_KEY_FILE`.
/// Returns `None` when neither source holds the credential.
pub fn load_secret(name: &str, env_var: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
    if let Ok(creds) = std::env::var("CREDENTIALS_DIRECTORY") {
        let path = PathBuf::from(&creds).join(name);
        if path.exists() {
            let bytes = std::fs::read(&path)
                .with_context(|| format!("failed to read {}", path.display()))?;
            return Ok(Some(Zeroizing::new(bytes)));
        }
    }

    if let Ok(file) = std::env::var(env_var) {
        let bytes =
            std::fs::read(&file).with_context(|| format!("failed to read {name} from {file}"))?;
        return Ok(Some(Zeroizing::new(bytes)));
    }

    Ok(None)
}

/// Read the encryption key, named `clipto-key`. The daemon cannot start
/// without it.
pub fn load_key() -> Result<Zeroizing<Vec<u8>>> {
    let Some(key) = load_secret("clipto-key", "CLIPTO_KEY_FILE")? else {
        bail!(
            "no key found: run as a systemd service with LoadCredentialEncrypted=clipto-key:…, \
             or set CLIPTO_KEY_FILE for development"
        );
    };

    if key.len() != 32 {
        bail!("the key must be exactly 32 bytes, got {}", key.len());
    }

    Ok(key)
}
