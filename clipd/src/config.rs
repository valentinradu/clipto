//! The daemon configuration.
//!
//! The file is `~/.config/clipto/config.toml`. Every value has a default, and
//! the file is optional.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    /// The TCP port the daemon listens on, and the port it connects to.
    pub port: u16,
    /// The largest payload the daemon sends with an announcement, in bytes.
    pub inline_limit: usize,
    /// False stops a sensitive payload at this machine.
    pub sync_sensitive: bool,
    /// Seconds between two peer list reads.
    pub peer_refresh: u64,
    /// Seconds for one network fetch.
    pub fetch_timeout: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            port: 17843,
            inline_limit: 65536,
            sync_sensitive: true,
            peer_refresh: 30,
            fetch_timeout: 2,
        }
    }
}

impl Config {
    pub fn peer_refresh(&self) -> Duration {
        Duration::from_secs(self.peer_refresh)
    }

    pub fn fetch_timeout(&self) -> Duration {
        Duration::from_secs(self.fetch_timeout)
    }
}

/// Path to the configuration file: `~/.config/clipto/config.toml`.
fn config_path() -> Option<PathBuf> {
    let dir = match std::env::var("XDG_CONFIG_HOME") {
        Ok(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => PathBuf::from(std::env::var("HOME").ok()?).join(".config"),
    };
    Some(dir.join("clipto").join("config.toml"))
}

/// Read the configuration. A missing file gives the defaults. A bad file is an
/// error, because a silent default would hide a typing mistake.
pub fn load() -> Result<Config> {
    let Some(path) = config_path() else {
        return Ok(Config::default());
    };

    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Config::default()),
        Err(e) => return Err(e).with_context(|| format!("failed to read {}", path.display())),
    };

    toml::from_str(&text).with_context(|| format!("failed to parse {}", path.display()))
}
