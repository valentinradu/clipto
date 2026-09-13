//! The configuration both binaries read.
//!
//! The file is `~/.config/clipto/config.toml`. Every value has a default, and
//! the file is optional.
//!
//! One type describes the whole file. `deny_unknown_fields` rejects a key it
//! does not know, so a key that only one binary uses must still be here:
//! otherwise the other binary refuses to start on a file that is correct.

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
    /// The TCP port the bridge listens on for the phone.
    pub web_port: u16,
    /// False stops a sensitive payload at the daemon, so the bridge never
    /// reads one.
    pub web_sensitive: bool,
    /// A node must carry this tag before the bridge answers it.
    pub web_tag: String,
    /// The network device the bridge binds. Linux delivers a packet to a
    /// socket bound to an address even when the packet arrived on another
    /// device, so the address alone does not keep the LAN out.
    pub web_device: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            port: 17843,
            inline_limit: 65536,
            sync_sensitive: true,
            peer_refresh: 30,
            fetch_timeout: 2,
            web_port: 17844,
            web_sensitive: false,
            web_tag: "tag:admin".to_string(),
            web_device: "tailscale0".to_string(),
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

// ─── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_defaults_gate_the_bridge() {
        let config = Config::default();
        assert_eq!(config.web_port, 17844);
        assert_eq!(config.web_tag, "tag:admin");
        assert!(!config.web_sensitive);
    }

    /// One type reads the whole file. A key that only the bridge uses must not
    /// make the daemon refuse a file that is correct.
    #[test]
    fn reads_a_file_that_holds_every_key() {
        let text = r#"
            port = 1
            inline_limit = 2
            sync_sensitive = false
            peer_refresh = 3
            fetch_timeout = 4
            web_port = 5
            web_sensitive = true
            web_tag = "tag:phone"
            web_device = "ts0"
        "#;
        let config: Config = toml::from_str(text).unwrap();
        assert_eq!(config.port, 1);
        assert_eq!(config.web_port, 5);
        assert!(config.web_sensitive);
        assert_eq!(config.web_tag, "tag:phone");
        assert_eq!(config.web_device, "ts0");
    }

    #[test]
    fn refuses_a_key_it_does_not_know() {
        assert!(toml::from_str::<Config>("web_prot = 5").is_err());
    }
}
