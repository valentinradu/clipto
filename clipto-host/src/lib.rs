//! What `clipd` and `clipw` both need from the machine they run on.
//!
//! The configuration file, the `tailscaled` lookups, and the failure limit for
//! one source address. Both binaries read the same `config.toml`, so the type
//! that describes it lives here rather than in either one.

pub mod config;
pub mod limit;
pub mod tailscale;
