//! The machines the daemon knows about.
//!
//! The daemon records the static public key of each machine at the first
//! successful handshake. A later handshake that shows a different key for the
//! same machine identifier is refused. The user removes one machine by deleting
//! its record.
//!
//! The daemon also caches which machines answer the `clipto` port, so it does
//! not retry a phone or a router on every copy.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use clipto_ipc::PeerInfo;

use crate::discovery::Node;
use crate::identity::format_id;

/// How long the daemon leaves a machine alone after the first failure. The
/// wait doubles with each failure that follows.
///
/// One failure is enough to stop asking for a while. An announcement waits for
/// every machine it tries, so a machine that is on the tailnet and answers
/// nothing — a phone, a router, a server that runs no clipd — would otherwise
/// put its whole connection timeout in front of the next copy.
const FIRST_QUIET: Duration = Duration::from_secs(15);

/// The longest the daemon leaves a machine alone. A phone and a router never
/// answer, and this stops a retry on every copy.
const LONGEST_QUIET: Duration = Duration::from_secs(300);

/// One machine, as the file on the disk holds it.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Record {
    /// The name at the first handshake. Only a log line uses it.
    hostname: String,
    /// The static public key, in hexadecimal.
    static_key: String,
}

/// What the daemon learned about one machine while it was running.
#[derive(Debug, Default, Clone)]
struct Runtime {
    machine_id: Option<[u8; 8]>,
    /// None before the first attempt.
    reachable: Option<bool>,
    /// How many attempts failed in a row. The wait grows with it.
    failures: u32,
    last_failure: Option<Instant>,
    last_error: Option<String>,
}

impl Runtime {
    /// True while the daemon must leave this machine alone.
    fn quiet(&self, now: Instant) -> bool {
        let Some(at) = self.last_failure else {
            return false;
        };
        let quiet = FIRST_QUIET
            .saturating_mul(2u32.saturating_pow(self.failures.saturating_sub(1).min(10)))
            .min(LONGEST_QUIET);
        now.duration_since(at) < quiet
    }
}

struct Inner {
    known: HashMap<String, Record>,
    nodes: Vec<Node>,
    runtime: HashMap<String, Runtime>,
}

pub struct Registry {
    path: Option<PathBuf>,
    inner: Mutex<Inner>,
}

impl Registry {
    /// Read the records from the disk. A missing file gives an empty registry.
    pub fn open() -> Self {
        let path = record_path();
        let known = path.as_ref().map(read_records).unwrap_or_default();

        Registry {
            path,
            inner: Mutex::new(Inner {
                known,
                nodes: Vec::new(),
                runtime: HashMap::new(),
            }),
        }
    }

    /// Replace the peer list with what `tailscaled` reports.
    pub fn set_nodes(&self, nodes: Vec<Node>) {
        self.inner.lock().unwrap().nodes = nodes;
    }

    /// The machines that are online and worth an attempt right now.
    pub fn candidates(&self) -> Vec<Node> {
        let inner = self.inner.lock().unwrap();
        let now = Instant::now();

        inner
            .nodes
            .iter()
            .filter(|node| node.online)
            .filter(|node| {
                inner
                    .runtime
                    .get(&node.hostname)
                    .is_none_or(|rt| !rt.quiet(now))
            })
            .cloned()
            .collect()
    }

    /// The machines that are worth an attempt and that this daemon has not
    /// talked to yet. A machine that is up but was not reachable a moment ago
    /// belongs here, so a daemon that starts first still finds the other one.
    pub fn ungreeted(&self) -> Vec<Node> {
        let reached: HashSet<String> = {
            let inner = self.inner.lock().unwrap();
            inner
                .runtime
                .iter()
                .filter(|(_, rt)| rt.reachable == Some(true))
                .map(|(host, _)| host.clone())
                .collect()
        };

        self.candidates()
            .into_iter()
            .filter(|node| !reached.contains(&node.hostname))
            .collect()
    }

    /// Drop what the daemon learned about one machine, so the next attempt
    /// starts with no failure behind it.
    pub fn forget(&self, hostname: &str) {
        self.inner.lock().unwrap().runtime.remove(hostname);
    }

    /// The machine that owns one identifier, when discovery still reports it.
    pub fn node_for(&self, machine_id: [u8; 8]) -> Option<Node> {
        let inner = self.inner.lock().unwrap();
        let hostname = inner
            .runtime
            .iter()
            .find(|(_, rt)| rt.machine_id == Some(machine_id))
            .map(|(host, _)| host.clone())?;
        inner
            .nodes
            .iter()
            .find(|node| node.hostname == hostname)
            .cloned()
    }

    /// The name discovery gives to one address.
    pub fn hostname_at(&self, address: IpAddr) -> Option<String> {
        let inner = self.inner.lock().unwrap();
        inner
            .nodes
            .iter()
            .find(|node| node.addresses.contains(&address))
            .map(|node| node.hostname.clone())
    }

    /// The name of one machine, for a message the user reads.
    pub fn name_for(&self, machine_id: [u8; 8]) -> String {
        let inner = self.inner.lock().unwrap();
        inner
            .runtime
            .iter()
            .find(|(_, rt)| rt.machine_id == Some(machine_id))
            .map(|(host, _)| host.clone())
            .or_else(|| {
                inner
                    .known
                    .get(&format_id(&machine_id))
                    .map(|r| r.hostname.clone())
            })
            .unwrap_or_else(|| format_id(&machine_id))
    }

    /// Accept a machine after a handshake, or refuse it when its static key
    /// changed. The first handshake writes the record.
    pub fn admit(&self, machine_id: [u8; 8], static_key: [u8; 32], hostname: &str) -> Result<()> {
        let id = format_id(&machine_id);
        let key = hex::encode(static_key);

        let mut inner = self.inner.lock().unwrap();
        match inner.known.get(&id) {
            Some(record) if record.static_key != key => {
                bail!(
                    "the machine {id} shows a different static key than the record for {}; \
                     delete its record to accept the new key",
                    record.hostname
                );
            }
            Some(_) => {}
            None => {
                inner.known.insert(
                    id,
                    Record {
                        hostname: hostname.to_string(),
                        static_key: key,
                    },
                );
                let known = inner.known.clone();
                drop(inner);
                if let Some(path) = &self.path {
                    if let Err(e) = write_records(path, &known) {
                        eprintln!("peers: failed to write {}: {e:#}", path.display());
                    }
                }
                return Ok(());
            }
        }
        Ok(())
    }

    /// Note that a machine answered the port.
    pub fn reached(&self, hostname: &str, machine_id: [u8; 8]) {
        let mut inner = self.inner.lock().unwrap();
        let rt = inner.runtime.entry(hostname.to_string()).or_default();
        rt.machine_id = Some(machine_id);
        rt.reachable = Some(true);
        rt.failures = 0;
        rt.last_failure = None;
        rt.last_error = None;
    }

    /// Note that a machine did not answer the port.
    pub fn failed(&self, hostname: &str, error: &str) {
        let mut inner = self.inner.lock().unwrap();
        let rt = inner.runtime.entry(hostname.to_string()).or_default();
        rt.reachable = Some(false);
        rt.failures = rt.failures.saturating_add(1);
        rt.last_failure = Some(Instant::now());
        rt.last_error = Some(error.to_string());
    }

    /// The list `clipto peers` prints.
    pub fn report(&self) -> Vec<PeerInfo> {
        let inner = self.inner.lock().unwrap();
        inner
            .nodes
            .iter()
            .map(|node| {
                let rt = inner.runtime.get(&node.hostname);
                let machine_id = rt
                    .and_then(|rt| rt.machine_id)
                    .map(|id| format_id(&id))
                    .unwrap_or_default();

                let state = match rt.map(|rt| (rt.reachable, rt.last_error.clone())) {
                    Some((Some(true), _)) => "joined".to_string(),
                    Some((Some(false), Some(error))) => error,
                    Some((Some(false), None)) => "unreachable".to_string(),
                    _ if !node.online => "offline".to_string(),
                    _ => "not tried yet".to_string(),
                };

                PeerInfo {
                    hostname: node.hostname.clone(),
                    address: node
                        .addresses
                        .first()
                        .map(IpAddr::to_string)
                        .unwrap_or_default(),
                    online: node.online,
                    machine_id,
                    state,
                }
            })
            .collect()
    }
}

/// Path to the record file: `$XDG_STATE_HOME/clipto/peers.json`.
///
/// The records must survive a restart, otherwise the daemon would accept a new
/// static key for a known machine every time it starts.
fn record_path() -> Option<PathBuf> {
    let dir = match std::env::var("XDG_STATE_HOME") {
        Ok(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => PathBuf::from(std::env::var("HOME").ok()?).join(".local/state"),
    };
    Some(dir.join("clipto").join("peers.json"))
}

fn read_records(path: &PathBuf) -> HashMap<String, Record> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return HashMap::new();
    };
    match serde_json::from_str(&text) {
        Ok(records) => records,
        Err(e) => {
            eprintln!("peers: {} is not readable: {e}", path.display());
            HashMap::new()
        }
    }
}

fn write_records(path: &PathBuf, records: &HashMap<String, Record>) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("failed to make {}", dir.display()))?;
    }
    let text = serde_json::to_string_pretty(records).context("failed to write the records")?;
    std::fs::write(path, text).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}
