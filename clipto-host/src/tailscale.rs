//! Reads the peer list and the node behind an address from `tailscaled`.
//!
//! Both binaries talk to the local API over the `tailscaled` Unix socket. They
//! spawn no process.
//!
//! `tailscaled` runs an HTTP server on that socket, so they speak HTTP to it.
//! They ask with HTTP/1.0, which keeps the answer simple: `tailscaled` then
//! sends no chunked body, and the body ends when the connection closes.
//! `httparse` reads the head. It is the parser that `hyper` uses, and it pulls
//! in no other crate.
//!
//! Both calls read the netmap that `tailscaled` already holds. Neither one
//! reaches the control server, so both keep working while it is unreachable.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use anyhow::{bail, Context, Result};

/// The socket `tailscaled` listens on. Mode `0666` on this machine.
const DEFAULT_SOCKET: &str = "/var/run/tailscale/tailscaled.sock";

/// `tailscaled` refuses a request that carries another host name.
const LOCAL_HOST: &str = "local-tailscaled.sock";

/// How long one read or write on the `tailscaled` socket may stall.
const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// The largest answer to read. A tailnet status is a few kilobytes.
const MAX_ANSWER: usize = 8 * 1024 * 1024;

/// Room for the headers `tailscaled` sends. It sends nine today.
const MAX_HEADERS: usize = 64;

/// One machine on the tailnet.
#[derive(Debug, Clone)]
pub struct Node {
    pub hostname: String,
    pub addresses: Vec<IpAddr>,
    pub online: bool,
}

/// What the tailnet looks like right now.
#[derive(Debug, Clone)]
pub struct Status {
    /// The addresses of this machine. A listener binds to these.
    pub own_addresses: Vec<IpAddr>,
    pub peers: Vec<Node>,
}

/// The node behind one address, as the netmap names it.
#[derive(Debug, Clone)]
pub struct Who {
    /// The MagicDNS name, with no trailing dot.
    pub name: String,
    /// The tags the control server gave the node. Empty for an untagged node.
    pub tags: Vec<String>,
}

impl Who {
    pub fn has_tag(&self, tag: &str) -> bool {
        self.tags.iter().any(|held| held == tag)
    }
}

/// Path to the `tailscaled` socket. `CLIPTO_TAILSCALED_SOCK` overrides it.
fn socket_path() -> String {
    std::env::var("CLIPTO_TAILSCALED_SOCK").unwrap_or_else(|_| DEFAULT_SOCKET.to_string())
}

/// Read `GET /localapi/v0/status` and turn the answer into a `Status`.
pub fn status() -> Result<Status> {
    let body = get("/localapi/v0/status")?;
    let value: serde_json::Value =
        serde_json::from_slice(&body).context("tailscaled sent an answer that is not JSON")?;
    parse_status(&value)
}

/// Read the node behind one source address.
///
/// The address carries the port, because `tailscaled` matches a whole socket
/// address. Only the holder of that node's private key can put a packet in the
/// tunnel that address belongs to, so the answer is a proof of identity, not a
/// label.
pub fn whois(address: SocketAddr) -> Result<Who> {
    let body = get(&format!(
        "/localapi/v0/whois?addr={}",
        encode(&address.to_string())
    ))?;
    let value: serde_json::Value =
        serde_json::from_slice(&body).context("tailscaled sent an answer that is not JSON")?;
    parse_who(&value)
}

/// Percent-encode everything that is not unreserved.
///
/// An IPv6 socket address holds `[`, `]` and `:`. RFC 3986 keeps those for the
/// host part, so they do not belong in a query value unencoded.
fn encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len() * 3);
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Send one GET request and return the body.
fn get(path: &str) -> Result<Vec<u8>> {
    let socket = socket_path();
    let mut stream = UnixStream::connect(&socket)
        .with_context(|| format!("failed to connect to tailscaled at {socket}"))?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;

    // HTTP/1.0, because a chunked body is not valid in HTTP/1.0. `tailscaled`
    // therefore writes the body and closes, and the caller reads to the end.
    write!(stream, "GET {path} HTTP/1.0\r\nHost: {LOCAL_HOST}\r\n\r\n")
        .context("failed to send the request to tailscaled")?;
    stream.flush()?;

    let mut answer = Vec::new();
    stream
        .take(MAX_ANSWER as u64)
        .read_to_end(&mut answer)
        .context("failed to read the answer from tailscaled")?;

    body(&answer).map(<[u8]>::to_vec)
}

/// Cut the head off the answer and give back the body.
fn body(answer: &[u8]) -> Result<&[u8]> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut response = httparse::Response::new(&mut headers);

    let httparse::Status::Complete(head) = response
        .parse(answer)
        .context("tailscaled sent an answer that is not HTTP")?
    else {
        bail!("tailscaled sent an answer that stops inside the head");
    };

    match response.code {
        Some(200) => {}
        Some(code) => bail!("tailscaled answered with status {code}"),
        None => bail!("tailscaled sent no status code"),
    }

    // HTTP/1.0 forbids this, so it means the answer is not what it claims.
    // Say so, rather than hand back a body full of chunk sizes.
    if response
        .headers
        .iter()
        .any(|h| h.name.eq_ignore_ascii_case("transfer-encoding"))
    {
        bail!("tailscaled sent an HTTP/1.0 answer with a transfer encoding");
    }

    Ok(&answer[head..])
}

/// Pull the fields the caller needs out of the status answer.
fn parse_status(value: &serde_json::Value) -> Result<Status> {
    let own_addresses = addresses(value.get("Self"));
    if own_addresses.is_empty() {
        bail!("tailscaled reports no address for this machine");
    }

    let mut peers = Vec::new();
    if let Some(map) = value.get("Peer").and_then(|p| p.as_object()) {
        for node in map.values() {
            let addresses = addresses(Some(node));
            if addresses.is_empty() {
                continue;
            }
            peers.push(Node {
                hostname: node
                    .get("HostName")
                    .and_then(|h| h.as_str())
                    .unwrap_or("unknown")
                    .to_string(),
                addresses,
                online: node
                    .get("Online")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false),
            });
        }
    }

    peers.sort_by(|a, b| a.hostname.cmp(&b.hostname));
    Ok(Status {
        own_addresses,
        peers,
    })
}

/// Pull the name and the tags out of a whois answer.
fn parse_who(value: &serde_json::Value) -> Result<Who> {
    let node = value
        .get("Node")
        .context("tailscaled reports no node for that address")?;

    let name = node
        .get("Name")
        .and_then(|n| n.as_str())
        .context("tailscaled reports a node with no name")?
        .trim_end_matches('.')
        .to_string();

    let tags = node
        .get("Tags")
        .and_then(|t| t.as_array())
        .map(|tags| {
            tags.iter()
                .filter_map(|tag| tag.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();

    Ok(Who { name, tags })
}

/// Read `TailscaleIPs` from one node.
fn addresses(node: Option<&serde_json::Value>) -> Vec<IpAddr> {
    node.and_then(|n| n.get("TailscaleIPs"))
        .and_then(|ips| ips.as_array())
        .map(|ips| {
            ips.iter()
                .filter_map(|ip| ip.as_str()?.parse().ok())
                .collect()
        })
        .unwrap_or_default()
}

// ─── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// An HTTP/1.0 body ends when the connection closes, so everything after
    /// the head is the body.
    #[test]
    fn reads_the_body_after_the_head() {
        let answer = "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\nhello world";
        assert_eq!(body(answer.as_bytes()).unwrap(), b"hello world");
    }

    #[test]
    fn reads_an_empty_body() {
        let answer = "HTTP/1.0 200 OK\r\n\r\n";
        assert_eq!(body(answer.as_bytes()).unwrap(), b"");
    }

    #[test]
    fn refuses_a_status_that_is_not_200() {
        let answer = "HTTP/1.0 403 Forbidden\r\n\r\ninvalid localapi request";
        assert!(body(answer.as_bytes()).is_err());
    }

    /// A chunked body cannot follow an HTTP/1.0 head. Report it, rather than
    /// hand back a body full of chunk sizes.
    #[test]
    fn refuses_a_body_it_cannot_read() {
        let answer = "HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        assert!(body(answer.as_bytes()).is_err());
    }

    #[test]
    fn refuses_a_head_that_does_not_end() {
        let answer = "HTTP/1.0 200 OK\r\nContent-Type: application/js";
        assert!(body(answer.as_bytes()).is_err());
    }

    #[test]
    fn reads_the_addresses_and_the_peers() {
        let answer = serde_json::json!({
            "Self": { "HostName": "omen", "TailscaleIPs": ["100.1.1.1", "fd7a::1"] },
            "Peer": {
                "nodekey:a": { "HostName": "edge", "TailscaleIPs": ["100.1.1.2"], "Online": true },
                "nodekey:b": { "HostName": "iphone", "TailscaleIPs": ["100.1.1.3"], "Online": false },
            }
        });

        let status = parse_status(&answer).unwrap();
        assert_eq!(status.own_addresses.len(), 2);
        assert_eq!(status.peers.len(), 2);
        assert_eq!(status.peers[0].hostname, "edge");
        assert!(status.peers[0].online);
        assert_eq!(status.peers[1].hostname, "iphone");
        assert!(!status.peers[1].online);
    }

    /// A node that carries no address, such as one that never came up, must not
    /// break the whole list.
    #[test]
    fn skips_a_peer_with_no_address() {
        let answer = serde_json::json!({
            "Self": { "TailscaleIPs": ["100.1.1.1"] },
            "Peer": {
                "nodekey:a": { "HostName": "ghost", "Online": true },
                "nodekey:b": { "HostName": "edge", "TailscaleIPs": ["100.1.1.2"], "Online": true },
            }
        });

        let status = parse_status(&answer).unwrap();
        assert_eq!(status.peers.len(), 1);
        assert_eq!(status.peers[0].hostname, "edge");
    }

    #[test]
    fn reads_the_name_and_the_tags() {
        let answer = serde_json::json!({
            "Node": { "Name": "iphone.example.ts.", "Tags": ["tag:admin", "tag:clipto"] },
        });

        let who = parse_who(&answer).unwrap();
        assert_eq!(who.name, "iphone.example.ts");
        assert!(who.has_tag("tag:clipto"));
        assert!(!who.has_tag("tag:edge"));
    }

    /// An untagged node carries no `Tags` key at all. It must read as a node
    /// with no tag, not as an error that hides why the bridge refused it.
    #[test]
    fn reads_a_node_that_holds_no_tag() {
        let answer = serde_json::json!({ "Node": { "Name": "omen.example.ts." } });

        let who = parse_who(&answer).unwrap();
        assert!(who.tags.is_empty());
        assert!(!who.has_tag("tag:clipto"));
    }

    /// `tailscaled` answers 200 with an empty object for an address the netmap
    /// does not hold.
    #[test]
    fn refuses_an_address_the_netmap_does_not_hold() {
        assert!(parse_who(&serde_json::json!({})).is_err());
    }

    #[test]
    fn encodes_an_address_for_the_query() {
        assert_eq!(encode("100.83.1.13:54321"), "100.83.1.13%3A54321");
        assert_eq!(encode("[fd7a::3]:80"), "%5Bfd7a%3A%3A3%5D%3A80");
    }
}
