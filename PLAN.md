# Plan: share the clipboard between machines

This plan adds a multi-machine clipboard to `clipto`. It adds no server. Read
it with `README.md`, which describes the daemon as it is today.

## Goal

A copy on one machine becomes a paste on another machine. The machines find
each other on the Tailscale network. A machine joins when it holds the shared
credential. No new server exists, and no third party reads a payload.

## The decisions that are settled

- **No server.** The machines talk to each other directly.
- **The tailnet is the transport, not the identity.** Any node on the tailnet
  may try to connect. The credential alone decides who joins. Do not add a
  Tailscale tag or an access control list for `clipto`.
- **Last writer wins.** A Lamport counter orders the copies. The wall clock
  does not order them, because the machines disagree on the time.
- **The credential never encrypts a payload.** It only gates the handshake.
  Each session derives new ephemeral keys, so a leaked credential exposes the
  later copies but not the recorded traffic.
- **A promise crosses the network, not always the bytes.** This repeats the
  Wayland model one layer up.

## What this decision costs

Every node on the tailnet can reach the port and start a handshake. The
handshake is therefore the only gate. Three rules follow, and the
implementation must obey all three:

1. The daemon sends nothing before the handshake completes. A peer that fails
   learns no version, no generation number and no size.
2. The daemon limits the handshake attempts for each source address.
3. The daemon writes a log line for each failure with the source address, so
   the user sees a machine that probes the port.

## The parts that exist today

| Part | File | Reuse |
|---|---|---|
| Encrypted buffer and the daemon state | `clipd/src/main.rs` | Add a generation number and an origin. |
| Wayland selection owner | `clipd/src/wayland.rs` | Add the remote promise to the `Send` handler. |
| Frame protocol, magic, version, timeouts | `clipto-ipc/src/lib.rs` | Reuse the frame for the network messages. |
| `CopySource` | `clipto-ipc/src/lib.rs` | Add a `Remote` variant. |

## Machine identity

The daemon derives its identity from the key it already holds. It does not
store a new file, and the user runs no new command.

```
static_key = HKDF-SHA256(ikm = clipto-key, info = "clipto peer identity v1")
machine_id = first 8 bytes of the static public key
```

The `clipto-key` is sealed to the TPM of one machine, so the identity is per
machine and stable across a restart.

## The credential

The credential is a second systemd credential, named `clipto-psk`. It holds 32
random bytes. The same bytes go to every machine that shares the clipboard.

The user creates it once:

```bash
dd if=/dev/urandom bs=32 count=1 2>/dev/null \
  | systemd-creds encrypt --name=clipto-psk - \
    ~/.config/clipto/clipto-psk.cred
```

The user then copies the plaintext bytes to each new machine and seals them
there. This is the only manual step. Add a second line to the unit file:

```
LoadCredentialEncrypted=clipto-psk:%h/.config/clipto/clipto-psk.cred
```

The daemon runs with no network when the credential is absent. The local
clipboard must keep working.

## Discovery

The daemon reads the peer list from `tailscaled` over its local socket. It
spawns no process.

- Socket: `/var/run/tailscale/tailscaled.sock`, mode `0666` on this machine.
- Request: `GET /localapi/v0/status` with the header
  `Host: local-tailscaled.sock`.
- Allow an override with the `CLIPTO_TAILSCALED_SOCK` variable.

Read these fields from the answer:

| Field | Use |
|---|---|
| `Self.TailscaleIPs` | The addresses to bind the listener to. |
| `Peer.*.TailscaleIPs` | The address to connect to. |
| `Peer.*.Online` | Skip a peer that is offline. |
| `Peer.*.HostName` | The name in a log line and in `clipto peers`. |

The daemon reads the list at start, then every 30 seconds, and again after a
connection fails. It caches which peers answer the `clipto` port, so it does
not retry a phone or a router on every copy.

## Transport

- The listener binds to the Tailscale addresses only, both IPv4 and IPv6. It
  must not bind `0.0.0.0`, because the port must not appear on the LAN.
- Port `17843`. The number is arbitrary. Make it a config value.
- Handshake: Noise `XX` with a pre-shared key in the third message. The full
  name is `Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s`. Use the `snow` crate.
- The static key is the derived identity above. The pre-shared key is the
  credential.
- Apply the same read timeout and write timeout that the Unix socket uses.

The daemon records the static public key of each peer at the first successful
handshake. It writes the record next to the socket, and `clipto peers` prints
it. The user removes one machine by deleting its record. The user rotates the
credential only to lock out a machine that still holds it.

## The messages

The messages travel inside the Noise session. They reuse the frame from
`clipto-ipc`, so the magic, the version byte and the size cap already apply.

```rust
pub enum PeerMessage {
    /// Sent by both sides after the handshake, and again to catch up.
    Hello {
        protocol_version: u8,
        machine_id: [u8; 8],
        generation: u64,
        state: Option<Meta>,
    },

    /// Sent to every peer after a local copy.
    Announce {
        machine_id: [u8; 8],
        generation: u64,
        meta: Meta,
        /// Present for a small payload that is not sensitive. Absent
        /// otherwise, and the peer then fetches the bytes when it needs them.
        inline: Option<Vec<u8>>,
    },

    /// Ask the origin for the bytes of one generation.
    Fetch { generation: u64 },

    Payload { data: Vec<u8> },

    /// The origin no longer holds that generation.
    Gone,
}

pub struct Meta {
    size: u64,
    sensitive: bool,
    /// Lets a peer skip a fetch when it already holds this content.
    digest: [u8; 32],
}
```

## Order and loops

The daemon state gains three fields: `generation: u64`, `origin: [u8; 8]` and
the source of the current buffer.

- A local copy sets `generation = generation + 1` and `origin = machine_id`.
- On an `Announce` or a `Hello`, set
  `generation = max(generation, message.generation)`.
- Take the content when `(message.generation, message.machine_id)` is larger
  than `(generation, origin)`. Compare the generation first, then the machine
  identifier.
- Store a remote payload with `CopySource::Remote`. The daemon claims the
  local Wayland selection for it, but it announces nothing. This stops the
  echo between two machines.

## What travels, and when

- **Send a small payload with the announcement.** Use a limit of 64 KiB, and
  make it a config value. A sleeping machine then still holds the last copy.
- **Fetch a large payload when a client pastes.** The announcement carries the
  size and the digest only.
- **Never send a sensitive payload with the announcement.** Fetch it every
  time. The receiving machine keeps it in the encrypted buffer, and it writes
  no copy anywhere else.
- Add a config value that stops a sensitive payload from crossing the network
  at all.

## The promise chain

A remote announcement with no inline payload gives the daemon a promise, not
the bytes. The daemon still claims the local Wayland selection at once.

When a client pastes, the Wayland `Send` handler fetches the bytes from the
origin peer, then writes them into the pipe. The chain runs from the
compositor, to the local daemon, to the remote daemon.

Two rules for this path:

- Use a shorter deadline for the network fetch than `PASTE_TIMEOUT`. Two
  seconds is a good start. The paste must not appear to hang.
- When the fetch fails, close the pipe and write nothing. Never serve the older
  content instead. A silent stale paste is worse than an empty one. `clipto
  paste` must report the name of the machine it cannot reach.

## Catch up

A machine that sleeps misses the announcements. The daemon repairs this without
a server:

1. Send `Hello` to each online peer at start.
2. Send `Hello` to a peer that returns to the online state.
3. Take the highest generation from the answers.

## Configuration

Add `~/.config/clipto/config.toml`. Every value has a default, and the file is
optional.

```toml
port = 17843
inline_limit = 65536      # bytes sent with the announcement
sync_sensitive = true     # false stops a sensitive payload at the machine
peer_refresh = 30         # seconds between two peer list reads
fetch_timeout = 2         # seconds for one network fetch
```

## The work, in order

1. **Foundations.** Add the generation number, the origin and
   `CopySource::Remote`. Derive the machine identity. Read the config file.
   Nothing touches the network yet.
2. **Discovery.** Write the `tailscaled` client and the peer cache. Add
   `clipto peers`, which prints the peers and their state.
3. **Transport.** Add the listener on the Tailscale addresses, the Noise
   handshake, the rate limit and the failure log.
4. **Sync.** Add the messages, the announcement after a local copy, the fetch,
   the catch up and the last writer wins rule.
5. **The promise chain.** Fetch a remote payload inside the Wayland `Send`
   handler.
6. **Documents.** Update `README.md`. It says today that two machines cannot
   share one clipboard. Describe the new key design, the credential and the
   single manual step.

## Tests

Three Linux machines on the tailnet run the daemon: `omen`, `thinkcentre` and
`edge`. The `iphone` node runs nothing, and it must not break the discovery.

- Copy on one machine, then paste on a second machine. Test both directions.
- Copy a payload of 5 MB. Compare the bytes on the far machine.
- Copy on one machine while a second machine sleeps. Wake it. The catch up
  must give it the payload.
- Copy on two machines at nearly the same moment. Both machines must agree
  which copy wins.
- Start a daemon with the wrong credential. The handshake must fail, and the
  daemon must send nothing.
- Connect to the port from a tailnet node that holds no credential. The daemon
  must reject it and log the address.
- Copy with `--sensitive`. The announcement must carry no payload.
- Stop the origin machine, then paste on a second machine. The paste must fail
  with a clear message, and it must not serve the older content.

## Out of scope

- The iPhone and any other node that cannot run the daemon.
- An image or any other format that is not text.
- A clipboard history.
- A machine outside the tailnet.

## Open questions

- **Does a peer keep a payload after it takes it?** The plan says yes, in the
  encrypted buffer, because that is what makes a paste work. Confirm that a
  sensitive payload may also stay there.
- **Which crate reads the local HTTP answer?** The answer is plain HTTP/1.1
  over a Unix socket. A small hand-written reader avoids a dependency. Measure
  the cost of both before you choose.
- **Does the daemon announce to a peer it has never reached?** The plan says
  it tries each online peer once, then caches the result. Confirm that the cost
  is acceptable with a larger tailnet.
