# clipto

A secure clipboard daemon for Linux, bridging tmux (TTY and Wayland), the
Wayland compositor, any environment that can invoke a CLI — and, over a
Tailscale network, your other machines.

## The problem

On Linux, clipboard access depends on which environment you're in:

- **Wayland** (foot + Hyprland): `wl-copy` / `wl-paste`
- **TTY** (virtual console, no display server): nothing
- **tmux copy mode**: pipes to a shell command
- **another machine**: nothing

These environments don't share a clipboard. Copying in TTY tmux and pasting in
a browser, or copying in a browser and pasting in TTY tmux, is not possible
without a bridge. Copying on a laptop and pasting on a desktop needs one too.

## How it works

`clipd` is a daemon that owns the clipboard. It runs as a systemd user service,
loads an encryption key from systemd credentials at startup (the key never
touches disk), and exposes a Unix socket. Any process that can reach the socket
can copy or paste — TTY, tmux, Hyprland keybindings, scripts.

In Wayland sessions, `clipd` connects to the compositor itself and owns the
selection through `ext-data-control-v1`. It spawns no helper process — no
`wl-copy`, no `wl-paste`.

```
 Browser / GUI app
       |  Ctrl-C / Ctrl-V
       ▼
 ┌───────────────────┐
 │  the compositor   │  holds a promise, never the bytes
 └─────▲─────────────┘
       |  ext-data-control-v1 (Wayland)
       |
 ┌─────┴──────────────────────────────────────────────┐      ┌──────────────┐
 │  clipd   (systemd user service)                    │      │ clipd on     │
 │                                                    │◀────▶│ another      │
 │  key    — loaded from systemd-creds, in memory,   │      │ machine      │
 │           zeroized on drop, never written to disk  │ Noise└──────────────┘
 │                                                    │  over the tailnet
 │  buffer — ChaCha20-Poly1305 encrypted, in memory  │
 │                                                    │
 │  socket — $XDG_RUNTIME_DIR/clipto.sock, mode 600  │
 └─────┬──────────────────────────────────────────────┘
       |  Unix socket (IPC)
       |
 ┌─────┴─────────────┐
 │  clipto copy      │  reads stdin, sends to daemon
 │  clipto paste     │  requests from daemon, prints to stdout
 │  clipto peers     │  prints the machines that share the clipboard
 └───────────────────┘
       |
 tmux `y` binding   →  clipto copy
 tmux paste binding →  clipto paste | tmux load-buffer - && tmux paste-buffer
```

### Why owning the selection matters

In Wayland the client that copies keeps the bytes. The compositor stores only a
promise, and asks the owner for the data when somebody pastes. So `clipd` sets
the selection, then waits. It decrypts the buffer inside the `send` handler,
writes it to the descriptor the compositor passes, and erases it again.

Three properties follow:

- **The plaintext lives for the length of one paste.** Nothing holds a decrypted
  copy between a copy and a paste.
- **`clipd` never fights the owner.** When another client copies, `clipd` reads
  the new selection into its buffer and leaves that client as the owner. Its
  richer formats — `text/html`, `image/png` — stay intact.
- **The clipboard survives.** An app that dies takes its selection with it, but
  `clipd` keeps the payload, so `clipto paste` still works. It also re-claims
  the selection after a compositor restart.

  One limit: Hyprland does not tell a data-control client when the owning app
  exits. So a GUI paste stays empty until the next copy, even though `clipto
  paste` works. Run `clipto paste | clipto copy` to put it back.

`clipd` handles text. A selection it cannot represent as text is left alone.

## The clipboard across machines

A copy on one machine becomes a paste on another machine. There is no server,
and no third party reads a payload. The machines find each other on the
Tailscale network, and a machine joins when it holds the shared credential.

```
   omen                                              thinkcentre
 ┌────────────┐                                    ┌────────────┐
 │   clipd    │──── Noise_XXpsk3 over the tailnet ─│   clipd    │
 └────────────┘        port 17843                  └────────────┘
       │  1. a local copy raises the generation number
       │  2. it announces the size, the digest and the sensitivity
       │  3. a small payload travels with the announcement
       │  4. a large payload stays here until the far machine pastes
```

### The key design

The daemon holds two credentials. They do different work.

| Credential | Scope | Work |
|---|---|---|
| `clipto-key` | one machine | Encrypts the buffer in memory. Never leaves. |
| `clipto-psk` | every machine | Gates the handshake. Encrypts nothing. |

The daemon derives its machine identity from the key it already holds, so it
stores no new file and you run no new command:

```
static_key = HKDF-SHA256(ikm = clipto-key, info = "clipto peer identity v1")
machine_id = first 8 bytes of the static public key
```

`systemd-creds` seals the `clipto-key` to one machine, so the identity is per
machine and stable across a restart. **Each machine needs its own `clipto-key`.**
The same key on two machines gives them the same machine identifier, and the
tie-break rule above can then never separate them.

The `clipto-psk` never encrypts a payload. Each session runs a Noise `XX`
handshake with fresh ephemeral keys, and the credential enters only the third
message. A leaked credential therefore exposes the later copies, but it does
not open traffic somebody recorded earlier.

### The single manual step

Create the credential once, then copy the same 32 bytes to each machine and
seal them there:

```bash
# on the first machine, keep the plaintext long enough to carry it over
dd if=/dev/urandom bs=32 count=1 2>/dev/null > /dev/shm/clipto-psk

# on every machine, including the first
systemd-creds encrypt --user --name=clipto-psk /dev/shm/clipto-psk \
  "$HOME/.config/clipto/clipto-psk.cred"

# then erase the plaintext everywhere
shred -u /dev/shm/clipto-psk
```

Add the second line to the unit file:

```ini
LoadCredentialEncrypted=clipto-psk:%h/.config/clipto/clipto-psk.cred
```

The daemon runs with no network when the credential is absent, and the local
clipboard keeps working. `clipto peers` then says so.

### Order, and the loop between two machines

A Lamport counter orders the copies. The wall clock does not order them,
because the machines disagree on the time.

- A local copy raises the generation number and sets the origin to this
  machine.
- A machine takes a payload when `(generation, machine_id)` is larger than what
  it holds. The generation decides first, then the machine identifier, so two
  machines that copy at the same moment still agree.
- A payload that came from another machine claims the local Wayland selection,
  but it announces nothing. That stops the echo between two machines.

### What travels, and when

- A payload of 64 KiB or less travels with the announcement, so a machine that
  sleeps still holds the last copy.
- A larger payload stays where it was copied. The announcement carries the
  size and the digest only, and the far machine fetches the bytes when a client
  pastes. This repeats the Wayland promise model one layer up.
- A sensitive payload never travels with the announcement. The far machine
  fetches it, and keeps it in its own encrypted buffer.
- `sync_sensitive = false` stops a sensitive payload at the machine.

When a fetch fails, `clipd` writes nothing and closes the pipe. It never serves
the older content instead: a silent stale paste is worse than an empty one.
`clipto paste` names the machine it cannot reach.

### Catch up

A machine that sleeps misses the announcements. It repairs this with no server:
it greets every machine on the tailnet when it starts, and again when one
returns to the online state. It then takes the highest generation from the
answers.

### Discovery

The daemon reads the peer list from `tailscaled` over its local socket, and it
spawns no process.

```bash
clipto peers
# omen         3f2a1b9c4d5e6f70  100.83.1.11  joined
# thinkcentre  a1b2c3d4e5f60718  100.83.1.12  joined
# iphone       -                 100.83.1.13  failed to connect to 100.83.1.13:17843
```

A node that runs nothing, such as a phone, cannot break the discovery. The
daemon caches which machines answer the port, and it waits longer after each
failure, up to five minutes.

### Configuration

`~/.config/clipto/config.toml` is optional, and every value has a default.

```toml
port = 17843
inline_limit = 65536      # bytes sent with the announcement
sync_sensitive = true     # false stops a sensitive payload at the machine
peer_refresh = 30         # seconds between two peer list reads
fetch_timeout = 2         # seconds for one network fetch
```

## Security model

- The encryption key is generated once and stored with `systemd-creds encrypt`,
  which seals it to this machine's TPM / machine identity.
- Only `clipd` — via `LoadCredentialEncrypted` in its unit file — can unseal
  the key. No other process on the system can access it.
- Once loaded, the key lives in a `zeroize`d buffer in `clipd`'s memory. It is
  never written to any file or passed over the socket.
- The in-memory clipboard buffer is encrypted with ChaCha20-Poly1305 (AEAD).
  Even a process that can read `clipd`'s memory sees only ciphertext until it
  has the key.
- Plaintext exists in `clipd` only for the length of one request. The IPC frame
  buffers, the request payload and the response payload are all erased with
  `zeroize` before they are dropped.
- The Unix socket is `chmod 600` (owner-only). No other user can connect.
- Plaintext crosses the socket only in the `Paste` response — over a socket
  that is owner-only and local to the machine.
- The unit file sets `LimitCORE=0`. A core dump would write both the key and
  the clipboard plaintext to the disk.
- A frame larger than `MAX_FRAME` (64 MiB) is refused. The length prefix comes
  from the peer, so the cap stops a bad peer from exhausting memory.

### The network gate

The tailnet is the transport, not the identity. Every node on the tailnet can
reach the port, so the handshake is the only gate. `clipto` adds no Tailscale
tag and no access control list. Three rules follow, and the daemon obeys all
three:

1. **The daemon sends nothing before the handshake completes.** A peer that
   fails learns no version, no generation number and no size.
2. **The daemon limits the handshake attempts for each source address.** Ten
   failures inside one minute close the port to that address.
3. **The daemon writes a log line for each failure with the source address**,
   so you see a machine that probes the port.

The daemon records the static public key of each machine at the first
successful handshake, in `~/.local/state/clipto/peers.json`. A later handshake
that shows a different key for the same machine identifier is refused. You
remove one machine by deleting its record. You rotate the credential only to
lock out a machine that still holds it.

The listener binds the Tailscale addresses only, both IPv4 and IPv6. It never
binds `0.0.0.0`, so the port does not appear on the LAN.

### Sensitive payloads

```bash
clipto copy --sensitive < secret.txt
```

`clipd` then adds `x-kde-passwordManagerHint` to the formats it offers, which
asks a clipboard history tool not to write the payload to the disk. `clipd`
also reads that format from other clients, so a password copied out of a
password manager stays marked.

The flag changes nothing about the encryption. The buffer is always encrypted.
Across machines the flag does more: the announcement carries no sensitive
payload, and `sync_sensitive = false` keeps it on this machine entirely.

### What the model does not cover

- **A paste reveals the plaintext to the pasting client.** That is the purpose
  of a clipboard. `clipd` cannot know what the receiver does with it.
- **Every machine that holds `clipto-psk` reads every copy.** The credential is
  the only gate. Treat it the way you treat the clipboard itself.
- **A sensitive payload rests on each machine that took it.** It rests in the
  encrypted buffer, in memory, exactly as a local copy does. Set
  `sync_sensitive = false` when that is too much.
- **No authentication on the socket.** Any process running as you can copy and
  paste. The socket mode is the only barrier.

## Workspace structure

```
clipto/
├── Cargo.toml            # workspace
├── clipto-ipc/           # shared protocol types (serde + bincode)
│   └── src/lib.rs        # Request / Response / PeerMessage enums
├── clipd/                # daemon binary
│   ├── src/main.rs       # key, Unix socket, request handling
│   ├── src/state.rs      # the encrypted buffer, the generation, the promise
│   ├── src/wayland.rs    # ext-data-control client: owns the selection
│   ├── src/config.rs     # ~/.config/clipto/config.toml
│   ├── src/keys.rs       # systemd credentials
│   ├── src/identity.rs   # the machine identity, derived from the key
│   ├── src/discovery.rs  # the tailscaled local API client
│   ├── src/peers.rs      # the machine records and the reachability cache
│   ├── src/noise.rs      # the Noise handshake and the encrypted stream
│   ├── src/net.rs        # the listener, the announcement, the fetch
│   └── tests/sync.rs     # two daemons, one fake tailnet, one clipboard
└── clipto/               # CLI binary
    └── src/main.rs       # `copy`, `paste` and `peers` subcommands
```

## IPC protocol

Length-prefixed bincode frames over a Unix stream socket.

```rust
// clipto-ipc

pub enum CopySource {
    User,     // from tmux, a TTY or a script — claim the selection
    Wayland,  // already the selection — store it, claim nothing
    Remote,   // from another machine — claim it, announce nothing
}

pub enum Request {
    Copy { payload: Vec<u8>, source: CopySource, sensitive: bool },
    Paste,
    Peers,
}

pub enum Response {
    Ok,
    Payload { data: Vec<u8> },
    Error { message: String },
    Peers { peers: Vec<PeerInfo> },
}
```

Each message is serialized with `bincode` and framed:

```
┌───────┬─────────┬──────────────┬─────────────────┐
│ "CT"  │ version │ length (u32) │ bincode payload │
│ 2 B   │  1 B    │  4 B, LE     │  ≤ MAX_FRAME    │
└───────┴─────────┴──────────────┴─────────────────┘
```

`bincode` writes no field names, so two builds that disagree on the shape of
`Request` would read each other's bytes as nonsense. The version byte turns
that into one clear message. The magic rejects a peer that speaks something
else entirely.

Every read and write has a 5-second timeout (`IO_TIMEOUT`). The timeout is per
operation, so a large payload that keeps moving still gets through, but a peer
that connects and goes quiet cannot hold a daemon thread. The daemon closes the
connection after each response.

`source` says whether the daemon should claim the Wayland selection. `clipd`
reads the compositor directly, so nothing sends `Wayland` over the socket
today. `Remote` follows the same rule in the other direction: store the
payload, claim the selection, but do not send it back where it came from.

`sensitive` marks a password or a key. The daemon then offers
`x-kde-passwordManagerHint` alongside the text formats.

## The protocol between two machines

The same frame carries the messages between two machines. The frame travels
inside the Noise session, so the magic, the version byte and the size cap
already apply.

```rust
// clipto-ipc

pub struct Meta {
    size: u64,
    sensitive: bool,
    digest: [u8; 32],   // lets a machine skip a fetch it does not need
}

pub enum PeerMessage {
    Hello { protocol_version: u8, machine_id: [u8; 8],
            generation: u64, origin: [u8; 8], state: Option<Meta> },
    Announce { machine_id: [u8; 8], generation: u64,
               meta: Meta, inline: Option<Vec<u8>> },
    Fetch { generation: u64 },
    Payload { data: Vec<u8> },
    Gone,
}
```

Every session opens with a `Hello` in each direction:

```
 machine A                                  machine B
     │                                          │
     │──── TCP to the Tailscale address ───────▶│
     │◀═══ Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s ═══▶│
     │──── Hello ──────────────────────────────▶│
     │◀─── Hello ───────────────────────────────│   the session is proven
     │──── Announce, or Fetch, or nothing ─────▶│
     │◀─── Payload, or Gone ────────────────────│
```

The `Hello` does two jobs. It carries the catch-up, and it proves the session:
`psk3` puts the credential in the third handshake message, so the machine that
connects learns nothing from the handshake alone. Only a message it can read
tells it that the other machine holds the same credential.

## Setup

### 1. Generate and seal the encryption key

```bash
# generate a random 32-byte key, seal it with systemd-creds
dd if=/dev/urandom bs=32 count=1 2>/dev/null \
  | systemd-creds encrypt --user --name=clipto-key - \
    "$HOME/.config/clipto/clipto-key.cred"
```

Repeat this on every machine. The key stays on the machine that made it.

### 2. Seal the shared credential (only for a shared clipboard)

Skip this step to keep the clipboard on one machine. See
[The single manual step](#the-single-manual-step) for the whole procedure.

```bash
systemd-creds encrypt --user --name=clipto-psk /dev/shm/clipto-psk \
  "$HOME/.config/clipto/clipto-psk.cred"
```

The same 32 bytes go to every machine.

### 3. Install the systemd user service

```ini
# ~/.config/systemd/user/clipd.service
[Unit]
Description=clipto clipboard daemon
After=default.target

[Service]
ExecStart=%h/.local/bin/clipd
Restart=on-failure
LimitCORE=0
LoadCredentialEncrypted=clipto-key:%h/.config/clipto/clipto-key.cred
# Delete the next line when you skipped step 2. systemd stops the unit when
# the file is absent.
LoadCredentialEncrypted=clipto-psk:%h/.config/clipto/clipto-psk.cred

[Install]
WantedBy=default.target
```

```bash
systemctl --user enable --now clipd
clipto peers
```

### 4. tmux bindings

```tmux
bind -T copy-mode-vi y send -X copy-pipe-and-cancel "clipto copy"
bind P run "clipto paste | tmux load-buffer - && tmux paste-buffer"
```

### 5. Wayland

Nothing required. `clipd` connects to the compositor on its own, and waits with
`inotify` when no compositor runs yet. The compositor must support
`ext-data-control-v1`. Hyprland, sway and other wlroots compositors do.

The unit starts at `default.target`, not `graphical-session.target`, so the
clipboard works in a TTY before you log in to a compositor. `$WAYLAND_DISPLAY`
is often missing that early, so `clipd` falls back to the lowest-numbered
`wayland-N` socket in `$XDG_RUNTIME_DIR`.

### 6. Tailscale

Nothing required beyond `tailscale up`. `clipd` reads the peer list from
`tailscaled` over `/var/run/tailscale/tailscaled.sock`, and it spawns no
process. `CLIPTO_TAILSCALED_SOCK` overrides the path.

Do not add a Tailscale tag or an access control list for `clipto`. The
credential is the gate, and a tag would only hide a machine you can already
remove by deleting its record.

## Building

```bash
cargo build --release
# binaries at target/release/clipto and target/release/clipd
```

## Testing

```bash
cargo test
```

`clipd/tests/sync.rs` starts two real daemons. A small server on a Unix socket
plays `tailscaled`, and each daemon binds its own loopback address, so the
whole path runs: discovery, the Noise handshake, the announcement, the fetch
and the last writer wins rule.
