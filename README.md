# clipto

A secure clipboard daemon for Linux, bridging tmux (TTY and Wayland), the
Wayland compositor, and any environment that can invoke a CLI.

## The problem

On Linux, clipboard access depends on which environment you're in:

- **Wayland** (foot + Hyprland): `wl-copy` / `wl-paste`
- **TTY** (virtual console, no display server): nothing
- **tmux copy mode**: pipes to a shell command

These three environments don't share a clipboard. Copying in TTY tmux and
pasting in a browser, or copying in a browser and pasting in TTY tmux, is not
possible without a bridge.

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
 ┌─────┴──────────────────────────────────────────────┐
 │  clipd   (systemd user service)                    │
 │                                                    │
 │  key    — loaded from systemd-creds, in memory,   │
 │           zeroized on drop, never written to disk  │
 │                                                    │
 │  buffer — ChaCha20-Poly1305 encrypted, in memory  │
 │                                                    │
 │  socket — $XDG_RUNTIME_DIR/clipto.sock, mode 600  │
 └─────┬──────────────────────────────────────────────┘
       |  Unix socket (IPC)
       |
 ┌─────┴─────────────┐
 │  clipto copy      │  reads stdin, sends to daemon
 │  clipto paste     │  requests from daemon, prints to stdout
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

### Sensitive payloads

```bash
clipto copy --sensitive < secret.txt
```

`clipd` then adds `x-kde-passwordManagerHint` to the formats it offers, which
asks a clipboard history tool not to write the payload to the disk. `clipd`
also reads that format from other clients, so a password copied out of a
password manager stays marked.

The flag changes nothing about the encryption. The buffer is always encrypted.

### What the model does not cover

- **A paste reveals the plaintext to the pasting client.** That is the purpose
  of a clipboard. `clipd` cannot know what the receiver does with it.
- **The key is sealed to one machine.** Two machines cannot share one clipboard
  under this model. That needs a different key design.
- **No authentication on the socket.** Any process running as you can copy and
  paste. The socket mode is the only barrier.

## Workspace structure

```
clipto/
├── Cargo.toml          # workspace
├── clipto-ipc/         # shared IPC protocol types (serde + bincode)
│   └── src/lib.rs      # Request / Response enums
├── clipd/              # daemon binary
│   ├── src/main.rs     # key, buffer, Unix socket, request handling
│   └── src/wayland.rs  # ext-data-control client: owns the selection
└── clipto/             # CLI binary
    └── src/main.rs     # `clipto copy` and `clipto paste` subcommands
```

## IPC protocol

Length-prefixed bincode frames over a Unix stream socket.

```rust
// clipto-ipc

pub enum CopySource {
    User,     // from tmux, a TTY or a script — claim the selection
    Wayland,  // already the selection — store it, claim nothing
}

pub enum Request {
    Copy { payload: Vec<u8>, source: CopySource, sensitive: bool },
    Paste,
}

pub enum Response {
    Ok,
    Payload { data: Vec<u8> },
    Error { message: String },
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
reads the compositor directly, so nothing sends `Wayland` today. The variant
stays because a remote peer will need the same rule: store the payload, but do
not send it back where it came from.

`sensitive` marks a password or a key. The daemon then offers
`x-kde-passwordManagerHint` alongside the text formats.

## Setup

### 1. Generate and seal the encryption key

```bash
# generate a random 32-byte key, seal it with systemd-creds
dd if=/dev/urandom bs=32 count=1 2>/dev/null \
  | systemd-creds encrypt --name=clipto-key - \
    "$HOME/.config/clipto/clipto-key.cred"
```

### 2. Install the systemd user service

```ini
# ~/.config/systemd/user/clipd.service
[Unit]
Description=clipto clipboard daemon
After=default.target

[Service]
ExecStart=%h/.local/bin/clipd
Restart=on-failure
LoadCredentialEncrypted=clipto-key:%h/.config/clipto/clipto-key.cred

[Install]
WantedBy=default.target
```

```bash
systemctl --user enable --now clipd
```

### 3. tmux bindings

```tmux
bind -T copy-mode-vi y send -X copy-pipe-and-cancel "clipto copy"
bind P run "clipto paste | tmux load-buffer - && tmux paste-buffer"
```

### 4. Wayland

Nothing required. `clipd` connects to the compositor on its own, and waits with
`inotify` when no compositor runs yet. The compositor must support
`ext-data-control-v1`. Hyprland, sway and other wlroots compositors do.

The unit starts at `default.target`, not `graphical-session.target`, so the
clipboard works in a TTY before you log in to a compositor. `$WAYLAND_DISPLAY`
is often missing that early, so `clipd` falls back to the lowest-numbered
`wayland-N` socket in `$XDG_RUNTIME_DIR`.

## Building

```bash
cargo build --release
# binaries at target/release/clipto and target/release/clipd
```
