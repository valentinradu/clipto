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

In Wayland sessions, `clipd` additionally spawns a `wl-paste --watch` listener
to sync the compositor clipboard into its buffer, and calls `wl-copy` on every
write so GUI apps (browsers etc.) share the same clipboard.

```
 Browser / GUI app
       |  wl-copy / wl-paste
       |
 ┌─────▼──────────────────────────────────────────────┐
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
 Hyprland bind      →  wl-paste | clipto copy  (on compositor clipboard change)
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
- The Unix socket is `chmod 600` (owner-only). No other user can connect.
- Plaintext crosses the socket only in the `Paste` response — over a socket
  that is owner-only and local to the machine.

## Workspace structure

```
clipto/
├── Cargo.toml          # workspace
├── clipto-ipc/         # shared IPC protocol types (serde + bincode)
│   └── src/lib.rs      # Request / Response enums
├── clipd/              # daemon binary
│   └── src/main.rs
└── clipto/             # CLI binary
    └── src/main.rs     # `clipto copy` and `clipto paste` subcommands
```

## IPC protocol

Length-prefixed bincode frames over a Unix stream socket.

```rust
// clipto-ipc

pub enum Request {
    Copy { payload: Vec<u8> },
    Paste,
}

pub enum Response {
    Ok,
    Payload { data: Vec<u8> },
    Error { message: String },
}
```

Each message is serialized with `bincode`, prefixed with a 4-byte little-endian
length, and written atomically. The daemon closes the connection after each
response.

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

### 4. Hyprland

Nothing required — `clipd` watches the Wayland clipboard internally when
`$WAYLAND_DISPLAY` is set at startup.

## Building

```bash
cargo build --release
# binaries at target/release/clipto and target/release/clipd
```
