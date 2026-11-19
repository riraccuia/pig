# Stdio

Stdio is pig’s netcat-style adapter (`adapter_type = "stdio"` / `-nc`).\
Each peer’s stdin is redirected to the other peer’s stdout over the encrypted tunnel (and vice versa).

Use it for interactive chat, one-shot messages, file transfer, or a remote shell. Without creating a TUN.

Also see:

- [AdapterStdIOConfig](../reference/config/config.md#adapterstdioconfig)
- [Listen](../reference/cli/listen.md) / [Connect](../reference/cli/connect.md)
- [Protocols](../reference/cli/protos.md) (`pig -docs protos`)

## Behavior notes

- Works on **listen and connect**. Both sides normally pass `-nc`.
- No `-ta`: addressing is fixed inside the adapter.
- `-R` / OS routes are not used in this mode.
- Reconnect and WRED early-drop are turned off for the tunnel.
- Logging is quiet unless you pass `-v`.

## Examples (CLI)

In every example Alice **listens** (`-l`) and Bob **connects** (`-c`). `-k` skips certificate verification.\
Use `-v 1`, `-v 2`, or `-v 3` to increase logging verbosity.

Two ways to connect the peers (shown in each snippet):

- **NAT traversal:** same `-id` on both sides, `-P .` enables all protocols. Pigs find each other.\
  Use `-sk` with a passphrase so that signaling messages will be encrypted (highly recommended).
- **Simple mode:** `-s -a [host]:port -P ws`. Alice binds to an address using WebSocket; Bob dials it. Needs a reachable port.

Pick **one** pair (NAT or simple) in each example. Simple mode with `-P ws` is usually the easiest to reproduce.

### Interactive chat

Run both sides in a terminal and start typing. Whatever you enter is sent; whatever arrives is printed.

```bash
# --- Alice (listen) ---
# NAT traversal
sudo ./pig -l -id pig-demo -P . -k -sk passphrase -nc
# Simple mode
sudo ./pig -l -s -P ws -a :443 -k -nc

# --- Bob (connect) ---
# NAT traversal
sudo ./pig -c -id pig-demo -k -sk passphrase -nc
# Simple mode
sudo ./pig -c -s -P ws -a alice.example.com:443 -k -nc
```

Windows (Administrator PowerShell), simple mode:

```powershell
# --- Alice ---
pig.exe -l -s -P ws -a :443 -k -nc

# --- Bob ---
pig.exe -c -s -P ws -a alice.example.com:443 -k -nc
```

Ctrl+C to quit.

### One-shot message

For a single message instead of a chat:

```bash
# --- Alice (send one line, then exit) ---
# NAT traversal
echo "Hello from Alice" | sudo ./pig -l -id pig-demo -P . -k -sk passphrase -nc
# Simple mode
echo "Hello from Alice" | sudo ./pig -l -s -P ws -a :443 -k -nc

# --- Bob (print it, then exit) ---
# NAT traversal
sudo ./pig -c -id pig-demo -k -sk passphrase -nc
# Simple mode
sudo ./pig -c -s -P ws -a alice.example.com:443 -k -nc
```

### File transfer

Same `-nc` bridge: `<` feeds bytes into the tunnel, `>` writes what arrives.\
Bob sends, Alice saves. Start Alice first.\
The `-o` (once) flag causes the listener to accept only one connection and exit after the peer disconnects.

```bash
# --- Alice (save) ---
# NAT traversal
sudo ./pig -l -id pig-demo -P . -k -sk passphrase -nc -o > received.bin
# Simple mode
sudo ./pig -l -s -P ws -a :443 -k -nc -o > received.bin

# --- Bob (send) ---
# NAT traversal
sudo ./pig -c -id pig-demo -k -sk passphrase -nc < original.bin
# Simple mode
sudo ./pig -c -s -P ws -a alice.example.com:443 -k -nc < original.bin
```

### Remote shell (FIFO)

Alice attaches an interactive bash to pig with a FIFO (classic netcat-style shell).\
Bob connects and gets the prompt. Linux.

```bash
# --- Alice (Linux, listen + shell) ---
rm -f /tmp/f && mkfifo /tmp/f
pigs() { cat /tmp/f | /bin/bash -i 2>&1 | sudo ./pig "$@" > /tmp/f; }

# NAT traversal
pigs -l -id pig-demo -P . -k -sk passphrase -nc
# Simple mode
pigs -l -s -P ws -a :443 -k -nc

# --- Bob (connect) ---
# NAT traversal
sudo ./pig -c -id pig-demo -k -sk passphrase -nc
# Simple mode
sudo ./pig -c -s -P ws -a alice.example.com:443 -k -nc
```

Make it an authenticated shell with `-A` and a provisioned JWT token. See [JWT authentication](../auth/jwt.md).

## Config file

Prefer generating a baseline with `-to-cfg`, then edit:

```bash
./pig -l -s -P ws -a :443 -k -nc -to-cfg toml > alice.toml
./pig -c -s -P ws -a alice.example.com:443 -k -nc -to-cfg toml > bob.toml
sudo ./pig -config alice.toml
sudo ./pig -config bob.toml
```

Stdio settings live under the tunnel adapter. The only field is optional `mtu` (default `1420`):

```toml
[[tunnels]]
name = "nc"
direction = "connect"
proto = "ws"

[tunnels.adapter]
adapter_type = "stdio"

[tunnels.adapter.adapter_config]
# mtu = 1420

[tunnels.connect]
address = "alice.example.com"
port = 443

[tunnels.tls]
insecure = true
```

Full field list: [AdapterStdIOConfig](../reference/config/config.md#adapterstdioconfig).
