![pig gopher](assets/pig-gopher-shovel.png)

![Docs](https://img.shields.io/badge/Docs-008CFF?logo=github&style=for-the-badge) ![CLI Reference](https://img.shields.io/badge/CLI%20Reference-008CFF?logo=github&style=for-the-badge)

# Packet Insertion Gear (pig)

**Pig** is a single binary that builds a direct, encrypted path, aka a tunnel, between two machines.  
Peers find each other either automatically with NAT traversal, or with a plain `host:port` dial when you already have a reachable address.  
Each side can expose a TUN interface (route IP traffic) or stdin/stdout (netcat-style byte streams).  
Pig can handle multiple connected tunnels at the same time, and/or chain them to create mesh networks.  
It can also connect to any [WireGuard](docs/wireguard/wireguard.md) server, inlcuding ones from many known VPN providers.

It is small and runs on Linux, macOS, and Windows.  
The project is in early development, please open an issue if you find any bugs or have any suggestions.

## Why

Pig is a passion project and a place to experiment with network standards, packets and protocols.  
It is also a privacy focused tool that I started for my personal use.

## Design

Avoiding a hard protocol lock matters when a tunnel is also a privacy boundary.  
Pig's bet is on flexibility. Its data plane does not know about concrete adapters or transports, it only uses a shared contract that every adapter and protocol must satisfy so new ones can be swapped in without changing how traffic flows.

## What you can do

Pig can be used as: 

- an **exit node**: send all (or selected) traffic from a laptop through a
home or VPS pig (`-R full` or specific subnet/s).
Authenticate with [JWT / OAuth / OIDC](docs/index.md#authentication);
- a **netcat over encrypted tunnel**: chat, copy files, or attach a shell with `-nc`,
without or without opening a listen port on the far side;
- a **site-to-site / mesh hop**: chain pigs, or mix pig tunnels with
WireGuard VPNs in one process;
- a **transport lab**: pick [QUIC, TLS, WebSocket, WireGuard, DTLS,
TLS-in-ICMP](docs/reference/cli/protos.md), or `-P .` to let pig choose;

## Getting started

- [Installation](docs/installation/installation.md) (Windows, macOS, Linux)
- [Quick start](docs/getting-started/quick-start.md) (first tunnel)
- Read the [user guide](docs/index.md), check out the [examples](examples/) and [Docker](docs/deploy/docker.md) files.

### Examples (CLI only)

In every example Alice **listens** (`-l`) and Bob **connects** (`-c`). `-k` skips certificate verification.  
Use `-v 1`, `-v 2`, or `-v 3` to increase logging verbosity.

Two ways to connect the peers (shown in each snippet):

- **NAT traversal:** same `-id` on both sides, `-P .` enables all protocols. Pigs find each other.  
  Use `-sk` with a passphrase so that signaling messages will be encrypted (highly recommended).
- **Simple mode:** `-s -a [host]:port -P ws`. Alice binds to an address using the specified protocol, Bob dials it. Needs a reachable port.

`-nc` is netcat mode: the stdin of each peer is redirected to the stdout of the other peer over the encrypted tunnel.

#### 1. Exit node

Bob sends **all** traffic through Alice (`-R full`).  
Alice must IP-forward and masquerade (see [start.sh](build/docker/start.sh), or the [exit-node](examples/exit-node/) Docker setup). Pick **one** pair.

```bash
# --- Alice (exit node) ---
# NAT traversal
sudo ./pig -l -id pig-demo -P . -k -sk passphrase
# Simple mode
sudo ./pig -l -s -P ws -a :443 -k

# --- Bob (full tunnel via Alice) ---
# NAT traversal
sudo ./pig -c -id pig-demo -k -sk passphrase -R full
# Simple mode
sudo ./pig -c -s -P ws -a alice.example.com:443 -k -R full
```

When the tunnel is up, Bob’s outbound traffic exits via Alice.

#### 2. Interactive chat

Run both sides in a terminal and start typing. Whatever you enter is sent, whatever arrives is printed. Pick **one** pair (NAT or simple).

```bash
# --- Alice (listen) ---
# NAT traversal
./pig -l -id pig-demo -P . -k -sk passphrase -nc
# Simple mode
./pig -l -s -P ws -a :443 -k -nc

# --- Bob (connect) ---
# NAT traversal
./pig -c -id pig-demo -k -sk passphrase -nc
# Simple mode
./pig -c -s -P ws -a alice.example.com:443 -k -nc
```

Ctrl+C to quit.  
For a one-shot message instead of a chat:

```bash
# --- Alice (send one line, then exit) ---
# NAT traversal
echo "Hello from Alice" | ./pig -l -id pig-demo -P . -k -sk passphrase -nc
# Simple mode
echo "Hello from Alice" | ./pig -l -s -P ws -a :443 -k -nc

# --- Bob (print it, then exit) ---
# NAT traversal
./pig -c -id pig-demo -k -sk passphrase -nc
# Simple mode
./pig -c -s -P ws -a alice.example.com:443 -k -nc
```

#### 3. File transfer

Same `-nc` bridge: `<` feeds bytes into the tunnel, `>` writes what arrives.  
Alice listens and sends, Bob connects and saves. Start Alice first. Pick **one** pair.

```bash
# --- Alice (listen + send) ---
# NAT traversal
./pig -l -id pig-demo -P . -k -sk passphrase -nc < original.bin
# Simple mode
./pig -l -s -P ws -a :443 -k -nc < original.bin

# --- Bob (connect + receive) ---
# NAT traversal
./pig -c -id pig-demo -k -sk passphrase -nc > received.bin
# Simple mode
./pig -c -s -P ws -a alice.example.com:443 -k -nc > received.bin
```

#### 4. Remote shell (using FIFO)

Alice attaches an interactive bash to pig with a FIFO (classic netcat-style shell).  
Bob connects and gets the prompt. Pick **one** pair.

```bash
# --- Alice (Linux, listen + shell) ---
# Set up the fifo and method wrapper
rm -f /tmp/f && mkfifo /tmp/f
pigs() { cat /tmp/f | /bin/bash -i 2>&1 | sudo ./pig "$@" > /tmp/f; }

# NAT traversal
pigs -l -s -P ws -a :443 -k -nc
# Simple mode
pigs -l -id pig-demo -P . -k -sk passphrase -nc

# --- Bob (connect) ---
# NAT traversal
./pig -c -id pig-demo -k -sk passphrase -nc
# Simple mode
./pig -c -s -P ws -a alice.example.com:443 -k -nc
```

Make it an authenticated shell by using `-A` and a provisioned JWT token.\
Check the docs [auth section](docs/auth/).

---

Turn a CLI line into a config baseline:

```bash
./pig -l -id pig-demo -P . -k -sk passphrase -to-cfg json > alice.json
./pig -config alice.json
```

More in the [user guide](docs/index.md), [examples](examples/), and [config reference](docs/reference/config/config.md).

## Nerd facts

- IPv6 is fully supported and can be routed between nodes.
- Pig features a [WRED (weighted random early detection)](https://en.wikipedia.org/wiki/Weighted_random_early_detection) implementation to combat network bufferbloat and maintain low latency. It is fully configurable.
- The ICMP transport protocol has a TCP style congestion control (New Reno) built on top of it. More testing and feedback appreciated.
- Implementing a new transport protocol is relatively simple and "only" requires some wrapping to honor the `transport.Conn` and `transport.Listener` interfaces.
- If one of the connecting nodes is behind [symmetric NAT](docs/nat/symmetric.md), pig can usually still find a path using the [birthday problem](https://en.wikipedia.org/wiki/Birthday_problem).
- Stream multiplexing support is built-in where the protocol allows it (e.g. QUIC). The number of streams to open is configurable, too.

## Acknowledgments

Packages that make this project possible. Thanks to the authors for their work!

- [BurntSushi/toml](https://github.com/BurntSushi/toml) - toml config parsing
- [cespare/xxhash](https://github.com/cespare/xxhash) - hashing
- [coder/websocket](https://github.com/coder/websocket) - WebSocket transport
- [eclipse/paho.mqtt.golang](https://github.com/eclipse/paho.mqtt.golang) - MQTT ICE signaling
- [golang-jwt/jwt](https://github.com/golang-jwt/jwt) - JWT auth
- [lestrrat-go/jwx](https://github.com/lestrrat-go/jwx) - JWK/JWKS for OIDC/OAuth
- [pion/dtls](https://github.com/pion/dtls) - DTLS transport
- [quic-go/quic-go](https://github.com/quic-go/quic-go) - QUIC transport
- [rs/zerolog](https://github.com/rs/zerolog) - logging
- [golang.zx2c4.com/wintun](https://golang.zx2c4.com/wintun) - Windows TUN driver
- [golang.zx2c4.com/wireguard](https://golang.zx2c4.com/wireguard) - WireGuard transport

## License

[Apache License 2.0](LICENSE)