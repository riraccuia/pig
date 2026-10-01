![pig gopher](assets/pig-gopher-shovel.png)

[![Docs](https://img.shields.io/badge/Docs-008CFF?logo=github&style=for-the-badge)](docs/index.md) [![CLI Reference](https://img.shields.io/badge/CLI%20Reference-008CFF?logo=github&style=for-the-badge)](docs/reference/cli/pig.md)

# Packet Insertion Gear (pig)

**pig** is a single binary that connects computers directly and securely to each other. 

Using NAT traversal techniques, it gets your endpoints connected through firewalls and NAT devices.\
In other words, you shouldn't need to setup your network/s at all. In most cases.

It has a small disk and memory footprint, it's fast and works on Linux, macOS, and Windows (and maybe mobile, at some point).

Pigs can also be chained to create mesh networks.

The project is still in early development, please open an issue if you find any bugs or have any suggestions.

## Why

Pig is a passion project and a place to experiment with network standards, packets and protocols.

It quickly became the primary tool for connecting to my home when I travel, doubling as a privacy protection tool whenever public Wi-Fis are the only option. 

## What you can do

**Connect two machines.** Simple or NAT traversal mode. Choose between traditional VPN-style tunnel and a less fiddly experience.

**Build a mesh.** Pigs can be chained.

**Skip firewall plumbing.** Don't worry about setting up your network. Pig's NAT traversal approach can beat symmetric NAT, too. More details in the [docs](docs/nat/symmetric.md).

**Pick a transport.** [QUIC, TLS, WebSocket, DTLS, TLS-in-ICMP](docs/reference/cli/protos.md), or let pig choose.

**Route traffic.** Pig can update the routing table for you, so packets go through the tunnel.

**Authenticate.** mTLS, JWT, OAuth, OIDC.

**Hook scripts.** Run setup/cleanup on tunnel events ([env vars](docs/reference/cli/env.md)).

**Act as STUN.** Query or become a STUN server with [`-stun`](docs/reference/cli/stun.md).

## Getting started

- [Installation](docs/installation/installation.md) (Windows, macOS, Linux)
- [Quick start](docs/getting-started/quick-start.md) (first tunnel)
- Read the [user guide](docs/index.md), check out the [examples](examples/) and [Docker](docs/docker/docker.md) files.

### Example

```
                              .-----------.               
    .-------.    +--------+  (             )   +--------+    .-------.
    |  Bob  |====| Router |==(   INTERNET   )==| Router |===>| Alice |
    |_______|    +--------+  (             )   +--------+    |_______|
   /_______/                  '-----------'                 /_______/ 

```

**Listen:**

```bash
# Alice - local address 192.168.1.100
nohup pig -l -id pig-demo-alice -P . -k &
printf '\t[Alice] Hello, Bob!\n' | nc -l 8080; killall -INT pig

```

**Connect:**

```bash
# Bob
nohup pig -c -id pig-demo-alice -k -R 192.168.1.100/32 &
nc 192.168.5.1 8080; killall -INT pig
	[Alice] Hello Bob!

```

Turn Alice's command into a baseline config:

```bash
pig -l -id pig-demo-alice -P . -k -to-cfg json > alice.json
```

Build your [advanced setup](docs/reference/config/config.md).
Run with it.

```bash
pig -config alice.json
```



## Nerd facts

- IPv6 is fully supported and can be routed between nodes.
- Pig features a [WRED (weighted random early detection)](https://en.wikipedia.org/wiki/Weighted_random_early_detection) implementation to combat network bufferbloat and maintain low latency. It is fully configurable.
- The ICMP transport protocol has a TCP style congestion control (New Reno) built on top of it. More testing and feedback would really help here.
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
- [WireGuard/wintun](https://golang.zx2c4.com/wintun) - Windows TUN driver



## License

[Apache License 2.0](LICENSE)