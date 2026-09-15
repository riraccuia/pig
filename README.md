![pig gopher](assets/pig-gopher.png)

# pig - packet insertion gear

**pig** is a single binary that connects two computers directly and securely to each other. Pigs can also be chained to create mesh networks.

Using NAT traversal techniques, it finds a suitable connection path automatically in a variety of network environments, even though firewalls/routers may be in the way. In other words you shouldn't need to setup your network/s at all. In most cases.

## Why

Pig is a passion project and a place to experiment with network standards, packets and protocols.

It quickly became the primary tool for connecting to my home when I travel, doubling as a privacy protection tool whenever public Wi-Fis are the only option. 

It is still a bit rough around the edges. Feel free to contribute and bring fresh ideas.

## What you can do

**Listen/connect tunnel.** Including traditional VPN-style (simple mode) connectivity.

**Pigs can be chained.** A pig can simultaneously connect to multiple remote targets and listen for incoming connections at the same time. Using this feature you can create mesh networks.

**Direct path discovery using NAT traversal.** STUN (for NAT discovery) and MQTT (for signaling) servers are required in this mode. While these dependencies seem daunting at first, these are very popular technologies. One can find plenty of public/free servers of both kinds available out there.

**IPv4 and IPv6 support.**

**Swappable transport protocols.** Choose from [available ones](docs/cli-help/protos.md) such as QUIC, TLS, WebSocket, DTLS, and the experimental TLS-in-ICMP. Or let NAT traversal pick one automatically. There are more planned.

**Routing table management.** Pig can manage the routing table on the local machine to ensure that traffic is routed correctly through the tunnel.

**Authentication.** JWT, mTLS, and OIDC, used independently or combined.

**Event driven script execution.** For extra setup or cleanup. Tunnel events and related information is passed to the called scripts via environment variables (see [`pig -docs env`](docs/cli-help/env.md)).

**Multi-platform.** Linux, macOS, and Windows. Would love to add mobile support, too.

**STUN mode.** Pig has a [`-stun`](docs/cli-help/stun.md) subcommand to query a remote server or become one on the fly.

## Getting started

- Download the [latest release](https://github.com/riraccuia/pig/releases) or build from source using the [makefile](Makefile).
- Run [`pig -h`](docs/cli-help/main.md) to see the available options.
- Use the [`-to-cfg`](docs/cli-help/connect.md) option with both `-c` and `-l` subcommands to quickly generate a config file to use as baseline for an advanced setup. See the [config file format documentation](docs/config.md).
- Read the [user guide](docs/guide.md).

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
# Alice - local address 192.168.5.1
nohup pig -l -id pig-demo-alice -P . -k &
printf '\t[Alice] Hello, Bob!\n' | nc -l 8080; killall -INT pig

```

**Connect:**

```bash
# Bob
nohup pig -c -id pig-demo-alice -k -R 192.168.5.1/32 &
nc 192.168.5.1 8080; killall -INT pig
	[Alice] Hello Bob!

```

To turn Alice's command into a config file, do
```bash
pig -l -id pig-demo-alice -P . -k -to-cfg json > alice.json
```

Check the [config file reference](docs/config.md) and customize the generated config for an advanced setup.
Then run with it.

```bash
pig -config alice.json
```

## Nerd facts

- Pig features a [WRED (weighted random early detection)](https://en.wikipedia.org/wiki/Weighted_random_early_detection) implementation to combat network bufferbloat and maintain low latency. It is fully configurable.
- The ICMP transport protocol has a TCP style congestion control (New Reno) built on top of it. More testing and feedback would really help here.
- Adding a new transport protocol is relatively simple and "only" requires some wrapping to honor the `transport.Conn` and `transport.Listener` interfaces.
- If one of the connecting nodes is behind [symmetric NAT](https://en.wikipedia.org/wiki/Network_address_translation#Methods_of_translation), pig can usually still find a path using the [birthday problem](https://en.wikipedia.org/wiki/Birthday_problem).
- Stream multiplexing support is built-in where the protocol allows it (e.g. QUIC). The number of streams to open is configurable, too.

## Acknowledgments

Packages that make this project possible. Thanks to the authors for their work!

- [BurntSushi/toml](https://github.com/BurntSushi/toml) - toml config parsing
- [cespare/xxhash](https://github.com/cespare/xxhash) - hashing
- [coder/websocket](https://github.com/coder/websocket) - WebSocket transport
- [eclipse/paho.mqtt.golang](https://github.com/eclipse/paho.mqtt.golang) — MQTT ICE signaling
- [golang-jwt/jwt](https://github.com/golang-jwt/jwt) - JWT auth
- [lestrrat-go/jwx](https://github.com/lestrrat-go/jwx) - JWK/JWKS for OIDC/OAuth
- [pion/dtls](https://github.com/pion/dtls) - DTLS transport
- [quic-go/quic-go](https://github.com/quic-go/quic-go) - QUIC transport
- [rs/zerolog](https://github.com/rs/zerolog) - logging
- [WireGuard/wintun](https://golang.zx2c4.com/wintun) - Windows TUN driver

## License

[Apache License 2.0](LICENSE)