# Quick start

This page assumes pig is already installed. If it is not, start with [Installation](../installation/installation.md).

## Adapters

Adapters are the way local traffic enters and leaves the tunnel on each pig side.

Unless specified otherwise, pig always uses the **[TUN](../adapters/tun.md)** adapter (`adapter_type = "tun"`).

| Adapter | When to use it | Privileges |
| ------- | -------------- | ---------- |
| [TUN](../adapters/tun.md) (default) | OS routes / exit node / site-to-site | Elevated |
| [HTTP](../adapters/http_proxy.md) / [SOCKS](../adapters/socks_proxy.md) proxy | Point apps at a local proxy; no OS routing | None on the proxy side, granted the listen port is not privileged (>1024) |
| [Stdio](../adapters/stdio.md) (`-nc`) | Netcat-style byte streams over the tunnel | None |

For proxy or `-nc` examples, see the related doc pages linked above.

## First tunnel (TUN)

This section uses the default **TUN** adapter on both sides: pig creates a tunnel interface and Bob installs routes with `-R`. You do not pass an adapter flag: TUN is implied.

Two machines. Alice listens. Bob connects. With NAT traversal enabled (`-id`), Bob does not need to know Alice’s public address.

NAT-T relies on signaling (MQTT) and STUN; both ship with defaults you can override, but only the **signaling** server must match on both sides. See [NAT traversal](../nat/nat.md).

Choose a shared id (any unique string) and an encryption passphrase for encrypted signaling between the nodes.

> [!WARNING]
> Always set a passphrase, especially if using the default or any public MQTT server.

**Alice (listen):**

```bash
# Alice's private ip address is 192.168.1.100
sudo ./pig -l -id pig-demo-alice -P . -k -sk passphrase
```

**Bob (connect):**

```bash
# Connect to Alice, routing Alice's private ip address through the tunnel
sudo ./pig -c -id pig-demo-alice -k -sk passphrase -R 192.168.1.100/32
```

On Windows, run the same commands from an Administrator terminal (`pig.exe` instead of `pig`, and without `sudo`).

Replace `192.168.1.100/32` with a host or subnet on Alice’s side that Bob should reach through the tunnel.

If you wish to make Alice an exit node, see the [exit node](../../examples/exit-node/README.md) example scenario.
In this case, on Bob side, you have a few shortcuts to tell pig to build a full tunnel:

- `-R full4` all ipv4 local traffic through the tunnel
- `-R full6` all ipv6 local traffic through the tunnel
- `-R full` all local traffic from both families through the tunnel

Flags we used so far:
| Flag        | Meaning                                             |
| ----------- | --------------------------------------------------- |
| `-l` / `-c` | Listen or connect mode                              |
| `-id`       | Shared, friendly name for NAT traversal signaling   |
| `-sk`       | Shared encryption passphrase for NAT-T signaling    |
| `-P .`      | Try all available transports as ICE candidates      |
| `-R`        | Tunnel routes to bring up on the connect side       |
| `-k`        | Skip certificate verification                       |


CLI tips: [CLI overview](cli-overview.md).\
Full flag list: [CLI reference](../reference/cli/pig.md) or `pig -h`.

## Simple mode

Still the default TUN adapter, but with a fixed address and ports you open yourself (no NAT traversal):

```bash
# Alice
sudo ./pig -l -s -a :443 -P quic -k

# Bob
sudo ./pig -c -s -a alice.example.com:443 -P quic -k -R 192.168.1.100/32
```

`-s` (simple mode) disables NAT traversal. `-a` is the listen bind address or the connect target.

## Config files

Turn flags into a file:

```bash
./pig -l -id pig-demo-alice -sk passphrase -P . -k -to-cfg json > alice.json
sudo ./pig -config alice.json
```

Json and toml formats are supported (`-to-cfg toml`).\

Omit `adapter_type` (or set it to `"tun"`) for the same default TUN behavior. Check out the [config reference](../reference/config/config.md) for the full list of options.

## Next steps

- [Adapters](../index.md#adapters)
- [CLI overview](cli-overview.md)
- [CLI reference](../reference/cli/pig.md)
- [Connect](../reference/cli/connect.md) / [Listen](../reference/cli/listen.md)
- [NAT traversal](../nat/nat.md)
- [Docker](../deploy/docker.md)
- [Examples](../../examples/)
