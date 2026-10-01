# Quick start

This page assumes pig is already installed. If it is not, start with [Installation](../installation/installation.md).

## First tunnel

Two machines. Alice listens. Bob connects. With NAT traversal enabled (`-id`), Bob does not need to know Alice’s public address.

Choose a shared id (any unique string) and an encryption passphrase for encrypted signaling between the nodes. 

> [!WARNING]
> Always set a passphrase, especially if using default or public [STUN and MQTT](../nat/nat.md).

**Alice (listen):**

```bash
# Alice's private ip address is 192.168.1.100
sudo pig -l -id pig-demo-alice -P . -k -sk passphrase
```

**Bob (connect):**

```bash
# Connect to Alice, routing Alice's private ip address through the tunnel
sudo pig -c -id pig-demo-alice -k -sk passphrase -R 192.168.1.100/32
```

On Windows, run the same commands from an Administrator terminal (`pig.exe` instead of `pig`, and without `sudo`).

Replace `192.168.1.100/32` with a host or subnet on Alice’s side that Bob should reach through the tunnel.

If you wish to make Alice an exit node, see the [exit node](../../examples/exit-node/README.md) example scenario.
In this case, on Bob side, you have a few shortcuts to tell pig to build a full tunnel:

- `-R full4` all ipv4 local traffic through the tunnel
- `-R full6` all ipv6 local traffic through the tunnel
- `-R full` all local traffic from both families through the tunnel


| Flag        | Meaning                                          |
| ----------- | ------------------------------------------------ |
| `-l` / `-c` | Listen or connect                                |
| `-id`       | Shared name for NAT traversal signaling          |
| `-sk`       | Shared encryption passphrase for NAT-T signaling |
| `-P .`      | Try all available transports as ICE candidates   |
| `-R`        | Tunnel routes to bring up on the connect side    |
| `-k`        | Skip certificate verification                    |


Full CLI reference: [CLI overview](../reference/cli/pig.md) or `pig -h`.

Stop with `Ctrl+C`.

## Simple mode

If you prefer a fixed address and open ports yourself (no smarts):

```bash
# Alice
sudo pig -l -s -a 0.0.0.0:443 -P quic -k

# Bob
sudo pig -c -s -a alice.example.com:443 -P quic -k -R 192.168.1.100/32
```

`-s` (simple mode) disables NAT traversal. `-a` is the listen bind address or the connect target.

## Config files

Turn flags into a file:

```bash
pig -l -id pig-demo-alice -sk passphrase -P . -k -to-cfg json > alice.json
sudo pig -config alice.json
```

Json and toml formats are supported (`-to-cfg toml`).\
See the [config reference](../reference/config/config.md).

## Next steps

- [CLI overview](../reference/cli/pig.md)
- [Connect](../reference/cli/connect.md) / [Listen](../reference/cli/listen.md)
- [NAT traversal](../nat/nat.md)
- [Docker](../docker/docker.md)
- [Examples](../../examples/)

