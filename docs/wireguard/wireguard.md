# WireGuard

WireGuard is one of the supported pig transports (`-P wg` / `"proto": "wg"`).

You can use it in a few different ways:

- **Any WireGuard VPN:** pig is a normal WireGuard client toward a provider or your own WireGuard server.
- **Pig-to-pig:** both sides run pig over WireGuard.
- **Hybrid:** multiple tunnels at once, mix of pig-to-pig and pig-to-VPN.

Keys and peers live in the tunnel `trust.wireguard` block, or in `PIG_WG_*` environment variables.\
There are currently no dedicated CLI flags for WireGuard keys.

Also see:
- [Config reference](../reference/config/config.md)
- Env vars: `pig -docs env` or [env](../reference/cli/env.md)

## Generating keys

Pig requires keys as per the WireGuard specification.
You can generate them in the [official way](https://www.wireguard.com/quickstart/#key-generation) and skip the rest of this section.\
Or have some fun with openssl:

**Private key:**

```bash
PRIV=$(openssl genpkey -algorithm X25519 -outform der | tail -c 32 | base64)
printf '%s\n' "$PRIV"
```

**Public key** (from the private key in `$PRIV`):

```bash
PUB=$(\
  (printf '%s' 'MC4CAQAwBQYDK2VuBCIEIA==' | base64 -d; printf '%s' "$PRIV" | base64 -d)\
  | openssl pkey -inform DER -pubout -outform DER | tail -c 32 | base64\
)
printf '%s\n' "$PUB"
```

## Pig-to-pig WireGuard

Generate a key pair on each machine. Put your private key and the peer’s public key in config or env.\
Env is mandatory for CLI usage, while using config files allows both env and explicit keys.

### Alice (listen) 


| Key | Value |
|-----|-------|
| Private | `AlicePriv` |
| Peer public | `BobPub` |

**Using CLI:**

macOS/Linux:
```bash
sudo su -
export PIG_WG_PRIVATE_KEY='AlicePriv'
export PIG_WG_PEER_PUBLIC_KEY='BobPub'
./pig -l -s -a :51820 -P wg
```

Windows (Administrator PowerShell):
```powershell
$env:PIG_WG_PRIVATE_KEY = 'AlicePriv'
$env:PIG_WG_PEER_PUBLIC_KEY = 'BobPub'
pig.exe -l -s -a :51820 -P wg
```

**Using config file:**

```toml
[[tunnels]]
name = "wg-listen"
direction = "listen"
proto = "wg"

[tunnels.listen]
address = "" # dual stack
port = 51820

# Anything from this point on can be omitted when using env
[tunnels.trust.wireguard]
private_key = "AlicePriv"

[[tunnels.trust.wireguard.peers]]
public_key = "BobPub"
```

If you'd rather keep the keys as environment variables, you can omit the `private_key` and `public_key` fields.
Empty `private_key` / `public_key` fields are filled from `PIG_WG_PRIVATE_KEY` and `PIG_WG_PEER_PUBLIC_KEY`.

Run with it:
```bash
sudo ./pig -config alice.toml
```

### Bob (connect)

| Key | Value |
|-----|-------|
| Private | `BobPriv` |
| Peer public | `AlicePub` |

**Using CLI:**

macOS/Linux:
```bash
sudo su -
export PIG_WG_PRIVATE_KEY='BobPriv'
export PIG_WG_PEER_PUBLIC_KEY='AlicePub'
./pig -c -s -a alice.example.com:51820 -P wg -R 192.168.1.100/32
```

Windows (Administrator PowerShell):
```powershell
$env:PIG_WG_PRIVATE_KEY = 'BobPriv'
$env:PIG_WG_PEER_PUBLIC_KEY = 'AlicePub'
pig.exe -c -s -a alice.example.com:51820 -P wg -R 192.168.1.100/32
```

**Using config file:**

```toml
[route]
enabled = true

[[tunnels]]
name = "wg-connect"
direction = "connect"
proto = "wg"

[[tunnels.routes]]
destination = "192.168.1.100/32"
type = "tunnel"

[tunnels.connect]
address = "alice.example.com"
port = 51820

# Anything from this point on can be omitted when using env
[tunnels.trust.wireguard]
private_key = "BobPriv"

[[tunnels.trust.wireguard.peers]]
public_key = "AlicePub"
```

Run with it:
```bash
sudo ./pig -config bob.toml
```

NAT traversal works the same as all other pig transports: enable ICE and use a shared `-id` / signaling config instead of a fixed `connect` / `listen` address. See [NAT traversal](../nat/nat.md).

## Connect to any WireGuard VPN provider

WireGuard VPN services are becoming more and more popular. Some, like [Proton VPN](https://proton.me/vpn), even have a free tier.
Pig can connect to them natively.

Example CLI command and `wg.conf` for a provider with endpoint `vpn.example.com:51820`, sending all IPv4/IPv6 traffic through the tunnel.

**Using CLI:**

macOS/Linux:
```bash
sudo su -
export PIG_WG_PRIVATE_KEY='your_key'
export PIG_WG_PEER_PUBLIC_KEY='your_peer_key_from_the_provider'
./pig -c -s -a vpn.example.com:51820 -P wg -ta 10.10.10.10/32,2a07:b9::2:5/128 -R full
# in many cases, just this will work too:
./pig -c -s -a vpn.example.com:51820 -P wg -R full
```

Windows (Administrator PowerShell):
```powershell
$env:PIG_WG_PRIVATE_KEY = 'your_key'
$env:PIG_WG_PEER_PUBLIC_KEY = 'your_peer_key_from_the_provider'
pig.exe -c -s -a vpn.example.com:51820 -P wg -ta 10.10.10.10/32,2a07:b9::2:5/128 -R full
# in many cases, just this will work too:
pig.exe -c -s -a vpn.example.com:51820 -P wg -R full
```

`-R full` expands to sending these networks through the tunnel: `0.0.0.0/1`, `128.0.0.0/1`, `2000::/3`, `64:ff9b::/96`.

**Using config file:**

```toml
[route]
enabled = true

[[tunnels]]
name = "my-vpn"
direction = "connect"
proto = "wg"
routes = [
  { destination = "0.0.0.0/1", type = "tunnel" },
  { destination = "128.0.0.0/1", type = "tunnel" },
  { destination = "2000::/3", type = "tunnel" },
  { destination = "64:ff9b::/96", type = "tunnel" }
]

[tunnels.adapter]
# This is the "Address" field from the provider's WireGuard config
tunnel_address = ["10.10.10.10/32", "2a07:b9::2:5/128"]
# Pig's MTU defaults to 1420, also the default MTU for WireGuard,
# but it's always good to be explicit
mtu = 1420

[tunnels.connect]
address = "vpn.example.com"
port = 51820

[tunnels.trust.wireguard]
private_key = "your_key"

[[tunnels.trust.wireguard.peers]]
public_key = "your_peer_key_from_the_provider"
```

```bash
sudo ./pig -config wg.conf
```

## Several at once

One of the most powerful features of pig is the ability to run multiple tunnels at once.
Currently, this more complex setup is only available using a config file.

Below is an example `multi.toml` config that illustrates the use of this feature.

The first tunnel (`my-vpn`) is a pure WireGuard connection to a public VPN provider.

The second tunnel (`home-pig`) is a pig-to-pig connection to a listener sitting in a home network.
It uses NAT traversal (ICE section) so you don’t need a public home IP, and it only sends the home LAN (`192.168.1.0/24`) through the tunnel, everything else stays on `my-vpn`.
The cherry picked protocols are `ws` (WebSocket, based on TCP) and `quic` (based on UDP), the fastest of the two protos to establish a connection will win.

To stand up the home listener, see the [exit node](../../examples/exit-node/README.md) example and the [Docker documentation](../../docs/docker/docker.md). 
Use the same `server_id` and `encryption_key` on both sides.

As usual, take a look at the [config reference](../reference/config/config.md) for more options.

```toml
[route]
enabled = true

# First tunnel: my-vpn public VPN provider
[[tunnels]]
name = "my-vpn"
direction = "connect"
proto = "wg"
routes = [
  { destination = "0.0.0.0/1", type = "tunnel" },
  { destination = "128.0.0.0/1", type = "tunnel" },
  { destination = "2000::/3", type = "tunnel" },
  { destination = "64:ff9b::/96", type = "tunnel" }
]

[tunnels.adapter]
tunnel_address = ["10.10.10.10/32", "2a07:b9::2:5/128"]
mtu = 1420

[tunnels.connect]
address = "vpn.example.com"
port = 51820

[tunnels.trust.wireguard]
private_key = "your_vpn_private_key"

[[tunnels.trust.wireguard.peers]]
public_key = "your_vpn_peer_public_key"

# Second tunnel: pig listener in the home network
[[tunnels]]
name = "home-pig"
direction = "connect"

[[tunnels.routes]]
destination = "192.168.1.0/24" # typical home network subnet
type = "tunnel"

[tunnels.ice]
enabled = true
protos = ["ws", "quic"] # the fastest of the two protos to establish a connection will win

[tunnels.ice.signaling]
server_id = "home-friendly-identifier"
encryption_key = "home-signaling-secret-passphrase"

```

Run with it:
```bash
sudo ./pig -config multi.toml
```