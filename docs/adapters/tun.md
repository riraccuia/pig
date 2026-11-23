# TUN

TUN is the default pig adapter (`adapter_type = "tun"`).\
It creates an OS tunnel interface so the kernel can send and receive IP packets over the pig tunnel.

Use TUN when you want to:

- Route selected subnets (or a full tunnel) through a peer with `-R` / `route.enabled`
- Run an [exit node](../../examples/exit-node/README.md) or site-to-site hop
- Connect to a [WireGuard](../transports/wireguard.md) VPN in full tunnel mode

Also see:

- [AdapterTunConfig](../reference/config/config.md#adaptertunconfig)
- [Listen](../reference/cli/listen.md) / [Connect](../reference/cli/connect.md)
- [Quick start](../getting-started/quick-start.md)

## Privileges

Creating a TUN needs elevated rights:

- **Linux / macOS:** `sudo` or root user
- **Windows:** Administrator PowerShell, plus [Wintun](../installation/windows.md)

## CLI

TUN is selected automatically when you do not pass `-nc` or `-http-proxy`.

| Flag | Meaning |
| ---- | ------- |
| `-ta` | Tunnel address(es), comma-separated CIDRs |
| `-mtu` | MTU (default `1420`) |
| `-R` | Install routes on the connect side (`full`, `full4`, `full6`, or CIDR list) |

`multi_queue` has no CLI flag. Set it in the config file. It only takes effect on Linux.

**Using CLI** (simple mode, Bob routes a host through Alice):

macOS/Linux:

```bash
# --- Alice (listen) ---
sudo ./pig -l -s -P ws -a :443 -k

# --- Bob (connect) ---
sudo ./pig -c -s -P ws -a alice.example.com:443 -k -R 192.168.1.100/32
```

Windows (Administrator PowerShell):

```powershell
# --- Alice (listen) ---
pig.exe -l -s -P ws -a :443 -k

# --- Bob (connect) ---
pig.exe -c -s -P ws -a alice.example.com:443 -k -R 192.168.1.100/32
```

Omit `-ta` to let pig generate addresses. Defaults:

- Connect: random `/30` inside `100.64.0.0/11`
- Listen: random `/16` inside `100.96.0.0/11`

NAT traversal works the same way: drop `-s` / `-a`, use a shared `-id` (and `-sk` for signaling encryption). See [NAT traversal](../nat/nat.md).

## Config file

Prefer generating a baseline with `-to-cfg`, then edit.

Listen tunnels need a per-tunnel adapter. Connect tunnels may use a top-level `[adapter]` shared across connect tunnels, or a per-tunnel `[tunnels.adapter]`.

**Using config file** (per-tunnel TUN on connect):

```toml
[route]
enabled = true

[[tunnels]]
name = "to-alice"
direction = "connect"
proto = "ws"
routes = [
  { destination = "192.168.1.100/32", type = "tunnel" }
]

[tunnels.adapter]
adapter_type = "tun"

[tunnels.adapter.adapter_config]
tunnel_address = ["10.10.10.2/30"]
mtu = 1420
# multi_queue = true  # Linux only

[tunnels.connect]
address = "alice.example.com"
port = 443

[tunnels.tls]
insecure = true
```

Top-level shared adapter for connect (optional):

```toml
[adapter]
adapter_type = "tun"

[adapter.adapter_config]
tunnel_address = ["10.10.10.2/30"]
mtu = 1420
```

Full field list: [AdapterTunConfig](../reference/config/config.md#adaptertunconfig). For full-tunnel and multi-tunnel recipes, see [WireGuard](../transports/wireguard.md) and the [exit node](../../examples/exit-node/README.md) example.
