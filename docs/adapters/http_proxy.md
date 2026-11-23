# HTTP proxy

The HTTP proxy adapter (`adapter_type = "http_proxy"` / `-http-proxy`) exposes a local HTTP(S) proxy whose outbound traffic always goes through the pig tunnel.\
No tunnel adapter is created on the machine in this mode.

Use it when you want apps to opt in via proxy settings instead of OS routes.

Also see:

- [AdapterHTTPProxyConfig](../reference/config/config.md#adapterhttpproxyconfig)
- [Connect](../reference/cli/connect.md)
- [Quick start](../getting-started/quick-start.md)

## Limits

- **Connect only:** listen tunnels cannot use this adapter.
- **No OS routes:** `-R` / `route.enabled` are not used with this mode (the CLI rejects `-R` together with `-http-proxy`).
- **Not with `-nc`:** `-http-proxy` and `-nc` cannot be used together.

## CLI

| Flag | Meaning |
| ---- | ------- |
| `-http-proxy [host]:port` | Local proxy listen address (connect only) |
| `-mtu` | Optional. Only matters for datagram transports; omit unless you need it |

In config, an empty `listen_address` defaults to `:8080`.

**Using CLI** (simple mode):

macOS/Linux:

```bash
# --- Alice (listen, normal TUN setup) ---
sudo ./pig -l -s -P ws -a :443 -k

# --- Bob (connect + local HTTP proxy) ---
./pig -c -s -P ws -a alice.example.com:443 -k -http-proxy :8080
```

Windows (Administrator PowerShell on Alice as she uses TUN, Bob needs no TUN):

```powershell
# --- Alice (listen) ---
pig.exe -l -s -P ws -a :443 -k

# --- Bob (connect + local HTTP proxy) ---
pig.exe -c -s -P ws -a alice.example.com:443 -k -http-proxy :8080
```

Point the browser or tool at `http://127.0.0.1:8080` (or the listen address you chose).

NAT traversal: same `-http-proxy` flag with a shared `-id` instead of `-s` / `-a`. See [NAT traversal](../nat/nat.md).

## Config file

```toml
[[tunnels]]
name = "proxy-via-alice"
direction = "connect"
proto = "ws"

[tunnels.adapter]
adapter_type = "http_proxy"

[tunnels.adapter.adapter_config]
listen_address = ":8080"
# use_ipv6 = true
# dns_address = "1.1.1.1:53"
# tunnel_address = ["100.64.0.2/32"]
# mtu = 1420  # optional; mainly for datagram transports

[tunnels.connect]
address = "alice.example.com"
port = 443

[tunnels.tls]
insecure = true
```

Optional settings:

- `use_ipv6`: prefer IPv6 when resolving targets
- `dns_address`: send DNS for the proxy through the tunnel (`host:port`)
- `tunnel_address`: optional CIDRs for the proxy’s tunnel identity. Pig can generate one if omitted.
- `mtu`: optional, only needed for some transports that are datagram-based.

Prefer `-to-cfg` from a working CLI line, then edit.

Full field list: [AdapterHTTPProxyConfig](../reference/config/config.md#adapterhttpproxyconfig).
