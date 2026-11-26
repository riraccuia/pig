# SOCKS proxy

The SOCKS proxy adapter (`adapter_type = "socks_proxy"` / `-socks-proxy`) exposes a local SOCKS5 proxy whose outbound traffic always goes through the pig tunnel.\
No tunnel adapter is created on the machine in this mode.

Setup, limits, and config fields match the [HTTP proxy](http_proxy.md) adapter: swap `-http-proxy` for `-socks-proxy`, or `adapter_type = "http_proxy"` for `"socks_proxy"`. Point clients at `socks5://127.0.0.1:8080` (or the listen address you chose).

Also see:

- [HTTP proxy](http_proxy.md) (shared CLI / config patterns)
- [AdapterSocksProxyConfig](../reference/config/config.md#adaptersocksproxyconfig)
- [Connect](../reference/cli/connect.md)

## Gotchas

### Resolve names through the proxy

By default many clients resolve the target hostname **locally**, then ask the proxy to connect to an IP. DNS then never traverses the tunnel, which can leak queries or fail when the local resolver cannot see the destination.

Prefer a client mode that sends the hostname to the proxy (SOCKS5 domain address / remote DNS). With curl that is `--socks5-hostname`:

```bash
# Alice sets up her listening side.
sudo ./pig -l -s -P ws -a :443 -k
# Bob connects to Alice and hooks a local socks proxy bound to the tunnel.
./pig -c -s -P ws -a alice.example.com:443 -k -socks-proxy :8080
# curl sends a SOCKS5 CONNECT request with the hostname to the proxy.
curl --socks5-hostname 127.0.0.1:8080 https://example.com/
# another curl equivalent is to use -x socks5h://...
curl -x socks5h://127.0.0.1:8080 http://example.com/
```

Plain `--socks5` (without `-hostname`) resolves on the client first. Pig can still resolve names when the client sends a hostname, and optional `dns_address` sends that DNS through the tunnel (same as [HTTP proxy](http_proxy.md)).

### UDP ASSOCIATE

The proxy accepts the SOCKS5 **UDP ASSOCIATE** command in addition to CONNECT. Clients that need UDP over SOCKS can use it.

## SSH over SOCKS

You can point ssh at the local SOCKS5 proxy with `ProxyCommand`.

```bash
# macOS
ssh -o ProxyCommand='nc -X 5 -x 127.0.0.1:8080 %h %p' user@host

# Linux / Windows WSL
ssh -o ProxyCommand='nc --proxy-type socks5 --proxy 127.0.0.1:8080 %h %p' user@host
```

Replace `8080` with your `-socks-proxy` listen port. `%h` and `%p` are filled in by ssh as the target host and port.
