# Docker

## Files

| File | Path |
|------|------|
| Dockerfile | [`build/docker/Dockerfile`](../build/docker/Dockerfile) |
| Compose | [`build/docker/compose.yaml`](../build/docker/compose.yaml) |
| Entrypoint | [`build/docker/start.sh`](../build/docker/start.sh) |

Build context is the repository root.
The entrypoint ensures `/dev/net/tun` exists and optionally installs masquerade rules (`PIG_MASQUERADE`).

## Quick start

Place a config next to the compose file named `pig.config`, then from `build/docker/`:

```bash
docker compose up --build
```

Useful environment variables:

| Variable | Default | Accepted values | Meaning |
|----------|---------|-----------------|---------|
| `PIG_MASQUERADE` | `1` | `1` or `0` | Enable (`1`) or disable (`0`) IP forwarding + masquerade |
| `PIG_NAT_OIF` | `eth0` | Interface name | Outbound interface for masquerade (used when masquerade is on) |
| `PIG_CONFIG` | `/etc/pig/pig.config` | Absolute path inside the container | Config file passed to `pig -config` |

See the [Examples](guide.md#examples) folder for more practical examples.
