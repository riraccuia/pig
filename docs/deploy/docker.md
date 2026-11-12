# Docker

Run pig in Docker. The image builds from source and starts with a config file you provide.

## Prerequisites

- [Docker](https://docs.docker.com/engine/install/) engine (or [Docker Desktop](https://docs.docker.com/get-started/get-docker/))
- [Git](https://git-scm.com/)

The container needs `NET_ADMIN` privileges.

## Clone the repository

Build context is the repository root. Clone pig, then work from there:

```bash
git clone https://github.com/riraccuia/pig
cd pig
```

## Files

| File | Path |
|------|------|
| Dockerfile | [`build/docker/Dockerfile`](../../build/docker/Dockerfile) |
| Compose | [`build/docker/compose.yaml`](../../build/docker/compose.yaml) |
| Entrypoint | [`build/docker/start.sh`](../../build/docker/start.sh) |

The entrypoint ensures `/dev/net/tun` exists and optionally installs masquerade rules (`PIG_MASQUERADE`).

## Config

Place a pig config next to the compose file as `pig.config`:

```bash
cp path/to/your.config build/docker/pig.config
```

Compose mounts that file at `/etc/pig/pig.config` inside the container.

## Run

From `build/docker/`:

```bash
cd build/docker
docker compose up --build
```

Stop with `docker compose down` from the same directory.

## Environment variables

| Variable | Default | Accepted values | Meaning |
|----------|---------|-----------------|---------|
| `PIG_MASQUERADE` | `1` | `1` or `0` | Enable (`1`) or disable (`0`) IP forwarding + masquerade |
| `PIG_NAT_OIF` | `eth0` | Interface name | Outbound interface for masquerade (used when masquerade is on) |
| `PIG_CONFIG` | `/etc/pig/pig.config` | Absolute path inside the container | Config file passed to `pig -config` |

Example, turn masquerade off:

```bash
PIG_MASQUERADE=0 docker compose up --build
```

## Next steps

- [Examples](../../examples/)
