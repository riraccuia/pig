# Linux

Install pig on Linux.

## Prerequisites

- Root privileges (`sudo`). Creating the tunnel interface needs them.
- A working TUN device, normally `/dev/net/tun`.

Confirm TUN is available:

```bash
ls -l /dev/net/tun
```

Most distributions enable this by default. Containers need the device mounted or created (see [Docker](../docker/docker.md)).

## Download a release

1. Open the [latest release](https://github.com/riraccuia/pig/releases) page.
2. Download the linux archive corresponding to your architecture (`linux-amd64`, `linux-arm64`, `linux-arm7`, and others as published).
3. Extract the binary and make it executable. Then move it somewhere on your `PATH` if you want.

```bash
chmod +x ./pig
sudo mv ./pig /usr/local/bin/pig
```

## Build from source

You need:

1. [Git](https://git-scm.com/)
2. [Go](https://go.dev/dl/) 1.27 or later
3. Make

```bash
git clone https://github.com/riraccuia/pig
cd pig
make pig
```

The binary is written to `bin/pig`.

Cross-compile examples:

```bash
make pig-linux-arm64
make pig-linux-arm7
```

## Run

```bash
./pig -h
```

Use `sudo` whenever you start a tunnel. Next: [Quick start](../getting-started/quick-start.md).
