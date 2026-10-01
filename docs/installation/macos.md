# macOS

Install pig on macOS.

## Prerequisites

- A terminal with permission to use `sudo` (creating the tunnel interface needs elevated privileges).

## Download a release

1. Open the [latest release](https://github.com/riraccuia/pig/releases) page.
2. Download the darwin archive corresponding to your CPU (`darwin-arm64` on Apple silicon, `darwin-amd64` on Intel).
3. Extract the binary and make it executable. Then move it somewhere on your `PATH` if you want.

Release binaries are **not signed**. macOS marks downloaded files as quarantined.\
Clear that flag before the first run, or Gatekeeper will block execution:

```bash
chmod +x ./pig
xattr -d com.apple.quarantine ./pig
```

Replace `./pig` with the path to the binary you downloaded.

## Build from source

You need:

1. [Git](https://git-scm.com/)
2. [Go](https://go.dev/dl/) 1.27 or later
3. Make (`xcode-select --install` provides it)

```bash
git clone https://github.com/riraccuia/pig
cd pig
make pig
```

The binary is written to `bin/pig`. Built locally, it is not quarantined.

## Run

```bash
./pig -h
```

Use `sudo` whenever you start a tunnel. Next: [Quick start](../getting-started/quick-start.md).
