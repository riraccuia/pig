# Windows

Install pig on Windows.

## Prerequisites

- Administrator rights (required to create the tunnel adapter and to install Wintun).
- [Wintun](https://www.wintun.net/) is a hard requirement. Without it, pig cannot create a tunnel interface.

### Install Wintun

1. Download Wintun from [https://www.wintun.net/](https://www.wintun.net/).
2. Extract the archive.
3. Copy `wintun.dll` to `C:\Windows\System32`.

Use the DLL that matches your architecture (typically `amd64`). If the file is missing from `System32`, pig fails to start.

## Download a release

1. Open the [latest release](https://github.com/riraccuia/pig/releases) page.
2. Download the Windows archive (for example `pig-windows-amd64.zip`).
3. Extract the binary and rename it to `pig.exe` if you like, then place it in a directory of your choice.
4. Optionally add that directory to your `PATH`.

## Build from source

You need:

1. [Git](https://git-scm.com/)
2. [Go](https://go.dev/dl/) 1.27 or later
3. [Make](https://gnuwin32.sourceforge.net/packages/make.htm) (or run `go build` directly)

```bat
git clone https://github.com/riraccuia/pig
cd pig
make pig
```

The binary is written under `bin\`.

Or build using the `go` command:

```bat
go build -o bin\pig.exe .\cmd\pig
```

## Run

Open an **Administrator** PowerShell or Command Prompt, then:

```bat
pig.exe -h
```

Next: [Quick start](../getting-started/quick-start.md).
