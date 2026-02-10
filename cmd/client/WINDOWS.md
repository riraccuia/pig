# Pig Client (Windows)

This document describes how to build, deploy, and test the Pig client on Windows.

## Compile for Windows (no CGO)

From the project root:

```powershell
$env:GOOS="windows"
$env:GOARCH="amd64"
$env:CGO_ENABLED="0"
go build -o pig-client.exe ./cmd/client
```

Or from bash/WSL:

```bash
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o pig-client.exe ./cmd/client
```

## Config File

- **Name:** `config.json`
- **Location:** Same directory as the executable

Example: if the binary is at `C:\pig-client\pig-client.exe`, the config must be at `C:\pig-client\config.json`.
For an example config file, see the [Example Test Scenario](#example-test-scenario) section.

## Running the client from terminal

Simply run the binary from an elevated Command Prompt or PowerShell (Run as Administrator):

```powershell
C:\pig-client\pig-client.exe
```

The client will exit when you press Ctrl+C.
If you want the logs to be written as standard output, remove or set to an empty string the `file` and `rotate_size` log fields in the config file.

## Create a Windows Service

Run an elevated Command Prompt or PowerShell (Run as Administrator), then:

```powershell
sc create PigClient binPath= "C:\pig-client\pig-client.exe -service" start= auto
```

Replace `C:\pig-client\pig-client.exe` with the actual path to your binary. The `-service` flag is required so the client runs in service mode.

Start the service:

```powershell
sc start PigClient
```

Stop or delete the service:

```powershell
sc stop PigClient
sc delete PigClient
```

## Example Test Scenario

### 1. Server (pig)

On a machine with network access (Linux, macOS, or Windows), start pig in server mode listening over WebSocket with no ICE:

```bash
pig -l 0.0.0.0:9443 -proto ws -k -v 2
```

This listens on all interfaces, port 9443, using the `ws` protocol and will automatically generate a self-signed certificate for TLS.
Any incoming connections will be accepted because of the `-k` flag.

### 2. Client (Windows)

On the Windows PC where the client service runs:

1. **Place the binary** in a folder, e.g. `C:\pig-client\`

2. **Create `config.json`** in the same folder:

```json
{
  "mode": "client",
  "log": {
    "file": "pig-client.log",
    "level": "trace",
    "rotate_size": "1m"
  },
  "tunnel": {
    "proto": "ws",
    "tunnel_address": "172.31.254.1/29",
    "tls": {
      "insecure": true
    },
    "mtu": 1400,
    "target": {
      "address": "192.168.1.100",
      "port": 9443
    },
    "auth": {
      "type": "",
      "mtls": {
        "trust_pem": "path/to/ca.pem" // not needed if insecure is true
      }
    }
  },
  "route": {
    "enabled": true,
    "tunnel_routes": ["0.0.0.0/1", "128.0.0.0/1"]
  }
}
```

Replace `192.168.1.100` with the IP or hostname of the server running pig. The routes `0/1` and `128/1` together cover all IPv4 addresses for a full tunnel.

3. **Install and start the service** (elevated shell):

```powershell
sc create PigClient binPath= "C:\pig-client\pig-client.exe -service" start= auto
sc start PigClient
```

4. **Verify:** The client should connect to the server. Logs are written to `pig-client.log` in the same directory (or change the path in the config).
