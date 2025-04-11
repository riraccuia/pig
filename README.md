# pig - packet insertion gear

pig is my playground for network protocol experimentation and a Swiss Army knife for network encapsulation. Think of it as a sandbox where networking ideas come to life - from VPN-like tunneling to creative protocol encapsulation. It creates virtual network interfaces and can push packets through just about any transport protocol you throw at it. Whether you're doing serious network testing or just curious about how packets can dance between protocols, pig's got you covered.

## Features

* Multiple transport protocol support (QUIC, UDP, TLS, WebSocket, ICMP, TLS-in-ICMP)
* Cross-platform (Linux, macOS, Windows*)
* Automatic self-signed certificate generation
* Congestion control with WRED (Weighted Random Early Detection)
* Stream multiplexing (for streamed protocols)
* Configurable via command line flags or TOML configuration file
* MTLS and JWT-based authentication for secure client-server connections

_*Windows support is implemented but not at all tested at this time_

## Design Principles

pig's architecture is built around a robust and flexible transport layer design that enables experimentation and reliable network protocol implementation:

#### Unified Interface Design
All transport protocols implement a common interface that provides consistent behavior across different protocols:
* Standard connection lifecycle management
* Common stream operations (Read, Write, Close, Flush)
* Unified error handling patterns
* Consistent configuration patterns

#### Extensible Transport Implementation
* New transports can be added like building blocks under `pkg/transport/`
* Each transport lives in its own dedicated folder (e.g., `pkg/transport/icmp/`, `pkg/transport/quic/`)
* Implementation only requires wrapping the underlying protocol to match interfaces in `pkg/transport/transport.go`
* Simple pathway to experiment with new transport protocols and ideas

#### Layered Protocol Stack
* Clean separation between transport protocols
* Support for protocol encapsulation (e.g., TLS-in-ICMP)
* Composable transport layers (e.g., TLS in ICMP)
* Pluggable design for easy addition of new protocols

#### Stream Abstraction
* Unified handling of both stream-oriented and packet-oriented protocols
* Built-in support for stream multiplexing where protocol allows
* Automatic stream management and lifecycle handling

#### Flow Control (applies to ICMP based transports)
* NewReno-style congestion control implementation
* Window management and packet tracking
* Fast retransmit and recovery mechanisms

## Quick Start

For quick testing with automatically generated certificates:

```bash
# Terminal 1 - Server
sudo pig -proto ws -l :8080 -k
# output: INF Creating client with adapter utun0, IP: 172.31.255.1, MTU 1400

# Terminal 2 - Client
sudo pig -proto ws -c localhost:8080 -k
```

## Congestion Control

pig implements WRED (Weighted Random Early Detection) to combat network bufferbloat. 
WRED helps maintain low latency by:

* Proactively dropping packets before queues are full
* Using weighted averaging to smooth out traffic bursts
* Preventing global TCP synchronization

## Transport Protocols

### QUIC
* Based on Go's standard library QUIC implementation
* Provides native stream multiplexing
* Handles connection migration
* Future plans include migration to quic-go for enhanced features

### TLS-in-ICMP
* Encapsulates TLS traffic within ICMP packets
* Provides additional layer of obfuscation
* Currently recommended for Linux servers only due to OS-level ICMP handling on other platforms
* Requires OS configuration to prevent interference with ICMP handling (except on Linux)

### ICMP
* Full-featured implementation with packet loss recovery
* Uses raw sockets and `golang.org/x/net/icmp`
* Currently recommended for Linux servers only due to OS-level ICMP handling on other platforms
* Requires OS configuration to prevent interference with ICMP handling (except on Linux)

### TLS
* Direct TLS connection using `crypto/tls`

### WebSocket
* Wraps around `github.com/coder/websocket`

### UDP
* Basic UDP implementation
* Lowest overhead

## Configuration Options

### Command line flags

| Category | Flag | Description | Default |
|----------|------|-------------|---------|
| **Config File** | `-config` | Path to configuration file in toml format | |
| **Network Settings** | `-proto` | Transport protocol: "quic", "udp", "tls", "ws", "icmp", or "tls-in-icmp" | quic |
| | `-mtu` | MTU size | 1400 |
| | `-streams` | Number of multiplexed streams for supported protocols | CPU cores available |
| | `-retry` | Reconnection interval in seconds | 5 |
| | `-I` | Network interface to use (e.g., wlan0, en0) | |
| | `-tunnel` | Tunnel address in CIDR format | 172.31.254.1/32 (client), 172.31.255.1/24 (server) |
| | `-qs` | Size of packet queues | 256 |
| **WRED Configuration** | `-factor` | Weight factor for WRED | 5 |
| | `-drop` | Drop probability | 0.25 |
| | `-thresh` | Queue length threshold | 0.1 |
| **Logging** | `-v` | Verbosity level for logging (0-2, where 2 is most verbose) | 0 |
| **Script Execution** | `-start-script` | Path to script to execute when a tunnel connection is established | |
| | `-stop-script` | Path to script to execute when a tunnel connection is disconnected | |
| **Authentication** | `-cert` | Path to certificate file for MTLS | |
| | `-key` | Path to private key file for MTLS | |
| | `-mtls-ca` | Path to a pem formatted certificate bundle containing trusted CAs for MTLS | |
| | `-k` | Disable certificate verification (insecure mode) | |
| | `-auth` | Specify non-tls authentication type to use, currently `jwt` only | |
| | `-tok` | The token to send to the server for applicable auth types | |
| | `-jwk` | Path to public key file used to verify JWT tokens. This can be a local file or a URL. The file can be in PEM or JWKS formats. | |

### Configuration File

The configuration file uses TOML format. 

| Setting | Type | Description | Default |
|---------|------|-------------|---------|
| `mode` | string | Operating mode: "client" or "server" | Required |
| `proto` | string | Transport protocol: "quic", "udp", "tls", "ws", "icmp", or "tls-in-icmp" | quic |
| `tunnel_address` | string | CIDR format for the tunnel interface (e.g., "10.0.0.1/24") | 172.31.254.1/32 (client), 172.31.255.1/24 (server) |
| `queue_size` | int | Size of packet queues | 256 |
| `mtu` | int | Maximum Transmission Unit for the tunnel | 1400 |
| `cert_file` | string | Path to TLS certificate file | Auto-generated if empty |
| `key_file` | string | Path to TLS private key file | Auto-generated if empty |
| `stream_count` | int | Number of multiplexed streams for protocols that support it | CPU cores available |
| `insecure` | bool | Skip TLS certificate verification if true | false |
| `reconnect_interval` | int | Time in seconds to wait before reconnecting | 5 |
| `bind_adapter` | string | Network interface to bind to (e.g., "eth0", "wlan0"), useful for icmp based protos | Default interface |
| `log_level` | string | Logging level: "debug", "info", "warn", "error" | info |
| `start_script` | string | Script to execute when a tunnel connection is established |  |
| `stop_script` | string | Script to execute when a tunnel connection is terminated |  |
| `target.address` | string | Target address to bind to (server) or connect to (client) | Required |
| `target.port` | int | Port to use for the connection | Required |
| `wred.weight_factor` | float | Weight factor for WRED algorithm | 5.0 |
| `wred.drop_probability` | float | Probability of packet drop in WRED | 0.25 |
| `wred.threshold` | float | Queue threshold for WRED | 0.1 |
| `auth.type` | string | Authentication type: "jwt" | None |
| `auth.jwt.public_key_source` | string | Path to public key file, URL to JWKS, or JSON file with JWKS |  |
| `auth.jwt.token` | string | JWT token for client authentication |  |
| `auth.mtls.trust_pem` | string | Path to trust bundle for mTLS | System CA |

Here's an example `config.toml` with explanations for all available settings:

```toml
# Server configuration
mode = "server"                # "server" or "client"
proto = "quic"                 # "quic", "udp", "tls", "ws", "icmp", or "tls-in-icmp"
tunnel_address = "10.0.0.1/24" # CIDR format for tunnel interface
queue_size = 128               # Size of packet queues for the transport layer
mtu = 1500                     # Maximum Transmission Unit
cert_file = "/path/to/cert.pem"
key_file = "/path/to/key.pem"
stream_count = 5               # Number of multiplexed streams for supported protocols
log_level = "info"             # Logging level
insecure = true                # Skip certificate verification if true
reconnect_interval = 5         # Reconnection interval in seconds
bind_adapter = "eth0"          # Network interface to bind to
start_script = "/path/to/start.sh" # Script to run when a connection is established
stop_script = "/path/to/stop.sh"   # Script to run when a connection is terminated

[target]
address = "0.0.0.0"            # Target address to bind to (server) or connect to (client)
port = 8080                    # Port to use

[wred]
weight_factor = 5.0            # Weight factor for WRED algorithm
drop_probability = 0.25        # Probability of packet drop
threshold = 0.1                # Queue threshold for WRED

[auth]
type = "jwt"                   # Authentication type: "jwt"

  [auth.jwt]
  public_key_source = "/path/to/keys.pem" # Path to public key file, URL to JWKS, or JSON file with JWKS
  token = "your.jwt.token"     # JWT token (client only)

  [auth.mtls]
  trust_pem = "/path/to/ca.pem" # Path to trust bundle for mTLS
```

Run with config file:
```bash
pig -config config.toml
```

#### Certificate Handling
* If certificate files are not provided, pig automatically generates self-signed certificates
* Use the `-k` flag to skip certificate verification

## Start/Stop Scripts

pig supports executing custom scripts when tunnel connections are established or disconnected. This feature is useful for performing additional setup or cleanup operations, such as configuring routing tables, firewall rules, etc...

### Configuration

Scripts can be specified using command-line flags or in the configuration file:

```bash
# Command-line example
pig -proto ws -c example.com:8080 -start-script /path/to/start.sh -stop-script /path/to/stop.sh

# Or in config.toml
start_script = "/path/to/start.sh"
stop_script = "/path/to/stop.sh"
```

### Environment Variables

The following environment variables are available to scripts:

| Variable | Description |
|----------|-------------|
| `PIG_TUN_NAME` | Tunnel adapter name (e.g., `utun1`, `tun0`) |
| `PIG_TUN_INDEX` | Numeric index of the tunnel adapter |
| `PIG_REMOTE_ADDR` | IP address of the remote endpoint |
| `PIG_NAT_ADDR` | Client's allocated IP for outgoing packets (server mode only) |
| `PIG_TUNNEL_PROTO` | Protocol used for the tunnel (e.g., `quic`, `ws`, `icmp`) |

### Execution Context

- Standard output from scripts is logged at debug level
- Error output and exit codes are logged at error level

### Example Scripts

#### Route All Traffic Through Tunnel (Linux)

This example start script configures the system to route all traffic through the tunnel:

```bash
#!/bin/bash
# start.sh - Route all traffic through the tunnel

# Log script execution
echo "Configuring routes for tunnel $PIG_TUN_NAME (index: $PIG_TUN_INDEX)"
echo "Remote address: $PIG_REMOTE_ADDR, Protocol: $PIG_TUNNEL_PROTO"

# Add routes for 0.0.0.0/1 and 128.0.0.0/1 (covering all IPs) via the tunnel
ip route add 0.0.0.0/1 dev $PIG_TUN_NAME
ip route add 128.0.0.0/1 dev $PIG_TUN_NAME
```

Corresponding stop script to clean up the routes:

```bash
#!/bin/bash
# stop.sh - Remove routes when tunnel disconnects

echo "Removing routes for tunnel $PIG_TUN_NAME"

# Remove the routes
ip route del 0.0.0.0/1 dev $PIG_TUN_NAME
ip route del 128.0.0.0/1 dev $PIG_TUN_NAME
```

#### Windows Example (PowerShell)

```powershell
# start.ps1 - Configure routing on Windows
$tunIndex = $env:PIG_TUN_INDEX
$tunName = $env:PIG_TUN_NAME
$remoteAddr = $env:PIG_REMOTE_ADDR

Write-Output "Configuring routes for tunnel $tunName with index $tunIndex"

# Add routes
route add 0.0.0.0 mask 128.0.0.0 if $tunIndex
route add 128.0.0.0 mask 128.0.0.0 $tunIndex

# Preserve route to remote server
$defaultGateway = (Get-NetRoute -DestinationPrefix "0.0.0.0/0").NextHop
$remoteIP = $remoteAddr.Split(":")[0]
route add $remoteIP mask 255.255.255.255 if $defaultGateway
```

## Authentication

pig supports multiple authentication mechanisms that can be used independently or combined for enhanced security:

* **JWT Token Authentication**: Client authentication using JWT tokens
* **TLS Mutual Authentication**: Certificate-based mutual authentication for TLS-based protocols (QUIC, TLS, WebSocket)

An interactive signtool is available as part of this project that simplifies JWT token generation and key management, see [JWT Signing Tool Documentation](tools/signtool/README.md).

### JWT Authentication Example

```bash
# Generate a token by running the interactive signtool
./signtool

# Use the token from file via terminal flag
sudo pig -proto ws -c server:8080 -auth jwt -tok "$(cat token.txt)"

# Or use it from an environment variable
export PIG_TOKEN="xxx"
sudo pig -proto ws -c server:8080 -auth jwt -tok "$PIG_TOKEN"
```

### TLS Mutual Authentication

For TLS-based protocols, you can enable mutual authentication by providing client certificates:

```bash
# Server with mutual TLS authentication
sudo pig -proto tls -l :8080 -cert server.crt -key server.key -mtls-ca ca.crt

# Client with certificate
sudo pig -proto tls -c server:8080 -cert client.crt -key client.key
```

### Combined Authentication

You can combine JWT and TLS mutual authentication for TLS-based protocols:

```bash
# Server with both authentication methods
sudo pig -proto tls -l :8080 \
-cert server.crt -key server.key -mtls-ca ca.crt \
-auth jwt -jwk bundle.pem

# Client with both token and certificate
export PIG_TOKEN="xxx"
sudo pig -proto tls -c server:8080 -cert client.crt -key client.key -auth jwt -tok "$PIG_TOKEN"
```

## Platform Support

### Linux
* Fully tested on both 32-bit and 64-bit architectures
* Requires root privileges for TUN device creation
* Supports all transport protocols
* For server deployment, add the following to `/etc/rc.local`:
```bash
sysctl -w net.ipv4.ip_forward=1
nft add table ip nat && sudo nft add chain ip nat postrouting { type nat hook postrouting priority 100 \; } && sudo nft add rule ip nat postrouting oifname "wlan0" masquerade
```
* This configuration enables IP forwarding and sets up NAT, which is essential for server operation

### macOS (Darwin)
* Fully tested on Apple Silicon 
* Requires root privileges for utun device creation
* Supports all transport protocols

### Windows
* Not tested
* Uses WinTun for TUN device creation
* Further testing needed
* Requires administrative privileges

### Certificate Management
* Generate production certificates:
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```

## Troubleshooting

### Common Issues

* **Permission Denied**: Make sure you're running with sufficient privileges (root/sudo) when creating tunnel interfaces
* **Certificate Errors**: Use `-k` flag for testing, but ensure proper certificates for production
* **Connection Refused**: Verify firewall rules allow the chosen protocol and port
* **MTU Issues**: If experiencing packet fragmentation, try adjusting the MTU with `-mtu` flag

### Debug Logging

Enable verbose logging with `-v` flag:
```bash
pig -v 2 ...  # Increased verbosity for debugging
```

### Command Line Examples

The `-proto` flag is used to specify the transport protocol for the tunnel. Valid values are: `quic`, `udp`, `tls`, `ws`, `icmp`, and `tls-in-icmp`.

#### Server mode:
```bash
# Start a server using QUIC
pig -s -l :8080 -proto quic

# Start a server using websocket
pig -s -l :8080 -proto ws

# Start a server using ICMP with tail drop settings
pig -proto icmp -I wlan0 -drop 0.50 -thresh 0.05 -k -v 2
```

#### Client mode:
```bash
# Connect to a server using QUIC
pig -c example.com:8080 -proto quic

# Connect to a server using websocket
pig -c example.com:8080 -proto ws

# Connect to a server using ICMP with tail drop settings
pig -proto icmp -c 192.168.1.100 -I en0 -drop 0.50 -thresh 0.01 -k -v 2
```

## Contributing

Contributions are welcome! Some areas that need attention:
* Windows platform testing
* icmp testing on public networks
* Additional transport protocols
* Performance optimizations

## License

[MIT License](LICENSE)