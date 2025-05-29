# pig - packet insertion gear
![pig gopher](assets/pig-gopher.png)

pig is my playground for network protocol experimentation and a Swiss Army knife for network encapsulation. Think of it as a sandbox where networking ideas come to life - from VPN-like tunneling to creative protocol encapsulation. It creates virtual network interfaces and can push packets through just about anything. Whether you're doing serious network testing or just curious about how packets can dance between protocols, pig's got you covered.

## Table of Contents

- [Quick Start](#quick-start)
- [Features](#features)
- [Transport Protocols](#transport-protocols)
  - [QUIC](#quic)
  - [TLS](#tls)
  - [WebSocket](#websocket)
  - [UDP](#udp)
  - [ICMP](#icmp)
  - [TLS-in-ICMP](#tls-in-icmp)
- [Congestion Control](#congestion-control)
- [Configuration Options](#configuration-options)
  - [Command line flags](#command-line-flags)
  - [Configuration File](#configuration-file)
  - [Certificate Handling](#certificate-handling)
- [Authentication](#authentication)
  - [JWT Authentication Example](#jwt-authentication-example)
  - [TLS Mutual Authentication](#tls-mutual-authentication)
  - [Combined Authentication](#combined-authentication)
- [ICE for direct p2p connectivity](#ice-for-direct-p2p-connectivity-across-nats-and-firewalls)
  - [Enabling ICE](#enabling-ice)
- [Start/Stop Scripts](#startstop-scripts)
  - [Configuration](#configuration)
  - [Environment Variables](#environment-variables)
  - [Execution Context](#execution-context)
  - [Example Scripts](#example-scripts)
- [Design Principles](#design-principles)
  - [Unified Interface Design](#unified-interface-design)
  - [Extensible Transport Implementation](#extensible-transport-implementation)
  - [Layered Protocol Stack](#layered-protocol-stack)
  - [Stream Abstraction](#stream-abstraction)
  - [Flow Control](#flow-control-applies-to-icmp-based-transports)
- [Platform Support](#platform-support)
  - [Linux](#linux)
  - [macOS (Darwin)](#macos-darwin)
  - [Windows](#windows)
  - [Certificate Management](#certificate-management)
- [Troubleshooting](#troubleshooting)
  - [Common Issues](#common-issues)
  - [Debug Logging](#debug-logging)
  - [Command Line Examples](#command-line-examples)
- [Contributing](#contributing)
- [License](#license)

## Quick Start

For quick testing with automatically generated certificates:

```bash
# ------------------------------------------------------------

# Scenario 1: Simple WebSocket tunnel, no authentication
# Router configuration: port forwarding on port 8080 pointing to the server

# Terminal 1 - Server
sudo pig -l :8080 -proto ws -k

# Terminal 2 - Client
sudo pig -c server:8080 -proto ws -k

# ------------------------------------------------------------

# Scenario 2: Simple WebSocket tunnel, no authentication, using ICE for direct p2p connectivity
# Router configuration: none

# Terminal 1 - Server
sudo pig -l :8080 -proto ws -k -ice ssl://broker.hivemq.com:8883

# Terminal 2 - Client
sudo pig -c server:8080 -proto ws -k -ice ssl://broker.hivemq.com:8883

# ------------------------------------------------------------
```

## Features

* Multiple transport protocol support (QUIC, UDP, TLS, WebSocket, ICMP, TLS-in-ICMP)
* Direct connections over the internet with no router configuration (uses ICE, UDP/TCP hole punching)
* Cross-platform (Linux, macOS, Windows*)
* Automatic self-signed certificate generation
* Congestion control with WRED (Weighted Random Early Detection)
* Stream multiplexing (for streamed protocols)
* Configurable via command line flags or TOML configuration file
* MTLS and JWT-based authentication for secure client-server connections

_*Windows support is implemented but not often tested_

## Transport Protocols

### QUIC
* Two wrapper implementations are available:
  * `quic-go` - (default) a wrapper around the [quic-go](https://github.com/quic-go/quic-go) QUIC implementation
  * `quic` - a wrapper around the Go standard library QUIC implementation
* Provides native stream multiplexing

### TLS
* Direct TLS connection using `crypto/tls`

### WebSocket
* Wraps around `github.com/coder/websocket`

### UDP
* Basic UDP implementation
* Lowest overhead

### ICMP
* Full-featured implementation with packet loss recovery
* Uses raw sockets and `golang.org/x/net/icmp`
* Currently recommended for Linux servers only due to OS-level ICMP handling on other platforms
* Requires OS configuration to prevent interference with ICMP handling (except on Linux)

### TLS-in-ICMP
* Encapsulates TLS traffic within ICMP packets
* Provides additional layer of obfuscation
* Currently recommended for Linux servers only due to OS-level ICMP handling on other platforms
* Requires OS configuration to prevent interference with ICMP handling (except on Linux)

## Congestion Control

pig implements WRED (Weighted Random Early Detection) to combat network bufferbloat. 
WRED helps maintain low latency by:

* Proactively dropping packets before queues are full
* Using weighted averaging to smooth out traffic bursts
* Preventing global TCP synchronization

## Configuration Options

### Command line flags

| Category | Flag | Description | Default |
|----------|------|-------------|---------|
| **Config File** | `-config` | Path to configuration file in toml format | |
| **Networks** | `-proto` | Transport protocol: "quic", "udp", "tls", "ws", "icmp", or "tls-in-icmp" | quic |
| | `-mtu` | MTU size | 1400 |
| | `-streams` | Number of multiplexed streams for supported protocols | CPU cores available |
| | `-retry` | Reconnection interval in seconds | 5 |
| | `-I` | Network interface to use (e.g., wlan0, en0) | |
| | `-tunnel` | Tunnel address in CIDR format | 172.31.254.1/32 (client), 172.31.255.1/24 (server) |
| | `-qs` | Size of packet queues | 256 |
| | `-p` | Source port to use for the connection (if applicable) | 0 (system assigned) |
| **WRED** | `-factor` | Weight factor for WRED | 5 |
| | `-drop` | Drop probability | 0.25 |
| | `-thresh` | Queue length threshold | 0.1 |
| **Logging** | `-v` | Verbosity level for logging (0-2, where 2 is most verbose) | 0 |
| **Script** | `-start-script` | Path to script to execute when a tunnel connection is established | |
| | `-stop-script` | Path to script to execute when a tunnel connection is disconnected | |
| **Auth** | `-cert` | Path to certificate file for MTLS | |
| | `-key` | Path to private key file for MTLS | |
| | `-mtls-ca` | Path to a pem formatted certificate bundle containing trusted CAs for MTLS | |
| | `-k` | Disable certificate verification (insecure mode) | |
| | `-auth` | Specify non-tls authentication type to use, currently `jwt` only | |
| | `-tok` | The token to send to the server for applicable auth types | |
| | `-jwk` | Path to public key file used to verify JWT tokens. This can be a local file or a URL. The file can be in PEM or JWKS formats. | |
| **ICE** | `-ice` | Enable ICE based hole punching, set to true (-ice true) to use the default server or provide a MQTT broker address | ssl://test.mosquitto.org:8883 |
| | `-ice-key` | Encryption passphrase for ICE signaling messages | |
| | `-stun-srv` | STUN server address for hole punching | stun.l.google.com:19302 |
| | `-stun-qry` | Source port to query, 'R' for random port | |

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
| `target.src_port` | int | Source port to use for the connection (if applicable) | 0 (system assigned) |
| `wred.weight_factor` | float | Weight factor for WRED algorithm | 5.0 |
| `wred.drop_probability` | float | Probability of packet drop in WRED | 0.25 |
| `wred.threshold` | float | Queue threshold for WRED | 0.1 |
| `auth.type` | string | Authentication type: "jwt" | None |
| `auth.jwt.public_key_source` | string | Path to public key file, URL to JWKS, or JSON file with JWKS |  |
| `auth.jwt.token` | string | JWT token for client authentication |  |
| `auth.mtls.trust_pem` | string | Path to trust bundle for mTLS | System CA |
| `ice.enabled` | bool | Enable automatic hole punching | false |
| `ice.stun_address` | string | STUN server address for hole punching | stun.l.google.com:19302 |
| `ice.signaling.encryption_key` | string | Encryption key for signaling messages | no encryption |
| `ice.signaling.mqtt_broker_address` | string | MQTT broker address for signaling | ssl://test.mosquitto.org:8883 |
| `ice.signaling.mqtt_client_id` | string | Client ID for MQTT connection | |
| `ice.signaling.mqtt_username` | string | Username for MQTT connection | |
| `ice.signaling.mqtt_password` | string | Password for MQTT connection | |

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
src_port = 0                   # Source port (0 for system assigned)

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

[ice]
enabled = true                 # Enable automatic hole punching
stun_address = "stun.l.google.com:19302"  # STUN server address

  [ice.signaling]
  encryption_key = "my-secure-passphrase"         # Encryption key for signaling messages
  mqtt_broker_address = "ssl://mqtt-broker:8883"  # Optional MQTT broker address, defaults to ssl://test.mosquitto.org:8883
  mqtt_client_id = "unique-client-id"             # Optional MQTT client ID
  mqtt_username = "user"                          # Optional MQTT username
  mqtt_password = "password"                      # Optional MQTT password
```

Run with config file:
```bash
pig -config config.toml
```

#### Certificate Handling
* If certificate files are not provided, pig automatically generates self-signed certificates
* Use the `-k` flag to skip certificate verification

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
sudo pig -c server:8080 -proto ws -a jwt -tok "$(cat token.txt)"

# Or use it from an environment variable
export PIG_TOKEN="xxx"
sudo pig -c server:8080 -proto ws -a jwt -tok "$PIG_TOKEN"
```

### TLS Mutual Authentication

For TLS-based protocols, you can enable mutual authentication by providing client certificates:

```bash
# Server with mutual TLS authentication
sudo pig -l :8080 -proto tls -cert server.crt -key server.key -mtls-ca ca.crt

# Client with certificate
sudo pig -c server:8080 -proto tls -cert client.crt -key client.key
```

### Combined Authentication

You can combine JWT and TLS mutual authentication for TLS-based protocols:

```bash
# Server with both authentication methods
sudo pig -l :8080 -proto tls \
-cert server.crt -key server.key -mtls-ca ca.crt \
-a jwt -jwk bundle.pem

# Client with both token and certificate
export PIG_TOKEN="xxx"
sudo pig -c server:8080 -proto tls -cert client.crt -key client.key -a jwt -tok "$PIG_TOKEN"
```

## ICE for direct p2p connectivity across NATs and firewalls

pig includes a simplified ICE implementation that helps establish direct peer-to-peer connections through NATs and firewalls without configuring port forwarding at all.
This feature can be enabled using the `-ice` flag.

Supported transports: QUIC, WebSocket.
Roadmap: UDP and TLS support.

The mechanism uses:
- STUN for discovering public endpoints
- MQTT for secure signaling between peers
- AES-256-GCM encryption (optional) for signaling messages
- UDP and TCP hole punching to establish direct connectivity between peers

For more details about pig's ICE implementation, see the [ICE Documentation](pkg/ice/README.md).

### Enabling ICE

ICE can be enabled using the `-ice true` flag, or `-ice <broker_addr>`. If no broker address is provided, pig connects by default to `ssl://test.mosquitto.org:8883`. 
You can optionally provide an encryption key as a passphrase, which will be used to encrypt messages exchanged during the signaling phase: this is particularly useful when connecting pig to free public MQTT brokers.

```bash
# Start a listener with ICE and hole punching enabled using default settings
sudo pig -l :8080 -proto quic -k -ice

# Connect to the server with ICE and hole punching using default settings
sudo pig -c server:8080 -proto quic -k -ice

# Start a listener with ICE and hole punching enabled with encryption passphrase
sudo pig -l :8080 -proto quic -k -ice -ice-key my-secure-passphrase

# Connect to the server with ICE and hole punching with encryption passphrase
sudo pig -c server:8080 -proto quic -ice -ice-key my-secure-passphrase

# Configure a custom STUN server and MQTT broker
sudo pig -c server:8080 -proto quic -ice ssl://my.broker.org:8883 -stun-srv stun.example.com:3478
```

The same settings can be configured in the TOML configuration file:

```toml
[ice]
enabled = true
stun_address = "stun.l.google.com:19302"

[ice.signaling]
encryption_key = "my-secure-passphrase"
mqtt_broker_address = "ssl://mqtt-broker:8883"
```

## Start/Stop Scripts

pig supports executing custom scripts when tunnel connections are established or disconnected. This feature is useful for performing additional setup or cleanup operations, such as configuring routing tables, firewall rules, etc...

### Configuration

Scripts can be specified using command-line flags or in the configuration file:

```bash
# Command-line example
pig -c example.com:8080 -proto ws -start-script /path/to/start.sh -stop-script /path/to/stop.sh

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
pig -l :8080 -v 2 ...  # Increased verbosity for debugging
```

### Command Line Examples

The `-proto` flag is used to specify the transport protocol for the tunnel. Valid values are: `quic`, `udp`, `tls`, `ws`, `icmp`, and `tls-in-icmp`.

#### Server mode:
```bash
# Start a server using QUIC
pig -l :8080 -proto quic

# Start a server using websocket
pig -l :8080 -proto ws

# Start a server using ICMP with WRED settings
pig -l :8080 -proto icmp -I wlan0 -drop 0.50 -thresh 0.05 -k -v 2
```

#### Client mode:
```bash
# Connect to a server using QUIC
pig -c example.com:8080 -proto quic

# Connect to a server using websocket
pig -c example.com:8080 -proto ws

# Connect to a server using ICMP with WRED settings
pig -c 192.168.1.100:8080 -proto icmp -I en0 -drop 0.50 -thresh 0.01 -k -v 2
```

#### STUN query mode:
```bash
# Query default STUN server
pig stun -p 12345

# Query specific STUN server
pig stun -srv stun.example.com:3478 -p R
```

## Contributing

Contributions are welcome! Some areas that need attention:
* Windows platform testing
* icmp testing on public networks
* Additional transport protocols
* Performance optimizations

## License

[MIT License](LICENSE)