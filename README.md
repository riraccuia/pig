# pig - packet insertion gear

pig is my playground for network protocol experimentation and a Swiss Army knife for network encapsulation. Think of it as a sandbox where networking ideas come to life - from VPN-like tunneling to creative protocol encapsulation. It creates virtual network interfaces and can push packets through just about any transport protocol you throw at it. Whether you're doing serious network testing or just curious about how packets can dance between protocols, pig's got you covered.

## Features

* Multiple transport protocol support (QUIC, UDP, TLS, WebSocket, ICMP, TLS-in-ICMP)
* Cross-platform (Linux, macOS, Windows*)
* Automatic self-signed certificate generation
* Congestion control with WRED (Weighted Random Early Detection)
* Stream multiplexing (for streamed protocols)
* Configurable via command line flags or TOML configuration file

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
sudo pig -proto ws -l :8080 -tunnel 10.0.0.1/24 -k

# Terminal 2 - Client
sudo pig -proto ws -c localhost:8080 -k

# Terminal 3 - Test connectivity
ping 10.0.0.1
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

### Configuration File

Example `config.toml`:

```toml
# Server configuration
mode = "server"
transport = "quic"
tunnel_address = "10.0.0.1/24"
mtu = 1500  # Adjust based on your network
cert_file = "/path/to/cert.pem"
key_file = "/path/to/key.pem"
stream_count = 5
log_level = "info"
insecure = true  # Set to true to skip certificate verification

[target]
address = "0.0.0.0"
port = 8080

[wred]
weight_factor = 5.0
drop_probability = 0.25
threshold = 0.1
```

Run with config file:
```bash
pig -config config.toml
```

## Configuration Options

### Network Settings
* `-mtu`: MTU size (default: 1300, adjust based on your network)
* `-streams`: Number of multiplexed streams for supported protocols (default: 5)
* `-retry`: Reconnection interval in seconds (default: 5)
* `-I`: Network interface to use (e.g., wlan0, en0)

### WRED Configuration
* `-factor`: Weight factor for WRED (default: 5)
* `-drop`: Drop probability (default: 0.25)
* `-thresh`: Queue length threshold (default: 0.1)

### Logging
* `-v`: Verbosity level for logging (0-2, where 2 is most verbose)

### Security
* `-cert`: Path to certificate file (recommended for production)
* `-key`: Path to private key file
* `-k`: Disable certificate verification (insecure mode)

#### Certificate Handling
* If certificate files are not provided, pig automatically generates self-signed certificates
* Use the `-k` flag to skip certificate verification

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
pig -s -l :8080 -tunnel 10.0.0.1/24 -proto quic

# Start a server using UDP
pig -s -l :8080 -tunnel 10.0.0.1/24 -proto ws

# Start a server using ICMP with tail drop settings
pig -proto icmp -I wlan0 -tunnel 10.0.0.1/28 -drop 0.50 -thresh 0.05 -k -v 2
```

#### Client mode:
```bash
# Connect to a server using QUIC
pig -c example.com:8080 -tunnel 10.1.0.2/24 -proto quic

# Connect to a server using UDP
pig -c example.com:8080 -tunnel 10.1.0.2/24 -proto ws

# Connect to a server using ICMP with tail drop settings
pig -proto icmp -c 192.168.2.100 -I en0 -drop 0.50 -thresh 0.01 -k -v 2
```

## Contributing

Contributions are welcome! Some areas that need attention:
* Windows platform testing
* icmp testing on public networks
* Additional transport protocols
* Performance optimizations

## License

[MIT License](LICENSE)