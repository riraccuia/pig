# ICE Package

## Table of Contents
- [Introduction](#introduction)
- [Features](#features)
- [Implementation Notes](#implementation-notes)
- [Components](#components)
  - [Core UDP/TCP Hole Punching](#core-udptcp-hole-punching)
  - [Listen and Connect Methods](#listen-and-connect-methods)
- [Configuration](#configuration)
  - [Signaling Options](#signaling-options)
  - [ICE Message Format](#ice-message-format)
- [How It Works](#how-it-works)
  - [Simplified vs. Full ICE](#simplified-vs-full-ice)
  - [Port Selection](#port-selection)
- [Security](#security)
  - [Message Encryption](#message-encryption)
  - [ICE Credentials](#ice-credentials)
  - [Topics](#topics)
- [Best Practices](#best-practices)
- [Limitations](#limitations)
- [Dependencies](#dependencies)
- [Future Enhancements](#future-enhancements)
- [Example Implementation](#example-implementation)
  - [Setting Up the Server with Listen](#setting-up-the-server-with-listen)
  - [Setting Up the Client with Connect](#setting-up-the-client-with-connect)

## Introduction

This package leverages key ICE protocol concepts like candidate gathering and NAT traversal (hole punching) to establish direct peer-to-peer connections, traversing NAT and firewalls. It supports both UDP and TCP for ICE, and the STUN client supports UDP, TCP, and TLS.

## Features

Currently supported techniques:

- **UDP and TCP Hole Punching**: Creates temporary openings in NAT/firewalls to enable direct UDP or TCP communication between peers.
- **STUN (UDP, TCP, TLS)**: Provides Session Traversal Utilities for NAT (STUN) to discover the public IP address and port of a device behind NAT, supporting UDP, TCP, and TLS protocols.
- **MQTT Signaling**: Uses MQTT for secure signaling between peers to coordinate hole punching.
- **Simplified ICE Protocol**: Implements a lightweight version of Interactive Connectivity Establishment (ICE) protocol for NAT traversal.

## Implementation Notes

This package implements a **simplified version** of the ICE protocol with the following characteristics:

1. **No Connectivity Checks**: Unlike full ICE, this implementation does not perform direct STUN binding requests between peers to verify connectivity.
2. **Direct Hole Punching**: Uses ICE candidate information to perform direct UDP or TCP hole punching.
3. **Unidirectional Signaling**: Focused on client-to-server signaling with server-to-client punching.
4. **ICE Answers**: The codebase includes logic for ICE answers, which are sent by the server in response to offers.
5. **Minimal Candidate Types**: Only supports host and server reflexive candidates (no relay candidates).

## Components

### Core UDP/TCP Hole Punching

The base package provides core UDP and TCP hole punching functionality:

```go
import (
    "context"
    "github.com/riraccuia/pig/pkg/ice/conn"
)

srcPort := 12345

// UDP example
result, err := conn.PunchUDP(ctx, logger, srcPort, "target.example.com:54321")
if err != nil {
    // Handle error
}

// TCP example
// DialTCP has the same signature as net.DialTCP
conn, err := conn.DialTCP("tcp", localAddr, remoteAddr)
if err != nil {
    // Handle error
}
```

### Listen and Connect Methods

#### Listen

The `Listen` function starts a new ICE server and returns a listener for incoming connections. It supports both UDP and TCP, performs STUN queries for public endpoint discovery, and processes incoming ICE offers via MQTT-based signaling.

```go
func Listen(ctx context.Context, opts *signaling.Options, listenAddr net.Addr) (listener any, err error)
```

- **Parameters:**
  - `ctx`: Context for cancellation and timeout.
  - `opts`: Signaling options (see Configuration section).
  - `listenAddr`: The local address to listen on (`*net.UDPAddr` for UDP, `*net.TCPAddr` for TCP).
- **Returns:**
  - `listener`: For UDP, a `*net.UDPConn`; for TCP, a `*conn.TCPListener` (custom type).
  - `err`: Error if setup fails.

**Behavior:**
- For UDP, binds to the specified address and performs a STUN query to discover the public endpoint.
- For TCP, creates a TCP listener (see `conn.TCPListener`).
- Listens for ICE offers via MQTT signaling and responds with ICE answers.
- Performs UDP or TCP hole punching to establish direct connections with clients.
- The returned listener can be used to accept connections (TCP) or receive packets (UDP).

#### Connect

The `Connect` function establishes a connection to a remote peer using ICE. It gathers local and server reflexive candidates, selects the best candidate, and performs the connection using the specified protocol.

```go
func Connect(ctx context.Context, opts *signaling.Options, srcPort, dstPort int, addr string, network string) (co net.Conn, remoteAddr net.Addr, err error)
```

- **Parameters:**
  - `ctx`: Context for cancellation and timeout.
  - `opts`: Signaling options (see Configuration section).
  - `srcPort`: Local port to use (0 for random ephemeral port).
  - `dstPort`: Remote port to connect to.
  - `addr`: Remote IP address as string.
  - `network`: Protocol to use, either "udp" or "tcp".
- **Returns:**
  - `co`: The established connection (`net.Conn`). For UDP, this is a `*net.UDPConn` bound to the local port; for TCP, a `*net.TCPConn` connected to the remote peer.
  - `remoteAddr`: The remote address connected to.
  - `err`: Error if connection fails.

**Behavior:**
- Gathers ICE candidates for the local and remote addresses using STUN and signaling.
- Selects the best candidate (prioritizing server reflexive candidates for NAT traversal).
- For UDP, returns a `*net.UDPConn` bound to the local port; you must send to `remoteAddr`.
- For TCP, returns a connected `*net.TCPConn`.
- Handles all signaling and candidate exchange automatically.

## Configuration

### Signaling Options

The `Options` struct provides configuration for both client and server:

```go
type Options struct {
    BrokerURL     string        // MQTT broker address
    ClientID      string        // Unique client identifier
    Username      string        // MQTT username
    Password      string        // MQTT password
    EncryptionKey []byte        // Encryption key for signaling
    Logger        common.Logger // Logger for debugging
    STUNServer    string        // STUN server address
    Protocol      string        // Protocol for ICE and STUN: "udp", "tcp", or "tls" (for STUN only)
}
```

- `Protocol` determines which protocol is used for ICE candidate gathering and connection. For STUN, valid values are `"udp"`, `"tcp"`, or `"tls"`. For ICE, valid values are `"udp"` or `"tcp"`.

### ICE Message Format

Clients and servers exchange ICE protocol messages using the following format:

```go
// ICEMessage represents an ICE protocol message
type ICEMessage struct {
    SessionID   string           `json:"session_id"`
    Type        ICEMessageType   `json:"type"`
    Timestamp   int64            `json:"timestamp"`
    Candidates  []ICECandidate   `json:"candidates"`
    Credentials ICECredentials   `json:"credentials"`
}

// ICECandidate represents an ICE candidate
type ICECandidate struct {
    Foundation  string           `json:"foundation"`
    Priority    uint32           `json:"priority"`
    Protocol    string           `json:"protocol"` // "udp" or "tcp"
    Address     string           `json:"address"`
    Port        int              `json:"port"`
    Type        ICECandidateType `json:"type"` // "host" or "srflx"
    RelatedAddr string           `json:"relatedAddr,omitempty"`
    RelatedPort int              `json:"relatedPort,omitempty"`
}
```

## How It Works

1. **Protocol Selection**: The client and server select the protocol for ICE and STUN (UDP, TCP, or TLS for STUN; UDP or TCP for ICE) via the `Options.Protocol` field.
2. **Discovery**: The client performs a STUN query using the selected protocol to discover its public endpoint (server reflexive candidate).
3. **ICE Offer**: The client creates an ICE offer containing:
   - Local candidates (host candidates)
   - Public candidates (server reflexive candidates from STUN)
   - ICE credentials for authentication
4. **Signaling**: The client publishes the encrypted ICE offer to an MQTT topic.
5. **Processing**: The server receives the client's ICE offer and extracts the candidates.
6. **Candidate Selection**: The server selects the best candidate for hole punching (prioritizing server reflexive candidates and matching the selected protocol).
7. **Direct Hole Punching**: The server performs UDP or TCP hole punching to the selected client candidate. The server also sends an ICE answer with its own candidates.
8. **Connection**: A direct UDP or TCP connection is established between the peers.

### Simplified vs. Full ICE

Our implementation differs from full ICE in several key ways:

| Feature              | Simplified ICE (Current) | Full ICE                       |
|----------------------|--------------------------|--------------------------------|
| Candidate Types      | Host, Server Reflexive   | Host, Server Reflexive, Relay  |
| Connectivity Checks  | No                       | Yes (STUN binding requests)    |
| ICE Answers          | Yes                      | Required                       |
| Candidate Pairs      | No (server uses best)    | Yes (all combinations tested)  |
| ICE Nomination       | No                       | Yes (regular or aggressive)    |
| ICE Restart          | No                       | Yes                            |
| TURN Support         | No                       | Yes                            |

### Port Selection

- **Specific Port**: Provide a positive port number (1-65535) to use that exact port for the socket.
- **Random Port**: Provide `0` as the port number to let the system assign a random ephemeral port.

## Security

### Message Encryption

If the caller provides an encryption key, all signaling messages are encrypted using AES-256-GCM. 

1. **Key Generation**: Each client-server pair uses a unique 32-byte encryption key
   ```go
   encryptionKey := make([]byte, 32)
   rand.Read(encryptionKey)
   ```

2. **Message Encryption**:
   - ICE messages are first serialized to JSON
   - The JSON is encrypted using AES-256-GCM
   - The ciphertext is base64 encoded for MQTT transmission

3. **Message Decryption**:
   - The base64-encoded ciphertext is decoded
   - The ciphertext is decrypted using AES-256-GCM
   - The decrypted JSON is unmarshaled into an `ICEMessage`

### ICE Credentials

The ICE protocol includes credential exchange for authentication:
- Username and password are randomly generated
- Credentials are included in each ICE message

### Topics

MQTT topics follow ICE message types:
1. The target address is hashed using SHA-256 to create a unique topic prefix
2. Messages are published to specific subtopics:
   - `{prefix}/offer/` - For ICE offers from clients
   - `{prefix}/answer/` - For ICE answers from servers

## Best Practices

1. Use a reliable MQTT broker for signaling
2. Use TLS for MQTT connections where possible

## Limitations

- UDP or TCP hole punching may not work with symmetric NATs
- The punched "hole" is temporary and may close if not used regularly
- Both peers must coordinate to create a 'hole' for bidirectional communication
- MQTT broker must be accessible to both peers
- STUN server must be accessible to both peers
- Encryption keys must be shared between client and server

## Dependencies

- github.com/eclipse/paho.mqtt.golang - MQTT client library

## Future Enhancements

Planned future implementations:

- Full ICE protocol implementation with connectivity checks

## Example Implementation

Here's a complete example of implementing the ICE signaling flow with client and server using the `Listen` and `Connect` methods:

### Setting Up the Server with Listen

```go
package main

import (
	"context"
	"net"
	"time"

	"github.com/riraccuia/pig/pkg/log"
	"github.com/riraccuia/pig/pkg/ice/signaling"
	"github.com/riraccuia/pig/pkg/ice"
)

func runServer(listenPort int, protocol string, encryptionKey []byte) error {
	logger := log.NewLogger()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	opts := &signaling.Options{
		BrokerURL:  "ssl://broker.hivemq.com:8883",
		ClientID:   "pig-server-" + time.Now().Format("20060102150405"),
		EncryptionKey: encryptionKey,
		Logger:     logger,
		STUNServer: "stun.l.google.com:19302",
		Protocol:   protocol, // "udp" or "tcp"
	}

	var listenAddr net.Addr
	switch protocol {
	case "tcp":
		listenAddr = &net.TCPAddr{IP: net.IPv4zero, Port: listenPort}
	case "udp":
		listenAddr = &net.UDPAddr{IP: net.IPv4zero, Port: listenPort}
	default:
		return fmt.Errorf("invalid protocol: %s", protocol)
	}

	listener, err := ice.Listen(ctx, opts, listenAddr)
	if err != nil {
		return err
	}
	// For TCP: accept connections using listener.(*conn.TCPListener).Accept()
	// For UDP: receive packets using listener.(*net.UDPConn).ReadFromUDP()
	return nil
}
```

### Setting Up the Client with Connect

```go
package main

import (
	"context"
	"crypto/rand"
	"net"
	"time"

	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/log"
	"github.com/riraccuia/pig/pkg/ice/signaling"
	"github.com/riraccuia/pig/pkg/ice"
)

func runClient(targetAddr string, targetPort int, protocol string, encryptionKey []byte) error {
	logger := log.NewLogger()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	opts := &signaling.Options{
		BrokerURL:  "ssl://broker.hivemq.com:8883",
		ClientID:   "pig-client-" + time.Now().Format("20060102150405"),
		EncryptionKey: encryptionKey,
		Logger:     logger,
		STUNServer: "stun.l.google.com:19302",
		Protocol:   protocol, // "udp" or "tcp"
	}

	srcPort := 0 // Use 0 for random local port
	conn, remoteAddr, err := ice.Connect(ctx, opts, srcPort, targetPort, targetAddr, protocol)
	if err != nil {
		return err
	}
	defer conn.Close()
	logger.Infof("Connected to %s", remoteAddr.String())
	// For UDP: send to remoteAddr using conn.(*net.UDPConn).WriteToUDP()
	// For TCP: use conn as a net.Conn
	return nil
}
```