# ICE Package

## Table of Contents
- [Introduction](#introduction)
- [Features](#features)
- [Implementation Notes](#implementation-notes)
- [Components](#components)
  - [Core Functions](#core-functions)
  - [ConnectPath Structure](#connectpath-structure)
  - [Protocol Definitions](#protocol-definitions)
- [Configuration](#configuration)
  - [Signaling Options](#signaling-options)
  - [ICE Message Format](#ice-message-format)
- [How It Works](#how-it-works)
  - [Candidate Gathering](#candidate-gathering)
  - [STUN Binding](#stun-binding)
  - [Connection Establishment](#connection-establishment)
- [Security](#security)
  - [Message Encryption](#message-encryption)
  - [ICE Credentials](#ice-credentials)
  - [Topics](#topics)
- [Best Practices](#best-practices)
- [Limitations](#limitations)
- [Dependencies](#dependencies)
- [References](#references)

## Introduction

This package implements a simplified ICE (Interactive Connectivity Establishment) protocol for NAT traversal and peer-to-peer connection establishment. It supports multiple transport protocols (WebSocket, QUIC, DTLS) over UDP and TCP, using MQTT for signaling and STUN for public endpoint discovery.

The implementation is based on the ICE protocol specification defined in [RFC 8445](https://tools.ietf.org/html/rfc8445) and uses STUN for NAT traversal as specified in [RFC 5389](https://tools.ietf.org/html/rfc5389).

## Features

The package provides the following key capabilities:

- **Multi-Protocol Support**: WebSocket (TCP), QUIC (UDP), and DTLS (UDP) transport protocols
- **STUN Integration**: Uses STUN servers to discover public IP addresses and ports for NAT traversal
- **MQTT Signaling**: Secure signaling between peers using MQTT broker
- **ICE Binding**: Full ICE binding protocol implementation with STUN binding requests/responses
- **Candidate Gathering**: Automatic gathering of host and server reflexive candidates
- **Connection Multiplexing**: Supports multiple connection paths with automatic selection

## Implementation Notes

This package implements a **simplified version** of the ICE protocol with the following characteristics:

1. **ICE Binding Protocol**: Implements full STUN binding requests/responses for connectivity verification as specified in [RFC 8445 Section 7](https://tools.ietf.org/html/rfc8445#section-7)
2. **Multi-Protocol Support**: Supports WebSocket (TCP), QUIC (UDP), and DTLS (UDP) as transport protocols
3. **Automatic Candidate Selection**: Uses ICE nomination process to select the best connection path
4. **Component-Based Architecture**: Each protocol has a unique component ID for proper candidate matching
5. **Bidirectional Signaling**: Full offer/answer exchange with proper ICE credentials

## Components

### Core Functions

#### GetConnectPaths

Gathers ICE candidates and establishes connection paths for client-side connections:

```go
func GetConnectPaths(ctx context.Context, opts *signaling.Options, addr string, pigProtos []transport.ICEProtocolDefinition) (cp []*ConnectPath, err error)
```

- **Parameters:**
  - `ctx`: Context for cancellation and timeout
  - `opts`: Signaling options (see Configuration section)
  - `addr`: Target server address
  - `pigProtos`: Array of protocol definitions to attempt
- **Returns:**
  - `cp`: Array of ConnectPath structures ready for connection attempts
  - `err`: Error if candidate gathering fails

#### GetListenPaths

Sets up server-side ICE listening for incoming connection offers:

```go
func GetListenPaths(ctx context.Context, opts *signaling.Options, listenPort uint16, pigProtos []transport.ICEProtocolDefinition) (chan []*ConnectPath, error)
```

- **Parameters:**
  - `ctx`: Context for cancellation and timeout
  - `opts`: Signaling options
  - `listenPort`: Port to listen on for incoming connections
  - `pigProtos`: Array of protocol definitions to support
- **Returns:**
  - `chan []*ConnectPath`: Channel that receives ConnectPath arrays for each incoming offer
  - `err`: Error if setup fails

### ConnectPath Structure

The `ConnectPath` structure represents a potential connection path:

```go
type ConnectPath struct {
    ICEID      string                           // ICE session identifier
    LocalNet   *net.IPNet                       // Local network interface
    LocalAddr  net.Addr                         // Local address
    RemoteAddr net.Addr                         // Remote address
    Protocol   transport.ICEProtocolDefinition  // Protocol definition
    BindAgent  *stun.IceBindingAgent           // STUN binding agent
    Conn       net.Conn                         // Established connection
}
```

Key methods:
- `Connect()`: Establishes the connection using the specified protocol
- `ICESetup()`: Performs ICE binding setup with STUN requests
- `CloseConn()`: Closes the connection

### Protocol Definitions

The package supports three main transport protocols:

```go
var (
    ICEProtocolWS = ICEProtocolDefinition{
        Network:     "tcp",
        Protocol:    "ws",
        ComponentID: 3,
    }
    ICEProtocolQUIC = ICEProtocolDefinition{
        Network:     "udp", 
        Protocol:    "quic",
        ComponentID: 4,
    }
    ICEProtocolDTLS = ICEProtocolDefinition{
        Network:     "udp",
        Protocol:    "dtls", 
        ComponentID: 5,
    }
)
```

## Configuration

### Signaling Options

The `Options` struct provides configuration for ICE signaling:

```go
type Options struct {
    BrokerURL     string        // MQTT broker address
    ClientID      string        // Unique client identifier
    Username      string        // MQTT username
    Password      string        // MQTT password
    EncryptionKey []byte        // Encryption key for signaling
    Logger        common.Logger // Logger for debugging
    STUNServer    string        // STUN server address
    Protocol      string        // Protocol for STUN queries
}
```

### ICE Message Format

ICE protocol messages follow the standard format defined in [RFC 8445 Section 5](https://tools.ietf.org/html/rfc8445#section-5):

```go
type ICEMessage struct {
    SessionID   string           `json:"session_id"`
    Type        ICEMessageType   `json:"type"`
    Timestamp   int64            `json:"timestamp"`
    Candidates  []ICECandidate   `json:"candidates"`
    Credentials ICECredentials   `json:"credentials"`
}

type ICECandidate struct {
    Foundation  string           `json:"foundation"`
    ComponentID int              `json:"componentId"`
    Priority    uint32           `json:"priority"`
    Protocol    string           `json:"protocol"`
    Address     string           `json:"address"`
    Port        int              `json:"port"`
    Type        ICECandidateType `json:"type"`
    RelatedAddr string           `json:"relatedAddr,omitempty"`
    RelatedPort int              `json:"relatedPort,omitempty"`
}
```

## How It Works

The ICE protocol operates in three main phases: candidate gathering, STUN binding, and connection establishment.

### Candidate Gathering

1. **Local Candidates**: For each protocol, gather local network interface addresses
2. **STUN Queries**: Perform STUN queries to discover public endpoints for each protocol
3. **Candidate Creation**: Create ICE candidates with proper priorities and component IDs
4. **Offer Generation**: Generate ICE offer with all gathered candidates

### STUN Binding

1. **Binding Requests**: Send STUN binding requests to verify connectivity
2. **Response Processing**: Handle STUN binding responses to confirm peer reachability
3. **ICE Attributes**: Exchange ICE-specific attributes (priority, controlling/controlled)
4. **Nomination**: Use ICE nomination process to select the best connection path

### Connection Establishment

1. **Multiple Paths**: Attempt connections on all valid candidate pairs
2. **Protocol Matching**: Match candidates by network type and component ID
3. **Path Selection**: Select the first successful connection or nominated path
4. **Transport Setup**: Establish the appropriate transport protocol (WS, QUIC, DTLS)

## Security

### Message Encryption

All signaling messages are encrypted using AES-256-GCM when an encryption key is provided:

1. **Key Generation**: 32-byte encryption key shared between peers
2. **Message Encryption**: JSON messages encrypted with AES-256-GCM
3. **Base64 Encoding**: Encrypted messages base64-encoded for MQTT transmission

### ICE Credentials

ICE authentication uses randomly generated short-term credentials as specified in [RFC 8445 Section 7.2.2](https://tools.ietf.org/html/rfc8445#section-7.2.2):
- Username and password generated for each session
- Credentials included in all ICE messages
- STUN binding requests use ICE credentials for authentication

### Topics

MQTT topics follow a structured pattern:
- Base topic derived from target address hash
- Session-specific subtopics: `{base}/{sessionId}/offer` and `{base}/{sessionId}/answer`
- Wildcard subscriptions for offer reception

## Best Practices

1. **Reliable MQTT Broker**: Use a reliable, low-latency MQTT broker for signaling
2. **STUN Server Selection**: Choose geographically close STUN servers for better performance
3. **Protocol Selection**: Configure multiple protocols for better connectivity success
4. **Timeout Handling**: Implement proper timeouts for connection attempts
5. **Error Recovery**: Handle MQTT connection failures with retry logic

## Limitations

- **Symmetric NATs**: May not work with symmetric NATs that don't preserve port mappings
- **Firewall Restrictions**: Corporate firewalls may block STUN or MQTT traffic
- **Protocol Dependencies**: Requires MQTT broker and STUN server accessibility
- **Connection Lifetime**: ICE connections may timeout if not actively used
- **Encryption Key Management**: Encryption keys must be securely shared between peers

## References

This implementation is based on the following RFC specifications:

- **[RFC 8445](https://tools.ietf.org/html/rfc8445)**: Interactive Connectivity Establishment (ICE): A Protocol for Network Address Translator (NAT) Traversal for Offer/Answer Protocols
- **[RFC 5389](https://tools.ietf.org/html/rfc5389)**: Session Traversal Utilities for NAT (STUN)
- **[RFC 5245](https://tools.ietf.org/html/rfc5245)**: Interactive Connectivity Establishment (ICE): A Protocol for Network Address Translator (NAT) Traversal for Offer/Answer Protocols (obsoleted by RFC 8445)