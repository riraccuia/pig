# TLS-in-ICMP

TLS-in-ICMP is an experimental pig transport (`-P tls-in-icmp` / `proto = "tls-in-icmp"`).\

This is pig’s own take on ICMP-based tunneling.

`tls-in-icmp` is regular TLS layered over the proprietary `icmp` transport implementation, which is not exposed to pig on its own as of today.

Packets use ICMP Echo: the connect side sends Echo Request, the listen side answers with Echo Reply.\
Inside each echo payload sits an 8-byte encapsulation header, a 32-bit sequence number and a 32-bit acknowledgment, followed by the user data.\
Such header is enough to run a connection-oriented, reliable byte stream over ICMP: cumulative ACKs, RTO-driven retransmission, and reassembly of out-of-order segments.\
The same layer applies flow control and TCP NewReno congestion control (cwnd / ssthresh, congestion avoidance, fast retransmit / fast recovery).

Where it sits in the ICMP Echo packet (IPv4 header omitted). Encapsulation fields are big-endian:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |     Code      |           Checksum            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Identifier          |        Sequence Number        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Sequence (pig)                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Acknowledgment (pig)                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               :
:                         TLS record data                       :
:                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Type / Code / Checksum / Identifier / Sequence Number are the standard ICMP Echo header (8 bytes). The next 8 bytes are pig’s encapsulation header and everything after that is the reliable-stream payload (TLS records).

Also see:
- [Protocols](../reference/cli/protos.md) (`pig -docs protos`)
- [Listen](../reference/cli/listen.md) / [Connect](../reference/cli/connect.md)
- [Config reference](../reference/config/config.md)
- [NAT traversal](../nat/nat.md)
- [Quick start — simple mode](../getting-started/quick-start.md#simple-mode)

## Simple mode (recommended today)

Use **simple mode** (`-s`): fixed peer address, no NAT traversal.

Requirements:

- **Bind adapter**: CLI `-I`, config `bind_adapter` (required for `*-ICMP`)
- **Elevated privileges**: raw ICMP needs them: `sudo` on Unix, **Administrator** on Windows
- **IPv4**: the connect target must be reachable by an IPv4 address

ICMP has no L4 port in the usual sense. For this transport:

- **Connect:** pass the peer host or IPv4 with `-a`. A port is optional and unused (you may omit it).
- **Listen:** bind with `-I` / `bind_adapter`. There is no listen port to open for ICMP itself. `-a` is not needed for the transport path.

> [!WARNING]
> TLS-in-ICMP works correctly in **simple mode** today. It may not work reliably (or at all) with NAT traversal / ICE right now. Prefer other transports when you need hole punching, and see [NAT traversal](../nat/nat.md).

### Alice (listen)

macOS/Linux:

```bash
sudo pig -l -s -P tls-in-icmp -I eth0 -k -nc
```

Windows (elevated cmd/powershell terminal):

```powershell
pig.exe -l -s -P tls-in-icmp -I WiFi -k -nc
```

Replace `eth0` / `WiFi` with the appropriate network adapter.

### Bob (connect)

macOS/Linux:

```bash
sudo pig -c -s -a alice.example.com -P tls-in-icmp -I eth0 -k -nc
```

Windows (Administrator PowerShell):

```powershell
pig.exe -c -s -a alice.example.com -P tls-in-icmp -I WiFi -k -nc
```

`-a` is Alice’s host or IPv4. `-nc` turns each side into a bidirectional stdin/stdout pipe over the encrypted tunnel: type on one side, see it on the other.

Flags used here:

| Flag | Meaning |
| ---- | ------- |
| `-l` / `-c` | Listen or connect |
| `-s` | Simple mode (no NAT traversal) |
| `-P tls-in-icmp` | This transport |
| `-I` | Bind adapter (required for ICMP-based protos) |
| `-a` | Connect target host / IPv4 (unused for listen on this transport) |
| `-nc` | Netcat mode (interactive chat over the tunnel) |
| `-k` | Skip certificate verification |

To tunnel IP traffic instead of chatting, drop `-nc` and add connect-side routes with `-R` the same way as in [quick start](../getting-started/quick-start.md) (for example `-R 192.168.1.100/32`, or `-R full` / `full4` / `full6` for a full tunnel).

## Windows Firewall

On Windows, disable Windows Firewall while using this transport if you want it to work reliably.

A custom allow rule for ICMP Echo Reply (or equivalent) can work instead; that is optional and outside the scope of this page.

## Config

Prefer generating a config from the CLI with `-to-cfg`, then edit the file if you need more options:

```bash
./pig -l -s -P tls-in-icmp -I eth0 -k -nc -to-cfg toml > alice.toml
./pig -c -s -a alice.example.com -P tls-in-icmp -I eth0 -k -nc -to-cfg toml > bob.toml
sudo ./pig -config alice.toml
sudo ./pig -config bob.toml
```

Full field list: [config reference](../reference/config/config.md).
