```
Supported transport protocols:

These protocols serve as the transport layer for tunnels.
Use the below strings in the cli ('-P' option) or in config files ('proto' field).

Example:
	pig -c -P ws [...]

+------------- +---------------------------------------------- +
| Name         | Description                                   |
+------------- +---------------------------------------------- +
| quic         | QUIC (Quick UDP Internet Connections)         |
| tls          | TLS (Transport Layer Security)                |
| ws           | WebSocket                                     |
| tls-in-icmp  | TLS over ICMP (ICMP tunneling), Experimental  |
| dtls         | DTLS (Datagram Transport Layer Security)      |
+------------- +---------------------------------------------- +
```
