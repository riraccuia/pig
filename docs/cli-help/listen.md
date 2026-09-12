```
Usage: pig -l [options] [-to-cfg]

OUTPUT

 -to-cfg Takes either 'json' or 'toml'. Outputs the config in the specified format and exits.

OPTIONS

General options:
 -s  Simple mode. Disables NAT traversal to establish direct connections, in which case ports need to be opened manually on edge routers and/or firewalls.
 -id ID or friendly name for a listening node. This identifier is registered for signaling during NAT traversal. When the connecting side uses it, it
     doesn't need to know the other node's address.
 -a  Address host[:port]. Or use -id in NAT traversal mode. In simple mode, this is the connect node's target address and the listen node's bind address.
 -I  The adapter/interface to bind to, required only when '-P' is *-ICMP.
 -P  Transport protocol for the tunnel. See 'pig -list-protos' for the list of supported ones. The special '.' option selects all available protocols for
     candidate generation when NAT traversal is used.
 -ta Tunnel address. Multiple addresses (IPv4 and/or IPv6) can be specified as a comma separated CIDR values. Defaults to 172.31.254.1/29 for connect
     nodes and 172.31.255.1/24 for listening nodes.

Scripting options:

Logging options:
 -v Print more verbose output. Use 0 (default) for info, 1 for debug, 2 for trace.

Certificate options:
 -cert Path to a certificate file for mTLS.
 -key  Path to a private key file for mTLS.

Trust options:
 -k  Insecure. Disable certificate verification.
 -ca Path to a CA certificate or bundle file for mTLS.

Auth options:
 -A   Authentication type. Set to 'jwt' to enable JWT authentication. More types will be supported in future versions.
 -jwk Path to a public key file used to verify JWT tokens. This can be a local file or a URL. PEM and JWKS (json) formats are supported.

NAT traversal options:
 -stun STUN server to query during NAT traversal.
 -mqtt MQTT broker to use for NAT traversal signaling. See 'pig -env' for additional configuration options.
 -sk   Encryption key for signaling messages. Connecting peers need to use the same key as the listeners.

Nerd options:
 -mtu MTU (Maximum Transmission Unit) size of the tunnel adapter.
 -qs  Size of the packet queues used by tunnels.

WRED options:
 -wf Weight factor for WRED, lower values mean more weight to recent packets. Defaults to 5.
 -wd Drop probability for WRED. Accepts decimals between 0 and 1. Defaults to 0.25.
 -wt Threshold for WRED as a fraction of the queue length. Accepts decimals between 0 and 1. Defaults to 0.3.
```
