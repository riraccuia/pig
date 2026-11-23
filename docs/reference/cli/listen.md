```
Usage: pig -l [options] [-to-cfg <json|toml>]

OUTPUT

 -to-cfg <format> (string)
   Takes either 'json' or 'toml'. Turns the current CLI options into a config file and exits.

OPTIONS

Adapters:
 -nc 
   Stdio adapter. Enables netcat mode: stdin is redirected to the stdout of the connected peer (and
   vice versa) over the encrypted tunnel.

General options:
 -s 
   Simple mode. Disables NAT traversal to establish direct connections, in which case ports need to be
   opened manually on edge routers and/or firewalls.
 -id <id> (string)
   ID or friendly name for a listening node. This identifier is registered for signaling during NAT
   traversal. When the connecting side uses it, it doesn't need to know the other node's address.
 -a <[host]:port> (string)
   Listen or connect address for simple mode. Use -id in NAT traversal mode.
 -I <adapter> (string)
   The adapter/interface to bind to, required only when '-P' is *-ICMP.
 -P <protocol> (string)
   Transport protocol for the tunnel. See 'pig -docs protos' for the list of supported ones. The
   special '.' option selects all available protocols for candidate generation with NAT traversal.
 -ta <addr1,addr2,...> (string)
   Tunnel address. Multiple addresses (IPv4 and/or IPv6) can be specified as a comma separated CIDR
   values. Defaults to random generated /30 within 100.64.0.0/11 for connect nodes and /16 within
   100.96.0.0/11 for listening nodes.
 -i <seconds> (int)
   Idle timeout in seconds for tunnels. Defaults to 0.
 -o 
   Accept one client, then exit after it disconnects.

Logging options:
 -v <level> (int)
   Print more verbose output. Use 1 (default) for info, 2 for debug, 3 for trace. 0 disables logging.

Certificate options:
 -cert <path> (string)
   Path to a certificate file for mTLS.
 -key <path> (string)
   Path to a private key file for mTLS.

Trust options:
 -k 
   Insecure. Disable certificate verification.
 -ca <path> (string)
   Path to a CA certificate or bundle file for mTLS.

Auth options:
 -A <type> (string)
   Authentication type. Set to 'jwt' to enable JWT authentication. More types will be supported in
   future versions.
 -jwk <path> (string)
   Path to a public key file used to verify JWT tokens. This can be a local file or a URL. PEM and
   JWKS (json) formats are supported.

NAT traversal options:
 -stun <host:port> (string)
   STUN server to query during NAT traversal.
 -mqtt <proto://host:port> (string)
   MQTT broker to use for NAT traversal signaling. See 'pig -docs env' for additional configuration
   options.
 -sk <key> (string)
   Encryption key for signaling messages. Connecting peers need to use the same key as the listeners.

Nerd options:
 -mtu <mtu> (int)
   MTU (Maximum Transmission Unit) size of the tunnel adapter. Defaults to 1420.
 -qs <size> (int)
   Size of the packet queues used by tunnels. Defaults to 256.

WRED options:
 -wf <value> (float)
   Weight factor for WRED, lower values mean more weight to recent packets. Defaults to 9.
 -wd <value> (float)
   Drop probability for WRED. Accepts decimals between 0 and 1. Defaults to 0.1.
 -wt <value> (float)
   Threshold for WRED as a fraction of the queue length. Accepts decimals between 0 and 1. Defaults to
   0.5.
```
