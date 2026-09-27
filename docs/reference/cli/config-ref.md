```
Config
+-------------+-------------------+----------+------------------------+--------------------------------------+
| Field       | Type              | Optional | Default                | Description                          |
+-------------+-------------------+----------+------------------------+--------------------------------------+
| log         | LogConfig?        | true     | -                      | Logging configuration block.         |
| adapter     | AdapterConfig?    | true     | -                      | Adapter configuration block.         |
| route       | RouteConfig?      | true     | -                      | Route configuration block.           |
| tunnels     | []TunnelConfig    | false    | -                      | Tunnel configuration block.          |
| stun_global | string?           | true     | stun.nextcloud.com:443 | Default STUN server address for NAT  |
|             |                   |          |                        | traversal in the form of host:port.  |
| mqtt_global | MQTTBrokerConfig? | true     | -                      | Default MQTT broker configuration    |
|             |                   |          |                        | for NAT traversal.                   |
| script_path | string?           | true     | -                      | Path to an executable file to call   |
|             |                   |          |                        | on various tunnel events.            |
+-------------+-------------------+----------+------------------------+--------------------------------------+

LogConfig
+-------------+---------+----------+---------+---------------------------------------------------------------+
| Field       | Type    | Optional | Default | Description                                                   |
+-------------+---------+----------+---------+---------------------------------------------------------------+
| file        | string? | true     | -       | Path to the log file to write to. Otherwise logs to stdout.   |
| level       | string? | true     | info    | Log level. Use one of "trace", "debug", "info", "warn",       |
|             |         |          |         | "error".                                                      |
| rotate_size | any?    | true     | -       | Size of the log file to rotate at. e.g. 100k, 1m, 1g, or      |
|             |         |          |         | actual size in bytes.                                         |
+-------------+---------+----------+---------+---------------------------------------------------------------+

AdapterConfig
+----------------+----------+----------+---------+-----------------------------------------------------------+
| Field          | Type     | Optional | Default | Description                                               |
+----------------+----------+----------+---------+-----------------------------------------------------------+
| tunnel_address | []string | false    | -       | CIDR format.                                              |
| mtu            | int      | false    | 1400    | Maximum Transmission Unit.                                |
| bind_adapter   | string?  | true     | -       | Adapter name to bind to, e.g. "eth0". Only required when  |
|                |          |          |         | 'proto' is tls-in-icmp.                                   |
| queue_size     | int?     | true     | 256     | Size of the network queues for the tunnel.                |
+----------------+----------+----------+---------+-----------------------------------------------------------+

RouteConfig
+---------+----------+----------+---------+----------------------------------------------------------+
| Field   | Type     | Optional | Default | Description                                              |
+---------+----------+----------+---------+----------------------------------------------------------+
| enabled | bool?    | true     | false   | Enable route configuration.                              |
| routes  | []Route? | true     | -       | Routes are the routes that will be used for the routing. |
+---------+----------+----------+---------+----------------------------------------------------------+

TunnelConfig
+--------------------+----------------+----------+---------+-------------------------------------------------+
| Field              | Type           | Optional | Default | Description                                     |
+--------------------+----------------+----------+---------+-------------------------------------------------+
| name               | string         | false    | -       | Friendly name for the tunnel.                   |
| direction          | string         | false    | -       | Tunnel direction, either "connect" or "listen". |
| adapter            | AdapterConfig? | true     | -       | Adapter configuration specific for this tunnel. |
|                    |                |          |         | Mandatory when the direction is "listen".       |
| connect            | ConnectTarget? | true     | -       | Connect target configuration. Use with NAT      |
|                    |                |          |         | traversal disabled.                             |
| listen             | ListenTarget?  | true     | -       | Listen address to bind to. Use with NAT         |
|                    |                |          |         | traversal disabled.                             |
| tls                | TLSConfig?     | true     | -       | TLS configuration.                              |
| stream_count       | int?           | true     | 0       | Number of streams to open. Valid only with      |
|                    |                |          |         | streamed protocols like QUIC. Zero means the    |
|                    |                |          |         | number of CPU cores.                            |
| proto              | string?        | true     | ws      | Transport protocol to use for the tunnel.       |
| reconnect_interval | int?           | true     | 5       | Reconnect interval in seconds.                  |
| wred               | WredConfig?    | true     | -       | WRED settings.                                  |
| auth               | AuthConfig?    | true     | -       | Authentication configuration.                   |
| ice                | ICEConfig?     | true     | -       | NAT traversal and path discovery configuration. |
|                    |                |          |         | To enable NAT traversal, set                    |
|                    |                |          |         | ICEConfig.Enabled=true.                         |
| routes             | []Route?       | true     | -       | Routes to enforce once the tunnel is            |
|                    |                |          |         | established.                                    |
+--------------------+----------------+----------+---------+-------------------------------------------------+

MQTTBrokerConfig
+-----------+---------+----------+------------------------------+--------------------------------------------+
| Field     | Type    | Optional | Default                      | Description                                |
+-----------+---------+----------+------------------------------+--------------------------------------------+
| address   | string  | false    | ssl://broker.hivemq.com:8883 | MQTT broker address in the form of         |
|           |         |          |                              | mqtt://host:port or ssl://host:port.       |
| client_id | string? | true     | -                            | MQTT client ID.                            |
| username  | string? | true     | -                            | MQTT username.                             |
| password  | string? | true     | -                            | MQTT password.                             |
+-----------+---------+----------+------------------------------+--------------------------------------------+

Route
+-------------+---------+----------+---------+---------------------------------------------------------------+
| Field       | Type    | Optional | Default | Description                                                   |
+-------------+---------+----------+---------+---------------------------------------------------------------+
| destination | string  | false    | -       | Destination CIDR to route. E.g. "192.168.1.0/24".             |
| type        | string  | false    | -       | Type of route. One of "tunnel", "bypass", "static".           |
| gateway     | string? | true     | -       | For "static" routes, the gateway IP address to use for the    |
|             |         |          |         | route.                                                        |
| interface   | string? | true     | -       | For "static" routes, the interface name to use for the route. |
+-------------+---------+----------+---------+---------------------------------------------------------------+

ConnectTarget
+----------+--------+----------+---------+-------------------------------------------------------------------+
| Field    | Type   | Optional | Default | Description                                                       |
+----------+--------+----------+---------+-------------------------------------------------------------------+
| address  | string | false    | -       | Remote address to connect to. Fqdn or IP address.                 |
| port     | int    | false    | -       | Target port to connect to.                                        |
| src_port | int    | false    | -       | Source port to use for the connection. Leave empty for random     |
|          |        |          |         | selection.                                                        |
+----------+--------+----------+---------+-------------------------------------------------------------------+

ListenTarget
+---------+--------+----------+---------+-----------------------------+
| Field   | Type   | Optional | Default | Description                 |
+---------+--------+----------+---------+-----------------------------+
| address | string | false    | -       | Local address to listen on. |
| port    | int    | false    | -       | Local port to listen on.    |
+---------+--------+----------+---------+-----------------------------+

TLSConfig
+-----------+---------+----------+---------+----------------------------------------------------------------+
| Field     | Type    | Optional | Default | Description                                                    |
+-----------+---------+----------+---------+----------------------------------------------------------------+
| insecure  | bool?   | true     | -       | Insecure is the flag to skip TLS certificate verification.     |
| cert_file | string? | true     | -       | CertFile is the local certificate presented by listen tunnels. |
| key_file  | string? | true     | -       | KeyFile is the private key for CertFile.                       |
+-----------+---------+----------+---------+----------------------------------------------------------------+

WredConfig
+------------------+--------+----------+---------+-----------------------------------------------------------+
| Field            | Type   | Optional | Default | Description                                               |
+------------------+--------+----------+---------+-----------------------------------------------------------+
| weight_factor    | float? | true     | 9       | Weight factor. Lower values give more weight to recent    |
|                  |        |          |         | packets.                                                  |
| drop_probability | float? | true     | 0.1     | Probability for packets to be dropped on busy queues.     |
|                  |        |          |         | Accepts decimals between 0 and 1.                         |
| threshold        | float? | true     | 0.5     | Threshold for WRED as a fraction of the queue length.     |
|                  |        |          |         | Accepts decimals between 0 and 1.                         |
+------------------+--------+----------+---------+-----------------------------------------------------------+

AuthConfig
+-------+-------------+----------+---------+----------------------------------------+
| Field | Type        | Optional | Default | Description                            |
+-------+-------------+----------+---------+----------------------------------------+
| type  | string?     | true     | none    | One of "none", "jwt", "oidc", "oauth". |
| jwt   | JWTAuth?    | true     | -       | JWT authentication configuration.      |
| oidc  | OIDCAuth?   | true     | -       | OIDC authentication configuration.     |
| oauth | OAuthAuth?  | true     | -       | OAuth authentication configuration.    |
| mtls  | MTLSConfig? | true     | -       | MTLS authentication configuration.     |
+-------+-------------+----------+---------+----------------------------------------+

ICEConfig
+--------------+-------------------+----------+---------+----------------------------------------------------+
| Field        | Type              | Optional | Default | Description                                        |
+--------------+-------------------+----------+---------+----------------------------------------------------+
| enabled      | bool?             | true     | false   | Enable ICE based network path discovery.           |
| protos       | []string?         | true     | -       | Protocols to use for candidate generation. Not     |
|              |                   |          |         | needed when TunnelConfig.Proto is already set.     |
| stun_address | string?           | true     | -       | Optional custom STUN server to use instead of the  |
|              |                   |          |         | global config.STUNAddress.                         |
| signaling    | ICESignalingOpts? | true     | -       | Signaling configuration.                           |
+--------------+-------------------+----------+---------+----------------------------------------------------+

JWTAuth
+-------------------+--------+----------+---------+----------------------------------------------------------+
| Field             | Type   | Optional | Default | Description                                              |
+-------------------+--------+----------+---------+----------------------------------------------------------+
| public_key_source | string | false    | -       | PublicKeySource is the path to the public key file used  |
|                   |        |          |         | to verify peer JWT tokens.                               |
| token             | string | false    | -       | Token is the JWT token presented to the peer during      |
|                   |        |          |         | authentication.                                          |
+-------------------+--------+----------+---------+----------------------------------------------------------+

OIDCAuth
+--------------------------+-----------------+----------+---------+------------------------------------------+
| Field                    | Type            | Optional | Default | Description                              |
+--------------------------+-----------------+----------+---------+------------------------------------------+
| issuer_url               | string          | false    | -       | Issuer URL of the authorization server.  |
| client_id                | string          | false    | -       | Client ID of the application.            |
| client_secret            | string?         | true     | -       | Client secret of the application.        |
| scopes                   | []string?       | true     | -       | Scopes for the authorization request     |
|                          |                 |          |         | (optional). Empty: oauth sends no scope; |
|                          |                 |          |         | oidc defaults to openid profile email.   |
| redirect_url             | string?         | true     | -       | RedirectURL is the full OAuth redirect   |
|                          |                 |          |         | URI registered at the IdP (optional;     |
|                          |                 |          |         | loopback ephemeral port if empty).       |
| redirect_path            | string?         | true     | -       | RedirectPath is used only when           |
|                          |                 |          |         | RedirectURL is empty (default in oauth   |
|                          |                 |          |         | is /oauth2/callback).                    |
| skip_open_browser        | bool?           | true     | false   | Skip opening the browser for the         |
|                          |                 |          |         | authorization code flow.                 |
| callback_timeout_seconds | int?            | true     | 60      | CallbackTimeoutSeconds bounds browser    |
|                          |                 |          |         | redirect wait (zero = oauth default).    |
| disable_pkce             | bool?           | true     | false   | Disable Proof Key for Code Exchange      |
|                          |                 |          |         | (PKCE).                                  |
| expected_audience        | string?         | true     | -       | ExpectedAudience overrides ClientID when |
|                          |                 |          |         | validating JWT aud on the server         |
|                          |                 |          |         | (optional).                              |
| clock_skew_seconds       | int?            | true     | 30      | ClockSkewSeconds is leeway for JWT       |
|                          |                 |          |         | exp/iat/nbf (zero = package default).    |
| claim_matchers           | map[string]any? | true     | -       | ClaimMatchers see                        |
|                          |                 |          |         | pkg/auth/oauth.Config.ClaimMatchers.     |
+--------------------------+-----------------+----------+---------+------------------------------------------+

OAuthAuth
+--------------------------+-----------------+----------+---------+------------------------------------------+
| Field                    | Type            | Optional | Default | Description                              |
+--------------------------+-----------------+----------+---------+------------------------------------------+
| issuer_url               | string          | false    | -       | Issuer URL of the authorization server.  |
| client_id                | string          | false    | -       | Client ID of the application.            |
| client_secret            | string?         | true     | -       | Client secret of the application.        |
| scopes                   | []string?       | true     | -       | Scopes for the authorization request     |
|                          |                 |          |         | (optional). Empty: oauth sends no scope; |
|                          |                 |          |         | oidc defaults to openid profile email.   |
| redirect_url             | string?         | true     | -       | RedirectURL is the full OAuth redirect   |
|                          |                 |          |         | URI registered at the IdP (optional;     |
|                          |                 |          |         | loopback ephemeral port if empty).       |
| redirect_path            | string?         | true     | -       | RedirectPath is used only when           |
|                          |                 |          |         | RedirectURL is empty (default in oauth   |
|                          |                 |          |         | is /oauth2/callback).                    |
| skip_open_browser        | bool?           | true     | false   | Skip opening the browser for the         |
|                          |                 |          |         | authorization code flow.                 |
| callback_timeout_seconds | int?            | true     | 60      | CallbackTimeoutSeconds bounds browser    |
|                          |                 |          |         | redirect wait (zero = oauth default).    |
| disable_pkce             | bool?           | true     | false   | Disable Proof Key for Code Exchange      |
|                          |                 |          |         | (PKCE).                                  |
| expected_audience        | string?         | true     | -       | ExpectedAudience overrides ClientID when |
|                          |                 |          |         | validating JWT aud on the server         |
|                          |                 |          |         | (optional).                              |
| clock_skew_seconds       | int?            | true     | 30      | ClockSkewSeconds is leeway for JWT       |
|                          |                 |          |         | exp/iat/nbf (zero = package default).    |
| claim_matchers           | map[string]any? | true     | -       | ClaimMatchers see                        |
|                          |                 |          |         | pkg/auth/oauth.Config.ClaimMatchers.     |
+--------------------------+-----------------+----------+---------+------------------------------------------+

MTLSConfig
+-----------+---------+----------+---------+-----------------------------------------------------------------+
| Field     | Type    | Optional | Default | Description                                                     |
+-----------+---------+----------+---------+-----------------------------------------------------------------+
| trust_pem | string? | true     | -       | TrustPEM is the path to the trust bundle for MTLS, if not       |
|           |         |          |         | provided, the system CA will be used. In client mode, this is   |
|           |         |          |         | used to validate the server certificate. In server mode, this   |
|           |         |          |         | is used to validate client certificates.                        |
| cert_file | string? | true     | -       | CertFile is the client certificate presented by connect         |
|           |         |          |         | tunnels.                                                        |
| key_file  | string? | true     | -       | KeyFile is the private key for CertFile.                        |
+-----------+---------+----------+---------+-----------------------------------------------------------------+

ICESignalingOpts
+----------------+-------------------+----------+---------+--------------------------------------------------+
| Field          | Type              | Optional | Default | Description                                      |
+----------------+-------------------+----------+---------+--------------------------------------------------+
| server_id      | string            | false    | -       | Use a connection ID to identify the connection,  |
|                |                   |          |         | instead of the mapped IP.                        |
| encryption_key | string?           | true     | -       | Encryption key for the signaling messages.       |
| connect_offset | int?              | true     | 500ms   | Connect offset in milliseconds.                  |
| mqtt           | MQTTBrokerConfig? | true     | -       | Optional MQTT broker configuration to use        |
|                |                   |          |         | instead of the default one.                      |
+----------------+-------------------+----------+---------+--------------------------------------------------+

```
