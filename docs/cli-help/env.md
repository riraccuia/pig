```
BOOTSTRAP ENVIRONMENT VARIABLES

The following variables are used for bootstrapping.
Configure these in your shell or in a .env file to be sourced.

+-------------------- +--------------------------------------------------- +
| Name                | Description                                        |
+-------------------- +--------------------------------------------------- +
| PIG_TOKEN           | JWT token string to use for client authentication  |
| PIG_STUN            | STUN server for NAT traversal                      |
| PIG_MQTT_BROKER     | MQTT broker for NAT traversal ICE signaling        |
| PIG_MQTT_CLIENT_ID  | MQTT client identifier for the signaling broker    |
| PIG_MQTT_USERNAME   | MQTT username for the signaling broker             |
| PIG_MQTT_PASSWORD   | MQTT password for the signaling broker             |
+-------------------- +--------------------------------------------------- +

SCRIPTING ENVIRONMENT VARIABLES

The following variables are read-only and available from called script files.

+------------------- +---------------------------------------- +
| Name               | Description                             |
+------------------- +---------------------------------------- +
| PIG_EVENT_NAME     | Name of the event                       |
| PIG_TUN_NAME       | Name of the tunnel                      |
| PIG_ADAPTER_NAME   | Name of the adapter                     |
| PIG_ADAPTER_INDEX  | Index of the adapter                    |
| PIG_REMOTE_ADDR    | Remote address                          |
| PIG_NAT_ADDR       | NAT address                             |
| PIG_TUNNEL_PROTO   | Transport protocol used for the tunnel  |
+------------------- +---------------------------------------- +
```
