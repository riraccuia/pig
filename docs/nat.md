# NAT traversal

Pig can discover a connection path between two endpoints automatically through NATs.
Two external services are involved:

- **STUN** for NAT discovery. Each peer queries a STUN server for its public address, and to discover its NAT type.
- **MQTT** for ICE signaling. Peers exchange candidates and related ICE messages through an MQTT broker. They do not need a direct connection to each other for that exchange.

Enable ICE on the tunnel (`ice.enabled`), and set a STUN server and MQTT broker.
Global defaults, per-tunnel overrides, flags, or env, see the [config reference](config.md) and/or run `pig docs env`).

For more information on ICE, start by reading the [Wikipedia article](https://en.wikipedia.org/wiki/Interactive_Connectivity_Establishment).

## STUN

Behind a NAT, your machine has a private address on the LAN. Outbound traffic is rewritten to a public IP and port. A STUN server sits on the public internet and tells you what that rewritten address looks like from the outside.

A **simple binding** is one question: “What public IP and port do you see for me?”. Any STUN server can answer that question.

**NAT discovery** asks more: does the NAT reuse that public mapping for every destination, or does it give you a new one when you talk to a different host or port? Some NATs (often called symmetric, or address-dependent) change the mapping per destination. If you only learned one binding, hole punching toward a peer can fail even though STUN "worked".

To run that discovery, the STUN server must expose **two different public IP addresses** on the same service, and tell the client about the second one (`OTHER-ADDRESS`). Pig then compares what mapping it gets when contacting each side. The server must also be willing to reply from the alternate address when asked (`CHANGE-REQUEST`). Many public STUN hosts only do a simple binding; those are not enough for full discovery.

## MQTT

STUN helps each peer learn about itself. It does not introduce the two peers to each other.

Before they can try a direct path, they must exchange what they learned (candidates and related ICE messages). That exchange is **signaling**. Pig uses an MQTT broker as a small meeting point both sides can reach: each peer connects outbound to the broker, publishes and subscribes, and reads the other side’s messages.

The broker is not the data path for your tunnel. After signaling, pig tries to connect peer-to-peer using the candidates. If the broker is down or unreachable, ICE cannot start even when STUN works.

### Privacy

MQTT signaling messages can be encrypted by pig with a shared key on participating nodes (`ice.signaling.encryption_key`). When set, peers encrypt ICE payloads before publishing and decrypt on receive. The broker still sees that signaling traffic exists but it cannot read the contents without the key.

## Public servers

The internet is full of free public STUN and MQTT servers. They are useful for tests and light use.

### STUN

A maintained list of hosts that respond for NAT testing, thanks [pradt2](https://github.com/pradt2) for your service!

- [https://github.com/pradt2/always-online-stun/blob/master/valid_nat_testing_hosts.txt](https://github.com/pradt2/always-online-stun/blob/master/valid_nat_testing_hosts.txt)

Pig’s default is `stun.nextcloud.com:443` (`stun_global`). 
This server does not expose two different public IP addresses, and it's not suitable for full NAT discovery. It was chosen for its reliability and the convenience around the usage of port TCP 443. 
If you know that you're behind a symmetric NAT, try other servers from the above list.

### MQTT

Popular free / public brokers (check each page for current endpoints and terms):

- [HiveMQ Public Broker](https://www.hivemq.com/mqtt/public-mqtt-broker/)
- [Eclipse Mosquitto test broker](https://test.mosquitto.org/)
- [EMQX Public MQTT Broker](https://www.emqx.com/en/mqtt/public-mqtt5-broker)

Pig’s default is `ssl://broker.hivemq.com:8883` (`mqtt_global`).