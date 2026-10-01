# Symmetric NAT

Classic TCP/UDP hole punching works when each peer can learn a stable public mapping and generate traffic that opens up a path the other side can reuse. That breaks down when the NAT creates a **new** external mapping for every distinct destination.

This page describes that failure mode and how pig responds with a probabilistic port search aided by the [birthday problem](https://en.wikipedia.org/wiki/Birthday_problem). For the overall STUN and MQTT setup, see [NAT traversal](nat.md).

## Mapping behavior

RFC 5780 classifies how a NAT assigns the public IP and port that STUN discovery reports:

| Mapping behavior | Meaning |
| --- | --- |
| Endpoint-independent | The same external mapping is reused for all destinations |
| Address-dependent | The mapping changes when the destination IP changes |
| Address-and-port-dependent | A new mapping is created for every distinct destination IP:port |

"Symmetric NAT" in everyday language usually means address-dependent or address-and-port-dependent mapping. Many enterprise firewalls and carrier-grade NATs behave this way.

With endpoint-independent mapping (e.g. most home setups, many hotels and public Wi-Fis), the address you learned from STUN is useful toward a peer: you publish it, the other side sends to it, and your router often accepts the reply on that same mapping.

With address-dependent or address-and-port-dependent mapping, the public port that the STUN server reported to you is not the public port you will get when talking to your intended destination. Publishing that STUN result is not enough. The other side would be punching toward a mapping that does not exist for that flow.

## Why one unknown port is enough to fail

A TCP or UDP flow is identified by a 4-tuple: local IP, local port, remote IP, remote port. After signaling, both sides usually know each other’s public IPs (or at least the addresses they intend to try). What they may not know is the external port the NAT will allocate, because it's mostly unpredictable.

If at least one endpoint has a predictable mapping (endpoint-independent), one side of the port pair can be considered as known. The remaining unknown is a single port number in a large but finite range (0-65535). Without that number, simultaneous connect attempts will be ineffective.

## Birthday collisions

The birthday problem asks how many random samples you need before two of them collide in a fixed set. Applied here: how many candidate ports must the two sides try, at the same time, before they are likely to hit a matching 4-tuple by chance.

Pig uses the usual approximation for the desired collision probability `m` (e.g. 50%) over a set of size `T`:

```
n ~= sqrt(-2 * ln(1-m)) * sqrt(T)
```

Well-known ports below 1024 are skipped, so `T = 65535 - 1024`.\
For about a 50% chance of at least one collision:

```
n ~= sqrt(-2 * ln(1-0.5)) * sqrt(64511) ~= 1.17 * 254 ~= 297
```

In other words, roughly three hundred random ports in that range give about one in two chances of a duplicate if one side calculated the whole set alone.

Pig splits the work: each side draws about half that many ports (**150**, currently hardcoded) and both attempt those candidates in parallel.\
Early testing shows success rate around **30%** for that split, which is lower than 50% but still useful when the alternative is failure or a TURN server.

From here, experimentation will continue to refine the number of ports to try and the success rate, an maybe using uneven splits to improve the odds. Eventually, we'll make some of these parameters configurable.

## What pig does

During ICE, each peer discovers its own NAT mapping behavior via STUN (see [NAT discovery](nat.md#stun)). NAT types are exchanged during signaling so both sides know the nature of both their own and their peer's mapping.

When building connect paths, pig keeps ordinary host and server-reflexive candidates.
For **public** remote addresses that are not on the local subnet, if either side is at least address-dependent, it expands the path set:

- If **our** mapping is endpoint-independent, pig keeps the local `<ip:port>` as-is and generates many paths with unique, random **remote** ports (toward the target’s public IP).
- If **our** mapping is address-dependent or address-and-port-dependent, pig generates unique, random **local** bind ports instead, while still aiming at the peer’s known public address.

Those extra paths are attempted together with the usual ICE timing. The first pair to establish a connection wins, just like any other candidate.

TLS-in-ICMP is excluded from this expansion: there is no TCP/UDP port pair to search in the same way.

## Limitations

- Both sides under symmetric NAT is a harder case. The current approach assumes at least one side of the tuple can be treated as known.
- You need a STUN server that supports full NAT discovery (two public addresses and `OTHER-ADDRESS` STUN attribute). A binding-only server will not classify mapping behavior correctly. See [Public servers](nat.md#public-servers).
- Success is not guaranteed on every run. Testing shows 1/3 should make it.

## Related

- [NAT traversal](nat.md)
- [Birthday problem](https://en.wikipedia.org/wiki/Birthday_problem)
- [Network address translation](https://en.wikipedia.org/wiki/Network_address_translation#Methods_of_translation)
