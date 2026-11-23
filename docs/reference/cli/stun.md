```
Usage: pig -stun [options]

 -c <host:port> (string)
   The address of the remote stun server to query.
 -l <port> (int)
   The local port to listen for incoming stun requests. E.g. 'pig -stun -l 3478'.
 -proto <protocol> (string)
   The protocol to use, udp or tcp.
 -p <port> (int)
   Source port to use to query a remote server, leave empty for random port.
 -v <level> (int)
   Print more verbose output, only useful with -l. Use 1 (default) for info, 2 for debug, 3 for trace.
   0 disables logging.
```
