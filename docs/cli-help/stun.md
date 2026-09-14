```
Usage: pig -stun [options]

 -c     host:port of the remote stun server to query.
 -l     The local port to listen for incoming stun requests. E.g. 'pig -stun -l 3478'.
 -proto Protocol to use, valid options are: udp, tcp.
 -p     Source port to use to query a remote server, leave empty for random port.
 -v     Print more verbose output, only useful with -l. Use 0 (default) for info, 1 for debug, 2 for trace.
```
