# TCP/UDP Port Forwarder

A simple TCP and UDP based port forwarder which supports concurrent connections written in Go.

### PortFwd Usage

```
 portfwd -tcp [bind_host:]<listen_port>:<remote_host>:<remote_port>
         -udp [bind_host:]<listen_port>:<remote_host>:<remote_port>
```

You can specify as many TCP and/or UDP forwarders as you wish on the command line - if you omit `bind_host` then it defaults to `127.0.0.1` - to listen on all IPs use `0.0.0.0`.
