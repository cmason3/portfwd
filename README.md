# TCP/UDP Port Forwarder

A simple TCP and UDP based port forwarder for IPv4 and IPv6 which supports concurrent connections written in Go.

### Usage

```
 portfwd -tcp [bind_host:]<listen_port>:<remote_host>:<remote_port>
         -udp [bind_host:]<listen_port>:<remote_host>:<remote_port>
         -logfile <portfwd.log>
         -config <portfwd.conf>
         -ft-tcp
```

You can specify as many TCP and/or UDP forwarders as you wish on the command line - if you omit `bind_host` then it defaults to `localhost` - to listen on all IPs use `0.0.0.0` for IPv4 or `[::]` for IPv6. If you duplicate `bind_host` and `listen_port` then it will load balance between the destinations (round-robin by default). For TCP connections instead of round-robin load balancing you can specify `-ft-tcp`, which will keep using the same destination until it fails and will then move to the next (fault tolerant).

For `bind_host` and `remote_host` you can either specify an IPv4 address (e.g. `192.0.2.1`), IPv6 address (e.g. `[2001:db8::1]`) or a DNS hostname (e.g. `host.domain`).

You also have the option of specifying multiple TCP and/or UDP forwarders (one per line) within a configuration file, e.g:

```
tcp [bind_host:]<listen_port>:<remote_host>:<remote_port>
udp [bind_host:]<listen_port>:<remote_host>:<remote_port>
```

Command line arguments can be shortened as long as they don't become ambiguous (e.g. `-t` for `-tcp` and `-c` for `-config`).

If you want to background the process and log the connections to a file then you can use the following syntax:

```
portfwd <arguments> -logfile <portfwd.log> &
```

Alternatively you can run it as a system service via Systemd using the following commands:

```
cat <<EOF | sudo tee /etc/systemd/system/portfwd.service 1>/dev/null
[Unit]
Description=TCP/UDP Port Forwarder

[Service]
ExecStart=/usr/local/bin/portfwd -conf /etc/portfwd.conf
Restart=on-success

[Install]
WantedBy=default.target
EOF

sudo systemctl daemon-reload

sudo systemctl enable --now portfwd.service

sudo systemctl status portfwd.service
```

**Note** There are no guarantees the code in any branch will compile or work successfully at any given time - only release tags are guaranteed to compile and work.
