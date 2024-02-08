# TCP/UDP Port Forwarder

A simple TCP and UDP based port forwarder which supports concurrent connections written in Go.

### Usage

```
 portfwd -tcp [bind_host:]<listen_port>:<remote_host>:<remote_port>
         -udp [bind_host:]<listen_port>:<remote_host>:<remote_port>
         -logfile <portfwd.log>
         -config <portfwd.conf>
```

You can specify as many TCP and/or UDP forwarders as you wish on the command line - if you omit `bind_host` then it defaults to `127.0.0.1` - to listen on all IPs use `0.0.0.0`. If you duplicate `bind_host` and `listen_port` then it will load balance between the destinations (round robin).

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

Alternatively you can run it via Systemd using the following commands as a regular user (assuming you aren't trying to bind to priviledged ports):

```
mkdir -p ~/.config/systemd/user

cat >~/.config/systemd/user/portfwd.service <<EOF
[Unit]
Description=TCP/UDP Port Forwarder

[Service]
ExecStart=${HOME}/bin/portfwd -conf ${HOME}/conf/portfwd.conf
Restart=on-success

[Install]
WantedBy=default.target
EOF

systemctl --user daemon-reload

systemctl --user enable --now portfwd.service

systemctl --user status portfwd.service
```

**Note** There are no guarantees that the `main` branch will compile or work successfully at any given time - only release tags are guaranteed to compile and work.
