## CHANGELOG

#### 1.1.0 - In Development
- Add support for ChaCha20-Poly1305 encrypted TCP tunnels using PQC X-Wing Key Encapsulation Mechanisms

#### 1.0.7 - 20th February 2024
- Add support for forwarders based on IPv6 or DNS hostnames

#### 1.0.6 - 19th February 2024
- Add support for fault tolerant TCP load balancing

#### 1.0.5 - 12th February 2024
- Various code cleanups to make the code easier to read and more efficient

#### 1.0.4 - 2nd February 2024
- Added support for load balancing when `bind_host` and `listen_port` are duplicated
- Cosmetic updates to logging - don't output timestamp if running via Systemd
- Added a 5 second timeout for outbound TCP connections

#### 1.0.3 - 1st February 2024
- Fixed an issue where shortened command line arguments weren't working for forwarders
- Added support for `SIGTERM` and `SIGINT` signals so we terminate gracefully
- Sort out exit codes so we have 0 on success and 1 on failure

#### 1.0.2 - 31st January 2024
- Added support for `-logfile` so you can specify where to log instead of `stdout`
- When a connection is closed the total number of bytes sent and received is now printed

#### 1.0.1 - 30th January 2024
- Added support for `-conf` so you can specify TCP and/or UDP forwarders within a configuration file
- Command line arguments can now be shortened so you can now pass `-t` instead of `-tcp` 

#### 1.0.0 - 29th January 2024
- Initial release
