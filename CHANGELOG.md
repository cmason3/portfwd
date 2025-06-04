## CHANGELOG

### [1.1.3] - June 4, 2025
- Updated package dependencies to latest versions
- Updated copyright notice in all files

### [1.1.2] - September 2, 2024
- Updated `ternary` function so it is generic
- Updated X-Wing KEM based on `draft-connolly-cfrg-xwing-kem-04`

### [1.1.1] - March 4, 2024
- Updates to Go files to adhere to Go best practices around modules and packages
- Updated the TCP shutdown routine to pass the listener socket to avoid a function closure
- The `log` function will now lock the mutex for file and screen to avoid `stdout` merging

### [1.1.0] - February 29, 2024
- Added support for ChaCha20-Poly1305 encrypted TCP tunnels using PQC X-Wing Key Encapsulation Mechanism
- Avoid a race condition by waiting for both sides of the TCP session to close via a WaitGroup

### [1.0.7] - February 20, 2024
- Added support for forwarders based on IPv6 or DNS hostnames

### [1.0.6] - February 19, 2024
- Added support for fault tolerant TCP load balancing

### [1.0.5] - February 12, 2024
- Various code cleanups to make the code easier to read and more efficient

### [1.0.4] - February 2, 2024
- Added support for load balancing when `bind_host` and `listen_port` are duplicated
- Cosmetic updates to logging - don't output timestamp if running via Systemd
- Added a 5 second timeout for outbound TCP connections

### [1.0.3] - February 1, 2024
- Fixed an issue where shortened command line arguments weren't working for forwarders
- Added support for `SIGTERM` and `SIGINT` signals so we terminate gracefully
- Sort out exit codes so we have 0 on success and 1 on failure

### [1.0.2] - January 31, 2024
- Added support for `-logfile` so you can specify where to log instead of `stdout`
- When a connection is closed the total number of bytes sent and received is now printed

### [1.0.1] - January 30, 2024
- Added support for `-conf` so you can specify TCP and/or UDP forwarders within a configuration file
- Command line arguments can now be shortened so you can now pass `-t` instead of `-tcp`

### 1.0.0 - January 29, 2024
- Initial release


[1.1.3]: https://github.com/cmason3/portfwd/compare/v1.1.2...v1.1.3
[1.1.2]: https://github.com/cmason3/portfwd/compare/v1.1.1...v1.1.2
[1.1.1]: https://github.com/cmason3/portfwd/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/cmason3/portfwd/compare/v1.0.7...v1.1.0
[1.0.7]: https://github.com/cmason3/portfwd/compare/v1.0.6...v1.0.7
[1.0.6]: https://github.com/cmason3/portfwd/compare/v1.0.5...v1.0.6
[1.0.5]: https://github.com/cmason3/portfwd/compare/v1.0.4...v1.0.5
[1.0.4]: https://github.com/cmason3/portfwd/compare/v1.0.3...v1.0.4
[1.0.3]: https://github.com/cmason3/portfwd/compare/v1.0.2...v1.0.3
[1.0.2]: https://github.com/cmason3/portfwd/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/cmason3/portfwd/compare/v1.0.0...v1.0.1
