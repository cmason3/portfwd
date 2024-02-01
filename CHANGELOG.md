## CHANGELOG

#### 1.0.3 - Pending
- Fixed an issue where shortened command line arguments weren''t working for forwarders
- Added support for `SIGTERM` and `SIGINT` signals so we terminate gracefully

#### 1.0.2 - 31st January 2024
- Added support for `-logfile` so you can specify where to log instead of `stdout`
- When a connection is closed the total number of bytes sent and received is now printed

#### 1.0.1 - 30th January 2024
- Added support for `-conf` so you can specify TCP and/or UDP forwarders within a configuration file
- Command line arguments can now be shortened so you can now pass `-t` instead of `-tcp` 

#### 1.0.0 - 29th January 2024
- Initial release
