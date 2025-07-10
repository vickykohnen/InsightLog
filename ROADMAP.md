# InsightLog Roadmap

## Planned Features and Improvements

- Log level filtering (e.g., only errors)
- Support for compressed log files (.gz)
- Progress bar for large files
- Support for time range filtering
- Export to CSV and JSON
- CLI options for output format, log level, and time range
- Improved error and warning logging
- More robust handling of malformed lines
- Support for additional log formats:
  - **IIS logs** (Microsoft web server log format)
  - **systemd journal logs** (binary logs from modern Linux systems)
  - **AWS ELB logs** (Amazon Elastic Load Balancer access logs)
  - (You can add more: e.g., Cisco ASA firewall logs, Windows Event logs, etc.)
- More edge case and performance tests
- Improved documentation and usage examples 