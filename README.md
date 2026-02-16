# Network Scanner Tool

A comprehensive network scanning tool that allows you to discover connected devices, analyze ports, and perform basic vulnerability checks.

## Features

- **Device discovery** via ARP or PING scan
- **Port scanning** with service detection
- **Basic vulnerability analysis**
- **Report generation** in JSON, CSV, and TXT formats

## Prerequisites

- **Python** 3.8 or higher
- **nmap** (Network Mapper)

### Installing nmap

- **Ubuntu/Debian**: `sudo apt-get install nmap`
- **macOS**: `brew install nmap`
- **Windows**: Download from [nmap.org](https://nmap.org/download.html)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/gayakaci20/ntwork-scan.git
cd ntwork-scan
```

2. Install the package:
```bash
pip install .
```

Or in development mode:
```bash
pip install -e .
```

## Usage

```bash
ntwork-scan -t TARGET [-s SCAN_TYPE] [-p PORT_RANGE] [-o OUTPUT_FILE] [-f FORMAT]
```

**Arguments**:

| Argument | Description | Default |
|---|---|---|
| `-t, --target` | Target network or IP range (e.g., `192.168.1.0/24`) | *required* |
| `-s, --scan_type` | Scan type (`arp` or `ping`) | `arp` |
| `-p, --port_range` | Port range to scan | `1-1024` |
| `-o, --output` | Output file path | `report.json` |
| `-f, --format` | Output format (`json`, `csv`, or `txt`) | `json` |

**Example**:
```bash
ntwork-scan -t 192.168.1.0/24 -s arp -p 1-100 -o network_scan.json
```

## Important Notes

Some features require root/administrator privileges:

- ARP scanning
- PING scanning
- Port scanning

Run with elevated privileges if needed:
```bash
sudo ntwork-scan -t 192.168.1.0/24
```

## License

MIT License - see [LICENSE](LICENSE) for details.
