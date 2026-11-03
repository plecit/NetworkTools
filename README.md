# 🌐 NetScope - Network Intelligence Suite

A comprehensive, beautiful network scanning and monitoring tool built with **pure Python 3** — no external dependencies required.

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔍 **Network Scanner** | Discover devices on your network with IP, Hostname, MAC, Vendor, Latency, Open Ports, and OS detection |
| 🚪 **Port Scanner** | Deep port scan on any host with service identification |
| 📡 **Interactive Ping** | Real-time ping with live canvas latency graph, statistics (min/avg/max), and packet loss % |
| 🗺️ **Traceroute** | Trace the path packets take to reach a destination with per-hop RTT |
| 🏷️ **DNS Lookup** | Query DNS records (A, AAAA, MX, NS, TXT, CNAME, PTR) |
| 🔎 **WHOIS Lookup** | Query domain and IP registration data via whois or RDAP fallback |
| 🧮 **Subnet Calculator** | CIDR calculation with usable hosts, broadcast, netmask, wildcard, and network type |
| 💓 **Node Monitor** | Real-time monitoring of troubled nodes with latency, packet loss, alerts, and mini sparklines |
| 📋 **Node Incident Logs** | Dedicated modal for any monitored node with full check history, latency trends, and log export |
| ⚡ **Speed Test** | Internet speed test with download, upload, ping, and jitter |
| 📋 **Global Logs** | Activity logging filterable by category (Scan, Ping, Monitor, Speed, Error) with export |

## 🚀 Quick Start

```bash
# Run the server
python3 app.py

# Open in your browser
# http://localhost:8888
```

**That's it!** No pip install, no dependencies. Just Python 3.

## 📋 Requirements

- Python 3.6+
- Linux/macOS (uses `ping`, `arp`, `ip` commands)
- A web browser

## 📸 Pages

- **Dashboard** — Overview with device count, online nodes, open ports, and alerts
- **Network Scanner** — Full network discovery with configurable options
- **Port Scanner** — Deep port scanning with service identification
- **Ping Tool** — Interactive ping with real-time chart and statistics
- **Traceroute** — Visual route tracing
- **DNS Lookup** — Complete DNS record lookup
- **Node Monitor** — Live monitoring dashboard with mini charts
- **Speed Test** — Download/Upload speed gauges with latency info
- **Logs** — Filterable activity logs and per-node history

## 🛠️ Configuration

Edit the `PORT` variable in `app.py` to change the server port (default: 8888).

## 📝 License

MIT
