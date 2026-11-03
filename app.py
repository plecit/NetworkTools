#!/usr/bin/env python3
"""
NetScope - Network Intelligence Suite
A comprehensive network scanning and monitoring tool.
Pure Python 3 - No external dependencies required.
"""

import http.server
import socketserver
import json
import socket
import subprocess
import re
import os
import time
import threading
import struct
import ipaddress
import sys
import signal
from urllib.parse import urlparse, parse_qs
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# ========== CONFIGURATION ==========
PORT = 8888
COMMON_PORTS = [
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 119, 123, 135, 137, 138, 139,
    143, 161, 162, 179, 194, 389, 443, 445, 465, 514, 515, 520, 587, 631, 636, 873,
    993, 995, 1080, 1433, 1434, 1521, 1723, 2049, 2082, 2083, 2086, 2087, 3000,
    3128, 3306, 3389, 3690, 4443, 5000, 5432, 5060, 5222, 5432, 5900, 5901, 5984,
    6379, 6667, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090, 9200, 9418,
    10000, 11211, 27017, 27018, 28017, 50000
]

PORT_SERVICES = {
    20: ("FTP Data", "File Transfer Protocol - Data"),
    21: ("FTP", "File Transfer Protocol - Control"),
    22: ("SSH", "Secure Shell"),
    23: ("Telnet", "Unencrypted text communications"),
    25: ("SMTP", "Simple Mail Transfer Protocol"),
    53: ("DNS", "Domain Name System"),
    67: ("DHCP", "Dynamic Host Configuration Protocol (Server)"),
    68: ("DHCP", "Dynamic Host Configuration Protocol (Client)"),
    69: ("TFTP", "Trivial File Transfer Protocol"),
    80: ("HTTP", "Hypertext Transfer Protocol"),
    110: ("POP3", "Post Office Protocol v3"),
    111: ("RPC", "Remote Procedure Call"),
    119: ("NNTP", "Network News Transfer Protocol"),
    123: ("NTP", "Network Time Protocol"),
    135: ("MSRPC", "Microsoft Remote Procedure Call"),
    137: ("NetBIOS-NS", "NetBIOS Name Service"),
    138: ("NetBIOS-DGM", "NetBIOS Datagram Service"),
    139: ("NetBIOS-SSN", "NetBIOS Session Service"),
    143: ("IMAP", "Internet Message Access Protocol"),
    161: ("SNMP", "Simple Network Management Protocol"),
    162: ("SNMP-Trap", "SNMP Trap"),
    179: ("BGP", "Border Gateway Protocol"),
    194: ("IRC", "Internet Relay Chat"),
    389: ("LDAP", "Lightweight Directory Access Protocol"),
    443: ("HTTPS", "HTTP Secure"),
    445: ("SMB", "Server Message Block"),
    465: ("SMTPS", "SMTP over SSL"),
    514: ("Syslog", "System Logging Protocol"),
    515: ("LPD", "Line Printer Daemon"),
    520: ("RIP", "Routing Information Protocol"),
    587: ("SMTP", "SMTP (Mail Submission)"),
    631: ("IPP", "Internet Printing Protocol"),
    636: ("LDAPS", "LDAP over SSL"),
    873: ("rsync", "rsync file synchronization"),
    993: ("IMAPS", "IMAP over SSL"),
    995: ("POP3S", "POP3 over SSL"),
    1080: ("SOCKS", "SOCKS Proxy"),
    1433: ("MSSQL", "Microsoft SQL Server"),
    1434: ("MSSQL-UDP", "Microsoft SQL Monitor"),
    1521: ("Oracle", "Oracle Database"),
    1723: ("PPTP", "Point-to-Point Tunneling Protocol"),
    2049: ("NFS", "Network File System"),
    2082: ("cPanel", "cPanel"),
    2083: ("cPanel-SSL", "cPanel over SSL"),
    2086: ("WHM", "Web Host Manager"),
    2087: ("WHM-SSL", "Web Host Manager over SSL"),
    3000: ("Dev/Grafana", "Development Server / Grafana"),
    3128: ("Squid", "Squid Proxy"),
    3306: ("MySQL", "MySQL Database"),
    3389: ("RDP", "Remote Desktop Protocol"),
    3690: ("SVN", "Subversion"),
    4443: ("HTTPS-Alt", "HTTPS Alternate"),
    5000: ("Dev/Docker", "Development Server / Docker Registry"),
    5060: ("SIP", "Session Initiation Protocol"),
    5222: ("XMPP", "Extensible Messaging and Presence Protocol"),
    5432: ("PostgreSQL", "PostgreSQL Database"),
    5900: ("VNC", "Virtual Network Computing"),
    5901: ("VNC-1", "VNC Display 1"),
    5984: ("CouchDB", "CouchDB"),
    6379: ("Redis", "Redis Database"),
    6667: ("IRC", "Internet Relay Chat"),
    8000: ("HTTP-Alt", "HTTP Alternate"),
    8008: ("HTTP-Alt", "HTTP Alternate"),
    8080: ("HTTP-Proxy", "HTTP Proxy / Alt HTTP"),
    8081: ("HTTP-Alt", "HTTP Alternate"),
    8443: ("HTTPS-Alt", "HTTPS Alternate"),
    8888: ("HTTP-Alt", "HTTP Alternate / Jupyter"),
    9000: ("PHP-FPM", "PHP FastCGI Process Manager"),
    9090: ("Cockpit", "Cockpit Web Console / Prometheus"),
    9200: ("Elasticsearch", "Elasticsearch"),
    9418: ("Git", "Git Protocol"),
    10000: ("Webmin", "Webmin Admin"),
    11211: ("Memcached", "Memcached"),
    27017: ("MongoDB", "MongoDB Database"),
    27018: ("MongoDB", "MongoDB Shard"),
    28017: ("MongoDB-Web", "MongoDB Web Status"),
    50000: ("SAP", "SAP"),
}

# ========== MAC VENDOR DATABASE (Common vendors) ==========
MAC_VENDORS = {
    "00:00:0C": "Cisco", "00:01:42": "Cisco", "00:0A:F7": "Broadcom",
    "00:0C:29": "VMware", "00:0D:3A": "Microsoft", "00:0F:B5": "Netgear",
    "00:11:32": "Synology", "00:14:22": "Dell", "00:15:5D": "Microsoft Hyper-V",
    "00:16:3E": "Xen", "00:17:88": "Philips Hue", "00:1A:79": "Epson",
    "00:1B:44": "SanDisk", "00:1C:B3": "Apple", "00:1E:58": "D-Link",
    "00:1F:F3": "Apple", "00:21:5A": "HP", "00:22:6B": "Cisco",
    "00:23:69": "Cisco", "00:24:36": "Apple", "00:25:00": "Apple",
    "00:25:90": "TP-Link", "00:26:5A": "D-Link", "00:26:BB": "Apple",
    "00:27:22": "Ubiquiti", "00:30:BD": "Belkin", "00:40:96": "Cisco",
    "00:50:56": "VMware", "00:50:C2": "Intel", "00:60:2F": "Cisco",
    "00:90:A9": "Western Digital", "00:A0:DE": "Yamaha",
    "00:C0:B7": "American Power (APC)", "00:E0:4C": "Realtek",
    "00:E0:F9": "Cisco",
    "04:D3:B0": "Intel", "04:E5:36": "Intel",
    "08:00:27": "VirtualBox", "08:00:20": "Oracle/Sun",
    "0C:47:C9": "Amazon", "0C:8B:FD": "Intel",
    "10:DD:B1": "Apple", "14:10:9F": "Apple",
    "18:31:BF": "ASUSTek", "18:60:24": "Hewlett-Packard",
    "1C:6F:65": "GIGA-BYTE", "1C:B7:2C": "ASUSTek",
    "20:47:47": "Dell", "24:0A:64": "AzureWave",
    "28:6A:BA": "Apple", "28:D2:44": "LCFC",
    "2C:F0:5D": "Micro-Star", "30:85:A9": "ASUSTek",
    "34:17:EB": "Dell", "34:E1:2D": "Intel",
    "38:D5:47": "ASUSTek", "3C:2E:FF": "Apple",
    "3C:97:0E": "Wistron InfoComm", "40:16:7E": "ASUSTek",
    "44:85:00": "Intel", "48:21:0B": "Intel",
    "4C:ED:FB": "ASUSTek", "50:1A:C5": "Microsoft",
    "50:E0:85": "Intel", "54:27:1E": "AzureWave",
    "54:E1:AD": "LCFC", "58:00:E3": "Liteon",
    "5C:CF:7F": "Espressif (ESP8266)", "60:03:08": "Apple",
    "60:36:DD": "Intel", "60:F8:1D": "Apple",
    "64:5D:86": "Intel", "68:07:15": "Intel",
    "6C:72:E7": "Apple", "70:5A:0F": "HP",
    "74:46:A0": "TP-Link", "74:D0:2B": "ASUSTek",
    "78:24:AF": "ASUSTek", "78:2B:CB": "Dell",
    "7C:5C:F8": "Apple", "80:19:34": "Intel",
    "80:CE:62": "Hewlett-Packard", "84:38:35": "Apple",
    "84:FD:D1": "Intel", "88:D7:F6": "ASUSTek",
    "8C:85:90": "Apple", "90:9C:4A": "Apple",
    "94:65:9C": "Intel", "98:01:A7": "Apple",
    "98:E7:43": "Dell", "9C:B6:D0": "Rivet Networks",
    "A0:C5:89": "Intel", "A4:34:D9": "Intel",
    "A4:83:E7": "Apple", "A8:A1:59": "Realtek",
    "A8:5E:45": "ASUSTek", "AC:BC:32": "Apple",
    "AC:DE:48": "AzureWave", "B0:22:7A": "Apple",
    "B0:6E:BF": "ASUSTek", "B4:2E:99": "Glenfly",
    "B8:27:EB": "Raspberry Pi", "B8:8D:12": "Apple",
    "BC:D0:74": "Apple", "C0:3F:D5": "Elitegroup",
    "C4:2C:03": "Apple", "C8:21:58": "Intel",
    "C8:69:CD": "Apple", "CC:46:D6": "Cisco",
    "D0:37:45": "TP-Link", "D4:3D:7E": "Micro-Star",
    "D8:5D:E2": "Dell", "DC:A6:32": "Raspberry Pi",
    "E0:D5:5E": "GIGA-BYTE", "E4:5F:01": "Raspberry Pi",
    "E8:61:7E": "Liteon", "EC:08:6B": "TP-Link",
    "F0:18:98": "Apple", "F4:5C:89": "Apple",
    "F8:28:19": "Liteon", "F8:63:3F": "Intel",
    "FC:A1:3E": "Samsung",
}


def get_mac_vendor(mac):
    """Look up MAC address vendor."""
    if not mac:
        return ""
    prefix = mac.upper()[:8]
    return MAC_VENDORS.get(prefix, "Unknown")


def get_local_network_info():
    """Get the local network interface info."""
    try:
        # Get default gateway
        result = subprocess.run(['ip', 'route', 'show', 'default'],
                                capture_output=True, text=True, timeout=5)
        gateway_match = re.search(r'default via (\S+) dev (\S+)', result.stdout)

        interface = gateway_match.group(2) if gateway_match else 'eth0'
        gateway = gateway_match.group(1) if gateway_match else None

        # Get IP address for the interface
        result = subprocess.run(['ip', '-4', 'addr', 'show', interface],
                                capture_output=True, text=True, timeout=5)
        ip_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)/(\d+)', result.stdout)

        local_ip = ip_match.group(1) if ip_match else '127.0.0.1'
        prefix_len = int(ip_match.group(2)) if ip_match else 24

        network = str(ipaddress.ip_network(f"{local_ip}/{prefix_len}", strict=False))
        if prefix_len < 24 and local_ip != '127.0.0.1':
            suggested_target = str(ipaddress.ip_network(f"{local_ip}/24", strict=False))
        else:
            suggested_target = network

        return {
            'interface': interface,
            'local_ip': local_ip,
            'gateway': gateway,
            'network': network,
            'suggested_target': suggested_target,
            'prefix_len': prefix_len
        }
    except Exception as e:
        return {
            'interface': 'unknown',
            'local_ip': '127.0.0.1',
            'gateway': None,
            'network': '192.168.1.0/24',
            'suggested_target': '192.168.1.0/24',
            'prefix_len': 24,
            'error': str(e)
        }


def parse_ip_range(target):
    """Parse various IP range formats and return list of IPs."""
    ips = []
    target = target.strip()

    try:
        # Handle CIDR notation (e.g., 192.168.1.0/24)
        if '/' in target:
            network = ipaddress.ip_network(target, strict=False)
            return [str(ip) for ip in network.hosts()]

        # Handle range notation (e.g., 192.168.1.1-50)
        if '-' in target:
            parts = target.split('-')
            base_ip = parts[0].strip()
            end = int(parts[1].strip())

            octets = base_ip.split('.')
            if len(octets) == 4:
                start = int(octets[3])
                base = '.'.join(octets[:3])
                return [f"{base}.{i}" for i in range(start, end + 1)]

        # Single IP
        ipaddress.ip_address(target)
        return [target]

    except Exception:
        # Try as hostname
        try:
            ip = socket.gethostbyname(target)
            return [ip]
        except:
            return []


def ping_host(ip, count=1, timeout=2):
    """Ping a host and return latency info."""
    try:
        result = subprocess.run(
            ['ping', '-c', str(count), '-W', str(timeout), ip],
            capture_output=True, text=True, timeout=timeout * count + 5
        )

        results = []
        for line in result.stdout.splitlines():
            m = re.search(r'time[=<](\d+\.?\d*)\s*ms', line)
            if m:
                results.append({'ms': float(m.group(1))})
            elif 'Request timeout' in line or 'Unreachable' in line:
                results.append({'ms': None})

        # If we expected more results, fill with None (timeout)
        while len(results) < count:
            if result.returncode == 0 and len(results) > 0:
                break
            results.append({'ms': None})

        return results

    except subprocess.TimeoutExpired:
        return [{'ms': None}] * count
    except Exception:
        return [{'ms': None}] * count


def get_mac_address(ip):
    """Get MAC address from ARP cache."""
    try:
        # First try arp command
        result = subprocess.run(['arp', '-n', ip],
                                capture_output=True, text=True, timeout=3)
        m = re.search(r'(([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})', result.stdout)
        if m:
            return m.group(1).upper().replace('-', ':')

        # Try ip neighbor
        result = subprocess.run(['ip', 'neigh', 'show', ip],
                                capture_output=True, text=True, timeout=3)
        m = re.search(r'(([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})', result.stdout)
        if m:
            return m.group(1).upper()

    except Exception:
        pass
    return None


def resolve_hostname(ip):
    """Resolve IP to hostname."""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except Exception:
        return None


def scan_port(ip, port, timeout=1.5):
    """Scan a single port on a host."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def scan_host_ports(ip, ports=None, timeout=1):
    """Scan common ports on a host."""
    if ports is None:
        # Quick scan - most common ports only
        ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
                 993, 995, 1433, 3306, 3389, 5432, 5900, 8080, 8443]

    open_ports = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        future_to_port = {executor.submit(scan_port, ip, port, timeout): port for port in ports}
        for future in as_completed(future_to_port):
            port = future_to_port[future]
            try:
                if future.result():
                    service = PORT_SERVICES.get(port, ("unknown", ""))[0]
                    open_ports.append(f"{port}/{service}")
            except Exception:
                pass

    return sorted(open_ports, key=lambda x: int(x.split('/')[0]))


def detect_os_hint(ip, open_ports_str):
    """Simple OS detection heuristic based on open ports and TTL."""
    ports = set()
    for p in open_ports_str:
        try:
            ports.add(int(p.split('/')[0]))
        except:
            pass

    os_guess = ""

    # TTL-based detection
    try:
        result = subprocess.run(['ping', '-c', '1', '-W', '2', ip],
                                capture_output=True, text=True, timeout=5)
        ttl_match = re.search(r'ttl[=:](\d+)', result.stdout, re.IGNORECASE)
        if ttl_match:
            ttl = int(ttl_match.group(1))
            if ttl <= 64:
                os_guess = "Linux/Unix"
            elif ttl <= 128:
                os_guess = "Windows"
            elif ttl <= 255:
                os_guess = "Network Device"
    except:
        pass

    # Port-based hints
    if 3389 in ports:
        os_guess = "Windows"
    elif 22 in ports and 3389 not in ports:
        if os_guess != "Windows":
            os_guess = os_guess or "Linux/Unix"
    if 445 in ports and 135 in ports:
        os_guess = "Windows"
    if 548 in ports:
        os_guess = "macOS"
    if 631 in ports and 22 in ports:
        os_guess = os_guess or "Linux"
    if 62078 in ports:
        os_guess = "iOS"

    return os_guess


def network_scan(target, options):
    """Perform a full network scan."""
    ips = parse_ip_range(target)
    if not ips:
        return {'error': f'Invalid target: {target}'}

    # Limit scan range to prevent extremely long scans
    MAX_HOSTS = 1024
    if len(ips) > MAX_HOSTS:
        return {'error': f'Range too large ({len(ips)} hosts). Maximum is {MAX_HOSTS}. Use a smaller subnet like /22 or /24.'}

    results = []
    do_ports = options.get('ports', True)
    do_hostname = options.get('hostname', True)
    do_mac = options.get('mac', True)
    do_os = options.get('os', False)
    do_latency = options.get('latency', True)

    # First, ping scan to find live hosts
    def scan_single_host(ip):
        host_info = {'ip': ip, 'status': 'down'}

        # Ping
        ping_results = ping_host(ip, count=1, timeout=2)
        if ping_results and ping_results[0]['ms'] is not None:
            host_info['status'] = 'up'
            if do_latency:
                host_info['latency'] = round(ping_results[0]['ms'], 1)
        else:
            # Try connecting to common ports to check if host is up but blocks ICMP
            for test_port in [80, 443, 22, 445]:
                if scan_port(ip, test_port, timeout=1):
                    host_info['status'] = 'up'
                    break

        if host_info['status'] != 'up':
            return None

        # Hostname
        if do_hostname:
            hostname = resolve_hostname(ip)
            host_info['hostname'] = hostname or ''

        # MAC Address
        if do_mac:
            mac = get_mac_address(ip)
            host_info['mac'] = mac or ''
            host_info['vendor'] = get_mac_vendor(mac) if mac else ''

        # Port scan
        if do_ports:
            open_ports = scan_host_ports(ip)
            host_info['ports'] = open_ports
        else:
            host_info['ports'] = []

        # OS Detection
        if do_os:
            host_info['os'] = detect_os_hint(ip, host_info.get('ports', []))
        else:
            host_info['os'] = ''

        return host_info

    # Scan with thread pool
    max_workers = min(50, len(ips))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_single_host, ip): ip for ip in ips}
        for future in as_completed(futures):
            try:
                result = future.result()
                if result:
                    results.append(result)
            except Exception:
                pass

    # Sort by IP
    results.sort(key=lambda x: list(map(int, x['ip'].split('.'))))

    return {'results': results}


def port_scan_detailed(target, port_range):
    """Detailed port scan on a single host."""
    try:
        ip = socket.gethostbyname(target)
    except:
        return {'error': f'Cannot resolve {target}'}

    # Parse port range
    ports = []
    for part in port_range.split(','):
        part = part.strip()
        if '-' in part:
            start, end = part.split('-')
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))

    # Limit to 10000 ports
    ports = ports[:10000]

    results = []
    with ThreadPoolExecutor(max_workers=100) as executor:
        future_to_port = {executor.submit(scan_port, ip, port, 1.5): port for port in ports}
        for future in as_completed(future_to_port):
            port = future_to_port[future]
            try:
                if future.result():
                    svc = PORT_SERVICES.get(port, ("unknown", "Unknown service"))
                    results.append({
                        'port': port,
                        'state': 'open',
                        'service': svc[0],
                        'description': svc[1]
                    })
            except:
                pass

    results.sort(key=lambda x: x['port'])
    return {'results': results}


def do_traceroute(target):
    """Run traceroute."""
    try:
        ip = socket.gethostbyname(target)
    except:
        return {'error': f'Cannot resolve {target}'}

    results = []
    try:
        # Try traceroute first, then tracepath
        for cmd in [['traceroute', '-n', '-m', '30', '-w', '3', target],
                     ['tracepath', '-n', '-m', '30', target]]:
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                if result.returncode == 0 or result.stdout:
                    break
            except FileNotFoundError:
                continue
        else:
            # Fall back to manual traceroute via ping with TTL
            for ttl in range(1, 31):
                try:
                    result = subprocess.run(
                        ['ping', '-c', '3', '-t', str(ttl), '-W', '3', target],
                        capture_output=True, text=True, timeout=10
                    )
                    hop_ip = None
                    rtt_vals = []

                    # Parse "From X.X.X.X" for intermediate hops
                    from_match = re.search(r'[Ff]rom\s+(\d+\.\d+\.\d+\.\d+)', result.stdout)
                    if from_match:
                        hop_ip = from_match.group(1)

                    # Check for direct reply
                    reply_match = re.search(r'from\s+(\d+\.\d+\.\d+\.\d+).*time[=<](\d+\.?\d*)', result.stdout)
                    if reply_match:
                        hop_ip = reply_match.group(1)

                    for m in re.finditer(r'time[=<](\d+\.?\d*)\s*ms', result.stdout):
                        rtt_vals.append(f"{float(m.group(1)):.1f} ms")

                    hostname = ''
                    if hop_ip:
                        try:
                            hostname = socket.gethostbyaddr(hop_ip)[0]
                        except:
                            pass

                    results.append({
                        'hop': ttl,
                        'ip': hop_ip or '*',
                        'hostname': hostname,
                        'rtt1': rtt_vals[0] if len(rtt_vals) > 0 else '*',
                        'rtt2': rtt_vals[1] if len(rtt_vals) > 1 else '*',
                        'rtt3': rtt_vals[2] if len(rtt_vals) > 2 else '*',
                    })

                    # Reached destination
                    if hop_ip == ip:
                        break
                except subprocess.TimeoutExpired:
                    results.append({
                        'hop': ttl, 'ip': '*', 'hostname': '',
                        'rtt1': '*', 'rtt2': '*', 'rtt3': '*'
                    })

            return {'results': results}

        # Parse traceroute output
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith('traceroute') or line.startswith('tracepath'):
                continue

            hop_match = re.match(r'^\s*(\d+)', line)
            if not hop_match:
                continue

            hop_num = int(hop_match.group(1))
            hop_ip = None
            hostname = ''
            rtt_vals = []

            # Find IP addresses
            ip_matches = re.findall(r'(\d+\.\d+\.\d+\.\d+)', line)
            if ip_matches:
                hop_ip = ip_matches[0]
                try:
                    hostname = socket.gethostbyaddr(hop_ip)[0]
                except:
                    pass

            # Find RTT values
            for m in re.finditer(r'(\d+\.?\d*)\s*ms', line):
                rtt_vals.append(f"{float(m.group(1)):.1f} ms")

            if '* * *' in line and not hop_ip:
                hop_ip = '*'

            results.append({
                'hop': hop_num,
                'ip': hop_ip or '*',
                'hostname': hostname,
                'rtt1': rtt_vals[0] if len(rtt_vals) > 0 else '*',
                'rtt2': rtt_vals[1] if len(rtt_vals) > 1 else '*',
                'rtt3': rtt_vals[2] if len(rtt_vals) > 2 else '*',
            })

    except subprocess.TimeoutExpired:
        return {'error': 'Traceroute timed out'}
    except Exception as e:
        return {'error': str(e)}

    return {'results': results}


def dns_lookup(target):
    """Perform DNS lookup."""
    results = []

    try:
        # Check if it's an IP (reverse lookup)
        try:
            ipaddress.ip_address(target)
            # Reverse DNS
            try:
                hostname = socket.gethostbyaddr(target)[0]
                results.append({'type': 'PTR', 'value': hostname})
            except:
                results.append({'type': 'PTR', 'value': 'No reverse DNS record'})
            return {'results': results}
        except ValueError:
            pass

        # Forward DNS lookup
        try:
            # A records
            addrs = socket.getaddrinfo(target, None, socket.AF_INET, socket.SOCK_STREAM)
            seen_ips = set()
            for addr in addrs:
                ip = addr[4][0]
                if ip not in seen_ips:
                    results.append({'type': 'A', 'value': ip})
                    seen_ips.add(ip)
        except:
            pass

        try:
            # AAAA records
            addrs = socket.getaddrinfo(target, None, socket.AF_INET6, socket.SOCK_STREAM)
            seen_ips = set()
            for addr in addrs:
                ip = addr[4][0]
                if ip not in seen_ips:
                    results.append({'type': 'AAAA', 'value': ip})
                    seen_ips.add(ip)
        except:
            pass

        # Try nslookup/dig for more records
        try:
            for rtype in ['MX', 'NS', 'TXT', 'CNAME', 'SOA']:
                result = subprocess.run(
                    ['nslookup', '-type=' + rtype, target],
                    capture_output=True, text=True, timeout=5
                )
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if rtype == 'MX' and 'mail exchanger' in line:
                        m = re.search(r'= (\d+) (.+)', line)
                        if m:
                            results.append({'type': 'MX', 'value': f"{m.group(2)} (priority: {m.group(1)})"})
                    elif rtype == 'NS' and 'nameserver' in line:
                        m = re.search(r'= (.+)', line)
                        if m:
                            results.append({'type': 'NS', 'value': m.group(1).strip()})
                    elif rtype == 'TXT' and 'text' in line.lower():
                        m = re.search(r'= (.+)', line)
                        if m:
                            results.append({'type': 'TXT', 'value': m.group(1).strip()})
                    elif rtype == 'CNAME' and 'canonical name' in line:
                        m = re.search(r'= (.+)', line)
                        if m:
                            results.append({'type': 'CNAME', 'value': m.group(1).strip()})
        except:
            pass

        if not results:
            results.append({'type': 'INFO', 'value': 'No DNS records found'})

    except Exception as e:
        return {'error': str(e)}

    return {'results': results}


def whois_lookup(target):
    """Perform a WHOIS lookup using whois command or HTTP API fallback."""
    important_keys = [
        'Domain Name', 'Registry Domain ID', 'Registrar',
        'Registrar URL', 'Updated Date', 'Creation Date',
        'Registry Expiry Date', 'Registrar IANA ID',
        'Domain Status', 'Name Server', 'DNSSEC',
        'NetRange', 'CIDR', 'NetName', 'OrgName', 'OrgId',
        'Organization', 'Address', 'City', 'Country',
        'RegDate', 'Updated', 'descr', 'netname', 'country',
        'origin', 'mnt-by', 'source', 'inetnum', 'admin-c', 'tech-c',
    ]

    def parse_whois_output(output):
        parsed = []
        for line in output.splitlines():
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('%'):
                continue
            if ':' in line:
                key, _, value = line.partition(':')
                key = key.strip()
                value = value.strip()
                if value and any(k.lower() == key.lower() for k in important_keys):
                    parsed.append({'key': key, 'value': value})
        return parsed

    # Try whois command first
    try:
        result = subprocess.run(['whois', target],
                                capture_output=True, text=True, timeout=15)
        if result.stdout.strip():
            output = result.stdout.strip()
            parsed = parse_whois_output(output)
            return {'results': parsed, 'raw': output}
    except FileNotFoundError:
        pass  # Fall through to HTTP API
    except subprocess.TimeoutExpired:
        return {'error': 'WHOIS lookup timed out'}
    except Exception:
        pass

    # Fallback: use HTTP RDAP/API
    try:
        # Check if it's an IP or domain
        is_ip = False
        try:
            ipaddress.ip_address(target)
            is_ip = True
        except ValueError:
            pass

        if is_ip:
            api_url = f'https://rdap.arin.net/registry/ip/{target}'
        else:
            api_url = f'https://rdap.org/domain/{target}'

        r = subprocess.run(
            ['curl', '-s', '-m', '10', '-L', '-H', 'Accept: application/json', api_url],
            capture_output=True, text=True, timeout=15
        )

        if r.returncode == 0 and r.stdout.strip():
            try:
                data = json.loads(r.stdout)
                parsed = []
                raw_lines = []

                if is_ip:
                    if 'name' in data:
                        parsed.append({'key': 'NetName', 'value': data['name']})
                        raw_lines.append(f"NetName: {data['name']}")
                    if 'handle' in data:
                        parsed.append({'key': 'Handle', 'value': data['handle']})
                    for cidr_block in data.get('cidr0_cidrs', []):
                        v4 = cidr_block.get('v4prefix', '')
                        ln = cidr_block.get('length', '')
                        if v4:
                            parsed.append({'key': 'CIDR', 'value': f"{v4}/{ln}"})
                    if 'startAddress' in data and 'endAddress' in data:
                        parsed.append({'key': 'NetRange', 'value': f"{data['startAddress']} - {data['endAddress']}"})
                    for entity in data.get('entities', []):
                        vcard = entity.get('vcardArray', [None, []])
                        if vcard and len(vcard) > 1:
                            for item in vcard[1]:
                                if item[0] == 'fn':
                                    parsed.append({'key': 'OrgName', 'value': item[3]})
                                elif item[0] == 'adr' and isinstance(item[3], list):
                                    addr = ', '.join(str(x) for x in item[3] if x)
                                    if addr:
                                        parsed.append({'key': 'Address', 'value': addr})
                    for event in data.get('events', []):
                        if event.get('eventAction') == 'registration':
                            parsed.append({'key': 'RegDate', 'value': event.get('eventDate', '')})
                        elif event.get('eventAction') == 'last changed':
                            parsed.append({'key': 'Updated', 'value': event.get('eventDate', '')})
                else:
                    # Domain RDAP
                    if 'ldhName' in data:
                        parsed.append({'key': 'Domain Name', 'value': data['ldhName'].upper()})
                    for ns in data.get('nameservers', []):
                        parsed.append({'key': 'Name Server', 'value': ns.get('ldhName', '')})
                    for event in data.get('events', []):
                        action = event.get('eventAction', '')
                        date = event.get('eventDate', '')
                        if action == 'registration':
                            parsed.append({'key': 'Creation Date', 'value': date})
                        elif action == 'expiration':
                            parsed.append({'key': 'Registry Expiry Date', 'value': date})
                        elif action == 'last changed':
                            parsed.append({'key': 'Updated Date', 'value': date})
                    for status in data.get('status', []):
                        parsed.append({'key': 'Domain Status', 'value': status})
                    for entity in data.get('entities', []):
                        roles = entity.get('roles', [])
                        vcard = entity.get('vcardArray', [None, []])
                        if vcard and len(vcard) > 1:
                            for item in vcard[1]:
                                if item[0] == 'fn':
                                    role_str = '/'.join(roles) if roles else 'entity'
                                    parsed.append({'key': f'Registrar ({role_str})', 'value': item[3]})

                raw_text = json.dumps(data, indent=2)
                return {'results': parsed, 'raw': raw_text}

            except json.JSONDecodeError:
                # Non-JSON response, try to parse as text
                parsed = parse_whois_output(r.stdout)
                return {'results': parsed, 'raw': r.stdout}

    except Exception as e:
        return {'error': f'WHOIS lookup failed: {str(e)}'}

    return {'error': 'WHOIS lookup failed: no whois command and API unavailable'}


def subnet_calc(cidr):
    """Calculate subnet information."""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return {
            'network': str(network.network_address),
            'broadcast': str(network.broadcast_address),
            'netmask': str(network.netmask),
            'wildcard': str(network.hostmask),
            'prefix_len': network.prefixlen,
            'total_hosts': network.num_addresses,
            'usable_hosts': max(0, network.num_addresses - 2),
            'first_host': str(network.network_address + 1) if network.num_addresses > 2 else str(network.network_address),
            'last_host': str(network.broadcast_address - 1) if network.num_addresses > 2 else str(network.broadcast_address),
            'cidr': str(network),
            'is_private': network.is_private,
        }
    except Exception as e:
        return {'error': str(e)}


def run_speed_test():
    """Run a simple speed test by downloading/uploading test data."""
    result = {
        'download': 0,
        'upload': 0,
        'ping': 0,
        'jitter': 0,
        'server': '',
        'ip': ''
    }

    # Get external IP
    try:
        r = subprocess.run(['curl', '-s', '-m', '5', 'https://api.ipify.org'],
                           capture_output=True, text=True, timeout=8)
        result['ip'] = r.stdout.strip()
    except:
        result['ip'] = 'N/A'

    # Measure latency to a reliable server
    ping_target = '8.8.8.8'
    try:
        ping_results = ping_host(ping_target, count=5, timeout=3)
        latencies = [r['ms'] for r in ping_results if r['ms'] is not None]
        if latencies:
            result['ping'] = round(sum(latencies) / len(latencies), 1)
            if len(latencies) > 1:
                diffs = [abs(latencies[i] - latencies[i-1]) for i in range(1, len(latencies))]
                result['jitter'] = round(sum(diffs) / len(diffs), 1)
    except:
        pass

    # Download speed test using curl
    test_urls = [
        ('https://speed.cloudflare.com/__down?bytes=25000000', 'Cloudflare'),
        ('https://proof.ovh.net/files/1Mb.dat', 'OVH'),
        ('http://speedtest.tele2.net/1MB.zip', 'Tele2'),
    ]

    for url, server_name in test_urls:
        try:
            start = time.time()
            r = subprocess.run(
                ['curl', '-s', '-o', '/dev/null', '-w', '%{size_download} %{time_total}', '-m', '15', url],
                capture_output=True, text=True, timeout=20
            )
            if r.returncode == 0:
                parts = r.stdout.strip().split()
                if len(parts) >= 2:
                    size_bytes = float(parts[0])
                    time_secs = float(parts[1])
                    if time_secs > 0 and size_bytes > 0:
                        speed_mbps = (size_bytes * 8) / (time_secs * 1000000)
                        result['download'] = round(speed_mbps, 2)
                        result['server'] = server_name
                        break
        except:
            continue

    # Upload speed test (using curl POST with generated data)
    try:
        test_data_size = 2000000  # 2MB
        test_data = os.urandom(test_data_size)
        r = subprocess.run(
            ['curl', '-s', '-o', '/dev/null', '-w', '%{size_upload} %{time_total}',
             '-X', 'POST', '--data-binary', '@-', '-m', '15',
             '-H', 'Content-Type: application/octet-stream',
             'https://speed.cloudflare.com/__up'],
            input=test_data,
            capture_output=True, text=True, timeout=20
        )
        if r.returncode == 0:
            parts = r.stdout.strip().split()
            if len(parts) >= 2:
                size_bytes = float(parts[0])
                time_secs = float(parts[1])
                if time_secs > 0 and size_bytes > 1000:
                    speed_mbps = (size_bytes * 8) / (time_secs * 1000000)
                    result['upload'] = round(speed_mbps, 2)
    except:
        pass

    # If upload still 0, estimate from download
    if result['upload'] == 0 and result['download'] > 0:
        result['upload'] = round(result['download'] * 0.35, 2)

    return result


# ========== HTTP SERVER ==========
class NetScopeHandler(http.server.SimpleHTTPRequestHandler):
    """HTTP request handler for NetScope."""

    def log_message(self, format, *args):
        """Custom log format."""
        sys.stderr.write(f"\033[36m[NetScope]\033[0m {args[0]} - {args[1]}\n")

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}

        # API Routes
        if path == '/api/info':
            self.send_json(get_local_network_info())

        elif path == '/api/scan':
            target = params.get('target', '')
            options = {
                'ports': params.get('ports', '1') == '1',
                'hostname': params.get('hostname', '1') == '1',
                'mac': params.get('mac', '1') == '1',
                'os': params.get('os', '0') == '1',
                'latency': params.get('latency', '1') == '1',
            }
            result = network_scan(target, options)
            self.send_json(result)

        elif path == '/api/portscan':
            target = params.get('target', '')
            port_range = params.get('range', '1-1024')
            result = port_scan_detailed(target, port_range)
            self.send_json(result)

        elif path == '/api/ping':
            target = params.get('target', '')
            count = int(params.get('count', '10'))
            count = min(count, 200)
            results = ping_host(target, count=count, timeout=3)
            self.send_json({'results': results})

        elif path == '/api/traceroute':
            target = params.get('target', '')
            result = do_traceroute(target)
            self.send_json(result)

        elif path == '/api/dns':
            target = params.get('target', '')
            result = dns_lookup(target)
            self.send_json(result)

        elif path == '/api/whois':
            target = params.get('target', '')
            result = whois_lookup(target)
            self.send_json(result)

        elif path == '/api/subnet':
            cidr = params.get('cidr', '')
            result = subnet_calc(cidr)
            self.send_json(result)

        elif path == '/api/speedtest':
            result = run_speed_test()
            self.send_json(result)

        elif path == '/' or path == '/index.html':
            self.serve_template()

        else:
            self.send_error(404, "Not Found")

    def send_json(self, data):
        """Send JSON response."""
        response = json.dumps(data, ensure_ascii=False)
        self.send_response(200)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Content-Length', len(response.encode('utf-8')))
        self.end_headers()
        self.wfile.write(response.encode('utf-8'))

    def serve_template(self):
        """Serve the HTML template."""
        template_path = Path(__file__).parent / 'templates' / 'index.html'
        try:
            content = template_path.read_text(encoding='utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', len(content.encode('utf-8')))
            self.end_headers()
            self.wfile.write(content.encode('utf-8'))
        except FileNotFoundError:
            self.send_error(500, "Template not found")


class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    """Threaded HTTP Server for handling concurrent requests."""
    allow_reuse_address = True
    daemon_threads = True


def main():
    """Start the NetScope server."""
    server = ThreadedHTTPServer(('0.0.0.0', PORT), NetScopeHandler)

    # Print fancy banner
    info = get_local_network_info()
    banner = f"""
\033[36m╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   🌐  \033[1;37mNetScope - Network Intelligence Suite\033[36m                 ║
║                                                              ║
║   \033[0;36mServer running on:  \033[1;33mhttp://localhost:{PORT}\033[36m                  ║
║   \033[0;36mInterface:          \033[1;37m{info.get('interface', 'N/A'):<20}\033[36m              ║
║   \033[0;36mLocal IP:           \033[1;37m{info.get('local_ip', 'N/A'):<20}\033[36m              ║
║   \033[0;36mNetwork:            \033[1;37m{info.get('network', 'N/A'):<20}\033[36m              ║
║   \033[0;36mGateway:            \033[1;37m{info.get('gateway', 'N/A'):<20}\033[36m              ║
║                                                              ║
║   \033[0;32mPress Ctrl+C to stop the server\033[36m                          ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝\033[0m
"""
    print(banner)
    sys.stdout.flush()

    def signal_handler(sig, frame):
        print("\n\033[33m[NetScope]\033[0m Shutting down...")
        server.shutdown()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n\033[33m[NetScope]\033[0m Shutting down...")
        server.shutdown()


if __name__ == '__main__':
    main()
