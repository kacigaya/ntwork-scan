"""Network scanning tool for device discovery, port scanning, and vulnerability analysis."""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import logging
import socket
from typing import Any

import nmap
import scapy.all as scapy

logger = logging.getLogger(__name__)

COMMON_VULNERABILITIES: dict[int, dict[str, str]] = {
    21: {"description": "FTP - Potential anonymous login vulnerability", "severity": "Medium"},
    22: {"description": "SSH - Check for weak ciphers and brute-forcing", "severity": "Medium"},
    23: {"description": "Telnet - Clear text communication vulnerability", "severity": "High"},
    25: {"description": "SMTP - Open relay and outdated version vulnerabilities", "severity": "Medium"},
    53: {"description": "DNS - Zone transfer and cache poisoning vulnerabilities", "severity": "Medium"},
    80: {"description": "HTTP - Check for outdated web server software and vulnerabilities", "severity": "Medium"},
    110: {"description": "POP3 - Clear text authentication vulnerability", "severity": "Medium"},
    143: {"description": "IMAP - Clear text authentication and outdated version vulnerabilities", "severity": "Medium"},
    443: {"description": "HTTPS - Check for SSL/TLS vulnerabilities", "severity": "Medium"},
    445: {"description": "SMB - Remote code execution and outdated version vulnerabilities", "severity": "High"},
    1433: {"description": "MS SQL Server - Default credentials and outdated version vulnerabilities", "severity": "High"},
    3306: {"description": "MySQL - Weak authentication and outdated version vulnerabilities", "severity": "Medium"},
    3389: {"description": "RDP - BlueKeep and other remote desktop vulnerabilities", "severity": "High"},
    5432: {"description": "PostgreSQL - Weak authentication and outdated version vulnerabilities", "severity": "Medium"},
    8080: {"description": "HTTP Alternate - Web application vulnerabilities", "severity": "Medium"},
    27017: {"description": "MongoDB - Unauthenticated access and default configuration vulnerabilities", "severity": "High"},
}


def _resolve_hostname(ip_address: str) -> str:
    """Resolve an IP address to a hostname, returning 'Unknown' on failure."""
    try:
        return socket.gethostbyaddr(ip_address)[0]
    except socket.herror:
        return "Unknown"


def discover_devices(target_network: str, scan_type: str = "arp") -> list[dict[str, str]]:
    """Discover devices on the network using ARP or PING scanning.

    Args:
        target_network: Target network in CIDR notation (e.g. '192.168.1.0/24').
        scan_type: Scan method to use ('arp' or 'ping').

    Returns:
        A list of dictionaries containing device information (ip, mac, hostname).
    """
    devices: list[dict[str, str]] = []

    if scan_type == "arp":
        arp_req_frame = scapy.ARP(pdst=target_network)
        broadcast_frame = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        broadcast_req_frame = broadcast_frame / arp_req_frame
        answered_list = scapy.srp(broadcast_req_frame, timeout=1, verbose=False)[0]
        for element in answered_list:
            device = {
                "ip": element[1].psrc,
                "mac": element[1].hwsrc,
                "hostname": _resolve_hostname(element[1].psrc),
            }
            devices.append(device)

    elif scan_type == "ping":
        for ip in ipaddress.IPv4Network(target_network):
            try:
                response = scapy.IP(dst=str(ip)) / scapy.ICMP()
                ans = scapy.sr1(response, timeout=1, verbose=False)
                if ans:
                    arp_req = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=str(ip))
                    arp_ans = scapy.srp1(arp_req, timeout=1, verbose=False)
                    mac = arp_ans[scapy.ARP].hwsrc if arp_ans else "Unknown"
                    devices.append({
                        "ip": str(ip),
                        "mac": mac,
                        "hostname": _resolve_hostname(str(ip)),
                    })
            except OSError as e:
                logger.warning("Error scanning %s: %s", ip, e)

    return devices


def scan_ports(ip_address: str, port_range: str) -> list[dict[str, Any]]:
    """Scan ports on a target IP address using nmap.

    Args:
        ip_address: Target IP address to scan.
        port_range: Port range string (e.g. '1-1024').

    Returns:
        A list of dictionaries describing open ports.
    """
    try:
        nm = nmap.PortScanner()
        nm.scan(ip_address, port_range)
        open_ports: list[dict[str, Any]] = []
        for host in nm.all_hosts():
            if nm[host].state() == "up":
                for protocol in nm[host].all_protocols():
                    for port in nm[host][protocol]:
                        port_info = nm[host][protocol][port]
                        if port_info["state"] == "open":
                            open_ports.append({
                                "port": port,
                                "protocol": protocol,
                                "service": port_info["name"],
                                "version": port_info.get("version", "Unknown"),
                            })
        return open_ports
    except nmap.PortScannerError as e:
        logger.error("Error scanning ports on %s: %s", ip_address, e)
        return []


def basic_vulnerability_check(open_ports: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Check open ports against a database of common vulnerabilities.

    Args:
        open_ports: List of open port dictionaries from scan_ports().

    Returns:
        A list of vulnerability dictionaries with description and severity.
    """
    vulnerabilities: list[dict[str, str]] = []
    for port_info in open_ports:
        port = port_info["port"]
        if port in COMMON_VULNERABILITIES:
            vulnerabilities.append(COMMON_VULNERABILITIES[port])
    return vulnerabilities


def generate_report(devices: list[dict[str, str]], port_range: str) -> list[dict[str, Any]]:
    """Generate a full scan report for all discovered devices.

    Args:
        devices: List of device dictionaries from discover_devices().
        port_range: Port range string to scan on each device.

    Returns:
        A list of device report dictionaries including open ports and vulnerabilities.
    """
    report: list[dict[str, Any]] = []
    for device in devices:
        device_report: dict[str, Any] = device.copy()
        open_ports = scan_ports(device["ip"], port_range)
        device_report["open_ports"] = open_ports
        device_report["vulnerabilities"] = basic_vulnerability_check(open_ports)
        report.append(device_report)
    return report


def save_report(report: list[dict[str, Any]], output_file: str, output_format: str) -> bool:
    """Save the scan report to a file in the specified format.

    Args:
        report: The scan report data to save.
        output_file: Path to the output file.
        output_format: Format to use ('json', 'csv', or 'txt').

    Returns:
        True if the report was saved successfully, False otherwise.
    """
    try:
        if output_format == "json":
            with open(output_file, "w") as f:
                json.dump(report, f, indent=4)
        elif output_format == "csv":
            with open(output_file, "w", newline="") as f:
                writer = csv.writer(f)
                headers = [
                    "IP", "MAC", "Hostname", "Port", "Protocol",
                    "Service", "Version", "Vulnerability Description", "Severity",
                ]
                writer.writerow(headers)
                for device in report:
                    for port in device.get("open_ports", []):
                        for vuln in device.get("vulnerabilities", []):
                            writer.writerow([
                                device["ip"],
                                device["mac"],
                                device["hostname"],
                                port["port"],
                                port["protocol"],
                                port["service"],
                                port["version"],
                                vuln["description"],
                                vuln["severity"],
                            ])
        elif output_format == "txt":
            with open(output_file, "w") as f:
                for device in report:
                    f.write(f"\nDevice Information:\n")
                    f.write(f"  IP Address: {device['ip']}\n")
                    f.write(f"  MAC Address: {device['mac']}\n")
                    f.write(f"  Hostname: {device['hostname']}\n\n")

                    f.write("  Open Ports:\n")
                    for port in device.get("open_ports", []):
                        f.write(f"    Port {port['port']} ({port['protocol']}):\n")
                        f.write(f"      Service: {port['service']}\n")
                        f.write(f"      Version: {port['version']}\n")

                    f.write("\n  Vulnerabilities:\n")
                    for vuln in device.get("vulnerabilities", []):
                        f.write(f"    {vuln['description']}\n")
                        f.write(f"    Severity: {vuln['severity']}\n\n")
                    f.write("-" * 50 + "\n")
    except IOError as e:
        logger.error("Error saving report to %s: %s", output_file, e)
        return False
    return True


def main() -> None:
    """Entry point for the ntwork-scan command-line tool."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    parser = argparse.ArgumentParser(description="Network Scanner - Discover devices, scan ports, and check vulnerabilities")
    parser.add_argument("-t", "--target", dest="target_network", required=True, help="Target network or IP range (e.g. 192.168.1.0/24)")
    parser.add_argument("-s", "--scan_type", dest="scan_type", default="arp", choices=["arp", "ping"], help="Scan type (default: arp)")
    parser.add_argument("-p", "--port_range", dest="port_range", default="1-1024", help="Port range to scan (default: 1-1024)")
    parser.add_argument("-o", "--output", dest="output_file", default="report.json", help="Output file (default: report.json)")
    parser.add_argument("-f", "--format", dest="output_format", default="json", choices=["json", "csv", "txt"], help="Output format (default: json)")
    args = parser.parse_args()

    devices = discover_devices(args.target_network, args.scan_type)
    report = generate_report(devices, args.port_range)
    if save_report(report, args.output_file, args.output_format):
        logger.info("Scan complete. Report saved to %s", args.output_file)
    else:
        logger.error("Failed to save report.")


if __name__ == "__main__":
    main()