"""
Port Scanner - Active TCP Port Scanning

Performs TCP port scanning on discovered live hosts.

⚠️  WARNING: Port scanning without authorization is ILLEGAL
Always obtain explicit written permission before scanning.
"""

import socket
import logging
from typing import Dict, List, Set, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import time


class PortScanner:
    """
    Active TCP port scanner for discovered hosts.

    Supports:
    - Common ports (fast)
    - Top 1000 ports (moderate)
    - Full port range (slow - 65535 ports)
    """

    # Common ports to scan (quick scan)
    COMMON_PORTS = {
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        143: 'IMAP',
        443: 'HTTPS',
        445: 'SMB',
        465: 'SMTPS',
        587: 'SMTP',
        993: 'IMAPS',
        995: 'POP3S',
        1433: 'MSSQL',
        3306: 'MySQL',
        3389: 'RDP',
        5432: 'PostgreSQL',
        5900: 'VNC',
        6379: 'Redis',
        8000: 'HTTP-Alt',
        8080: 'HTTP-Proxy',
        8443: 'HTTPS-Alt',
        8888: 'HTTP-Alt',
        9200: 'Elasticsearch',
        27017: 'MongoDB'
    }

    # Top 100 ports (medium scan)
    TOP_100_PORTS = [
        7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106,
        110, 111, 113, 119, 135, 139, 143, 144, 179, 199, 389, 427,
        443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554, 587,
        631, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029,
        1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121,
        2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051,
        5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000,
        6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888,
        9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156, 49157
    ]

    def __init__(self, config: Dict):
        """
        Initialize the port scanner.

        Args:
            config: Configuration dictionary with scan settings
        """
        self.config = config
        self.logger = logging.getLogger(__name__)

        self.scan_type = config.get('scan_type', 'common')  # common, top100, top1000, full
        self.custom_ports = config.get('ports', [])
        self.timeout = config.get('timeout', 2)
        self.max_workers = config.get('threads', 50)
        self.rate_limit = config.get('rate_limit', 100)  # ports per second

        # Determine ports to scan
        self.ports_to_scan = self._get_ports_list()

    def _get_ports_list(self) -> List[int]:
        """
        Get list of ports to scan based on configuration.

        Returns:
            List of port numbers
        """
        if self.custom_ports:
            return sorted(self.custom_ports)

        if self.scan_type == 'common':
            return sorted(self.COMMON_PORTS.keys())
        elif self.scan_type == 'top100':
            return sorted(self.TOP_100_PORTS)
        elif self.scan_type == 'top1000':
            # For top1000, we'd need to import from nmap-services or similar
            # For now, return top100 + common
            return sorted(set(self.TOP_100_PORTS) | set(self.COMMON_PORTS.keys()))
        elif self.scan_type == 'full':
            self.logger.warning("Full port scan (1-65535) will take a VERY long time!")
            return list(range(1, 65536))
        else:
            return sorted(self.COMMON_PORTS.keys())

    def scan_hosts(self, hosts: List[Dict]) -> List[Dict]:
        """
        Scan ports for a list of hosts.

        Args:
            hosts: List of host dictionaries (from subdomain prober)

        Returns:
            List of scan results with open ports
        """
        if not hosts:
            self.logger.info("No hosts to scan")
            return []

        self.logger.info(f"Scanning {len(hosts)} hosts for open ports...")
        self.logger.info(f"Scan type: {self.scan_type} ({len(self.ports_to_scan)} ports per host)")

        results = []

        for host_info in hosts:
            subdomain = host_info.get('subdomain')
            ip_addresses = host_info.get('dns_records', {}).get('A', [])

            if not ip_addresses:
                self.logger.debug(f"No IP addresses for {subdomain}, skipping port scan")
                continue

            # Scan first IP address
            target = ip_addresses[0]
            self.logger.info(f"Scanning {subdomain} ({target})...")

            open_ports = self._scan_target(target)

            if open_ports:
                result = {
                    'subdomain': subdomain,
                    'ip': target,
                    'open_ports': open_ports,
                    'scan_type': self.scan_type,
                    'total_scanned': len(self.ports_to_scan),
                    'total_open': len(open_ports)
                }
                results.append(result)

                self.logger.info(f"  Found {len(open_ports)} open ports on {subdomain}")

        self.logger.info(f"Port scan complete: {len(results)} hosts with open ports")

        return results

    def _scan_target(self, target: str) -> List[Dict]:
        """
        Scan a single target for open ports.

        Args:
            target: IP address or hostname to scan

        Returns:
            List of open port dictionaries
        """
        open_ports = []
        scan_start = time.time()

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_port = {
                executor.submit(self._scan_port, target, port): port
                for port in self.ports_to_scan
            }

            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    is_open, banner = future.result()
                    if is_open:
                        port_info = {
                            'port': port,
                            'service': self.COMMON_PORTS.get(port, 'unknown'),
                            'banner': banner
                        }
                        open_ports.append(port_info)
                except Exception as e:
                    self.logger.debug(f"Error scanning port {port}: {e}")

                # Rate limiting
                elapsed = time.time() - scan_start
                ports_scanned = len([f for f in future_to_port if f.done()])
                if ports_scanned > 0:
                    current_rate = ports_scanned / max(elapsed, 0.001)
                    if current_rate > self.rate_limit:
                        time.sleep(0.1)

        return sorted(open_ports, key=lambda x: x['port'])

    def _scan_port(self, target: str, port: int) -> tuple:
        """
        Scan a single port on a target.

        Args:
            target: IP address or hostname
            port: Port number to scan

        Returns:
            Tuple of (is_open: bool, banner: str or None)
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        try:
            result = sock.connect_ex((target, port))

            if result == 0:
                # Port is open, try to grab banner
                banner = self._grab_banner(sock, port)
                sock.close()
                return True, banner
            else:
                sock.close()
                return False, None

        except socket.timeout:
            sock.close()
            return False, None
        except socket.error:
            sock.close()
            return False, None
        except Exception as e:
            sock.close()
            self.logger.debug(f"Error scanning {target}:{port} - {e}")
            return False, None

    def _grab_banner(self, sock: socket.socket, port: int) -> Optional[str]:
        """
        Attempt to grab banner from an open port.

        Args:
            sock: Connected socket
            port: Port number

        Returns:
            Banner string or None
        """
        try:
            # Some services send banner immediately
            sock.settimeout(1)
            try:
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                if banner:
                    return banner[:200]  # Limit length
            except socket.timeout:
                pass

            # For HTTP/HTTPS, send a request
            if port in [80, 8080, 8000, 8888]:
                sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                if banner:
                    # Extract Server header
                    for line in banner.split('\n'):
                        if line.lower().startswith('server:'):
                            return line.split(':', 1)[1].strip()[:200]

            # For SSH, banner is sent immediately
            # For FTP, banner is sent immediately
            # For SMTP, banner is sent immediately

        except Exception as e:
            self.logger.debug(f"Error grabbing banner on port {port}: {e}")

        return None

    def format_results(self, scan_results: List[Dict]) -> str:
        """
        Format port scan results for display.

        Args:
            scan_results: List of scan result dictionaries

        Returns:
            Formatted string for logging/display
        """
        if not scan_results:
            return "No open ports found on any hosts"

        output = []
        output.append(f"\n{'='*70}")
        output.append(f"PORT SCAN RESULTS ({len(scan_results)} hosts with open ports)")
        output.append(f"{'='*70}\n")

        for result in scan_results:
            output.append(f"Host: {result['subdomain']} ({result['ip']})")
            output.append(f"Open Ports: {result['total_open']}/{result['total_scanned']} scanned")
            output.append("")

            for port_info in result['open_ports']:
                port_line = f"  {port_info['port']}/tcp"
                if port_info['service'] != 'unknown':
                    port_line += f"  {port_info['service']}"
                if port_info['banner']:
                    port_line += f"  - {port_info['banner']}"

                output.append(port_line)

            output.append("")  # Blank line between hosts

        return "\n".join(output)
