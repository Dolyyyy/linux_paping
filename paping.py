#!/usr/bin/env python3
"""
Advanced Network Pentest Tool - Enhanced paping with comprehensive reconnaissance capabilities

Features:
- ICMP/TCP/UDP ping with detailed statistics
- WHOIS lookup with AS information
- DNS reconnaissance
- Port scanning
- Network topology discovery
- Service fingerprinting
- Comprehensive error handling

Usage:
  python3 paping.py 8.8.8.8
  python3 paping.py example.com --whois
  python3 paping.py 192.168.1.1 --scan-ports
  python3 paping.py target.com --full-recon
"""

import argparse
import asyncio
import concurrent.futures
import dns.resolver
import json
import os
import re
import socket
import struct
import sys
import time
import urllib.request
import urllib.error
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple, Any
from enum import Enum
import threading
from datetime import datetime

# ANSI colors for better output
class Colors:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    PURPLE = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

class Protocol(Enum):
    ICMP = "ICMP"
    TCP = "TCP"
    UDP = "UDP"

@dataclass
class PingResult:
    """Data class for storing ping results"""
    host: str
    ip: str
    protocol: Protocol
    port: Optional[int]
    rtt_ms: float
    timestamp: float
    success: bool
    error_message: Optional[str] = None

@dataclass
class WhoisInfo:
    """Data class for storing WHOIS information"""
    domain: str
    registrar: Optional[str]
    creation_date: Optional[str]
    expiration_date: Optional[str]
    as_number: Optional[str]
    as_name: Optional[str]
    country: Optional[str]
    organization: Optional[str]
    ip_range: Optional[str]

class NetworkError(Exception):
    """Custom exception for network-related errors"""
    pass

class PermissionError(Exception):
    """Custom exception for permission-related errors"""
    pass

class ICMPPinger:
    """ICMP ping implementation with raw sockets"""

    ICMP_ECHO_REQUEST = 8
    ICMP_ECHO_REPLY = 0

    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout
        self.ident = os.getpid() & 0xFFFF
        self.seq = 0

    def _checksum(self, data: bytes) -> int:
        """Compute ICMP checksum"""
        if len(data) % 2:
            data += b"\x00"
        s = sum(struct.unpack("!%dH" % (len(data)//2), data))
        s = (s >> 16) + (s & 0xffff)
        s += s >> 16
        return (~s) & 0xffff

    def ping(self, host: str) -> PingResult:
        """Perform ICMP ping to target host"""
        try:
            dst_ip = socket.gethostbyname(host)
        except socket.gaierror as e:
            return PingResult(
                host=host, ip="", protocol=Protocol.ICMP, port=None,
                rtt_ms=0.0, timestamp=time.time(), success=False,
                error_message=f"Cannot resolve {host}: {e}"
            )

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.settimeout(self.timeout)
        except PermissionError:
            return PingResult(
                host=host, ip=dst_ip, protocol=Protocol.ICMP, port=None,
                rtt_ms=0.0, timestamp=time.time(), success=False,
                error_message="ICMP requires root or CAP_NET_RAW (try sudo)"
            )

        try:
            self.seq = (self.seq + 1) & 0xFFFF
            payload = struct.pack("!d", time.perf_counter())
            header = struct.pack("!BBHHH", self.ICMP_ECHO_REQUEST, 0, 0, self.ident, self.seq)
            chksum = self._checksum(header + payload)
            packet = struct.pack("!BBHHH", self.ICMP_ECHO_REQUEST, 0, chksum, self.ident, self.seq) + payload

            start = time.perf_counter()
            sock.sendto(packet, (dst_ip, 0))

            while True:
                data, addr = sock.recvfrom(1024)
                icmp = data[20:28]
                if len(icmp) < 8:
                    continue
                _type, _code, _cs, _id, _seq = struct.unpack("!BBHHH", icmp)
                if _type == self.ICMP_ECHO_REPLY and _id == self.ident and _seq == self.seq:
                    end = time.perf_counter()
                    rtt_ms = (end - start) * 1000.0
                    return PingResult(
                        host=host, ip=dst_ip, protocol=Protocol.ICMP, port=None,
                        rtt_ms=rtt_ms, timestamp=time.time(), success=True
                    )

        except socket.timeout:
            return PingResult(
                host=host, ip=dst_ip, protocol=Protocol.ICMP, port=None,
                rtt_ms=0.0, timestamp=time.time(), success=False,
                error_message="Connection timed out"
            )
        except Exception as e:
            return PingResult(
                host=host, ip=dst_ip, protocol=Protocol.ICMP, port=None,
                rtt_ms=0.0, timestamp=time.time(), success=False,
                error_message=str(e)
            )
        finally:
            try:
                sock.close()
            except Exception:
                pass

class TCPUDPPinger:
    """TCP/UDP ping implementation"""

    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout

    def ping(self, host: str, port: int, protocol: Protocol) -> PingResult:
        """Perform TCP/UDP ping to target host and port"""
        try:
            dst_ip = socket.gethostbyname(host)
        except socket.gaierror as e:
            return PingResult(
                host=host, ip="", protocol=protocol, port=port,
                rtt_ms=0.0, timestamp=time.time(), success=False,
                error_message=f"Cannot resolve {host}: {e}"
            )

        sock = None
        try:
            if protocol == Protocol.UDP:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(self.timeout)
                start = time.perf_counter()
                sock.sendto(b"", (dst_ip, port))
                sock.recvfrom(1024)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                start = time.perf_counter()
                err = sock.connect_ex((dst_ip, port))
                if err != 0:
                    raise OSError(f"connect_ex errno={err}")

            end = time.perf_counter()
            rtt_ms = (end - start) * 1000.0
            return PingResult(
                host=host, ip=dst_ip, protocol=protocol, port=port,
                rtt_ms=rtt_ms, timestamp=time.time(), success=True
            )

        except Exception as e:
            return PingResult(
                host=host, ip=dst_ip, protocol=protocol, port=port,
                rtt_ms=0.0, timestamp=time.time(), success=False,
                error_message=str(e)
            )
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

class WhoisLookup:
    """WHOIS lookup with AS information using multiple APIs"""

    def __init__(self):
        self.apis = [
            "https://ipapi.co/{ip}/json/",
            "https://ipinfo.io/{ip}/json",
            "https://api.ipgeolocation.io/ipgeo?apiKey=free&ip={ip}"
        ]

    def get_whois_info(self, ip: str) -> WhoisInfo:
        """Get detailed WHOIS information for an IP address"""
        for api_url in self.apis:
            try:
                url = api_url.format(ip=ip)
                with urllib.request.urlopen(url, timeout=10) as response:
                    response_data = response.read().decode()
                    try:
                        data = json.loads(response_data)
                        if isinstance(data, dict):
                            return self._parse_api_response(data, ip)
                    except json.JSONDecodeError:
                        continue
            except (urllib.error.URLError, urllib.error.HTTPError, KeyError, Exception):
                continue

        # Fallback to basic socket-based lookup
        return self._basic_whois_lookup(ip)

    def _parse_api_response(self, data: Dict[str, Any], ip: str) -> WhoisInfo:
        """Parse API response and extract WHOIS information"""
        try:
            # Handle different API response formats
            domain = data.get('hostname', '') or data.get('reverse', '')
            registrar = data.get('org', '') or data.get('organization', '')

            # Handle nested timezone data
            creation_date = ''
            if 'timezone' in data and isinstance(data['timezone'], dict):
                creation_date = data['timezone'].get('current_time', '')

            # Handle AS information
            as_number = data.get('asn', '') or data.get('as', '')
            as_name = data.get('org', '') or data.get('as_name', '')

            # Handle country information
            country = data.get('country_name', '') or data.get('country', '')

            # Handle network information
            ip_range = data.get('network', '') or data.get('ip_range', '')

            return WhoisInfo(
                domain=domain,
                registrar=registrar,
                creation_date=creation_date,
                expiration_date='',
                as_number=as_number,
                as_name=as_name,
                country=country,
                organization=registrar,
                ip_range=ip_range
            )
        except Exception:
            # Fallback to basic info if parsing fails
            return WhoisInfo(
                domain=data.get('hostname', ''),
                registrar=data.get('org', ''),
                creation_date='',
                expiration_date='',
                as_number=data.get('asn', ''),
                as_name=data.get('org', ''),
                country=data.get('country_name', ''),
                organization=data.get('org', ''),
                ip_range=data.get('network', '')
            )

    def _basic_whois_lookup(self, ip: str) -> WhoisInfo:
        """Basic WHOIS lookup using socket"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except socket.herror:
            hostname = ''

        return WhoisInfo(
            domain=hostname,
            registrar='',
            creation_date='',
            expiration_date='',
            as_number='',
            as_name='',
            country='',
            organization='',
            ip_range=''
        )

class DNSReconnaissance:
    """DNS reconnaissance and enumeration"""

    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 10

    def get_dns_info(self, domain: str) -> Dict[str, Any]:
        """Get comprehensive DNS information for a domain"""
        results = {}

        # Common record types to check
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']

        for record_type in record_types:
            try:
                answers = self.resolver.resolve(domain, record_type)
                results[record_type] = [str(answer) for answer in answers]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                results[record_type] = []

        return results

    def reverse_dns_lookup(self, ip: str) -> str:
        """Perform reverse DNS lookup"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except socket.herror:
            return ""

class PortScanner:
    """Port scanning capabilities"""

    def __init__(self, timeout: float = 1.0, max_workers: int = 100):
        self.timeout = timeout
        self.max_workers = max_workers
        self.common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 3389, 5432, 8080, 8443, 30120, 30121, 30122, 40120, 40121, 40122, 9999]

    def scan_ports(self, host: str, ports: Optional[List[int]] = None) -> Dict[int, bool]:
        """Scan ports on target host"""
        if ports is None:
            ports = self.common_ports

        results = {}

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_port = {
                executor.submit(self._check_port, host, port): port
                for port in ports
            }

            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    results[port] = future.result()
                except Exception:
                    results[port] = False

        return results

    def _check_port(self, host: str, port: int) -> bool:
        """Check if a specific port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception:
            return False

class NetworkPentestTool:
    """Main pentest tool class that orchestrates all functionality"""

    def __init__(self):
        self.icmp_pinger = ICMPPinger()
        self.tcp_udp_pinger = TCPUDPPinger()
        self.whois_lookup = WhoisLookup()
        self.dns_recon = DNSReconnaissance()
        self.port_scanner = PortScanner()
        self.results = []

    def ping_target(self, host: str, protocol: Protocol = Protocol.ICMP,
                   port: Optional[int] = None, count: Optional[int] = None,
                   interval: float = 1.0) -> List[PingResult]:
        """Perform ping operations on target"""
        results = []
        i = 0

        try:
            while count is None or i < count:
                i += 1

                if protocol == Protocol.ICMP:
                    result = self.icmp_pinger.ping(host)
                else:
                    result = self.tcp_udp_pinger.ping(host, port, protocol)

                results.append(result)
                self._print_ping_result(result)

                if count is None or i < count:
                    time.sleep(interval)

        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}Interrupted by user{Colors.RESET}")

        return results

    def full_reconnaissance(self, target: str) -> Dict[str, Any]:
        """Perform full reconnaissance on target"""
        print(f"{Colors.BOLD}{Colors.CYAN}=== FULL RECONNAISSANCE: {target} ==={Colors.RESET}\n")

        # Resolve IP
        try:
            ip = socket.gethostbyname(target)
            print(f"{Colors.GREEN}IP Address: {ip}{Colors.RESET}")
        except socket.gaierror as e:
            print(f"{Colors.RED}Failed to resolve {target}: {e}{Colors.RESET}")
            return {}

        results = {
            'target': target,
            'ip': ip,
            'timestamp': datetime.now().isoformat()
        }

        # WHOIS Information
        print(f"\n{Colors.BOLD}WHOIS Information:{Colors.RESET}")
        whois_info = self.whois_lookup.get_whois_info(ip)
        self._print_whois_info(whois_info)
        results['whois'] = whois_info.__dict__

        # DNS Reconnaissance
        print(f"\n{Colors.BOLD}DNS Information:{Colors.RESET}")
        dns_info = self.dns_recon.get_dns_info(target)
        self._print_dns_info(dns_info)
        results['dns'] = dns_info

        # Reverse DNS
        reverse_dns = self.dns_recon.reverse_dns_lookup(ip)
        if reverse_dns:
            print(f"{Colors.GREEN}Reverse DNS: {reverse_dns}{Colors.RESET}")
            results['reverse_dns'] = reverse_dns

        # Port Scan
        print(f"\n{Colors.BOLD}Port Scan Results:{Colors.RESET}")
        port_results = self.port_scanner.scan_ports(ip)
        self._print_port_scan_results(port_results)
        results['ports'] = port_results

        # ICMP Ping
        print(f"\n{Colors.BOLD}ICMP Ping Test:{Colors.RESET}")
        ping_results = self.ping_target(target, Protocol.ICMP, count=3)
        results['ping'] = [r.__dict__ for r in ping_results]

        return results

    def _print_ping_result(self, result: PingResult):
        """Print formatted ping result"""
        if result.success:
            protocol_str = f"{result.protocol.value}"
            if result.port:
                protocol_str += f":{result.port}"

            print(f"Connected to {Colors.GREEN}{result.ip}{Colors.RESET}: "
                  f"time={Colors.GREEN}{result.rtt_ms:.2f}ms{Colors.RESET} "
                  f"protocol={Colors.GREEN}{protocol_str}{Colors.RESET}")
        else:
            print(f"{Colors.RED}Connection failed: {result.error_message}{Colors.RESET}")

    def _print_whois_info(self, whois_info: WhoisInfo):
        """Print formatted WHOIS information"""
        if whois_info.domain:
            print(f"{Colors.GREEN}Domain: {whois_info.domain}{Colors.RESET}")
        if whois_info.organization:
            print(f"{Colors.GREEN}Organization: {whois_info.organization}{Colors.RESET}")
        if whois_info.as_number:
            print(f"{Colors.GREEN}AS Number: {whois_info.as_number}{Colors.RESET}")
        if whois_info.as_name:
            print(f"{Colors.GREEN}AS Name: {whois_info.as_name}{Colors.RESET}")
        if whois_info.country:
            print(f"{Colors.GREEN}Country: {whois_info.country}{Colors.RESET}")
        if whois_info.ip_range:
            print(f"{Colors.GREEN}IP Range: {whois_info.ip_range}{Colors.RESET}")

        # If no information found, show a message
        if not any([whois_info.domain, whois_info.organization, whois_info.as_number,
                   whois_info.as_name, whois_info.country, whois_info.ip_range]):
            print(f"{Colors.YELLOW}No detailed WHOIS information available{Colors.RESET}")

    def _print_dns_info(self, dns_info: Dict[str, Any]):
        """Print formatted DNS information"""
        for record_type, records in dns_info.items():
            if records:
                print(f"{Colors.GREEN}{record_type}: {', '.join(records)}{Colors.RESET}")

    def _print_port_scan_results(self, port_results: Dict[int, bool]):
        """Print formatted port scan results"""
        open_ports = [port for port, is_open in port_results.items() if is_open]
        closed_ports = [port for port, is_open in port_results.items() if not is_open]

        if open_ports:
            print(f"{Colors.GREEN}Open ports: {', '.join(map(str, sorted(open_ports)))}{Colors.RESET}")
        if closed_ports:
            print(f"{Colors.RED}Closed ports: {', '.join(map(str, sorted(closed_ports)))}{Colors.RESET}")

def main():
    """Main CLI interface"""
    parser = argparse.ArgumentParser(
        description="Advanced Network Pentest Tool - Enhanced paping with reconnaissance capabilities",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 paping.py 8.8.8.8                    # Basic ICMP ping
  python3 paping.py example.com --whois        # WHOIS lookup
  python3 paping.py 192.168.1.1 --scan-ports   # Port scan
  python3 paping.py target.com --full-recon    # Full reconnaissance
  python3 paping.py 8.8.8.8 -p 443 -c 5       # TCP ping to port 443
  python3 paping.py 8.8.8.8 -p 53 -u          # UDP ping to port 53
        """
    )

    parser.add_argument("target", help="Target host or IP address")
    parser.add_argument("-p", "--port", type=int, help="Port number (enables TCP/UDP mode)")
    parser.add_argument("-u", "--udp", action="store_true", help="Use UDP instead of TCP (when -p is given)")
    parser.add_argument("-c", "--count", type=int, help="Number of probes (default: infinite)")
    parser.add_argument("-i", "--interval", type=float, default=1.0, help="Interval between probes in seconds")
    parser.add_argument("-t", "--timeout", type=float, default=3.0, help="Timeout in seconds")
    parser.add_argument("--whois", action="store_true", help="Perform WHOIS lookup")
    parser.add_argument("--scan-ports", action="store_true", help="Scan common ports")
    parser.add_argument("--full-recon", action="store_true", help="Perform full reconnaissance")
    parser.add_argument("--ports", nargs='+', type=int, help="Custom port list for scanning")
    parser.add_argument("-o", "--output", help="Save results to JSON file")

    args = parser.parse_args()

    # Initialize the pentest tool
    tool = NetworkPentestTool()

    try:
        if args.full_recon:
            # Full reconnaissance mode
            results = tool.full_reconnaissance(args.target)

            # Save results if output file specified
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(results, f, indent=2, default=str)
                print(f"\n{Colors.GREEN}Results saved to {args.output}{Colors.RESET}")

        elif args.whois:
            # WHOIS lookup mode
            try:
                ip = socket.gethostbyname(args.target)
                print(f"{Colors.GREEN}IP Address: {ip}{Colors.RESET}")
                whois_info = tool.whois_lookup.get_whois_info(ip)
                tool._print_whois_info(whois_info)
            except socket.gaierror as e:
                print(f"{Colors.RED}Failed to resolve {args.target}: {e}{Colors.RESET}")
                sys.exit(1)
            except Exception as e:
                print(f"{Colors.RED}Error during WHOIS lookup: {e}{Colors.RESET}")
                sys.exit(1)

        elif args.scan_ports:
            # Port scanning mode
            try:
                ip = socket.gethostbyname(args.target)
                ports = args.ports if args.ports else None
                port_results = tool.port_scanner.scan_ports(ip, ports)
                tool._print_port_scan_results(port_results)
            except socket.gaierror as e:
                print(f"{Colors.RED}Failed to resolve {args.target}: {e}{Colors.RESET}")
                sys.exit(1)

        else:
            # Ping mode
            if args.port is None:
                # ICMP ping
                tool.ping_target(args.target, Protocol.ICMP, count=args.count, interval=args.interval)
            else:
                # TCP/UDP ping
                protocol = Protocol.UDP if args.udp else Protocol.TCP
                tool.ping_target(args.target, protocol, args.port, args.count, args.interval)

    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Operation interrupted by user{Colors.RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.RED}Unexpected error: {e}{Colors.RESET}")
        sys.exit(1)

if __name__ == "__main__":
    main()
