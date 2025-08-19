#!/usr/bin/env python3
"""
paping - A paping-like TCP/UDP/ICMP ping tool for Linux

Behavior
- No port specified  -> ICMP mode (raw sockets), paping-styled output.
- -p/--port given    -> TCP mode by default, UDP if -u/--udp.
- Infinite by default; stop with Ctrl+C.

Examples
  paping 8.8.8.8
  paping 8.8.8.8 -p 443
  paping 8.8.8.8 -p 53 -u
"""

import argparse, os, socket, struct, time, sys

# ANSI colors
GREEN = "\033[92m"   # light green
RED   = "\033[91m"
RESET = "\033[0m"

# ------------------------- ICMP helpers -------------------------

ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY   = 0

def _checksum(data: bytes) -> int:
    """Compute ICMP checksum."""
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data)//2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return (~s) & 0xffff

def icmp_ping(host: str, count=None, interval: float = 1.0, timeout: float = 3.0):
    """Raw ICMP echo, paping-style output (needs root or CAP_NET_RAW)."""
    try:
        dst_ip = socket.gethostbyname(host)
    except socket.gaierror as e:
        print(f"{RED}Cannot resolve {host}: {e}{RESET}")
        sys.exit(2)

    ident = os.getpid() & 0xFFFF
    seq = 0

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.settimeout(timeout)
    except PermissionError:
        print(f"{RED}ICMP requires root or CAP_NET_RAW (try sudo).{RESET}")
        sys.exit(1)

    sent = 0
    received = 0

    try:
        i = 0
        while count is None or i < count:
            i += 1
            seq = (seq + 1) & 0xFFFF
            # payload: current monotonic time (double)
            payload = struct.pack("!d", time.perf_counter())
            header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, 0, ident, seq)
            chksum = _checksum(header + payload)
            packet = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, chksum, ident, seq) + payload

            sent += 1
            start = time.perf_counter()
            try:
                sock.sendto(packet, (dst_ip, 0))
                # wait for reply
                while True:
                    data, addr = sock.recvfrom(1024)
                    # IP header is variable; ICMP starts after it.
                    # We just look at the last 8+payload bytes for echo reply.
                    icmp = data[20:28]  # works for no-IP-options packets (common)
                    if len(icmp) < 8:
                        continue
                    _type, _code, _cs, _id, _seq = struct.unpack("!BBHHH", icmp)
                    if _type == ICMP_ECHO_REPLY and _id == ident and _seq == seq:
                        end = time.perf_counter()
                        rtt_ms = (end - start) * 1000.0
                        received += 1
                        print(
                            f"Connected to {GREEN}{dst_ip}{RESET}: "
                            f"time={GREEN}{rtt_ms:.2f}ms{RESET} "
                            f"protocol={GREEN}ICMP{RESET}"
                        )
                        break
            except socket.timeout:
                print(f"{RED}Connection timed out{RESET}")
            except KeyboardInterrupt:
                break

            if count is None or i < count:
                try:
                    time.sleep(interval)
                except KeyboardInterrupt:
                    break
    finally:
        try: sock.close()
        except Exception: pass

# ------------------------- TCP/UDP -------------------------

def tcp_udp_ping(host: str, port: int, count=None, interval: float = 1.0, timeout: float = 3.0, udp: bool = False):
    proto = "UDP" if udp else "TCP"
    try:
        dst_ip = socket.gethostbyname(host)
    except socket.gaierror as e:
        print(f"{RED}Cannot resolve {host}: {e}{RESET}")
        sys.exit(2)

    i = 0
    while count is None or i < count:
        i += 1
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM)
        s.settimeout(timeout)
        start = time.perf_counter()
        try:
            if udp:
                s.sendto(b"", (dst_ip, port))
                s.recvfrom(1024)  # most servers won't reply; expect timeout
            else:
                err = s.connect_ex((dst_ip, port))
                if err != 0:
                    raise OSError(f"connect_ex errno={err}")
            end = time.perf_counter()
            rtt_ms = (end - start) * 1000.0
            print(
                f"Connected to {GREEN}{dst_ip}{RESET}: "
                f"time={GREEN}{rtt_ms:.2f}ms{RESET} "
                f"protocol={GREEN}{proto}{RESET} "
                f"port={GREEN}{port}{RESET}"
            )
        except Exception:
            print(f"{RED}Connection timed out{RESET}")
        finally:
            s.close()

        if count is None or i < count:
            try:
                time.sleep(interval)
            except KeyboardInterrupt:
                break

# ------------------------- CLI -------------------------

def main():
    ap = argparse.ArgumentParser(description="paping - paping-like TCP/UDP/ICMP ping for Linux")
    ap.add_argument("host", help="Host or IP to ping")
    ap.add_argument("-p", "--port", type=int, help="Port number (enables TCP mode by default)")
    ap.add_argument("-u", "--udp", action="store_true", help="Use UDP instead of TCP (when -p is given)")
    ap.add_argument("-c", "--count", type=int, help="Number of probes (default: infinite)")
    ap.add_argument("-i", "--interval", type=float, default=1.0, help="Interval between probes in seconds")
    ap.add_argument("-t", "--timeout", type=float, default=3.0, help="Timeout in seconds")
    args = ap.parse_args()

    if args.port is None:
        icmp_ping(args.host, args.count, args.interval, args.timeout)
    else:
        tcp_udp_ping(args.host, args.port, args.count, args.interval, args.timeout, args.udp)

if __name__ == "__main__":
    main()
