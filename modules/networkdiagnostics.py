"""
ROGUEBYTE Network Diagnostics Module
Safe network connectivity checks, TCP handshake latency, DNS timing, and export capabilities.
"""

import socket
import time
import json
import csv
import io
import platform
import subprocess
from typing import Dict, Any, List, Optional
from ..core.security import SecurityValidator, SecurityViolationException
from ..config.settings import DEFAULT_ALLOWLIST

class NetworkDiagnostics:
    def __init__(self, allowlist: Optional[List[str]] = None):
        self.allowlist = allowlist if allowlist is not None else DEFAULT_ALLOWLIST

    def get_local_interfaces(self) -> List[Dict[str, str]]:
        """Retrieve local network interfaces and IP configurations."""
        results = []
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            results.append({
                "interface": "Primary Host",
                "hostname": hostname,
                "ip": local_ip,
                "family": "IPv4"
            })
        except Exception:
            results.append({
                "interface": "Primary Host",
                "hostname": "localhost",
                "ip": "127.0.0.1",
                "family": "IPv4"
            })

        # Discover all IPs
        try:
            fqdn = socket.getfqdn()
            _, _, ip_list = socket.gethostbyname_ex(fqdn)
            for ip in ip_list:
                if ip not in [r["ip"] for r in results]:
                    results.append({
                        "interface": "Network Adapter",
                        "hostname": fqdn,
                        "ip": ip,
                        "family": "IPv4"
                    })
        except Exception:
            pass

        return results

    def resolve_dns(self, hostname: str) -> Dict[str, Any]:
        """Measure DNS resolution timing and return resolved addresses."""
        # Validate target
        SecurityValidator.validate_target_host(hostname, self.allowlist)

        t_start = time.perf_counter()
        try:
            addr_info = socket.getaddrinfo(hostname, None)
            duration_ms = (time.perf_counter() - t_start) * 1000.0
            resolved_ips = list({entry[4][0] for entry in addr_info})
            return {
                "hostname": hostname,
                "status": "SUCCESS",
                "dns_time_ms": round(duration_ms, 2),
                "resolved_ips": resolved_ips,
                "error": None
            }
        except socket.gaierror as e:
            duration_ms = (time.perf_counter() - t_start) * 1000.0
            return {
                "hostname": hostname,
                "status": "FAILED",
                "dns_time_ms": round(duration_ms, 2),
                "resolved_ips": [],
                "error": str(e)
            }

    def check_tcp_port(self, host: str, port: int, timeout_sec: float = 2.0) -> Dict[str, Any]:
        """
        Perform a safe TCP 3-way handshake to measure connection latency.
        Closes socket immediately upon connection without payload transmission.
        """
        # Security checks
        SecurityValidator.validate_target_host(host, self.allowlist)
        port = SecurityValidator.validate_port(port)

        t_start = time.perf_counter()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout_sec)
        try:
            sock.connect((host, port))
            latency_ms = (time.perf_counter() - t_start) * 1000.0
            sock.close()
            return {
                "host": host,
                "port": port,
                "status": "OPEN",
                "latency_ms": round(latency_ms, 2),
                "error": None
            }
        except socket.timeout:
            return {
                "host": host,
                "port": port,
                "status": "TIMEOUT",
                "latency_ms": None,
                "error": f"Connection timed out after {timeout_sec}s"
            }
        except ConnectionRefusedError:
            latency_ms = (time.perf_counter() - t_start) * 1000.0
            return {
                "host": host,
                "port": port,
                "status": "REFUSED",
                "latency_ms": round(latency_ms, 2),
                "error": "Connection refused by target port"
            }
        except Exception as e:
            return {
                "host": host,
                "port": port,
                "status": "ERROR",
                "latency_ms": None,
                "error": str(e)
            }
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def run_icmp_or_socket_ping(self, host: str, count: int = 4, timeout_sec: float = 2.0) -> Dict[str, Any]:
        """
        Measure ping latency and packet loss. Uses ping CLI safely via subprocess list
        or falls back to TCP handshake latency on port 80/443/53.
        """
        SecurityValidator.validate_target_host(host, self.allowlist)
        count = max(1, min(count, 10))

        system = platform.system()
        ping_cmd = ["ping", "-n" if system == "Windows" else "-c", str(count), "-W" if system != "Windows" else "-w", str(int(timeout_sec * 1000)), host]

        try:
            proc = subprocess.run(
                ping_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout_sec * count + 2.0
            )
            output = proc.stdout
            # Calculate metrics
            packet_loss = 0.0
            avg_rtt = 0.0
            if "loss" in output.lower():
                for line in output.splitlines():
                    if "loss" in line.lower() or "lost" in line.lower():
                        if "%" in line:
                            try:
                                pct_part = line.split("%")[0].split()[-1]
                                packet_loss = float(pct_part.replace("(", "").replace(",", ""))
                            except Exception:
                                pass
            return {
                "host": host,
                "packets_transmitted": count,
                "packet_loss_pct": packet_loss,
                "output": output,
                "status": "SUCCESS" if proc.returncode == 0 else "PARTIAL_OR_FAILED"
            }
        except Exception as e:
            # Fallback to TCP probe on port 80/443
            probes = []
            for _ in range(count):
                res = self.check_tcp_port(host, 80, timeout_sec=timeout_sec)
                if res["latency_ms"] is not None:
                    probes.append(res["latency_ms"])
                time.sleep(0.05)

            loss = (count - len(probes)) / count * 100.0
            avg_lat = sum(probes) / len(probes) if probes else None
            return {
                "host": host,
                "packets_transmitted": count,
                "packet_loss_pct": loss,
                "average_latency_ms": round(avg_lat, 2) if avg_lat else None,
                "output": f"Fallback socket probe completed. {len(probes)}/{count} succeeded.",
                "status": "SUCCESS" if probes else "FAILED"
            }

    def export_results_json(self, results: List[Dict[str, Any]]) -> str:
        """Export results list to JSON string."""
        return json.dumps({
            "tool": "ROGUEBYTE Network Diagnostics",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "count": len(results),
            "results": results
        }, indent=2)

    def export_results_csv(self, results: List[Dict[str, Any]]) -> str:
        """Export results list to CSV string."""
        if not results:
            return "host,port,status,latency_ms,error\n"

        output = io.StringIO()
        fieldnames = ["host", "port", "status", "latency_ms", "dns_time_ms", "packet_loss_pct", "error"]
        writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for r in results:
            writer.writerow(r)
        return output.getvalue()
