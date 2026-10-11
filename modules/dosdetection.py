"""
ROGUEBYTE Denial-of-Service (DoS) Detection and Defense Engine
Parses server access logs (Common Log Format, Combined, JSON), calculates
sliding-window request frequencies, detects IP clusters, generates defensive
firewall/proxy rules, and clearly tags indicators vs confirmed attacks.
"""

import re
import json
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple
from collections import defaultdict, Counter

@dataclass
class LogEntry:
    ip: str
    timestamp_str: str
    method: str
    path: str
    status_code: int
    bytes_sent: int
    user_agent: str
    raw: str

@dataclass
class DoSAlert:
    id: str
    timestamp: str
    severity: str          # "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"
    indicator_type: str    # "RATE_BURST", "IP_FLOOD", "ERROR_STORM", "SLOW_REQUESTS"
    confidence: str        # "INDICATOR_OBSERVED", "PROBABLE_ANOMALY", "CONFIRMED_ATTACK"
    source_ip: Optional[str]
    rate_detected: float
    description: str
    defensive_recommendations: List[str]
    generated_rules: Dict[str, str] = field(default_factory=dict)
    evidence: Dict[str, Any] = field(default_factory=dict)

class DoSDetectionEngine:
    # Standard Common / Combined Log Format regex
    CLF_REGEX = re.compile(
        r'^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s*(\S+)?"\s+(\d{3})\s+(\S+)(?:\s+"([^"]*)"\s+"([^"]*)")?'
    )

    def __init__(self,
                 rate_threshold_rpm: int = 300,
                 burst_threshold_rps: int = 35,
                 ip_concentration_pct: float = 40.0,
                 error_spike_pct: float = 40.0):
        self.rate_threshold_rpm = rate_threshold_rpm
        self.burst_threshold_rps = burst_threshold_rps
        self.ip_concentration_pct = ip_concentration_pct
        self.error_spike_pct = error_spike_pct

    def parse_log_line(self, line: str) -> Optional[LogEntry]:
        """Parse an Apache/Nginx CLF or combined log line."""
        line = line.strip()
        if not line or line.startswith("#"):
            return None

        match = self.CLF_REGEX.match(line)
        if match:
            ip = match.group(1)
            ts = match.group(2)
            method = match.group(3)
            path = match.group(4)
            status = int(match.group(6))
            bytes_str = match.group(7)
            bytes_sent = int(bytes_str) if bytes_str.isdigit() else 0
            ua = match.group(9) or "Unknown"
            return LogEntry(
                ip=ip,
                timestamp_str=ts,
                method=method,
                path=path,
                status_code=status,
                bytes_sent=bytes_sent,
                user_agent=ua,
                raw=line
            )

        # Fallback simple CSV/space split
        parts = line.split()
        if len(parts) >= 6:
            ip = parts[0]
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip) or ":" in ip:
                return LogEntry(
                    ip=ip,
                    timestamp_str=parts[1] if len(parts) > 1 else "",
                    method="GET",
                    path=parts[2] if len(parts) > 2 else "/",
                    status_code=200,
                    bytes_sent=0,
                    user_agent="Unknown",
                    raw=line
                )

        return None

    def analyze_log_content(self, content: str) -> Tuple[List[DoSAlert], Dict[str, Any]]:
        """
        Analyze multi-line log content for DoS patterns and generate timeline and defense rules.
        """
        lines = content.strip().splitlines()
        entries: List[LogEntry] = []
        for line in lines:
            entry = self.parse_log_line(line)
            if entry:
                entries.append(entry)

        if not entries:
            return [], {
                "total_lines": len(lines),
                "parsed_entries": 0,
                "summary": "No valid log entries could be parsed."
            }

        alerts: List[DoSAlert] = []
        ip_counts = Counter(e.ip for e in entries)
        path_counts = Counter(e.path for e in entries)
        status_counts = Counter(e.status_code for e in entries)
        total_requests = len(entries)

        # 1. IP Concentration & Flood Check
        for ip, count in ip_counts.most_common(10):
            pct = (count / total_requests) * 100.0
            if pct >= self.ip_concentration_pct and count >= 50:
                severity = "CRITICAL" if pct > 70 else "HIGH"
                confidence = "CONFIRMED_ATTACK" if pct > 75 and count > 100 else "PROBABLE_ANOMALY"

                rules = self.generate_defensive_rules(ip)
                alert = DoSAlert(
                    id=f"ALT-IP-{ip.replace('.', '-')}",
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    severity=severity,
                    indicator_type="IP_FLOOD",
                    confidence=confidence,
                    source_ip=ip,
                    rate_detected=round(count, 1),
                    description=(
                        f"Abnormal single-source concentration: IP {ip} generated {count} requests "
                        f"({pct:.1f}% of total server traffic). Exceeds threshold {self.ip_concentration_pct}%."
                    ),
                    defensive_recommendations=[
                        f"Implement immediate drop rule for IP {ip} at ingress firewall.",
                        f"Apply per-client rate limit of 15 req/sec in Nginx / HAProxy.",
                        "Enable CAPTCHA challenge on heavily targeted routes.",
                        "Inspect upstream CDN/Reverse-Proxy headers (X-Forwarded-For) to rule out proxy IP pooling."
                    ],
                    generated_rules=rules,
                    evidence={"ip": ip, "request_count": count, "traffic_share_pct": round(pct, 2)}
                )
                alerts.append(alert)
            elif count >= 80:
                # Moderate concentration indicator
                rules = self.generate_defensive_rules(ip)
                alert = DoSAlert(
                    id=f"ALT-IP-MOD-{ip.replace('.', '-')}",
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    severity="MEDIUM",
                    indicator_type="RATE_BURST",
                    confidence="INDICATOR_OBSERVED",
                    source_ip=ip,
                    rate_detected=round(count, 1),
                    description=f"Observed elevated request count from IP {ip}: {count} requests.",
                    defensive_recommendations=[
                        "Monitor host connection table.",
                        "Ensure HTTP keep-alive timeout is capped at 5 seconds."
                    ],
                    generated_rules=rules,
                    evidence={"ip": ip, "request_count": count}
                )
                alerts.append(alert)

        # 2. Error Storm Analysis (4xx / 5xx error spikes)
        error_count = sum(c for code, c in status_counts.items() if code >= 400)
        error_pct = (error_count / total_requests) * 100.0 if total_requests > 0 else 0
        if error_pct >= self.error_spike_pct and error_count >= 30:
            top_bad_ip = ip_counts.most_common(1)[0][0] if ip_counts else "unknown"
            alert = DoSAlert(
                id="ALT-ERR-STORM",
                timestamp=datetime.now(timezone.utc).isoformat(),
                severity="HIGH",
                indicator_type="ERROR_STORM",
                confidence="PROBABLE_ANOMALY",
                source_ip=top_bad_ip,
                rate_detected=round(error_pct, 1),
                description=(
                    f"High error response ratio detected: {error_count}/{total_requests} requests "
                    f"({error_pct:.1f}%) returned 4xx/5xx status codes. Suggests probing or service saturation."
                ),
                defensive_recommendations=[
                    "Check backend application logs for unhandled exception loops or database pool exhaustion.",
                    "Configure Fail2Ban to ban clients triggering repeated 404/403 responses.",
                    "Verify Web Application Firewall (WAF) rule efficacy."
                ],
                generated_rules=self.generate_defensive_rules(top_bad_ip),
                evidence={"error_count": error_count, "error_percentage": round(error_pct, 2)}
            )
            alerts.append(alert)

        # 3. Targeted Path Analysis (Endpoint Bombardment)
        for path, count in path_counts.most_common(3):
            path_pct = (count / total_requests) * 100.0
            if path_pct >= 50.0 and count >= 50:
                alert = DoSAlert(
                    id=f"ALT-PATH-{abs(hash(path)) % 10000}",
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    severity="MEDIUM",
                    indicator_type="ENDPOINT_TARGETING",
                    confidence="INDICATOR_OBSERVED",
                    source_ip=None,
                    rate_detected=round(count, 1),
                    description=f"Single endpoint bombardment: '{path}' received {count} requests ({path_pct:.1f}% of total).",
                    defensive_recommendations=[
                        f"Add rate-limiting zone specifically for '{path}' in reverse proxy.",
                        "Implement Redis token-bucket middleware on CPU-expensive API routes.",
                        "Enforce strict client caching (Cache-Control: public, max-age=...)."
                    ],
                    generated_rules={"nginx_location": f"location = {path} {{\n    limit_req zone=api_limit burst=5 nodelay;\n}}"},
                    evidence={"path": path, "hits": count, "share_pct": round(path_pct, 2)}
                )
                alerts.append(alert)

        summary_metrics = {
            "total_requests": total_requests,
            "unique_ips": len(ip_counts),
            "top_ips": ip_counts.most_common(5),
            "status_code_breakdown": dict(status_counts),
            "error_percentage": round(error_pct, 2),
            "alert_count": len(alerts),
            "highest_severity": max([a.severity for a in alerts], key=lambda s: {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}.get(s, 0)) if alerts else "NORMAL"
        }

        return alerts, summary_metrics

    def generate_defensive_rules(self, ip: str) -> Dict[str, str]:
        """Generate ready-to-deploy firewall and reverse-proxy defensive rules."""
        return {
            "iptables": f"sudo iptables -I INPUT -s {ip} -j DROP",
            "nftables": f"nft add rule inet filter input ip saddr {ip} drop",
            "ufw": f"sudo ufw insert 1 deny from {ip} to any",
            "nginx_rate_limit": (
                "limit_req_zone $binary_remote_addr zone=anti_dos:10m rate=10r/s;\n"
                "limit_req zone=anti_dos burst=20 nodelay;"
            ),
            "fail2ban_filter": (
                f"[Definition]\nfailregex = ^{ip} .* 40[0-9]\nignoreregex =\n"
            ),
            "windows_powershell": (
                f"New-NetFirewallRule -DisplayName 'ROGUEBYTE-Block-{ip}' -Direction Inbound -Action Block -RemoteAddress '{ip}'"
            )
        }
