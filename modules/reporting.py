"""
ROGUEBYTE Reporting and Audit Engine
Generates professional HTML, JSON, and CSV security reports from diagnostic
runs, load test lab sessions, and DoS detection incidents.
"""

import json
import csv
import io
import time
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from ..database.db import DatabaseManager

class ReportGenerator:
    def __init__(self, db: Optional[DatabaseManager] = None):
        self.db = db

    def generate_json_report(self, session_data: Dict[str, Any]) -> str:
        """Export session data to formatted JSON."""
        payload = {
            "application": "ROGUEBYTE Cybersecurity Workstation",
            "report_version": "1.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "data": session_data
        }
        return json.dumps(payload, indent=2)

    def generate_csv_report(self, records: List[Dict[str, Any]], record_type: str = "diagnostics") -> str:
        """Export records to CSV string."""
        if not records:
            return "id,timestamp,status,summary\n"

        output = io.StringIO()
        if record_type == "diagnostics":
            fields = ["id", "timestamp", "target", "port", "status", "latency_ms", "dns_time_ms", "packet_loss_pct", "environment"]
        elif record_type == "load_tests":
            fields = ["id", "timestamp", "target_url", "total_requests", "concurrency", "success_count", "failure_count", "duration_sec", "rps", "p50_ms", "p95_ms", "p99_ms"]
        elif record_type == "dos_alerts":
            fields = ["id", "timestamp", "severity", "alert_type", "source_ip", "request_rate", "description", "recommendation"]
        else:
            fields = list(records[0].keys())

        writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for r in records:
            writer.writerow(r)
        return output.getvalue()

    def generate_html_report(self,
                             title: str,
                             diagnostics: Optional[List[Dict[str, Any]]] = None,
                             load_tests: Optional[List[Dict[str, Any]]] = None,
                             dos_alerts: Optional[List[Dict[str, Any]]] = None,
                             system_summary: Optional[Dict[str, Any]] = None) -> str:
        """Generate a standalone, sleek, dark-themed HTML report."""
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        diag_rows = ""
        for d in (diagnostics or []):
            status_color = "#00ff66" if d.get("status") in ("OPEN", "SUCCESS") else "#ff4444"
            lat = f"{d.get('latency_ms', 'N/A')} ms" if d.get('latency_ms') is not None else "N/A"
            diag_rows += f"""
            <tr>
                <td style="padding:10px;border-bottom:1px solid #222;">{d.get('timestamp', '')}</td>
                <td style="padding:10px;border-bottom:1px solid #222;font-weight:bold;">{d.get('target', '')}:{d.get('port', '')}</td>
                <td style="padding:10px;border-bottom:1px solid #222;color:{status_color};">{d.get('status', '')}</td>
                <td style="padding:10px;border-bottom:1px solid #222;">{lat}</td>
                <td style="padding:10px;border-bottom:1px solid #222;">{d.get('environment', 'local')}</td>
            </tr>
            """

        load_rows = ""
        for lt in (load_tests or []):
            load_rows += f"""
            <tr>
                <td style="padding:10px;border-bottom:1px solid #222;">{lt.get('timestamp', '')}</td>
                <td style="padding:10px;border-bottom:1px solid #222;">{lt.get('target_url', '')}</td>
                <td style="padding:10px;border-bottom:1px solid #222;">{lt.get('total_requests', '')} (Conc: {lt.get('concurrency', '')})</td>
                <td style="padding:10px;border-bottom:1px solid #222;color:#00ff66;">{lt.get('success_count', '')} / <span style="color:#ff4444;">{lt.get('failure_count', '')}</span></td>
                <td style="padding:10px;border-bottom:1px solid #222;font-weight:bold;color:#00f0ff;">{lt.get('rps', '')} req/s</td>
                <td style="padding:10px;border-bottom:1px solid #222;">p50: {lt.get('p50_ms', '')}ms | p95: {lt.get('p95_ms', '')}ms</td>
            </tr>
            """

        alert_rows = ""
        for a in (dos_alerts or []):
            sev = a.get('severity', 'INFO')
            sev_color = "#ff4444" if sev in ("CRITICAL", "HIGH") else ("#ffbb00" if sev == "MEDIUM" else "#00f0ff")
            alert_rows += f"""
            <div style="background:#161c22;border-left:4px solid {sev_color};padding:14px;margin-bottom:12px;border-radius:4px;">
                <div style="display:flex;justify-content:space-between;margin-bottom:6px;">
                    <span style="font-weight:bold;color:{sev_color};">[{sev}] {a.get('alert_type', '')}</span>
                    <span style="color:#888;font-size:12px;">{a.get('timestamp', '')}</span>
                </div>
                <div style="color:#ddd;margin-bottom:8px;">{a.get('description', '')}</div>
                <div style="color:#00ff66;font-size:13px;"><strong>Mitigation:</strong> {a.get('recommendation', '')}</div>
            </div>
            """

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>ROGUEBYTE Security Audit Report - {title}</title>
    <style>
        body {{
            background-color: #0b0e14;
            color: #d1d5db;
            font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, sans-serif;
            margin: 0;
            padding: 30px;
        }}
        .container {{
            max-width: 1100px;
            margin: 0 auto;
        }}
        .header {{
            border-bottom: 2px solid #00ff66;
            padding-bottom: 16px;
            margin-bottom: 24px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        h1 {{
            color: #00ff66;
            margin: 0;
            font-size: 26px;
            letter-spacing: 1px;
        }}
        .subtitle {{
            color: #9ca3af;
            font-size: 13px;
        }}
        .section-title {{
            color: #00f0ff;
            font-size: 18px;
            margin-top: 30px;
            margin-bottom: 12px;
            border-bottom: 1px solid #1f2937;
            padding-bottom: 6px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: #111822;
            border-radius: 6px;
            overflow: hidden;
            font-size: 14px;
        }}
        th {{
            background: #182230;
            color: #9ca3af;
            text-align: left;
            padding: 12px;
            border-bottom: 1px solid #2d3748;
        }}
        .footer {{
            margin-top: 40px;
            text-align: center;
            font-size: 12px;
            color: #6b7280;
            border-top: 1px solid #1f2937;
            padding-top: 16px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1>ROGUEBYTE // SECURITY AUDIT REPORT</h1>
                <div class="subtitle">Title: {title} | Generated: {now}</div>
            </div>
            <div style="text-align:right;color:#00f0ff;font-family:monospace;font-weight:bold;">
                SEC-OPS // COMPLIANT
            </div>
        </div>

        {"<div class='section-title'>Denial-of-Service Alerts & Defense Telemetry</div>" + alert_rows if alert_rows else ""}

        <div class="section-title">Network Diagnostics & Latency Probes</div>
        <table>
            <thead>
                <tr>
                    <th>Timestamp</th>
                    <th>Target Host</th>
                    <th>Status</th>
                    <th>Latency</th>
                    <th>Environment</th>
                </tr>
            </thead>
            <tbody>
                {diag_rows if diag_rows else '<tr><td colspan="5" style="padding:12px;text-align:center;color:#666;">No diagnostic records in this session.</td></tr>'}
            </tbody>
        </table>

        {"<div class='section-title'>Controlled Load Testing Lab Results</div><table><thead><tr><th>Timestamp</th><th>Target</th><th>Volume</th><th>Success/Fail</th><th>Throughput</th><th>Latency</th></tr></thead><tbody>" + load_rows + "</tbody></table>" if load_rows else ""}

        <div class="footer">
            ROGUEBYTE v1.0.0 &bull; Safe Network & Security Engineering &bull; Confidential Audit Record
        </div>
    </div>
</body>
</html>
        """
        return html
