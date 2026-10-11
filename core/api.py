"""
ROGUEBYTE Local-Only REST API (FastAPI)
Strictly bound to 127.0.0.1 for local automation, test harnesses, and headless scripting.
"""

from typing import Dict, Any, List, Optional
import os
import uvicorn
from fastapi import FastAPI, HTTPException, Query, Body
from pydantic import BaseModel, Field

from ..config.settings import Config, get_default_config
from ..database.db import get_db
from ..core.security import SecurityViolationException
from ..modules.systemmonitor import SystemMonitor
from ..modules.networkdiagnostics import NetworkDiagnostics
from ..modules.loadtesting import LoadTestEngine
from ..modules.dosdetection import DoSDetectionEngine
from ..modules.wslintegration import WSLIntegration
from ..modules.reporting import ReportGenerator

app = FastAPI(
    title="ROGUEBYTE Local Security API",
    description="Local loopback API for system monitoring, safe diagnostics, and DoS analysis.",
    version="1.0.0"
)

# Instantiate core module singletons
monitor = SystemMonitor()
diagnostics = NetworkDiagnostics()
load_tester = LoadTestEngine()
dos_engine = DoSDetectionEngine()
wsl_integration = WSLIntegration()
db = get_db()
reporter = ReportGenerator(db)

class DnsCheckRequest(BaseModel):
    hostname: str

class PortCheckRequest(BaseModel):
    host: str
    port: int
    timeout_sec: float = 2.0

class LoadTestRequest(BaseModel):
    target_url: str
    total_requests: int = Field(default=20, le=1000)
    concurrency: int = Field(default=5, le=50)
    max_duration_sec: int = Field(default=10, le=60)
    rate_limit_rps: int = Field(default=20, le=100)
    timeout_sec: float = 3.0
    dry_run: bool = False
    confirmed_authorized: bool = False

class DoSAnalyzeRequest(BaseModel):
    log_content: str
    rate_threshold_rpm: int = 300
    ip_concentration_pct: float = 40.0

@app.get("/health")
def get_health() -> Dict[str, Any]:
    return {"status": "ONLINE", "application": "ROGUEBYTE", "binding": "127.0.0.1"}

@app.get("/system/overview")
def get_system_overview() -> Dict[str, Any]:
    return monitor.get_system_overview()

@app.get("/system/processes")
def get_system_processes(limit: int = Query(default=15, le=50)) -> List[Dict[str, Any]]:
    return monitor.get_process_list(limit=limit)

@app.post("/diagnostics/dns")
def check_dns(req: DnsCheckRequest) -> Dict[str, Any]:
    try:
        res = diagnostics.resolve_dns(req.hostname)
        db.record_diagnostic(
            target=req.hostname,
            port=53,
            status=res["status"],
            latency_ms=res["dns_time_ms"],
            dns_time_ms=res["dns_time_ms"],
            details=res
        )
        return res
    except SecurityViolationException as e:
        raise HTTPException(status_code=403, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/diagnostics/port")
def check_tcp_port(req: PortCheckRequest) -> Dict[str, Any]:
    try:
        res = diagnostics.check_tcp_port(req.host, req.port, req.timeout_sec)
        db.record_diagnostic(
            target=req.host,
            port=req.port,
            status=res["status"],
            latency_ms=res.get("latency_ms"),
            dns_time_ms=None,
            details=res
        )
        return res
    except SecurityViolationException as e:
        raise HTTPException(status_code=403, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/loadtest/run")
def execute_load_test(req: LoadTestRequest) -> Dict[str, Any]:
    try:
        res = load_tester.run_load_test(
            target_url=req.target_url,
            total_requests=req.total_requests,
            concurrency=req.concurrency,
            max_duration_sec=req.max_duration_sec,
            rate_limit_rps=req.rate_limit_rps,
            timeout_sec=req.timeout_sec,
            dry_run=req.dry_run,
            confirmed_authorized=req.confirmed_authorized
        )
        if not req.dry_run:
            db.record_load_test(
                target_url=res.target_url,
                total_requests=res.total_requested,
                concurrency=req.concurrency,
                success_count=res.successful_requests,
                failure_count=res.failed_requests,
                duration_sec=res.duration_seconds,
                rps=res.requests_per_second,
                p50_ms=res.p50_latency_ms,
                p95_ms=res.p95_latency_ms,
                p99_ms=res.p99_latency_ms,
                config=req.model_dump(),
                details={"status_codes": res.status_codes, "errors": res.error_summary}
            )
        return res.__dict__
    except SecurityViolationException as e:
        raise HTTPException(status_code=403, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/dos/analyze")
def analyze_dos(req: DoSAnalyzeRequest) -> Dict[str, Any]:
    engine = DoSDetectionEngine(
        rate_threshold_rpm=req.rate_threshold_rpm,
        ip_concentration_pct=req.ip_concentration_pct
    )
    alerts, metrics = engine.analyze_log_content(req.log_content)
    for alert in alerts:
        db.record_dos_alert(
            severity=alert.severity,
            alert_type=alert.indicator_type,
            source_ip=alert.source_ip,
            request_rate=alert.rate_detected,
            description=alert.description,
            recommendation="; ".join(alert.defensive_recommendations),
            evidence=alert.evidence
        )
    return {
        "alerts": [a.__dict__ for a in alerts],
        "metrics": metrics
    }

@app.get("/wsl/status")
def get_wsl_status() -> Dict[str, Any]:
    return wsl_integration.detect_wsl_status()

def run_api_server(host: str = "127.0.0.1", port: int = 8765):
    """Start local API server bound to loopback only."""
    uvicorn.run(app, host=host, port=port, log_level="warning")
