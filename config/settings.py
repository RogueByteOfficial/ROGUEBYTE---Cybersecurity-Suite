"""
ROGUEBYTE Configuration and Security Policies
Enforces conservative defaults, hard safety boundaries, and target allowlisting.
"""

import os
import json
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional

DEFAULT_ALLOWLIST = [
    "localhost",
    "127.0.0.1",
    "::1",
    "0.0.0.0",
    "http://localhost",
    "http://127.0.0.1",
    "https://localhost",
    "https://127.0.0.1",
    "testserver.local",
    "dev.local"
]

@dataclass
class SecurityPolicy:
    """Security bounds and authorization rules for ROGUEBYTE."""
    # Hard bounds that can never be exceeded at runtime
    HARD_MAX_REQUESTS: int = 2000
    HARD_MAX_CONCURRENCY: int = 50
    HARD_MAX_DURATION_SECONDS: int = 120
    HARD_MAX_RPS: int = 250
    HARD_MIN_TIMEOUT_SECONDS: float = 0.5
    HARD_MAX_TIMEOUT_SECONDS: float = 30.0

    # Command Execution Allowlist (Safe Diagnostic Subprocesses)
    APPROVED_DIAGNOSTIC_COMMANDS: List[str] = field(default_factory=lambda: [
        "ping",
        "netstat",
        "ss",
        "traceroute",
        "tracert",
        "nslookup",
        "dig",
        "ip",
        "ifconfig",
        "wsl",
        "uname",
        "uptime",
        "whoami",
        "hostname"
    ])

@dataclass
class LoadTestConfig:
    target_url: str = "http://127.0.0.1:8000"
    total_requests: int = 50
    concurrency: int = 5
    max_duration_sec: int = 10
    rate_limit_rps: int = 20
    timeout_sec: float = 3.0
    dry_run: bool = False
    http_method: str = "GET"
    payload: str = ""
    custom_headers: Dict[str, str] = field(default_factory=dict)
    confirmed_authorized: bool = False

@dataclass
class DoSDetectionConfig:
    rate_threshold_rpm: int = 300          # Requests per minute threshold
    burst_threshold_rps: int = 35          # Sudden burst per second
    ip_concentration_pct: float = 40.0     # % traffic from a single IP
    error_spike_threshold_pct: float = 50.0# 4xx/5xx spike %
    sliding_window_seconds: int = 60
    severity_weights: Dict[str, int] = field(default_factory=lambda: {
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4
    })

@dataclass
class Config:
    app_name: str = "ROGUEBYTE"
    version: str = "1.0.0"
    environment: str = "production"
    api_host: str = "127.0.0.1"   # Strict loopback binding
    api_port: int = 8765
    db_path: str = "roguebyte.db"
    log_level: str = "INFO"
    allowed_targets: List[str] = field(default_factory=lambda: list(DEFAULT_ALLOWLIST))
    load_test: LoadTestConfig = field(default_factory=LoadTestConfig)
    dos_detection: DoSDetectionConfig = field(default_factory=DoSDetectionConfig)
    system_monitor_interval_sec: float = 1.0

    def is_target_allowed(self, target: str) -> bool:
        """Verify target against allowlist and loopback safeguards."""
        cleaned = target.strip().lower()
        # Strip protocols and ports for hostname evaluation
        clean_host = cleaned
        for proto in ("http://", "https://", "tcp://", "udp://"):
            if clean_host.startswith(proto):
                clean_host = clean_host[len(proto):]
        if "/" in clean_host:
            clean_host = clean_host.split("/", 1)[0]
        if ":" in clean_host:
            clean_host = clean_host.split(":", 1)[0]

        # Explicit loopback match
        if clean_host in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
            return True

        # Check configured allowed hosts
        for allowed in self.allowed_targets:
            allowed_clean = allowed.strip().lower()
            for proto in ("http://", "https://"):
                if allowed_clean.startswith(proto):
                    allowed_clean = allowed_clean[len(proto):]
            if "/" in allowed_clean:
                allowed_clean = allowed_clean.split("/")[0]
            if ":" in allowed_clean:
                allowed_clean = allowed_clean.split(":")[0]

            if clean_host == allowed_clean:
                return True

        return False

def get_default_config() -> Config:
    return Config()

def load_config(filepath: Optional[str] = None) -> Config:
    """Load configuration from file or return default."""
    if filepath and os.path.exists(filepath):
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
                cfg = Config()
                if "allowed_targets" in data:
                    cfg.allowed_targets = data["allowed_targets"]
                if "api_port" in data:
                    cfg.api_port = int(data["api_port"])
                if "db_path" in data:
                    cfg.db_path = data["db_path"]
                return cfg
        except Exception:
            return get_default_config()
    return get_default_config()
