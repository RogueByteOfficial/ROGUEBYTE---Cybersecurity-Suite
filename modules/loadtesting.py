"""
ROGUEBYTE Controlled Load Testing Lab
Enforces strict target authorization, hard safety caps, concurrency control,
dry-run preview, and latency percentile calculation (p50, p95, p99).
"""

import time
import math
import threading
import urllib.request
import urllib.error
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Callable
from ..core.security import SecurityValidator, SecurityViolationException
from ..config.settings import SecurityPolicy, DEFAULT_ALLOWLIST, LoadTestConfig

@dataclass
class SingleRequestResult:
    status_code: int
    latency_ms: float
    success: bool
    error: Optional[str] = None
    bytes_transferred: int = 0

@dataclass
class LoadTestResult:
    target_url: str
    total_requested: int
    total_completed: int
    successful_requests: int
    failed_requests: int
    duration_seconds: float
    requests_per_second: float
    p50_latency_ms: float
    p95_latency_ms: float
    p99_latency_ms: float
    min_latency_ms: float
    max_latency_ms: float
    avg_latency_ms: float
    status_codes: Dict[int, int]
    dry_run: bool
    aborted_early: bool
    error_summary: List[str]

class LoadTestEngine:
    def __init__(self, allowlist: Optional[List[str]] = None):
        self.allowlist = allowlist if allowlist is not None else DEFAULT_ALLOWLIST
        self._stop_event = threading.Event()
        self._is_running = False

    @property
    def is_running(self) -> bool:
        return self._is_running

    def stop(self) -> None:
        """Signal ongoing test to abort gracefully."""
        self._stop_event.set()

    def run_load_test(self,
                      target_url: str,
                      total_requests: int = 50,
                      concurrency: int = 5,
                      max_duration_sec: int = 10,
                      rate_limit_rps: int = 20,
                      timeout_sec: float = 3.0,
                      dry_run: bool = False,
                      confirmed_authorized: bool = False,
                      progress_callback: Optional[Callable[[int, int, float], None]] = None) -> LoadTestResult:
        """
        Execute controlled load test with safety invariant checks.
        """
        self._stop_event.clear()
        self._is_running = True

        # 1. Authorization & Policy Invariants
        if not confirmed_authorized:
            self._is_running = False
            raise SecurityViolationException(
                "Explicit authorization confirmation is required. "
                "You must verify you own or are formally authorized to test this target."
            )

        SecurityValidator.validate_target_host(target_url, self.allowlist)
        SecurityValidator.enforce_load_test_limits(
            requests=total_requests,
            concurrency=concurrency,
            duration_sec=max_duration_sec,
            rps=rate_limit_rps
        )

        # 2. Dry Run Simulation Mode
        if dry_run:
            self._is_running = False
            simulated_latencies = [12.0 + (i % 7) * 3.5 for i in range(min(total_requests, 20))]
            sim_p50 = 15.5
            sim_p95 = 31.2
            sim_p99 = 35.0
            return LoadTestResult(
                target_url=target_url,
                total_requested=total_requests,
                total_completed=min(total_requests, 20),
                successful_requests=min(total_requests, 20),
                failed_requests=0,
                duration_seconds=1.0,
                requests_per_second=float(min(total_requests, 20)),
                p50_latency_ms=sim_p50,
                p95_latency_ms=sim_p95,
                p99_latency_ms=sim_p99,
                min_latency_ms=12.0,
                max_latency_ms=36.0,
                avg_latency_ms=18.4,
                status_codes={200: min(total_requests, 20)},
                dry_run=True,
                aborted_early=False,
                error_summary=["DRY RUN ONLY: No live requests dispatched."]
            )

        # 3. Live Execution
        latencies: List[float] = []
        status_codes: Dict[int, int] = {}
        errors: List[str] = []
        success_count = 0
        fail_count = 0
        aborted = False

        start_time = time.perf_counter()
        req_interval = 1.0 / max(1, rate_limit_rps)
        last_req_time = start_time

        def send_request() -> SingleRequestResult:
            req_start = time.perf_counter()
            try:
                req = urllib.request.Request(
                    target_url,
                    headers={"User-Agent": "ROGUEBYTE-LoadTester/1.0 (+http://localhost)"}
                )
                with urllib.request.urlopen(req, timeout=timeout_sec) as response:
                    body = response.read(1024)  # Read limited chunk to avoid buffer overflow
                    lat = (time.perf_counter() - req_start) * 1000.0
                    return SingleRequestResult(
                        status_code=response.status,
                        latency_ms=lat,
                        success=200 <= response.status < 400,
                        bytes_transferred=len(body)
                    )
            except urllib.error.HTTPError as e:
                lat = (time.perf_counter() - req_start) * 1000.0
                return SingleRequestResult(
                    status_code=e.code,
                    latency_ms=lat,
                    success=False,
                    error=f"HTTP {e.code}"
                )
            except Exception as e:
                lat = (time.perf_counter() - req_start) * 1000.0
                return SingleRequestResult(
                    status_code=0,
                    latency_ms=lat,
                    success=False,
                    error=str(e)
                )

        completed_count = 0
        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            futures = []
            for i in range(total_requests):
                if self._stop_event.is_set():
                    aborted = True
                    break

                elapsed = time.perf_counter() - start_time
                if elapsed >= max_duration_sec:
                    aborted = True
                    break

                # Rate limiting pacing
                sleep_needed = req_interval - (time.perf_counter() - last_req_time)
                if sleep_needed > 0:
                    time.sleep(sleep_needed)
                last_req_time = time.perf_counter()

                futures.append(executor.submit(send_request))

            # Gather results
            for future in as_completed(futures):
                if self._stop_event.is_set():
                    aborted = True

                try:
                    res: SingleRequestResult = future.result()
                    completed_count += 1
                    latencies.append(res.latency_ms)
                    code = res.status_code
                    status_codes[code] = status_codes.get(code, 0) + 1

                    if res.success:
                        success_count += 1
                    else:
                        fail_count += 1
                        if res.error and res.error not in errors:
                            errors.append(res.error)

                    if progress_callback:
                        progress_callback(completed_count, total_requests, res.latency_ms)
                except Exception as e:
                    fail_count += 1
                    errors.append(str(e))

        total_duration = max(0.001, time.perf_counter() - start_time)
        self._is_running = False

        # Percentile metrics calculation
        if latencies:
            latencies.sort()
            n = len(latencies)
            p50 = latencies[int(math.ceil(0.50 * n)) - 1]
            p95 = latencies[int(math.ceil(0.95 * n)) - 1]
            p99 = latencies[int(math.ceil(0.99 * n)) - 1]
            min_lat = min(latencies)
            max_lat = max(latencies)
            avg_lat = sum(latencies) / n
        else:
            p50 = p95 = p99 = min_lat = max_lat = avg_lat = 0.0

        rps = completed_count / total_duration if total_duration > 0 else 0.0

        return LoadTestResult(
            target_url=target_url,
            total_requested=total_requests,
            total_completed=completed_count,
            successful_requests=success_count,
            failed_requests=fail_count,
            duration_seconds=round(total_duration, 2),
            requests_per_second=round(rps, 2),
            p50_latency_ms=round(p50, 2),
            p95_latency_ms=round(p95, 2),
            p99_latency_ms=round(p99, 2),
            min_latency_ms=round(min_lat, 2),
            max_latency_ms=round(max_lat, 2),
            avg_latency_ms=round(avg_lat, 2),
            status_codes=status_codes,
            dry_run=False,
            aborted_early=aborted,
            error_summary=errors[:5]
        )
