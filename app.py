"""
ROGUEBYTE - Desktop & CLI Application Entry Point
Supports GUI Mode (PySide6), Headless CLI Operations, and Local-only REST API.
"""

import sys
import os
import argparse
import json

# --- Bootstrap sys.path & module resolution ---
# Allows running directly via `python app.py` inside the directory or `python -m roguebyte.app`
_CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
_PARENT_DIR = os.path.dirname(_CURRENT_DIR)

if _CURRENT_DIR not in sys.path:
    sys.path.insert(0, _CURRENT_DIR)
if _PARENT_DIR not in sys.path:
    sys.path.insert(0, _PARENT_DIR)

if "roguebyte" not in sys.modules:
    try:
        import roguebyte
    except ModuleNotFoundError:
        import types
        _pkg = types.ModuleType("roguebyte")
        _pkg.__path__ = [_CURRENT_DIR]
        _pkg.__file__ = os.path.join(_CURRENT_DIR, "__init__.py")
        sys.modules["roguebyte"] = _pkg

from roguebyte.config.settings import Config, get_default_config, load_config
from roguebyte.core.logger import setup_logger
from roguebyte.core.security import SecurityViolationException
from roguebyte.database.db import get_db
from roguebyte.modules.systemmonitor import SystemMonitor
from roguebyte.modules.networkdiagnostics import NetworkDiagnostics
from roguebyte.modules.dosdetection import DoSDetectionEngine
from roguebyte.modules.wslintegration import WSLIntegration
from roguebyte.modules.reporting import ReportGenerator

def main():
    parser = argparse.ArgumentParser(
        description="ROGUEBYTE - Professional Cybersecurity & Network Defense Suite"
    )
    parser.add_argument("--gui", action="store_true", help="Launch the PySide6 Desktop GUI (Default)")
    parser.add_argument("--api", action="store_true", help="Launch the local-only REST API (127.0.0.1)")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="API Host binding (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8765, help="API Port (default: 8765)")
    parser.add_argument("--system", action="store_true", help="Display live system & resource overview")
    parser.add_argument("--wsl", action="store_true", help="Detect and display WSL2 environment status")
    parser.add_argument("--diagnose", nargs=2, metavar=("HOST", "PORT"), help="Run safe TCP diagnostic on host & port")
    parser.add_argument("--analyze-log", type=str, metavar="LOG_FILE", help="Analyze access log file for DoS patterns")
    parser.add_argument("--report-html", type=str, metavar="OUTPUT_HTML", help="Generate standalone HTML audit report")

    args = parser.parse_args()
    logger = setup_logger()

    # If --api flag provided, start FastAPI service
    if args.api:
        logger.info(f"Starting ROGUEBYTE local API on {args.host}:{args.port}")
        from roguebyte.core.api import run_api_server
        run_api_server(host=args.host, port=args.port)
        return 0

    # System overview CLI
    if args.system:
        monitor = SystemMonitor()
        print(json.dumps(monitor.get_system_overview(), indent=2))
        return 0

    # WSL Status CLI
    if args.wsl:
        wsl = WSLIntegration()
        print(json.dumps(wsl.detect_wsl_status(), indent=2))
        return 0

    # Quick diagnostic probe
    if args.diagnose:
        host, port = args.diagnose
        diag = NetworkDiagnostics()
        try:
            res = diag.check_tcp_port(host, int(port))
            print(json.dumps(res, indent=2))
            return 0 if res["status"] in ("OPEN", "SUCCESS") else 1
        except SecurityViolationException as e:
            print(f"[SECURITY VIOLATION]: {e}", file=sys.stderr)
            return 2

    # DoS log analysis
    if args.analyze_log:
        if not os.path.exists(args.analyze_log):
            print(f"Error: Log file '{args.analyze_log}' not found.", file=sys.stderr)
            return 1
        with open(args.analyze_log, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        engine = DoSDetectionEngine()
        alerts, metrics = engine.analyze_log_content(content)
        print(json.dumps({"metrics": metrics, "alerts": [a.__dict__ for a in alerts]}, indent=2))
        return 0

    # HTML Report generation
    if args.report_html:
        db = get_db()
        reporter = ReportGenerator(db)
        html = reporter.generate_html_report(
            title="ROGUEBYTE Audit Export",
            diagnostics=db.get_diagnostics_history(25),
            load_tests=db.get_load_test_history(25),
            dos_alerts=db.get_dos_alerts(25)
        )
        with open(args.report_html, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"[+] HTML Report generated successfully: {args.report_html}")
        return 0

    # Default: Attempt Desktop GUI
    try:
        from roguebyte.ui.gui_main import run_gui
        return run_gui()
    except Exception as e:
        logger.warning(f"Could not initialize PySide6 GUI ({e}). Falling back to interactive CLI status.")
        monitor = SystemMonitor()
        wsl = WSLIntegration()
        print("=" * 60)
        print("  ROGUEBYTE // CYBERSECURITY & DEFENSE WORKSTATION")
        print("=" * 60)
        print("Host System:", monitor.os_type)
        print("WSL Status :", wsl.detect_wsl_status().get("environment"))
        print("Database   : SQLite initialized (roguebyte.db)")
        print("\nRun with --help to see all available CLI commands.")
        return 0

if __name__ == "__main__":
    sys.exit(main())
