"""
ROGUEBYTE Desktop GUI (PySide6)
Dark graphite & black cybersecurity theme with neon green and cyan accents.
Multi-threaded architecture ensuring GUI responsiveness during heavy tasks.
"""

import sys
import os
import json
import time
from typing import Dict, Any, List, Optional

try:
    from PySide6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QTabWidget, QLabel, QPushButton, QLineEdit, QTextEdit, QProgressBar,
        QTableWidget, QTableWidgetItem, QHeaderView, QCheckBox, QSpinBox,
        QDoubleSpinBox, QComboBox, QFileDialog, QMessageBox, QFrame, QSplitter
    )
    from PySide6.QtCore import Qt, QTimer, QThread, Signal
    from PySide6.QtGui import QFont, QColor, QPalette, QIcon
    HAS_PYSIDE = True
except ImportError:
    HAS_PYSIDE = False

from ..config.settings import Config, get_default_config, SecurityPolicy
from ..database.db import get_db
from ..core.security import SecurityViolationException
from ..modules.systemmonitor import SystemMonitor
from ..modules.networkdiagnostics import NetworkDiagnostics
from ..modules.loadtesting import LoadTestEngine, LoadTestResult
from ..modules.dosdetection import DoSDetectionEngine
from ..modules.wslintegration import WSLIntegration
from ..modules.reporting import ReportGenerator

# Dark Cyberpunk / Security Operations Theme Stylesheet
ROGUEBYTE_STYLESHEET = """
QMainWindow, QWidget {
    background-color: #0d1117;
    color: #e6edf3;
    font-family: 'Segoe UI', 'Ubuntu', 'Helvetica Neue', sans-serif;
    font-size: 13px;
}

QTabWidget::pane {
    border: 1px solid #30363d;
    background-color: #0d1117;
    border-radius: 4px;
}

QTabBar::tab {
    background-color: #161b22;
    color: #8b949e;
    padding: 10px 20px;
    margin-right: 4px;
    border-top-left-radius: 4px;
    border-top-right-radius: 4px;
    border: 1px solid #21262d;
    font-weight: 600;
}

QTabBar::tab:selected {
    background-color: #0d1117;
    color: #00ff66;
    border-bottom: 2px solid #00ff66;
}

QPushButton {
    background-color: #21262d;
    border: 1px solid #30363d;
    color: #00f0ff;
    padding: 8px 16px;
    border-radius: 4px;
    font-weight: 600;
}

QPushButton:hover {
    background-color: #30363d;
    border-color: #00f0ff;
}

QPushButton#btn-primary {
    background-color: #1f6feb;
    color: #ffffff;
    border: 1px solid #388bfd;
}

QPushButton#btn-primary:hover {
    background-color: #388bfd;
}

QPushButton#btn-accent {
    background-color: #00ff66;
    color: #0d1117;
    border: 1px solid #00ff66;
}

QPushButton#btn-accent:hover {
    background-color: #26ff7d;
}

QPushButton#btn-danger {
    background-color: #da3633;
    color: #ffffff;
    border: 1px solid #f85149;
}

QLineEdit, QTextEdit, QSpinBox, QDoubleSpinBox, QComboBox {
    background-color: #161b22;
    border: 1px solid #30363d;
    border-radius: 4px;
    padding: 6px 10px;
    color: #e6edf3;
    selection-background-color: #1f6feb;
}

QLineEdit:focus, QTextEdit:focus {
    border-color: #00ff66;
}

QTableWidget {
    background-color: #161b22;
    border: 1px solid #30363d;
    gridline-color: #21262d;
    color: #e6edf3;
}

QHeaderView::section {
    background-color: #0d1117;
    color: #8b949e;
    padding: 6px;
    border: 1px solid #21262d;
    font-weight: 600;
}

QProgressBar {
    background-color: #161b22;
    border: 1px solid #30363d;
    border-radius: 4px;
    text-align: center;
    color: #e6edf3;
}

QProgressBar::chunk {
    background-color: #00ff66;
    border-radius: 3px;
}
"""

if HAS_PYSIDE:
    class WorkerThread(QThread):
        finished_signal = Signal(object)
        error_signal = Signal(str)

        def __init__(self, task_fn, *args, **kwargs):
            super().__init__()
            self.task_fn = task_fn
            self.args = args
            self.kwargs = kwargs

        def run(self):
            try:
                res = self.task_fn(*self.args, **self.kwargs)
                self.finished_signal.emit(res)
            except Exception as e:
                self.error_signal.emit(str(e))

    class MainWindow(QMainWindow):
        def __init__(self):
            super().__init__()
            self.config = get_default_config()
            self.db = get_db(self.config.db_path)
            self.monitor = SystemMonitor()
            self.diagnostics = NetworkDiagnostics(self.config.allowed_targets)
            self.load_tester = LoadTestEngine(self.config.allowed_targets)
            self.dos_engine = DoSDetectionEngine()
            self.wsl = WSLIntegration()
            self.reporter = ReportGenerator(self.db)

            self.init_ui()
            self.start_system_timer()

        def init_ui(self):
            self.setWindowTitle("ROGUEBYTE // CYBERSECURITY & DEFENSE WORKSTATION [v1.0.0]")
            self.resize(1180, 780)
            self.setStyleSheet(ROGUEBYTE_STYLESHEET)

            central_widget = QWidget()
            self.setCentralWidget(central_widget)
            main_layout = QVBoxLayout(central_widget)
            main_layout.setContentsMargins(16, 16, 16, 16)
            main_layout.setSpacing(12)

            # Header Banner
            header_layout = QHBoxLayout()
            title_label = QLabel("ROGUEBYTE")
            title_label.setStyleSheet("font-size: 22px; font-weight: 800; color: #00ff66; letter-spacing: 2px;")
            subtitle_label = QLabel("// DEFENSIVE CYBERSECURITY & LOAD AUDIT WORKSTATION (WINDOWS & WSL2)")
            subtitle_label.setStyleSheet("font-size: 12px; color: #8b949e; font-weight: 600; margin-left: 8px;")

            header_layout.addWidget(title_label)
            header_layout.addWidget(subtitle_label)
            header_layout.addStretch()

            self.wsl_badge = QLabel("WSL2: CHECKING...")
            self.wsl_badge.setStyleSheet("color: #00f0ff; background: #161b22; padding: 4px 8px; border-radius: 4px; border: 1px solid #30363d;")
            header_layout.addWidget(self.wsl_badge)

            main_layout.addLayout(header_layout)

            # Tab Widget
            self.tabs = QTabWidget()
            self.tabs.addTab(self.create_dashboard_tab(), "DASHBOARD")
            self.tabs.addTab(self.create_system_monitor_tab(), "SYSTEM MONITOR")
            self.tabs.addTab(self.create_network_diag_tab(), "NETWORK DIAGNOSTICS")
            self.tabs.addTab(self.create_load_test_tab(), "LOAD TESTING LAB")
            self.tabs.addTab(self.create_dos_defense_tab(), "DoS DEFENSE STUDIO")
            self.tabs.addTab(self.create_wsl_console_tab(), "WSL & CMD CONSOLE")
            self.tabs.addTab(self.create_reports_tab(), "REPORTS & AUDIT")

            main_layout.addWidget(self.tabs)

            # Status bar
            self.status_bar_label = QLabel("STATUS: ALL SYSTEMS NOMINAL | LOCAL API: 127.0.0.1:8765")
            self.status_bar_label.setStyleSheet("color: #8b949e; font-size: 11px;")
            main_layout.addWidget(self.status_bar_label)

            # Detect initial WSL state
            self.check_initial_wsl()

        def check_initial_wsl(self):
            wsl_stat = self.wsl.detect_wsl_status()
            if wsl_stat.get("installed"):
                distro = wsl_stat.get("active_distribution") or "WSL2"
                self.wsl_badge.setText(f"WSL2: ONLINE ({distro})")
                self.wsl_badge.setStyleSheet("color: #00ff66; background: #161b22; padding: 4px 8px; border-radius: 4px; border: 1px solid #00ff66;")
            else:
                self.wsl_badge.setText("WSL: NATIVE HOST")
                self.wsl_badge.setStyleSheet("color: #8b949e; background: #161b22; padding: 4px 8px; border-radius: 4px; border: 1px solid #30363d;")

        def create_dashboard_tab(self) -> QWidget:
            tab = QWidget()
            layout = QVBoxLayout(tab)
            layout.setSpacing(16)

            # Overview Cards
            cards_layout = QHBoxLayout()
            self.card_cpu = self.create_metric_card("CPU USAGE", "0.0%", "#00ff66")
            self.card_ram = self.create_metric_card("MEMORY (RAM)", "0.0%", "#00f0ff")
            self.card_disk = self.create_metric_card("DISK STORAGE", "0.0%", "#a371f7")
            self.card_alerts = self.create_metric_card("SECURITY ALERTS", "0 ACTIVE", "#f85149")

            cards_layout.addWidget(self.card_cpu)
            cards_layout.addWidget(self.card_ram)
            cards_layout.addWidget(self.card_disk)
            cards_layout.addWidget(self.card_alerts)
            layout.addLayout(cards_layout)

            # Quick Action & Live Activity Log
            quick_layout = QHBoxLayout()
            btn_quick_scan = QPushButton("QUICK LOCALHOST AUDIT")
            btn_quick_scan.setObjectName("btn-accent")
            btn_quick_scan.clicked.connect(self.run_quick_audit)

            btn_test_loopback = QPushButton("PING LOOPBACK")
            btn_test_loopback.clicked.connect(lambda: self.quick_ping("127.0.0.1"))

            quick_layout.addWidget(btn_quick_scan)
            quick_layout.addWidget(btn_test_loopback)
            quick_layout.addStretch()
            layout.addLayout(quick_layout)

            # Live Log Console
            lbl_console = QLabel("LIVE SECURITY EVENT LOG:")
            lbl_console.setStyleSheet("font-weight: 600; color: #8b949e;")
            layout.addWidget(lbl_console)

            self.dash_log = QTextEdit()
            self.dash_log.setReadOnly(True)
            self.dash_log.setStyleSheet("background-color: #0d1117; color: #00ff66; font-family: monospace; font-size: 12px; border: 1px solid #30363d;")
            layout.addWidget(self.dash_log)
            self.log_to_dash("ROGUEBYTE Core Initialized. Safe boundaries enforced.")

            return tab

        def create_metric_card(self, title: str, value: str, accent_color: str) -> QFrame:
            frame = QFrame()
            frame.setStyleSheet(f"background-color: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 12px;")
            lay = QVBoxLayout(frame)
            lbl_t = QLabel(title)
            lbl_t.setStyleSheet("font-size: 11px; color: #8b949e; font-weight: 600;")
            lbl_v = QLabel(value)
            lbl_v.setStyleSheet(f"font-size: 24px; font-weight: 700; color: {accent_color}; margin-top: 4px;")
            lay.addWidget(lbl_t)
            lay.addWidget(lbl_v)
            frame.value_label = lbl_v  # Store ref
            return frame

        def create_system_monitor_tab(self) -> QWidget:
            tab = QWidget()
            layout = QVBoxLayout(tab)

            # Process List
            lbl = QLabel("RUNNING PROCESSES & THREADS (ORDERED BY CPU%):")
            lbl.setStyleSheet("font-weight: 600; color: #8b949e;")
            layout.addWidget(lbl)

            self.proc_table = QTableWidget()
            self.proc_table.setColumnCount(5)
            self.proc_table.setHorizontalHeaderLabels(["PID", "PROCESS NAME", "CPU %", "MEM %", "STATUS"])
            self.proc_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
            layout.addWidget(self.proc_table)

            btn_refresh = QPushButton("REFRESH PROCESSES")
            btn_refresh.clicked.connect(self.refresh_process_table)
            layout.addWidget(btn_refresh)
            return tab

        def create_network_diag_tab(self) -> QWidget:
            tab = QWidget()
            layout = QVBoxLayout(tab)

            form_lay = QHBoxLayout()
            form_lay.addWidget(QLabel("Target Host:"))
            self.diag_host_input = QLineEdit("127.0.0.1")
            form_lay.addWidget(self.diag_host_input)

            form_lay.addWidget(QLabel("Port:"))
            self.diag_port_input = QSpinBox()
            self.diag_port_input.setRange(1, 65535)
            self.diag_port_input.setValue(80)
            form_lay.addWidget(self.diag_port_input)

            btn_probe = QPushButton("SAFE TCP HANDSHAKE")
            btn_probe.setObjectName("btn-accent")
            btn_probe.clicked.connect(self.run_tcp_probe)
            form_lay.addWidget(btn_probe)

            btn_dns = QPushButton("RESOLVE DNS")
            btn_dns.clicked.connect(self.run_dns_probe)
            form_lay.addWidget(btn_dns)

            layout.addLayout(form_lay)

            self.diag_log = QTextEdit()
            self.diag_log.setReadOnly(True)
            self.diag_log.setStyleSheet("background-color: #0d1117; color: #00f0ff; font-family: monospace; border: 1px solid #30363d;")
            layout.addWidget(self.diag_log)

            btn_export_csv = QPushButton("EXPORT DIAGNOSTICS AS CSV")
            btn_export_csv.clicked.connect(self.export_diagnostics_csv)
            layout.addWidget(btn_export_csv)
            return tab

        def create_load_test_tab(self) -> QWidget:
            tab = QWidget()
            layout = QVBoxLayout(tab)

            warning_lbl = QLabel("WARNING: Controlled Load Testing Lab is strictly restricted to loopback and authorized targets.")
            warning_lbl.setStyleSheet("color: #f85149; font-weight: 600; padding: 4px; background: #211215; border-radius: 4px;")
            layout.addWidget(warning_lbl)

            form_lay = QHBoxLayout()
            form_lay.addWidget(QLabel("Target URL:"))
            self.load_target_input = QLineEdit("http://127.0.0.1:8765/health")
            form_lay.addWidget(self.load_target_input)

            form_lay.addWidget(QLabel("Requests:"))
            self.load_reqs = QSpinBox()
            self.load_reqs.setRange(5, SecurityPolicy.HARD_MAX_REQUESTS)
            self.load_reqs.setValue(30)
            form_lay.addWidget(self.load_reqs)

            form_lay.addWidget(QLabel("Concurrency:"))
            self.load_conc = QSpinBox()
            self.load_conc.setRange(1, SecurityPolicy.HARD_MAX_CONCURRENCY)
            self.load_conc.setValue(5)
            form_lay.addWidget(self.load_conc)

            layout.addLayout(form_lay)

            opts_lay = QHBoxLayout()
            self.chk_auth = QCheckBox("I confirm I am explicitly authorized to test this target")
            self.chk_auth.setChecked(True)
            self.chk_dry = QCheckBox("Dry-Run Simulation Mode (Zero real traffic)")
            opts_lay.addWidget(self.chk_auth)
            opts_lay.addWidget(self.chk_dry)
            layout.addLayout(opts_lay)

            btn_lay = QHBoxLayout()
            self.btn_run_load = QPushButton("START CONTROLLED LOAD TEST")
            self.btn_run_load.setObjectName("btn-accent")
            self.btn_run_load.clicked.connect(self.start_load_test)

            self.btn_stop_load = QPushButton("ABORT / STOP")
            self.btn_stop_load.setObjectName("btn-danger")
            self.btn_stop_load.clicked.connect(self.stop_load_test)
            self.btn_stop_load.setEnabled(False)

            btn_lay.addWidget(self.btn_run_load)
            btn_lay.addWidget(self.btn_stop_load)
            layout.addLayout(btn_lay)

            self.load_progress = QProgressBar()
            self.load_progress.setValue(0)
            layout.addWidget(self.load_progress)

            self.load_output = QTextEdit()
            self.load_output.setReadOnly(True)
            self.load_output.setStyleSheet("background-color: #0d1117; color: #00ff66; font-family: monospace; border: 1px solid #30363d;")
            layout.addWidget(self.load_output)

            return tab

        def create_dos_defense_tab(self) -> QWidget:
            tab = QWidget()
            layout = QVBoxLayout(tab)

            desc = QLabel("Analyze server access logs to detect DoS signatures, rate anomalies, and generate defense rules.")
            desc.setStyleSheet("color: #8b949e;")
            layout.addWidget(desc)

            btn_load_sample = QPushButton("LOAD SYNTHETIC ATTACK LOG SAMPLE")
            btn_load_sample.clicked.connect(self.load_synthetic_dos_sample)
            layout.addWidget(btn_load_sample)

            self.dos_log_input = QTextEdit()
            self.dos_log_input.setPlaceholderText("Paste Apache or Nginx access.log lines here...")
            layout.addWidget(self.dos_log_input)

            btn_analyze = QPushButton("ANALYZE TRAFFIC & GENERATE DEFENSE RULES")
            btn_analyze.setObjectName("btn-accent")
            btn_analyze.clicked.connect(self.analyze_dos_traffic)
            layout.addWidget(btn_analyze)

            self.dos_results_view = QTextEdit()
            self.dos_results_view.setReadOnly(True)
            self.dos_results_view.setStyleSheet("background-color: #0d1117; color: #00f0ff; font-family: monospace; border: 1px solid #30363d;")
            layout.addWidget(self.dos_results_view)

            return tab

        def create_wsl_console_tab(self) -> QWidget:
            tab = QWidget()
            layout = QVBoxLayout(tab)

            lbl = QLabel("APPROVED DIAGNOSTIC COMMAND CONSOLE (SAFE SUBPROCESS WRAPPER)")
            lbl.setStyleSheet("font-weight: 600; color: #8b949e;")
            layout.addWidget(lbl)

            input_lay = QHBoxLayout()
            self.wsl_cmd_combo = QComboBox()
            self.wsl_cmd_combo.addItems(["ping", "netstat", "ss", "nslookup", "uname", "uptime", "whoami", "hostname"])
            self.wsl_args_input = QLineEdit("-c 2 127.0.0.1")

            input_lay.addWidget(QLabel("Command:"))
            input_lay.addWidget(self.wsl_cmd_combo)
            input_lay.addWidget(QLabel("Arguments:"))
            input_lay.addWidget(self.wsl_args_input)

            btn_exec = QPushButton("RUN IN WSL / HOST")
            btn_exec.setObjectName("btn-accent")
            btn_exec.clicked.connect(self.run_console_command)
            input_lay.addWidget(btn_exec)

            layout.addLayout(input_lay)

            self.console_output = QTextEdit()
            self.console_output.setReadOnly(True)
            self.console_output.setStyleSheet("background-color: #0d1117; color: #e6edf3; font-family: monospace; border: 1px solid #30363d;")
            layout.addWidget(self.console_output)

            return tab

        def create_reports_tab(self) -> QWidget:
            tab = QWidget()
            layout = QVBoxLayout(tab)

            lbl = QLabel("SESSION AUDIT TRAIL & EXPORT ENGINE")
            lbl.setStyleSheet("font-weight: 600; color: #8b949e;")
            layout.addWidget(lbl)

            btn_lay = QHBoxLayout()
            btn_html = QPushButton("GENERATE HTML AUDIT REPORT")
            btn_html.setObjectName("btn-accent")
            btn_html.clicked.connect(self.export_html_report)

            btn_json = QPushButton("EXPORT FULL AUDIT AS JSON")
            btn_json.clicked.connect(self.export_json_report)

            btn_lay.addWidget(btn_html)
            btn_lay.addWidget(btn_json)
            layout.addLayout(btn_lay)

            self.report_preview = QTextEdit()
            self.report_preview.setReadOnly(True)
            self.report_preview.setStyleSheet("background-color: #0d1117; color: #8b949e; font-family: monospace; border: 1px solid #30363d;")
            layout.addWidget(self.report_preview)

            return tab

        def log_to_dash(self, msg: str):
            ts = time.strftime("%H:%M:%S")
            self.dash_log.append(f"[{ts}] {msg}")

        def start_system_timer(self):
            self.timer = QTimer(self)
            self.timer.timeout.connect(self.update_system_stats)
            self.timer.start(2000)

        def update_system_stats(self):
            cpu = self.monitor.get_cpu_metrics()
            mem = self.monitor.get_memory_metrics()
            disk = self.monitor.get_disk_metrics()

            self.card_cpu.value_label.setText(f"{cpu.get('percent', 0.0)}%")
            self.card_ram.value_label.setText(f"{mem.get('percent', 0.0)}%")
            self.card_disk.value_label.setText(f"{disk.get('percent', 0.0)}%")

        def refresh_process_table(self):
            procs = self.monitor.get_process_list(limit=25)
            self.proc_table.setRowCount(len(procs))
            for row, p in enumerate(procs):
                self.proc_table.setItem(row, 0, QTableWidgetItem(str(p['pid'])))
                self.proc_table.setItem(row, 1, QTableWidgetItem(p['name']))
                self.proc_table.setItem(row, 2, QTableWidgetItem(f"{p['cpu_percent']}%"))
                self.proc_table.setItem(row, 3, QTableWidgetItem(f"{p['memory_percent']}%"))
                self.proc_table.setItem(row, 4, QTableWidgetItem(p['status']))

        def run_quick_audit(self):
            self.log_to_dash("Starting Quick Localhost Security Probe...")
            res = self.diagnostics.check_tcp_port("127.0.0.1", 80, timeout_sec=1.0)
            self.log_to_dash(f"Probe 127.0.0.1:80 -> Status: {res['status']} | Latency: {res.get('latency_ms')} ms")

        def quick_ping(self, host: str):
            self.log_to_dash(f"Pinging loopback {host}...")
            res = self.diagnostics.check_tcp_port(host, 53, timeout_sec=1.0)
            self.log_to_dash(f"Ping result: {res['status']}")

        def run_tcp_probe(self):
            host = self.diag_host_input.text().strip()
            port = self.diag_port_input.value()
            try:
                res = self.diagnostics.check_tcp_port(host, port)
                self.diag_log.append(json.dumps(res, indent=2))
                self.db.record_diagnostic(host, port, res['status'], res.get('latency_ms'), None, details=res)
            except Exception as e:
                self.diag_log.append(f"ERROR: {str(e)}")

        def run_dns_probe(self):
            host = self.diag_host_input.text().strip()
            try:
                res = self.diagnostics.resolve_dns(host)
                self.diag_log.append(json.dumps(res, indent=2))
            except Exception as e:
                self.diag_log.append(f"ERROR: {str(e)}")

        def export_diagnostics_csv(self):
            rows = self.db.get_diagnostics_history(limit=50)
            csv_text = self.diagnostics.export_results_csv(rows)
            self.diag_log.append("\n--- CSV EXPORT ---\n" + csv_text)

        def start_load_test(self):
            target = self.load_target_input.text().strip()
            reqs = self.load_reqs.value()
            conc = self.load_conc.value()
            dry = self.chk_dry.isChecked()
            auth = self.chk_auth.isChecked()

            self.btn_run_load.setEnabled(False)
            self.btn_stop_load.setEnabled(True)
            self.load_progress.setValue(0)
            self.load_output.setText(f"Initializing Load Test on {target}...\n")

            def on_progress(done, total, lat):
                pct = int((done / total) * 100)
                self.load_progress.setValue(pct)

            def task():
                return self.load_tester.run_load_test(
                    target_url=target,
                    total_requests=reqs,
                    concurrency=conc,
                    dry_run=dry,
                    confirmed_authorized=auth,
                    progress_callback=on_progress
                )

            self.worker = WorkerThread(task)
            self.worker.finished_signal.connect(self.on_load_test_done)
            self.worker.error_signal.connect(self.on_load_test_error)
            self.worker.start()

        def stop_load_test(self):
            self.load_tester.stop()
            self.load_output.append("\n[ABORT SIGNAL DISPATCHED BY OPERATOR]")

        def on_load_test_done(self, res: LoadTestResult):
            self.btn_run_load.setEnabled(True)
            self.btn_stop_load.setEnabled(False)
            self.load_progress.setValue(100)
            summary = (
                f"\n=== LOAD TEST COMPLETED ===\n"
                f"Target: {res.target_url}\n"
                f"Total Requests: {res.total_completed} / {res.total_requested}\n"
                f"Success: {res.successful_requests} | Failed: {res.failed_requests}\n"
                f"Duration: {res.duration_seconds}s | Throughput: {res.requests_per_second} req/s\n"
                f"Latency: p50={res.p50_latency_ms}ms | p95={res.p95_latency_ms}ms | p99={res.p99_latency_ms}ms\n"
                f"Status Codes: {json.dumps(res.status_codes)}\n"
            )
            self.load_output.append(summary)

        def on_load_test_error(self, err_msg: str):
            self.btn_run_load.setEnabled(True)
            self.btn_stop_load.setEnabled(False)
            self.load_output.append(f"\n[ERROR]: {err_msg}")

        def load_synthetic_dos_sample(self):
            sample = (
                '192.168.1.105 - - [11/Oct/2026:14:00:01 +0000] "GET /api/v1/data HTTP/1.1" 200 1204 "-" "curl/8.1"\n'
                '192.168.1.105 - - [11/Oct/2026:14:00:02 +0000] "GET /api/v1/data HTTP/1.1" 200 1204 "-" "curl/8.1"\n'
                '10.0.0.99 - - [11/Oct/2026:14:00:03 +0000] "GET /login HTTP/1.1" 500 234 "-" "AttackBot/2.0"\n'
            )
            # Add burst from single IP
            for _ in range(65):
                sample += '198.51.100.42 - - [11/Oct/2026:14:00:05 +0000] "GET /search?q=test HTTP/1.1" 503 450 "-" "FloodTool"\n'
            self.dos_log_input.setText(sample)

        def analyze_dos_traffic(self):
            content = self.dos_log_input.toPlainText()
            alerts, summary = self.dos_engine.analyze_log_content(content)
            out = f"=== TRAFFIC AUDIT METRICS ===\n{json.dumps(summary, indent=2)}\n\n"
            out += f"=== DETECTED ALERTS ({len(alerts)}) ===\n"
            for a in alerts:
                out += f"[{a.severity}] [{a.confidence}] {a.indicator_type}\n"
                out += f"Description: {a.description}\n"
                out += f"Rules Generated:\n"
                for r_name, r_val in a.generated_rules.items():
                    out += f"  - {r_name}:\n      {r_val}\n"
                out += "-" * 50 + "\n"
            self.dos_results_view.setText(out)

        def run_console_command(self):
            cmd = self.wsl_cmd_combo.currentText()
            args = self.wsl_args_input.text().split()
            res = self.wsl.execute_in_wsl("Ubuntu", cmd, args)
            self.console_output.setText(
                f"$ {cmd} {' '.join(args)}\n"
                f"Exit Code: {res['returncode']}\n\n"
                f"{res['stdout']}\n{res['stderr']}"
            )

        def export_html_report(self):
            diags = self.db.get_diagnostics_history(20)
            tests = self.db.get_load_test_history(20)
            alerts = self.db.get_dos_alerts(20)
            html = self.reporter.generate_html_report("Executive Cybersecurity Audit", diags, tests, alerts)
            self.report_preview.setText(html[:2000] + "\n... [Full HTML Output Generated]")
            QMessageBox.information(self, "Report Generated", "HTML Security Report successfully compiled.")

        def export_json_report(self):
            data = {
                "diagnostics": self.db.get_diagnostics_history(50),
                "load_tests": self.db.get_load_test_history(50),
                "dos_alerts": self.db.get_dos_alerts(50)
            }
            json_str = self.reporter.generate_json_report(data)
            self.report_preview.setText(json_str)

def run_gui():
    if not HAS_PYSIDE:
        print("[!] PySide6 is not installed or GUI display is unavailable.")
        print("    Install dependencies via: pip install -r requirements.txt")
        return 1

    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    return app.exec()
