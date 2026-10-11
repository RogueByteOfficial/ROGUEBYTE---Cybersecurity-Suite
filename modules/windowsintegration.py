"""
ROGUEBYTE Windows 10/11 Native Integration Module
Safe subprocess execution, Windows firewall status, network adapter enumeration,
and PowerShell interop without unsafe string concatenation.
"""

import os
import platform
import subprocess
from typing import Dict, Any, List, Optional
from ..core.security import SecurityValidator, SecurityViolationException

class WindowsIntegration:
    def __init__(self):
        self.is_windows = platform.system() == "Windows"

    def check_windows_environment(self) -> Dict[str, Any]:
        """Inspect host Windows platform details."""
        if not self.is_windows:
            return {
                "is_windows": False,
                "version": "Non-Windows Host (Linux/WSL)",
                "build": "N/A",
                "powershell_available": os.path.exists("/usr/bin/pwsh") or False
            }

        try:
            ver = platform.version()
            release = platform.release()
            return {
                "is_windows": True,
                "version": f"Windows {release}",
                "build": ver,
                "powershell_available": True
            }
        except Exception as e:
            return {
                "is_windows": True,
                "version": "Windows Unknown",
                "error": str(e)
            }

    def run_safe_diagnostic(self, command: str, args: List[str], timeout_sec: float = 5.0) -> Dict[str, Any]:
        """
        Execute an approved diagnostic command safely with strict argument validation
        and structured subprocess execution (never shell=True).
        """
        clean_cmd, clean_args = SecurityValidator.sanitize_command_arguments(command, args)
        full_command = [clean_cmd] + clean_args

        try:
            res = subprocess.run(
                full_command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=False,  # Enforce no shell expansion
                timeout=timeout_sec
            )
            return {
                "command": full_command,
                "returncode": res.returncode,
                "stdout": res.stdout,
                "stderr": res.stderr,
                "success": res.returncode == 0
            }
        except subprocess.TimeoutExpired:
            return {
                "command": full_command,
                "returncode": -1,
                "stdout": "",
                "stderr": f"Diagnostic command timed out after {timeout_sec}s.",
                "success": False
            }
        except FileNotFoundError:
            return {
                "command": full_command,
                "returncode": -1,
                "stdout": "",
                "stderr": f"Executable '{clean_cmd}' not found on system PATH.",
                "success": False
            }
        except Exception as e:
            return {
                "command": full_command,
                "returncode": -1,
                "stdout": "",
                "stderr": str(e),
                "success": False
            }
