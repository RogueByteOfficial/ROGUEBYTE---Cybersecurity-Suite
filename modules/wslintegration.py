"""
ROGUEBYTE WSL2 (Ubuntu / Kali Linux) Integration Module
Detects WSL installation, lists registered distributions, evaluates health,
and bridges safe diagnostic operations between Windows and Linux environments.
"""

import os
import platform
import subprocess
import shutil
from typing import Dict, Any, List, Optional
from ..core.security import SecurityValidator, SecurityViolationException

class WSLIntegration:
    def __init__(self):
        self.host_is_windows = platform.system() == "Windows"
        self.host_is_wsl = self._is_running_inside_wsl()

    def _is_running_inside_wsl(self) -> bool:
        if platform.system() == "Linux":
            try:
                with open("/proc/version", "r") as f:
                    content = f.read().lower()
                    return "microsoft" in content or "wsl" in content
            except Exception:
                pass
        return False

    def detect_wsl_status(self) -> Dict[str, Any]:
        """Detect WSL status, version, and registered distributions."""
        if self.host_is_wsl:
            distro_name = os.environ.get("WSL_DISTRO_NAME", "Ubuntu/Linux")
            return {
                "installed": True,
                "environment": "Inside WSL2 Environment",
                "active_distribution": distro_name,
                "distributions": [
                    {"name": distro_name, "state": "Running", "version": "2", "default": True}
                ],
                "wsl_executable_found": True,
                "guidance": "Running directly inside WSL2 instance."
            }

        if not self.host_is_windows:
            return {
                "installed": False,
                "environment": "Native Linux",
                "active_distribution": None,
                "distributions": [],
                "wsl_executable_found": False,
                "guidance": "Running on a native Linux or container environment."
            }

        # On Windows host: check if wsl.exe is in path
        wsl_path = shutil.which("wsl.exe") or shutil.which("wsl")
        if not wsl_path:
            return {
                "installed": False,
                "environment": "Windows (No WSL)",
                "active_distribution": None,
                "distributions": [],
                "wsl_executable_found": False,
                "guidance": (
                    "WSL is not installed. To install WSL2 with Kali or Ubuntu, open PowerShell as Admin "
                    "and run:\n  wsl --install -d Ubuntu\nor\n  wsl --install -d kali-linux"
                )
            }

        # Probe distributions via `wsl -l -v`
        distros: List[Dict[str, Any]] = []
        try:
            res = subprocess.run(
                ["wsl", "-l", "-v"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=4.0
            )
            # wsl -l -v returns UTF-16LE or UTF-8 depending on Windows build
            output = ""
            for enc in ("utf-16le", "utf-8", "cp1252"):
                try:
                    output = res.stdout.decode(enc)
                    if "NAME" in output or "STATE" in output:
                        break
                except Exception:
                    continue

            lines = output.strip().splitlines()
            for line in lines[1:]:  # skip header
                clean = line.strip().replace("\x00", "")
                if not clean:
                    continue
                is_default = clean.startswith("*")
                parts = clean.lstrip("* ").split()
                if len(parts) >= 3:
                    distros.append({
                        "name": parts[0],
                        "state": parts[1],
                        "version": parts[2],
                        "default": is_default
                    })
        except Exception:
            pass

        return {
            "installed": True,
            "environment": "Windows 10/11 Host",
            "active_distribution": distros[0]["name"] if distros else None,
            "distributions": distros,
            "wsl_executable_found": True,
            "guidance": "WSL2 environment detected and ready for diagnostic bridging."
        }

    def execute_in_wsl(self, distro_name: str, command: str, args: List[str], timeout_sec: float = 6.0) -> Dict[str, Any]:
        """
        Execute an approved diagnostic command safely within a designated WSL distro.
        """
        clean_cmd, clean_args = SecurityValidator.sanitize_command_arguments(command, args)

        # If already inside WSL, run directly
        if self.host_is_wsl or not self.host_is_windows:
            full_cmd = [clean_cmd] + clean_args
            try:
                res = subprocess.run(
                    full_cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=timeout_sec
                )
                return {
                    "distro": distro_name or "local",
                    "command": full_cmd,
                    "returncode": res.returncode,
                    "stdout": res.stdout,
                    "stderr": res.stderr,
                    "success": res.returncode == 0
                }
            except Exception as e:
                return {
                    "distro": distro_name,
                    "command": full_cmd,
                    "returncode": -1,
                    "stdout": "",
                    "stderr": str(e),
                    "success": False
                }

        # Bridging from Windows host to WSL via `wsl -d <distro> -- <cmd> <args>`
        full_exec = ["wsl", "-d", distro_name, "--", clean_cmd] + clean_args
        try:
            res = subprocess.run(
                full_exec,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout_sec
            )
            return {
                "distro": distro_name,
                "command": full_exec,
                "returncode": res.returncode,
                "stdout": res.stdout,
                "stderr": res.stderr,
                "success": res.returncode == 0
            }
        except subprocess.TimeoutExpired:
            return {
                "distro": distro_name,
                "command": full_exec,
                "returncode": -1,
                "stdout": "",
                "stderr": f"Command timed out in WSL '{distro_name}' after {timeout_sec}s.",
                "success": False
            }
        except Exception as e:
            return {
                "distro": distro_name,
                "command": full_exec,
                "returncode": -1,
                "stdout": "",
                "stderr": str(e),
                "success": False
            }
