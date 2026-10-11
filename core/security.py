"""
ROGUEBYTE Security Validation
Enforces target restrictions, command sanitization, and safety invariants.
"""

import re
import socket
import urllib.parse
from typing import List, Tuple, Optional
from ..config.settings import SecurityPolicy, DEFAULT_ALLOWLIST

class SecurityViolationException(Exception):
    """Raised when an operation violates ROGUEBYTE safety boundaries."""
    pass

class SecurityValidator:
    # Safe allowed commands for diagnostic runs
    SAFE_COMMANDS = {
        "ping", "netstat", "ss", "traceroute", "tracert",
        "nslookup", "dig", "ip", "ifconfig", "wsl", "uname", "uptime", "hostname", "whoami"
    }

    # Prohibited shell characters to prevent injection
    SHELL_INJECTION_CHARS = re.compile(r"[;&|`$><!]")

    @classmethod
    def sanitize_command_arguments(cls, command: str, args: List[str]) -> Tuple[str, List[str]]:
        """Validate command and arguments against execution whitelist."""
        clean_cmd = command.strip().lower()
        if clean_cmd not in cls.SAFE_COMMANDS:
            raise SecurityViolationException(f"Command '{command}' is not in the approved diagnostic command allowlist.")

        clean_args = []
        for arg in args:
            arg_str = str(arg).strip()
            if cls.SHELL_INJECTION_CHARS.search(arg_str):
                raise SecurityViolationException(f"Argument '{arg_str}' contains dangerous shell control characters.")
            # Disallow flag manipulation that spawns execution
            if arg_str.startswith("-e") or arg_str.startswith("--exec") or arg_str == "--command":
                raise SecurityViolationException(f"Flag '{arg_str}' is forbidden for security.")
            clean_args.append(arg_str)

        return clean_cmd, clean_args

    @classmethod
    def validate_target_host(cls, target: str, allowlist: Optional[List[str]] = None) -> str:
        """
        Validate target hostname or IP. Ensures it is non-empty, well-formed,
        and within the authorized testing allowlist.
        """
        if not target or not target.strip():
            raise SecurityViolationException("Target cannot be empty.")

        target = target.strip()

        # Parse if full URL
        if target.startswith("http://") or target.startswith("https://"):
            parsed = urllib.parse.urlparse(target)
            host = parsed.hostname or ""
        else:
            host = target.split(":")[0]

        # Hostname character sanity check
        if not re.match(r"^[a-zA-Z0-9.\-_:]+$", host):
            raise SecurityViolationException(f"Target '{target}' contains invalid characters.")

        active_allowlist = allowlist if allowlist is not None else DEFAULT_ALLOWLIST
        allowed_hosts = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}
        for item in active_allowlist:
            clean_item = item.lower().replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
            allowed_hosts.add(clean_item)

        if host.lower() not in allowed_hosts:
            raise SecurityViolationException(
                f"Target '{host}' is NOT in the authorized allowlist. "
                f"Testing unauthorized external targets is forbidden by policy."
            )

        return host

    @classmethod
    def validate_port(cls, port: int) -> int:
        """Validate port range."""
        try:
            p = int(port)
            if p < 1 or p > 65535:
                raise ValueError()
            return p
        except Exception:
            raise SecurityViolationException(f"Port '{port}' must be an integer between 1 and 65535.")

    @classmethod
    def enforce_load_test_limits(cls, requests: int, concurrency: int, duration_sec: int, rps: int) -> None:
        """Enforce hard safety caps for load testing."""
        if requests > SecurityPolicy.HARD_MAX_REQUESTS:
            raise SecurityViolationException(f"Requested {requests} exceeds hard safety limit of {SecurityPolicy.HARD_MAX_REQUESTS} requests.")
        if concurrency > SecurityPolicy.HARD_MAX_CONCURRENCY:
            raise SecurityViolationException(f"Concurrency {concurrency} exceeds hard safety limit of {SecurityPolicy.HARD_MAX_CONCURRENCY}.")
        if duration_sec > SecurityPolicy.HARD_MAX_DURATION_SECONDS:
            raise SecurityViolationException(f"Duration {duration_sec}s exceeds hard limit of {SecurityPolicy.HARD_MAX_DURATION_SECONDS}s.")
        if rps > SecurityPolicy.HARD_MAX_RPS:
            raise SecurityViolationException(f"Rate {rps} RPS exceeds hard safety cap of {SecurityPolicy.HARD_MAX_RPS} RPS.")
