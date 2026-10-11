"""
ROGUEBYTE Structured Logging
Provides unified logging across UI, background workers, and persistent logs.
"""

import logging
import sys
import os
from typing import Optional

def setup_logger(name: str = "ROGUEBYTE", log_file: Optional[str] = "roguebyte.log", level: int = logging.INFO) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Avoid duplicate handlers
    if not logger.handlers:
        formatter = logging.Formatter(
            fmt="[%(asctime)s] [%(levelname)s] [%(name)s:%(funcName)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )

        # Console handler
        ch = logging.StreamHandler(sys.stdout)
        ch.setFormatter(formatter)
        logger.addHandler(ch)

        # File handler if enabled
        if log_file:
            try:
                fh = logging.FileHandler(log_file, encoding="utf-8")
                fh.setFormatter(formatter)
                logger.addHandler(fh)
            except Exception:
                pass

    return logger

def get_logger(name: str = "ROGUEBYTE") -> logging.Logger:
    return logging.getLogger(name)
