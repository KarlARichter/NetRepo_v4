"""
NetRepo Secure - logging setup (rotating file logs)
"""

from __future__ import annotations

import logging
import os
from logging.handlers import RotatingFileHandler


def setup_logger(name: str, log_dir: str) -> logging.Logger:
    os.makedirs(log_dir, exist_ok=True)
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)

    if logger.handlers:
        return logger  # already configured

    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")

    # Console
    ch = logging.StreamHandler()
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    # Rotating file
    fh = RotatingFileHandler(
        os.path.join(log_dir, "netrepo.log"),
        maxBytes=256_000,
        backupCount=5,
        encoding="utf-8",
    )
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    logger.propagate = False
    return logger
