"""
NetRepo Secure - Security helpers
- filename sanitization (prevents directory traversal)
- sha256 hashing
- simple token-bucket rate limiter
"""

from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass
from typing import Optional


def safe_join(repo_dir: str, filename: str) -> Optional[str]:
    """
    Return an absolute path to filename inside repo_dir, or None if invalid.

    Blocks:
    - path traversal (../)
    - absolute paths
    - path separators
    """
    if not filename or len(filename) > 255:
        return None
    # Disallow any path separators
    if "/" in filename or "\\" in filename:
        return None
    # Normalize to basename only
    fname = os.path.basename(filename)
    repo_abs = os.path.abspath(repo_dir)
    target = os.path.abspath(os.path.join(repo_abs, fname))
    # Ensure inside repo directory
    if not (target.startswith(repo_abs + os.sep) or target == repo_abs):
        return None
    return target


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass
class TokenBucket:
    capacity: float = 20.0        # max burst
    refill_per_sec: float = 10.0  # tokens per second
    tokens: float = 20.0
    last: float = 0.0

    def __post_init__(self) -> None:
        self.last = time.monotonic()

    def allow(self, cost: float = 1.0) -> bool:
        now = time.monotonic()
        elapsed = max(0.0, now - self.last)
        self.last = now
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_per_sec)
        if self.tokens >= cost:
            self.tokens -= cost
            return True
        return False
