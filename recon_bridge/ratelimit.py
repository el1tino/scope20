"""A small sliding-window rate limiter shared across all tools.

This keeps the toolkit from hammering a target harder than you intended — a
courtesy to the client's infrastructure and a safeguard against an LLM looping
on a tool call. The limit is global (across every tool) and measured per
minute.
"""

from __future__ import annotations

import threading
import time
from collections import deque


class RateLimitError(Exception):
    """Raised when the per-minute invocation budget is exhausted."""


class RateLimiter:
    def __init__(self, per_minute: int):
        self.per_minute = max(1, per_minute)
        self._events: deque[float] = deque()
        self._lock = threading.Lock()

    def check(self) -> None:
        """Consume one unit of budget, or raise RateLimitError."""
        now = time.monotonic()
        window_start = now - 60.0
        with self._lock:
            while self._events and self._events[0] < window_start:
                self._events.popleft()
            if len(self._events) >= self.per_minute:
                wait = 60.0 - (now - self._events[0])
                raise RateLimitError(
                    f"Rate limit of {self.per_minute}/min reached. "
                    f"Try again in about {wait:.0f}s."
                )
            self._events.append(now)
