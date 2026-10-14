"""Append-only audit log.

Every tool invocation — allowed or refused — is written as one JSON object per
line (JSONL). On a real engagement this is your record of exactly what was
touched, when, and with what result. The log is append-only by convention and
flushed on every write so a crash never loses the trail.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import socket
import threading
import uuid
from pathlib import Path
from typing import Any

_lock = threading.Lock()


class AuditLog:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._operator = os.environ.get("USER") or os.environ.get("USERNAME") or "unknown"
        self._host = socket.gethostname()

    def record(
        self,
        *,
        tool: str,
        target: str,
        arguments: dict[str, Any],
        status: str,
        detail: str = "",
        result_summary: dict[str, Any] | None = None,
    ) -> str:
        """Write one audit entry. Returns the entry id.

        status is one of: "allowed", "refused", "error", "completed".
        """
        entry = {
            "id": str(uuid.uuid4()),
            "ts": _dt.datetime.now(_dt.timezone.utc).isoformat(),
            "operator": self._operator,
            "operator_host": self._host,
            "tool": tool,
            "target": target,
            "arguments": _redact(arguments),
            "status": status,
            "detail": detail,
            "result_summary": result_summary or {},
        }
        line = json.dumps(entry, ensure_ascii=False)
        with _lock:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
                fh.flush()
        return entry["id"]


def _redact(arguments: dict[str, Any]) -> dict[str, Any]:
    """Strip anything that looks like a secret before it reaches the log."""
    redacted = {}
    for key, value in arguments.items():
        if any(s in key.lower() for s in ("key", "token", "secret", "password", "auth")):
            redacted[key] = "<redacted>"
        else:
            redacted[key] = value
    return redacted
