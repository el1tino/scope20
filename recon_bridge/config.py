"""Runtime configuration, loaded from environment variables with sane defaults.

Reading .env is optional: if python-dotenv is installed we load it, otherwise
we rely on the ambient environment. We deliberately avoid a hard dependency.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _load_dotenv() -> None:
    """Best-effort .env load without a hard dependency on python-dotenv."""
    env_path = Path(".env")
    if not env_path.exists():
        return
    for raw in env_path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        # Do not clobber a value already set in the real environment.
        os.environ.setdefault(key, value)


@dataclass(frozen=True)
class Config:
    scope_path: Path
    audit_log_path: Path
    rate_per_min: int
    dry_run: bool

    @classmethod
    def load(cls) -> "Config":
        _load_dotenv()
        return cls(
            scope_path=Path(os.environ.get("RECON_BRIDGE_SCOPE", "./scope.yaml")),
            audit_log_path=Path(
                os.environ.get("RECON_BRIDGE_AUDIT_LOG", "./logs/audit.jsonl")
            ),
            rate_per_min=int(os.environ.get("RECON_BRIDGE_RATE_PER_MIN", "30")),
            dry_run=os.environ.get("RECON_BRIDGE_DRY_RUN", "0") == "1",
        )
