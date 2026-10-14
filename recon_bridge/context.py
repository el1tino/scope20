"""Shared runtime context: config + scope + audit + rate limiter in one object.

Tools receive a Context and call ``ctx.guard(...)`` once at the top. That single
call enforces scope, checks the rate limit, and opens an audit record. The tool
then does its work and calls ``record.complete(...)`` (or the guard's context
manager does it automatically). This is the only seam a new tool needs to learn.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Iterator

from .audit import AuditLog
from .config import Config
from .ratelimit import RateLimiter, RateLimitError
from .scope import Scope, ScopeError


class ToolRefused(Exception):
    """A tool was refused by the backbone (scope or rate limit). Message is safe to surface."""


class Context:
    def __init__(self, config: Config, scope: Scope, audit: AuditLog, limiter: RateLimiter):
        self.config = config
        self.scope = scope
        self.audit = audit
        self.limiter = limiter

    @classmethod
    def bootstrap(cls) -> "Context":
        config = Config.load()
        scope = Scope.load(config.scope_path)
        audit = AuditLog(config.audit_log_path)
        limiter = RateLimiter(config.rate_per_min)
        return cls(config, scope, audit, limiter)

    @contextmanager
    def guard(
        self,
        *,
        tool: str,
        target: str,
        arguments: dict[str, Any],
        port: int | None = None,
        resolved_ips: list[str] | None = None,
    ) -> Iterator["Record"]:
        """Enforce scope + rate limit, open an audit record, yield it.

        Raises ToolRefused if the target is out of scope or the rate limit is
        hit; both are logged before raising so refusals are auditable too.
        """
        # Scope first — cheapest and most important.
        try:
            if resolved_ips is not None:
                self.scope.enforce_resolved(target, resolved_ips, port)
            else:
                self.scope.enforce(target, port)
        except ScopeError as exc:
            self.audit.record(
                tool=tool, target=target, arguments=arguments,
                status="refused", detail=str(exc),
            )
            raise ToolRefused(str(exc)) from exc

        # Then the rate limit.
        try:
            self.limiter.check()
        except RateLimitError as exc:
            self.audit.record(
                tool=tool, target=target, arguments=arguments,
                status="refused", detail=str(exc),
            )
            raise ToolRefused(str(exc)) from exc

        entry_id = self.audit.record(
            tool=tool, target=target, arguments=arguments, status="allowed",
        )
        record = Record(self.audit, tool=tool, target=target, arguments=arguments, parent_id=entry_id)
        try:
            yield record
        except Exception as exc:  # noqa: BLE001 — we log then re-raise
            self.audit.record(
                tool=tool, target=target, arguments=arguments,
                status="error", detail=repr(exc),
            )
            raise
        finally:
            if not record.completed:
                record.complete({})


class Record:
    """Handle a tool uses to mark completion with a result summary."""

    def __init__(self, audit: AuditLog, *, tool: str, target: str, arguments: dict, parent_id: str):
        self._audit = audit
        self._tool = tool
        self._target = target
        self._arguments = arguments
        self._parent_id = parent_id
        self.completed = False

    def complete(self, result_summary: dict[str, Any]) -> None:
        if self.completed:
            return
        self.completed = True
        self._audit.record(
            tool=self._tool, target=self._target, arguments=self._arguments,
            status="completed", detail=f"parent={self._parent_id}",
            result_summary=result_summary,
        )
