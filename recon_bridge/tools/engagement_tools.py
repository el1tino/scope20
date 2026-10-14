"""Operator controls over the engagement task tree (PTT).

These tools are the human-in-the-loop controls PentestGPT exposes — inspect the
to-do (``engagement_status``), ask what to do next (``next_steps``), ask what is
in scope (``explain_scope``), jot an observation (``record_finding``), and turn
the tree into a report (``export_report``). Unlike the recon tools, none of
these touch the network: they read and advance local state only, so they never
need (and never perform) a scoped network action. ``next_steps`` still filters
every suggestion through the engagement scope, so it can only ever point at
authorized targets.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..context import Context


def explain_scope(ctx: Context) -> dict[str, Any]:
    """Report exactly what this engagement authorizes — the ``discuss`` control.

    Lets the operator (or the model) see the authorization boundary without
    guessing: allowed hosts/CIDRs, the port allowlist, and the expiry.
    """
    summary = ctx.scope.summary()
    summary["note"] = (
        "Tools act only on these targets. Anything else — including loopback, "
        "private ranges, and the cloud metadata endpoint — is refused."
    )
    return summary


def engagement_status(ctx: Context) -> dict[str, Any]:
    """Show the current task tree, findings tally, and pending steps (``todo``)."""
    return ctx.engagement.status()


def next_steps(ctx: Context) -> dict[str, Any]:
    """Suggest the next in-scope recon actions from current findings (``next``).

    Deterministic: derived from what the tree already knows and filtered through
    scope. Each suggestion is also recorded as a pending task.
    """
    suggestions = ctx.engagement.suggest_next_steps(ctx.scope)
    return {
        "suggestions": suggestions,
        "count": len(suggestions),
        "note": (
            "No further automated recon suggested from current findings."
            if not suggestions
            else "Each suggestion names a tool and an in-scope target; run them to advance the tree."
        ),
    }


def record_finding(
    ctx: Context,
    target: str,
    title: str,
    severity: str = "info",
    detail: str = "",
) -> dict[str, Any]:
    """Record a manual observation in the tree (an operator note).

    A local annotation only — it performs no network action. ``severity`` is one
    of info|low|medium|high.
    """
    sev = severity.lower()
    if sev not in {"info", "low", "medium", "high"}:
        sev = "info"
    finding = ctx.engagement.add_finding(
        category="note",
        target=target,
        title=title,
        source_tool="record_finding",
        severity=sev,
        detail={"note": detail} if detail else {},
    )
    ctx.engagement.save()
    return {
        "recorded": finding is not None,
        "duplicate": finding is None,
        "target": target,
        "title": title,
        "severity": sev,
    }


def export_report(ctx: Context, path: str | None = None) -> dict[str, Any]:
    """Render the task tree as a Markdown recon report and write it to disk.

    Defaults to ./recon-report.md. Returns the path plus a short preview.
    """
    markdown = ctx.engagement.report_markdown(ctx.scope.summary())
    out = Path(path) if path else Path("recon-report.md")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(markdown, encoding="utf-8")
    preview = "\n".join(markdown.splitlines()[:20])
    return {"path": str(out), "bytes": len(markdown), "preview": preview}
