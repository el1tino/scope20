"""Tool registry.

Each tool is a plain function ``fn(ctx, **kwargs) -> dict``. The registry below
is the single source of truth that both the MCP server and the OpenAI bridge
read, so adding a capability means adding one entry here — not editing the
server and the bridge separately.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from .dns_lookup import dns_lookup
from .engagement_tools import (
    engagement_status,
    explain_scope,
    export_report,
    next_steps,
    record_finding,
)
from .http_fingerprint import http_fingerprint
from .port_scan import port_scan
from .subdomain_enum import subdomain_enum


@dataclass
class ToolSpec:
    name: str
    description: str
    fn: Callable[..., dict[str, Any]]
    # JSON-schema-style parameter description, reused by MCP and OpenAI.
    parameters: dict[str, Any]


REGISTRY: list[ToolSpec] = [
    ToolSpec(
        name="dns_lookup",
        description=(
            "Resolve DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA) for a host in "
            "scope. Pure passive lookup."
        ),
        fn=dns_lookup,
        parameters={
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Hostname to resolve."},
                "record_types": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional subset of record types to query.",
                },
            },
            "required": ["host"],
        },
    ),
    ToolSpec(
        name="subdomain_enum",
        description=(
            "Passively enumerate subdomains of an in-scope domain from Certificate "
            "Transparency logs. Returns only names that are themselves in scope."
        ),
        fn=subdomain_enum,
        parameters={
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Apex domain, e.g. acme.example."},
            },
            "required": ["domain"],
        },
    ),
    ToolSpec(
        name="port_scan",
        description=(
            "Scan TCP ports on an in-scope target. Uses nmap with service/version "
            "detection when available, else a Python TCP-connect scan of common ports."
        ),
        fn=port_scan,
        parameters={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Hostname or IP in scope."},
                "ports": {
                    "type": "array",
                    "items": {"type": "integer"},
                    "description": "Optional explicit port list; defaults to a common set.",
                },
                "service_detection": {
                    "type": "boolean",
                    "description": "Attempt service/version detection (nmap only).",
                },
            },
            "required": ["target"],
        },
    ),
    ToolSpec(
        name="http_fingerprint",
        description=(
            "Fetch a single page from an in-scope URL and report status, server "
            "banner, title, security-header posture, and redirect chain."
        ),
        fn=http_fingerprint,
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "URL or host; scheme optional."},
            },
            "required": ["url"],
        },
    ),
    # --- Engagement controls (the PentestGPT-style task-tree operators) -------
    # These read/advance the local engagement state; they perform no network I/O.
    ToolSpec(
        name="explain_scope",
        description=(
            "Explain exactly what this engagement authorizes: allowed hosts and "
            "CIDRs, the port allowlist, and the expiry. Performs no network action."
        ),
        fn=explain_scope,
        parameters={"type": "object", "properties": {}},
    ),
    ToolSpec(
        name="engagement_status",
        description=(
            "Show the engagement task tree: discovered assets, findings by "
            "severity, completed steps, and the pending to-do list."
        ),
        fn=engagement_status,
        parameters={"type": "object", "properties": {}},
    ),
    ToolSpec(
        name="next_steps",
        description=(
            "Suggest the next in-scope reconnaissance actions, derived from the "
            "current findings and filtered through scope. Records each as a "
            "pending task."
        ),
        fn=next_steps,
        parameters={"type": "object", "properties": {}},
    ),
    ToolSpec(
        name="record_finding",
        description=(
            "Record a manual observation (an operator note) in the engagement "
            "tree. Local annotation only; performs no network action."
        ),
        fn=record_finding,
        parameters={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Host or asset the note is about."},
                "title": {"type": "string", "description": "Short description of the observation."},
                "severity": {
                    "type": "string",
                    "description": "info | low | medium | high.",
                },
                "detail": {"type": "string", "description": "Optional longer note."},
            },
            "required": ["target", "title"],
        },
    ),
    ToolSpec(
        name="export_report",
        description=(
            "Render the engagement task tree as a Markdown recon report and write "
            "it to disk (default ./recon-report.md)."
        ),
        fn=export_report,
        parameters={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Optional output path for the report."},
            },
        },
    ),
]

BY_NAME = {spec.name: spec for spec in REGISTRY}
