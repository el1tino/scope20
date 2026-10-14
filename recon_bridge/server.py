"""MCP server entry point (mcp SDK 2.x / MCPServer).

Exposes the recon tools over the Model Context Protocol so any MCP-capable
client — Claude Code, Claude Desktop, or another host — can drive them. The
tool logic lives in recon_bridge.tools; the thin typed wrappers below are what
the SDK introspects to build each tool's schema. Blocking work is offloaded to
a worker thread so it never stalls the event loop.

Run::

    python -m recon_bridge.server            # start the MCP server over stdio
    python -m recon_bridge.server --check    # validate scope config and exit
"""

from __future__ import annotations

import json
import sys

import anyio
from mcp.server.mcpserver import MCPServer

from .context import Context, ToolRefused
from .tools import BY_NAME

INSTRUCTIONS = (
    "Authorization-aware reconnaissance tools. Every tool refuses any target "
    "not listed in the engagement scope file, and logs every call. If a tool "
    "returns a message beginning 'REFUSED:', the target is out of scope or the "
    "rate limit was hit — do not retry; report the refusal to the operator."
)

_ctx: Context | None = None


def _context() -> Context:
    global _ctx
    if _ctx is None:
        _ctx = Context.bootstrap()
    return _ctx


async def _run_tool(name: str, **kwargs) -> str:
    """Shared body for every wrapper: offload to a thread, format the result."""
    ctx = _context()
    spec = BY_NAME[name]
    try:
        result = await anyio.to_thread.run_sync(lambda: spec.fn(ctx, **kwargs))
    except ToolRefused as exc:
        return f"REFUSED: {exc}"
    return json.dumps(result, indent=2, ensure_ascii=False)


# --- Typed wrappers the SDK turns into MCP tools -------------------------------
# Signatures and docstrings here become each tool's advertised schema.

async def dns_lookup(host: str, record_types: list[str] | None = None) -> str:
    """Resolve DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA) for an in-scope host.

    host: hostname to resolve.
    record_types: optional subset of record types; omit for all.
    """
    return await _run_tool("dns_lookup", host=host, record_types=record_types)


async def subdomain_enum(domain: str) -> str:
    """Passively enumerate subdomains of an in-scope domain from Certificate
    Transparency logs. Only names that are themselves in scope are returned.

    domain: apex domain, e.g. acme.example.
    """
    return await _run_tool("subdomain_enum", domain=domain)


async def port_scan(
    target: str,
    ports: list[int] | None = None,
    service_detection: bool = True,
) -> str:
    """Scan TCP ports on an in-scope target. Uses nmap with service/version
    detection when installed, else a Python TCP-connect scan of common ports.

    target: hostname or IP in scope.
    ports: optional explicit port list; omit for a common-ports default.
    service_detection: attempt service/version detection (nmap only).
    """
    return await _run_tool(
        "port_scan", target=target, ports=ports, service_detection=service_detection
    )


async def http_fingerprint(url: str) -> str:
    """Fetch a single page from an in-scope URL and report status, server banner,
    page title, security-header posture, and redirect chain. One request, no crawl.

    url: URL or host; scheme optional.
    """
    return await _run_tool("http_fingerprint", url=url)


def build_server() -> MCPServer:
    server = MCPServer("recon-bridge", instructions=INSTRUCTIONS, version="0.1.0")
    server.add_tool(dns_lookup)
    server.add_tool(subdomain_enum)
    server.add_tool(port_scan)
    server.add_tool(http_fingerprint)
    return server


def main() -> None:
    if "--check" in sys.argv:
        ctx = _context()
        print("Scope loaded successfully:\n")
        print(json.dumps(ctx.scope.summary(), indent=2))
        print(f"\nAudit log: {ctx.config.audit_log_path}")
        print(f"Rate limit: {ctx.config.rate_per_min}/min")
        print(f"Dry run:    {ctx.config.dry_run}")
        return
    # Validate scope before opening the transport, so misconfig fails loudly.
    _context()
    build_server().run("stdio")


if __name__ == "__main__":
    main()
