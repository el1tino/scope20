"""HTTP(S) fingerprint — a single, polite GET to read response metadata.

Collects status, server banner, security headers, title, and a few technology
hints from response headers. One request, no crawling, no fuzzing. Scope (and
the resolved IPs) are enforced before the request.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

import httpx

from ..context import Context
from .common import resolve_ips

_SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def http_fingerprint(ctx: Context, url: str) -> dict[str, Any]:
    parsed = urlparse(url if "://" in url else f"http://{url}")
    host = parsed.hostname or url
    ips = resolve_ips(host) if not _looks_like_ip(host) else [host]

    with ctx.guard(
        tool="http_fingerprint",
        target=host,
        arguments={"url": url},
        port=parsed.port or (443 if parsed.scheme == "https" else 80),
        resolved_ips=ips,
    ) as record:
        if ctx.config.dry_run:
            record.complete({"dry_run": True})
            return {"url": url, "dry_run": True}

        target_url = parsed.geturl()
        try:
            resp = httpx.get(
                target_url,
                timeout=15.0,
                follow_redirects=True,
                headers={"User-Agent": "recon-bridge/0.1 (authorized assessment)"},
            )
        except Exception as exc:  # noqa: BLE001
            record.complete({"reachable": False})
            return {"url": target_url, "reachable": False, "error": str(exc)[:200]}

        headers = {k.lower(): v for k, v in resp.headers.items()}
        title_match = _TITLE_RE.search(resp.text[:20000]) if resp.text else None
        present_sec = [h for h in _SECURITY_HEADERS if h in headers]
        missing_sec = [h for h in _SECURITY_HEADERS if h not in headers]

        result = {
            "url": str(resp.url),
            "final_status": resp.status_code,
            "reachable": True,
            "server": headers.get("server"),
            "powered_by": headers.get("x-powered-by"),
            "title": title_match.group(1).strip()[:200] if title_match else None,
            "security_headers_present": present_sec,
            "security_headers_missing": missing_sec,
            "redirect_chain": [str(r.url) for r in resp.history],
        }
        record.complete(
            {"status": resp.status_code, "missing_security_headers": len(missing_sec)}
        )
        return result


def _looks_like_ip(host: str) -> bool:
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host)) or ":" in host
