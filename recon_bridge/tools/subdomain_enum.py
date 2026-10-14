"""Passive subdomain enumeration via Certificate Transparency logs (crt.sh).

Passive by design: it reads public CT log data rather than probing the target,
so it is low-impact. Every discovered name is checked against scope before it is
returned — names that fall outside the engagement are dropped and counted, so
the operator sees that the apex has broader attack surface without the tool
reaching outside its authorization.
"""

from __future__ import annotations

from typing import Any

import httpx

from ..context import Context
from ..scope import ScopeError

_CRT_SH = "https://crt.sh/"


def subdomain_enum(ctx: Context, domain: str) -> dict[str, Any]:
    with ctx.guard(
        tool="subdomain_enum",
        target=domain,
        arguments={"domain": domain, "source": "crt.sh"},
    ) as record:
        if ctx.config.dry_run:
            record.complete({"dry_run": True})
            return {"domain": domain, "dry_run": True, "subdomains": []}

        names = _query_crtsh(domain)

        in_scope: list[str] = []
        out_of_scope = 0
        for name in sorted(names):
            try:
                ctx.scope.enforce(name)
                in_scope.append(name)
            except ScopeError:
                out_of_scope += 1

        record.complete(
            {"found_total": len(names), "in_scope": len(in_scope), "dropped_out_of_scope": out_of_scope}
        )
        ctx.engagement.record_subdomains(domain, in_scope)
        return {
            "domain": domain,
            "source": "crt.sh (Certificate Transparency)",
            "subdomains": in_scope,
            "dropped_out_of_scope": out_of_scope,
            "note": (
                f"{out_of_scope} discovered name(s) were outside the engagement "
                f"scope and withheld." if out_of_scope else None
            ),
        }


def _query_crtsh(domain: str) -> set[str]:
    names: set[str] = set()
    try:
        resp = httpx.get(
            _CRT_SH,
            params={"q": f"%.{domain}", "output": "json"},
            timeout=30.0,
            follow_redirects=True,
        )
        resp.raise_for_status()
        for row in resp.json():
            value = row.get("name_value", "")
            for line in value.splitlines():
                line = line.strip().lstrip("*.").lower()
                if line.endswith(domain):
                    names.add(line)
    except Exception:  # noqa: BLE001 — network/JSON issues shouldn't crash the tool
        return names
    return names
