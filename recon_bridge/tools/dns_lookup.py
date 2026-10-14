"""DNS lookup — pure Python, no external binary required.

Returns common record types for a host. Scope is enforced on the host (and on
the addresses it resolves to) before any query runs.
"""

from __future__ import annotations

from typing import Any

import dns.resolver

from ..context import Context
from .common import resolve_ips

_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]


def dns_lookup(ctx: Context, host: str, record_types: list[str] | None = None) -> dict[str, Any]:
    types = record_types or _RECORD_TYPES
    ips = resolve_ips(host)

    with ctx.guard(
        tool="dns_lookup",
        target=host,
        arguments={"host": host, "record_types": types},
        resolved_ips=ips,
    ) as record:
        if ctx.config.dry_run:
            record.complete({"dry_run": True})
            return {"host": host, "dry_run": True, "records": {}}

        resolver = dns.resolver.Resolver()
        resolver.lifetime = 5.0
        records: dict[str, list[str]] = {}
        for rtype in types:
            try:
                answers = resolver.resolve(host, rtype)
                records[rtype] = [str(a) for a in answers]
            except dns.resolver.NoAnswer:
                continue
            except dns.resolver.NXDOMAIN:
                records["_error"] = ["NXDOMAIN — host does not exist"]
                break
            except Exception as exc:  # noqa: BLE001
                records.setdefault("_warnings", []).append(f"{rtype}: {exc}")

        record.complete({"record_types_found": [k for k in records if not k.startswith("_")]})
        ctx.engagement.record_dns(host, ips, [k for k in records if not k.startswith("_")])
        return {"host": host, "resolved_ips": ips, "records": records}
