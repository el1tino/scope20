"""Scope enforcement — the heart of the authorization model.

No tool is allowed to touch a target unless that target matches an allow rule
in the engagement scope file, is not caught by a hard denylist, and the
engagement has not expired. Every tool calls ``enforce()`` before doing work.

Scope file (YAML) shape::

    engagement: "Acme Corp external assessment"
    authorized_by: "jane.doe@acme.example"      # who signed off
    expires: "2026-12-31"                         # inclusive, ISO date
    allow:
      hosts:
        - app.acme.example
        - "*.staging.acme.example"               # wildcard: one label
      cidrs:
        - 203.0.113.0/24
    deny:                                          # optional; overrides allow
      hosts:
        - admin.acme.example
      cidrs:
        - 203.0.113.1/32
    ports:                                         # optional; empty = any port
      - 80
      - 443
      - 8080

A built-in denylist (loopback, link-local, cloud metadata, RFC1918 private
space) is always applied *unless* a matching allow rule explicitly opts the
range in — this stops an operator from accidentally pointing the toolkit at
localhost, their own LAN, or a cloud metadata endpoint.
"""

from __future__ import annotations

import datetime as _dt
import fnmatch
import ipaddress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

import yaml

# Ranges we refuse by default. An allow rule whose CIDR falls inside one of
# these opts that specific range back in (useful for authorized internal work).
_DEFAULT_DENY_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),      # loopback
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("169.254.0.0/16"),   # link-local / cloud metadata
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("10.0.0.0/8"),       # RFC1918 private
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),         # unique local
]


class ScopeError(Exception):
    """Raised when a target is out of scope, denied, or the engagement lapsed."""


@dataclass
class Scope:
    engagement: str
    authorized_by: str
    expires: _dt.date | None
    allow_hosts: list[str] = field(default_factory=list)
    allow_nets: list[ipaddress._BaseNetwork] = field(default_factory=list)
    deny_hosts: list[str] = field(default_factory=list)
    deny_nets: list[ipaddress._BaseNetwork] = field(default_factory=list)
    ports: list[int] = field(default_factory=list)

    # ---- loading -------------------------------------------------------

    @classmethod
    def load(cls, path: Path) -> "Scope":
        if not path.exists():
            raise ScopeError(
                f"No scope file at {path}. Refusing to run without an "
                f"explicit list of authorized targets. Copy examples/scope.example.yaml."
            )
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        allow = data.get("allow", {}) or {}
        deny = data.get("deny", {}) or {}

        expires = data.get("expires")
        expires_date = (
            _dt.date.fromisoformat(str(expires)) if expires is not None else None
        )

        scope = cls(
            engagement=str(data.get("engagement", "unnamed engagement")),
            authorized_by=str(data.get("authorized_by", "UNSPECIFIED")),
            expires=expires_date,
            allow_hosts=[str(h).lower() for h in (allow.get("hosts") or [])],
            allow_nets=[ipaddress.ip_network(str(c)) for c in (allow.get("cidrs") or [])],
            deny_hosts=[str(h).lower() for h in (deny.get("hosts") or [])],
            deny_nets=[ipaddress.ip_network(str(c)) for c in (deny.get("cidrs") or [])],
            ports=[int(p) for p in (data.get("ports") or [])],
        )
        if not scope.allow_hosts and not scope.allow_nets:
            raise ScopeError(
                "Scope file has no allowed hosts or CIDRs. Nothing is in scope."
            )
        return scope

    # ---- checks --------------------------------------------------------

    def _expired(self) -> bool:
        return self.expires is not None and _dt.date.today() > self.expires

    def _net_default_denied(self, ip: ipaddress._BaseAddress) -> bool:
        """True if ip is in a built-in deny net and not *specifically* allowed.

        A protected range (loopback/private/metadata) is only opted back in by
        an allow rule that is itself a subnet of that protected range — a
        deliberate carve-out. A broad catch-all like 0.0.0.0/0 does NOT count,
        so it can never silently re-enable the metadata endpoint or localhost.
        """
        for deny_net in _DEFAULT_DENY_NETS:
            if ip not in deny_net:
                continue
            for allow_net in self.allow_nets:
                if allow_net.version != deny_net.version:
                    continue
                if ip in allow_net and allow_net.subnet_of(deny_net):
                    return False  # specific carve-out opts this range in
            return True  # in a protected range, no specific allow
        return False

    def _host_allowed(self, host: str) -> bool:
        host = host.lower()
        for pattern in self.allow_hosts:
            if pattern == host or fnmatch.fnmatch(host, pattern):
                return True
        return False

    def _ip_allowed(self, ip: ipaddress._BaseAddress) -> bool:
        return any(ip in n for n in self.allow_nets)

    def _denied(self, host: str, ips: Iterable[ipaddress._BaseAddress]) -> str | None:
        host = host.lower()
        for pattern in self.deny_hosts:
            if pattern == host or fnmatch.fnmatch(host, pattern):
                return f"host {host} matches an explicit deny rule"
        for ip in ips:
            if any(ip in n for n in self.deny_nets):
                return f"{ip} matches an explicit deny rule"
            if self._net_default_denied(ip):
                return (
                    f"{ip} is in a protected range (loopback/private/metadata) "
                    f"and not explicitly allowed in scope"
                )
        return None

    def enforce(self, target: str, port: int | None = None) -> None:
        """Raise ScopeError unless ``target`` (and optional port) is authorized.

        ``target`` may be a hostname or an IP literal. Hostnames are matched
        against allow/deny host rules; IP literals against CIDR rules. DNS is
        resolved lazily by the caller when it needs to validate resolved IPs;
        here we validate what we were given plus any IPs the caller passes via
        ``resolved_ips`` is handled in enforce_resolved below.
        """
        if self._expired():
            raise ScopeError(
                f"Engagement '{self.engagement}' expired on {self.expires}. "
                f"Update the scope file's authorization before continuing."
            )

        ip_literal: ipaddress._BaseAddress | None = None
        try:
            ip_literal = ipaddress.ip_address(target)
        except ValueError:
            ip_literal = None

        # Deny rules first — they always win.
        ips_to_check = [ip_literal] if ip_literal is not None else []
        reason = self._denied(target, ips_to_check)
        if reason:
            raise ScopeError(f"Target refused: {reason}.")

        # Allow check.
        if ip_literal is not None:
            allowed = self._ip_allowed(ip_literal)
        else:
            allowed = self._host_allowed(target)
        if not allowed:
            raise ScopeError(
                f"Target '{target}' is not in scope for '{self.engagement}'. "
                f"Add it to the scope file's allow list if you are authorized."
            )

        if port is not None and self.ports and port not in self.ports:
            raise ScopeError(
                f"Port {port} is outside the authorized port list for this engagement."
            )

    def enforce_resolved(
        self, target: str, resolved_ips: Iterable[str], port: int | None = None
    ) -> None:
        """Like enforce(), but also validates the IPs a hostname resolves to.

        Call this after DNS resolution so a scoped-looking hostname cannot be
        used to reach a denied or protected IP.
        """
        self.enforce(target, port)
        parsed = []
        for raw in resolved_ips:
            try:
                parsed.append(ipaddress.ip_address(raw))
            except ValueError:
                continue
        reason = self._denied(target, parsed)
        if reason:
            raise ScopeError(f"Target '{target}' resolves to a refused address: {reason}.")

    def summary(self) -> dict:
        return {
            "engagement": self.engagement,
            "authorized_by": self.authorized_by,
            "expires": self.expires.isoformat() if self.expires else None,
            "allow_hosts": self.allow_hosts,
            "allow_cidrs": [str(n) for n in self.allow_nets],
            "ports": self.ports or "any",
        }
