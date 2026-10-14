"""Tests for the scope enforcement layer — the authorization boundary."""

import datetime as dt
import textwrap

import pytest

from recon_bridge.scope import Scope, ScopeError


def _write_scope(tmp_path, body: str):
    p = tmp_path / "scope.yaml"
    p.write_text(textwrap.dedent(body), encoding="utf-8")
    return Scope.load(p)


def test_allows_exact_host(tmp_path):
    scope = _write_scope(tmp_path, """
        engagement: t
        expires: "2099-01-01"
        allow:
          hosts: [app.acme.example]
    """)
    scope.enforce("app.acme.example")  # should not raise


def test_allows_wildcard_one_label(tmp_path):
    scope = _write_scope(tmp_path, """
        engagement: t
        expires: "2099-01-01"
        allow:
          hosts: ["*.acme.example"]
    """)
    scope.enforce("api.acme.example")


def test_refuses_out_of_scope_host(tmp_path):
    scope = _write_scope(tmp_path, """
        engagement: t
        expires: "2099-01-01"
        allow:
          hosts: [app.acme.example]
    """)
    with pytest.raises(ScopeError):
        scope.enforce("evil.other.example")


def test_deny_overrides_allow(tmp_path):
    scope = _write_scope(tmp_path, """
        engagement: t
        expires: "2099-01-01"
        allow:
          hosts: ["*.acme.example"]
        deny:
          hosts: [admin.acme.example]
    """)
    with pytest.raises(ScopeError):
        scope.enforce("admin.acme.example")


def test_cidr_allow_and_private_default_deny(tmp_path):
    scope = _write_scope(tmp_path, """
        engagement: t
        expires: "2099-01-01"
        allow:
          cidrs: [203.0.113.0/24]
    """)
    scope.enforce("203.0.113.10")  # allowed public range
    with pytest.raises(ScopeError):
        scope.enforce("192.168.1.1")  # private, not allowed -> default deny


def test_metadata_ip_refused_even_if_broadly_allowed(tmp_path):
    scope = _write_scope(tmp_path, """
        engagement: t
        expires: "2099-01-01"
        allow:
          cidrs: [0.0.0.0/0]
    """)
    # 0.0.0.0/0 allows everything, but link-local/metadata stays denied unless
    # a specific allow net opts it in.
    with pytest.raises(ScopeError):
        scope.enforce("169.254.169.254")


def test_expired_engagement_refused(tmp_path):
    yesterday = (dt.date.today() - dt.timedelta(days=1)).isoformat()
    scope = _write_scope(tmp_path, f"""
        engagement: t
        expires: "{yesterday}"
        allow:
          hosts: [app.acme.example]
    """)
    with pytest.raises(ScopeError):
        scope.enforce("app.acme.example")


def test_port_allowlist(tmp_path):
    scope = _write_scope(tmp_path, """
        engagement: t
        expires: "2099-01-01"
        allow:
          hosts: [app.acme.example]
        ports: [80, 443]
    """)
    scope.enforce("app.acme.example", port=443)
    with pytest.raises(ScopeError):
        scope.enforce("app.acme.example", port=22)


def test_resolved_ip_to_private_refused(tmp_path):
    scope = _write_scope(tmp_path, """
        engagement: t
        expires: "2099-01-01"
        allow:
          hosts: [app.acme.example]
    """)
    # Host is allowed, but if it resolves into private space we still refuse.
    with pytest.raises(ScopeError):
        scope.enforce_resolved("app.acme.example", ["10.0.0.5"])


def test_empty_allowlist_rejected(tmp_path):
    with pytest.raises(ScopeError):
        _write_scope(tmp_path, """
            engagement: t
            expires: "2099-01-01"
            allow: {}
        """)
