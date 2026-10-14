"""Tests for the engagement task tree (PTT) and its scope-filtered suggestions."""

import textwrap

from recon_bridge.engagement import Engagement
from recon_bridge.scope import Scope


def _scope(tmp_path, body: str) -> Scope:
    p = tmp_path / "scope.yaml"
    p.write_text(textwrap.dedent(body), encoding="utf-8")
    return Scope.load(p)


def _engagement(tmp_path) -> Engagement:
    return Engagement.load(tmp_path / "engagement.json")


def test_findings_are_deduplicated(tmp_path):
    eng = _engagement(tmp_path)
    assert eng.add_finding(category="asset", target="a.acme.example", title="x", source_tool="t")
    # Same (category, target, title) again -> no duplicate.
    assert eng.add_finding(category="asset", target="a.acme.example", title="x", source_tool="t") is None
    assert len(eng.findings) == 1


def test_recording_persists_and_reloads(tmp_path):
    eng = _engagement(tmp_path)
    eng.record_subdomains("acme.example", ["app.acme.example"])
    eng.record_ports("app.acme.example", [{"port": 443, "service": "https", "version": ""}])

    reloaded = Engagement.load(tmp_path / "engagement.json")
    assert "app.acme.example" in reloaded.assets
    assert 443 in reloaded.assets["app.acme.example"]["ports"]
    assert any(f.category == "open-port" for f in reloaded.findings)


def test_suggestions_cold_start_from_scope(tmp_path):
    scope = _scope(tmp_path, """
        engagement: t
        expires: "2099-01-01"
        allow:
          hosts:
            - app.acme.example
            - "*.acme.example"
    """)
    eng = _engagement(tmp_path)
    suggestions = eng.suggest_next_steps(scope)
    tools = {s["tool"] for s in suggestions}
    # Exact host -> resolve it; wildcard -> enumerate the apex.
    assert "dns_lookup" in tools
    assert "subdomain_enum" in tools
    # Cold-start suggestions are materialised as pending tasks.
    assert any(t.status == "pending" for t in eng.tasks)


def test_suggestions_forward_from_findings(tmp_path):
    scope = _scope(tmp_path, """
        engagement: t
        expires: "2099-01-01"
        allow:
          hosts: ["*.acme.example"]
    """)
    eng = _engagement(tmp_path)
    eng.record_subdomains("acme.example", ["app.acme.example"])
    suggestions = eng.suggest_next_steps(scope)
    targets = {(s["tool"], s["target"]) for s in suggestions}
    # A discovered-but-unprobed asset should be queued for DNS, ports, and HTTP.
    assert ("port_scan", "app.acme.example") in targets
    assert ("dns_lookup", "app.acme.example") in targets
    assert any(tool == "http_fingerprint" for tool, _ in targets)


def test_suggestions_skip_out_of_scope_assets(tmp_path):
    scope = _scope(tmp_path, """
        engagement: t
        expires: "2099-01-01"
        allow:
          hosts: [app.acme.example]
    """)
    eng = _engagement(tmp_path)
    # An asset recorded earlier that is no longer in scope must not be suggested.
    eng._asset("old.other.example")
    suggestions = eng.suggest_next_steps(scope)
    assert all("other.example" not in s["target"] for s in suggestions)


def test_header_gap_triggers_report_suggestion(tmp_path):
    scope = _scope(tmp_path, """
        engagement: t
        expires: "2099-01-01"
        allow:
          hosts: ["*.acme.example"]
    """)
    eng = _engagement(tmp_path)
    eng.record_http(
        "app.acme.example",
        {"reachable": True, "final_status": 200, "security_headers_missing": ["csp", "hsts", "x-frame-options"]},
    )
    suggestions = eng.suggest_next_steps(scope)
    assert any(s["tool"] == "export_report" for s in suggestions)
    assert any(f.category == "header-gap" and f.severity == "medium" for f in eng.findings)


def test_report_markdown_contains_assets_and_findings(tmp_path):
    scope = _scope(tmp_path, """
        engagement: Acme test
        authorized_by: lead@acme.example
        expires: "2099-01-01"
        allow:
          hosts: ["*.acme.example"]
    """)
    eng = _engagement(tmp_path)
    eng.record_ports("app.acme.example", [{"port": 22, "service": "ssh", "version": ""}])
    md = eng.report_markdown(scope.summary())
    assert "# Recon report" in md
    assert "app.acme.example" in md
    assert "Open port 22/tcp (ssh)" in md


def test_status_counts(tmp_path):
    eng = _engagement(tmp_path)
    eng.record_subdomains("acme.example", ["a.acme.example", "b.acme.example"])
    status = eng.status()
    assert status["assets"] == 2
    assert status["findings_total"] >= 2
    assert status["tasks_done"] >= 1
