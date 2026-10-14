"""Engagement state — a resumable Pentesting-Task-Tree for reconnaissance.

Inspired by PentestGPT's Pentesting Task Tree (PTT): a single, inspectable
structure that holds everything learned so far about an engagement, so each
recon phase's findings can seed the next. Where PentestGPT drives the tree with
cooperating LLM sessions, recon-bridge keeps the *state* layer deterministic and
model-agnostic — any LLM front-end (Claude, ChatGPT, …) reads and advances the
same tree through the MCP tools, and nothing here depends on a model being
present at all.

Three things live here:

* **Assets** — hosts the toolkit has touched, with what is known about each
  (resolved IPs, open ports, whether it has been fingerprinted / resolved).
  The recon tools feed this automatically as they run.
* **Findings** — timestamped observations (a discovered subdomain, an open
  port, a missing security header), each tied to the tool that produced it.
* **Tasks** — a small phased tree (discovery → enumeration → analysis). Tools
  append the steps they complete; ``suggest_next_steps`` appends *pending*
  steps derived from the current findings. This is the PTT: a living to-do the
  operator can inspect (``todo``), advance (``next``), and turn into a report.

State persists to a JSON file so a long engagement survives a restart. It never
reaches out to the network and never widens scope: suggestions are always
filtered through the same ``Scope`` the rest of the toolkit obeys, so the tree
can only ever point at targets you are already authorized to test.
"""

from __future__ import annotations

import datetime as _dt
import json
import threading
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # avoid a runtime import cycle; Scope is only used for typing
    from .scope import Scope

_WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888}


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


@dataclass
class Finding:
    """One timestamped observation, attributed to the tool that produced it."""

    category: str  # asset | open-port | web-service | header-gap | note
    target: str
    title: str
    source_tool: str
    severity: str = "info"  # info | low | medium | high
    detail: dict[str, Any] = field(default_factory=dict)
    ts: str = field(default_factory=_now)
    id: str = field(default_factory=lambda: str(uuid.uuid4()))


@dataclass
class Task:
    """A node in the task tree: a step either completed by a tool or suggested."""

    phase: str  # discovery | enumeration | analysis
    title: str
    status: str = "done"  # done | pending
    origin: str = "manual"  # tool name, "suggested", or "manual"
    detail: str = ""
    ts: str = field(default_factory=_now)
    id: str = field(default_factory=lambda: str(uuid.uuid4()))


_PHASES = ["discovery", "enumeration", "analysis"]


class Engagement:
    """The task tree + findings + asset map for one engagement, persisted to JSON.

    All mutating methods are safe to call from multiple tool threads and save
    after each change, so the on-disk file is always a faithful snapshot.
    """

    def __init__(self, path: Path):
        self.path = path
        self.started: str = _now()
        self.assets: dict[str, dict[str, Any]] = {}
        self.findings: list[Finding] = []
        self.tasks: list[Task] = []
        self._lock = threading.RLock()

    # ---- persistence ---------------------------------------------------

    @classmethod
    def load(cls, path: Path) -> "Engagement":
        eng = cls(path)
        if not path.exists():
            return eng
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return eng  # a corrupt/unreadable file starts a fresh tree, not a crash
        eng.started = data.get("started", eng.started)
        eng.assets = data.get("assets", {})
        eng.findings = [Finding(**f) for f in data.get("findings", [])]
        eng.tasks = [Task(**t) for t in data.get("tasks", [])]
        return eng

    def save(self) -> None:
        with self._lock:
            payload = {
                "started": self.started,
                "assets": self.assets,
                "findings": [asdict(f) for f in self.findings],
                "tasks": [asdict(t) for t in self.tasks],
            }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(self.path)  # atomic swap so a crash never leaves a half-written file

    # ---- low-level mutation -------------------------------------------

    def _asset(self, host: str) -> dict[str, Any]:
        return self.assets.setdefault(
            host.lower(),
            {"ips": [], "ports": [], "fingerprinted": False, "resolved": False, "first_seen": _now()},
        )

    def add_finding(
        self,
        *,
        category: str,
        target: str,
        title: str,
        source_tool: str,
        severity: str = "info",
        detail: dict[str, Any] | None = None,
    ) -> Finding | None:
        """Append a finding, de-duplicating on (category, target, title)."""
        with self._lock:
            for existing in self.findings:
                if (existing.category, existing.target.lower(), existing.title) == (
                    category, target.lower(), title
                ):
                    return None
            finding = Finding(
                category=category, target=target, title=title,
                source_tool=source_tool, severity=severity, detail=detail or {},
            )
            self.findings.append(finding)
            return finding

    def log_task(
        self, *, phase: str, title: str, origin: str, status: str = "done", detail: str = ""
    ) -> Task | None:
        """Append a task, de-duplicating a *pending* suggestion against any
        existing task with the same title (a completed step supersedes a
        pending one of the same name)."""
        with self._lock:
            for existing in self.tasks:
                if existing.title == title:
                    if existing.status == "pending" and status == "done":
                        existing.status = "done"
                        existing.origin = origin
                        existing.ts = _now()
                    return None
            task = Task(phase=phase, title=title, status=status, origin=origin, detail=detail)
            self.tasks.append(task)
            return task

    # ---- high-level recorders the recon tools call --------------------

    def record_subdomains(self, domain: str, names: list[str]) -> None:
        with self._lock:
            for name in names:
                self._asset(name)
                self.add_finding(
                    category="asset", target=name,
                    title=f"Subdomain of {domain} in scope",
                    source_tool="subdomain_enum",
                )
            self.log_task(
                phase="discovery", origin="subdomain_enum",
                title=f"Enumerate subdomains of {domain}",
                detail=f"{len(names)} in-scope name(s) via Certificate Transparency",
            )
            self.save()

    def record_dns(self, host: str, ips: list[str], record_types: list[str]) -> None:
        with self._lock:
            asset = self._asset(host)
            asset["resolved"] = True
            asset["ips"] = sorted(set(asset["ips"]) | set(ips))
            self.add_finding(
                category="asset", target=host,
                title="Resolved via DNS",
                source_tool="dns_lookup",
                detail={"ips": ips, "record_types": record_types},
            )
            self.log_task(
                phase="discovery", origin="dns_lookup",
                title=f"DNS lookup for {host}",
                detail=f"{len(ips)} address(es)",
            )
            self.save()

    def record_ports(self, target: str, open_ports: list[dict[str, Any]]) -> None:
        with self._lock:
            asset = self._asset(target)
            nums = [p["port"] for p in open_ports if "port" in p]
            asset["ports"] = sorted(set(asset["ports"]) | set(nums))
            for p in open_ports:
                svc = p.get("service") or "unknown"
                self.add_finding(
                    category="open-port", target=target,
                    title=f"Open port {p.get('port')}/tcp ({svc})",
                    source_tool="port_scan", severity="low",
                    detail={k: p.get(k) for k in ("port", "service", "version")},
                )
            self.log_task(
                phase="enumeration", origin="port_scan",
                title=f"Port scan {target}",
                detail=f"{len(nums)} open port(s)",
            )
            self.save()

    def record_http(self, host: str, result: dict[str, Any]) -> None:
        with self._lock:
            asset = self._asset(host)
            asset["fingerprinted"] = True
            if result.get("reachable"):
                self.add_finding(
                    category="web-service", target=host,
                    title=f"HTTP service ({result.get('final_status')})",
                    source_tool="http_fingerprint",
                    detail={
                        "server": result.get("server"),
                        "title": result.get("title"),
                        "url": result.get("url"),
                    },
                )
                missing = result.get("security_headers_missing") or []
                if missing:
                    sev = "medium" if len(missing) >= 3 else "low"
                    self.add_finding(
                        category="header-gap", target=host,
                        title=f"{len(missing)} security header(s) missing",
                        source_tool="http_fingerprint", severity=sev,
                        detail={"missing": missing},
                    )
            self.log_task(
                phase="enumeration", origin="http_fingerprint",
                title=f"Fingerprint {host}",
            )
            self.save()

    # ---- the PTT engine: suggest the next in-scope recon steps --------

    def suggest_next_steps(self, scope: "Scope") -> list[dict[str, str]]:
        """Derive the next recon actions from what is known, filtered to scope.

        Deterministic and rule-based — the "forward-passing findings" idea from
        PentestGPT without needing a second model. Each suggestion is also
        materialised as a *pending* task so it shows up in ``todo`` until a tool
        completes the matching step.
        """
        from .scope import ScopeError  # local import avoids a module cycle

        suggestions: list[dict[str, str]] = []

        def in_scope(host: str) -> bool:
            try:
                scope.enforce(host)
                return True
            except ScopeError:
                return False

        def add(tool: str, target: str, why: str, phase: str, title: str) -> None:
            suggestions.append({"tool": tool, "target": target, "why": why})
            self.log_task(phase=phase, origin="suggested", title=title, status="pending", detail=why)

        with self._lock:
            # Cold start: nothing discovered yet. Seed from the scope's own hosts.
            if not self.assets:
                for host in scope.allow_hosts:
                    if "*" in host:
                        apex = host.lstrip("*.")
                        add("subdomain_enum", apex,
                            "No assets discovered yet; enumerate the apex from CT logs.",
                            "discovery", f"Enumerate subdomains of {apex}")
                    else:
                        add("dns_lookup", host,
                            "No assets discovered yet; resolve this in-scope host.",
                            "discovery", f"DNS lookup for {host}")
                if suggestions:
                    self.save()
                    return suggestions

            for host, info in sorted(self.assets.items()):
                if not in_scope(host):
                    continue
                if not info.get("resolved"):
                    add("dns_lookup", host,
                        "Asset not yet resolved; DNS maps it to addresses and reveals mail/NS records.",
                        "discovery", f"DNS lookup for {host}")
                if not info.get("ports"):
                    add("port_scan", host,
                        "No port data yet; enumerate exposed TCP services.",
                        "enumeration", f"Port scan {host}")
                web_ports = [p for p in info.get("ports", []) if p in _WEB_PORTS]
                if not info.get("fingerprinted") and (web_ports or not info.get("ports")):
                    scheme = "https" if 443 in web_ports or not info.get("ports") else "http"
                    add("http_fingerprint", f"{scheme}://{host}",
                        "Web port open (or ports unknown); fingerprint headers and banner.",
                        "enumeration", f"Fingerprint {host}")

            gaps = [f for f in self.findings if f.category == "header-gap"]
            if gaps:
                add("export_report", "engagement",
                    f"{len(gaps)} host(s) have missing security headers; capture them in the report.",
                    "analysis", "Review security-header gaps and export report")

            self.save()
        return suggestions

    # ---- read views ----------------------------------------------------

    def status(self) -> dict[str, Any]:
        with self._lock:
            by_sev: dict[str, int] = {}
            for f in self.findings:
                by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
            pending = [t.title for t in self.tasks if t.status == "pending"]
            return {
                "started": self.started,
                "assets": len(self.assets),
                "findings_total": len(self.findings),
                "findings_by_severity": by_sev,
                "tasks_done": sum(1 for t in self.tasks if t.status == "done"),
                "tasks_pending": pending,
                "asset_detail": self.assets,
            }

    def report_markdown(self, scope_summary: dict[str, Any]) -> str:
        """Render the tree as a Markdown recon report (the roadmap's export)."""
        with self._lock:
            lines: list[str] = []
            lines.append(f"# Recon report — {scope_summary.get('engagement', 'engagement')}")
            lines.append("")
            lines.append(f"- **Authorized by:** {scope_summary.get('authorized_by', 'UNSPECIFIED')}")
            lines.append(f"- **Scope expires:** {scope_summary.get('expires') or 'n/a'}")
            lines.append(f"- **Started:** {self.started}")
            lines.append(f"- **Generated:** {_now()}")
            lines.append("")

            lines.append("## Assets")
            lines.append("")
            if self.assets:
                lines.append("| Host | Addresses | Open ports | Fingerprinted |")
                lines.append("| --- | --- | --- | --- |")
                for host, info in sorted(self.assets.items()):
                    ips = ", ".join(info.get("ips") or []) or "—"
                    ports = ", ".join(str(p) for p in info.get("ports") or []) or "—"
                    fp = "yes" if info.get("fingerprinted") else "no"
                    lines.append(f"| {host} | {ips} | {ports} | {fp} |")
            else:
                lines.append("_No assets recorded yet._")
            lines.append("")

            lines.append("## Findings")
            lines.append("")
            notable = [f for f in self.findings if f.severity != "info"]
            if notable:
                lines.append("| Severity | Target | Finding | Tool |")
                lines.append("| --- | --- | --- | --- |")
                order = {"high": 0, "medium": 1, "low": 2, "info": 3}
                for f in sorted(notable, key=lambda x: order.get(x.severity, 9)):
                    lines.append(f"| {f.severity} | {f.target} | {f.title} | {f.source_tool} |")
            else:
                lines.append("_No notable (low/medium/high) findings recorded._")
            lines.append("")

            phases = {p: [t for t in self.tasks if t.phase == p] for p in _PHASES}
            lines.append("## Task tree")
            lines.append("")
            for phase in _PHASES:
                tasks = phases[phase]
                if not tasks:
                    continue
                lines.append(f"### {phase.capitalize()}")
                for t in tasks:
                    mark = "x" if t.status == "done" else " "
                    suffix = f" — {t.detail}" if t.detail else ""
                    lines.append(f"- [{mark}] {t.title}{suffix}")
                lines.append("")
            return "\n".join(lines).rstrip() + "\n"
