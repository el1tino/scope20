"""Port / service scan.

Uses nmap when it is installed (richer: service + version detection). Falls
back to a pure-Python TCP connect scan of a common-ports list when nmap is
absent, so the tool is useful on any machine. Scope — including the per-port
allowlist — is enforced before any packet leaves the host.
"""

from __future__ import annotations

import socket
from typing import Any

from ..context import Context, ToolRefused
from ..scope import ScopeError
from .common import have_binary, resolve_ips, run_cmd

# A small, sensible default set for the fallback scanner.
_COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 587,
    993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379,
    8000, 8080, 8443, 9200, 27017,
]


def port_scan(
    ctx: Context,
    target: str,
    ports: list[int] | None = None,
    service_detection: bool = True,
) -> dict[str, Any]:
    ips = resolve_ips(target) if not _is_ip(target) else [target]
    scan_ports = ports or _COMMON_PORTS

    # Enforce scope on the target and each requested port up front. If a
    # specific port is out of scope we refuse the whole call rather than
    # silently dropping it, so the operator knows.
    with ctx.guard(
        tool="port_scan",
        target=target,
        arguments={"ports": scan_ports, "service_detection": service_detection},
        resolved_ips=ips,
    ) as record:
        # Per-port scope check (guard already checked the target).
        for p in scan_ports:
            try:
                ctx.scope.enforce(target, port=p)
            except ScopeError as exc:
                raise ToolRefused(str(exc)) from exc

        if ctx.config.dry_run:
            record.complete({"dry_run": True, "ports_requested": len(scan_ports)})
            return {"target": target, "dry_run": True, "open_ports": []}

        if have_binary("nmap"):
            result = _nmap_scan(target, scan_ports, service_detection)
            engine = "nmap"
        else:
            result = _tcp_connect_scan(target, scan_ports)
            engine = "tcp-connect (nmap not installed)"

        record.complete({"engine": engine, "open_ports": len(result.get("open_ports", []))})
        result["engine"] = engine
        ctx.engagement.record_ports(target, result.get("open_ports", []))
        return result


def _is_ip(target: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET, target)
        return True
    except OSError:
        try:
            socket.inet_pton(socket.AF_INET6, target)
            return True
        except OSError:
            return False


def _nmap_scan(target: str, ports: list[int], service_detection: bool) -> dict[str, Any]:
    port_arg = ",".join(str(p) for p in ports)
    args = ["nmap", "-Pn", "-p", port_arg]
    if service_detection:
        args.append("-sV")
    args.append(target)
    res = run_cmd(args, timeout=300)
    open_ports = _parse_nmap(res.stdout)
    return {
        "target": target,
        "open_ports": open_ports,
        "raw_available": True,
        "note": None if res.ok else f"nmap exited {res.returncode}: {res.stderr.strip()[:200]}",
    }


def _parse_nmap(stdout: str) -> list[dict[str, Any]]:
    out = []
    for line in stdout.splitlines():
        line = line.strip()
        # Lines look like: "22/tcp open ssh OpenSSH 8.9p1"
        if "/tcp" in line and (" open" in line or " filtered" in line):
            parts = line.split()
            port_proto = parts[0]
            state = parts[1] if len(parts) > 1 else ""
            service = parts[2] if len(parts) > 2 else ""
            version = " ".join(parts[3:]) if len(parts) > 3 else ""
            try:
                port_num = int(port_proto.split("/")[0])
            except ValueError:
                continue
            if state == "open":
                out.append({"port": port_num, "state": state, "service": service, "version": version})
    return out


def _tcp_connect_scan(target: str, ports: list[int]) -> dict[str, Any]:
    open_ports = []
    for p in ports:
        if _tcp_open(target, p):
            open_ports.append({"port": p, "state": "open", "service": _guess_service(p), "version": ""})
    return {"target": target, "open_ports": open_ports, "raw_available": False, "note": None}


def _tcp_open(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


_SERVICE_HINTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 143: "imap", 443: "https", 445: "smb", 3306: "mysql",
    3389: "rdp", 5432: "postgresql", 6379: "redis", 8080: "http-alt", 8443: "https-alt",
}


def _guess_service(port: int) -> str:
    return _SERVICE_HINTS.get(port, "")
