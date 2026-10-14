"""Shared helpers for tools: binary detection, bounded subprocess, DNS resolve."""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass

import dns.resolver


def have_binary(name: str) -> bool:
    return shutil.which(name) is not None


@dataclass
class CmdResult:
    ok: bool
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False


def run_cmd(args: list[str], timeout: int = 120) -> CmdResult:
    """Run an external command with a hard timeout, capturing output.

    Never shell=True: args are passed as a list so there is no shell injection
    surface even if a target string is odd.
    """
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return CmdResult(
            ok=proc.returncode == 0,
            returncode=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
        )
    except subprocess.TimeoutExpired as exc:
        return CmdResult(
            ok=False,
            returncode=-1,
            stdout=exc.stdout or "",
            stderr=f"timed out after {timeout}s",
            timed_out=True,
        )
    except FileNotFoundError:
        return CmdResult(ok=False, returncode=-1, stdout="", stderr="binary not found")


def resolve_ips(host: str, timeout: float = 5.0) -> list[str]:
    """Resolve A and AAAA records for a host. Returns [] on failure.

    Used both for enrichment and, crucially, so scope enforcement can validate
    the addresses a hostname actually points to.
    """
    ips: list[str] = []
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    for rtype in ("A", "AAAA"):
        try:
            answers = resolver.resolve(host, rtype)
            ips.extend(str(a) for a in answers)
        except Exception:  # noqa: BLE001 — absence of a record is normal
            continue
    return ips
