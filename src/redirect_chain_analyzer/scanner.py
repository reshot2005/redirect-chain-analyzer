"""Redirect chain tracing and misconfiguration detection."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from secintel_core.security import bounded_read_file

_REDIRECT_STATUSES = frozenset(range(300, 400))


@dataclass(frozen=True)
class RedirectHop:
    entry_index: int
    request_url: str
    status: int
    location: str


@dataclass(frozen=True)
class RedirectChain:
    hops: tuple[RedirectHop, ...]
    chain_id: str


@dataclass(frozen=True)
class RedirectIssue:
    chain_id: str
    issue: str
    severity: str
    confidence_score: float
    detail: str
    hop_index: int


@dataclass
class RedirectCapture:
    hops: list[RedirectHop] = field(default_factory=list)


def load_redirects(path: Path) -> RedirectCapture:
    data = json.loads(bounded_read_file(path, max_bytes=50 * 1024 * 1024))
    entries = data if isinstance(data, list) else data.get("log", {}).get("entries", [])
    capture = RedirectCapture()
    for i, entry in enumerate(entries):
        req = entry.get("request", {})
        resp = entry.get("response", {})
        status = int(resp.get("status", 0))
        if status not in _REDIRECT_STATUSES:
            continue
        headers = {h["name"].lower(): h["value"] for h in resp.get("headers", [])}
        location = headers.get("location", "")
        if location:
            capture.hops.append(
                RedirectHop(
                    entry_index=i,
                    request_url=req.get("url", ""),
                    status=status,
                    location=location,
                )
            )
    return capture


def _host(url: str) -> str:
    return urlparse(url).netloc.lower()


def _scheme(url: str) -> str:
    return urlparse(url).scheme.lower()


def build_chains(hops: list[RedirectHop]) -> list[RedirectChain]:
    if not hops:
        return []
    chains: list[RedirectChain] = []
    current: list[RedirectHop] = [hops[0]]
    for hop in hops[1:]:
        prev = current[-1]
        if _host(prev.location) == _host(hop.request_url) or prev.location.rstrip("/") == hop.request_url.rstrip("/"):
            current.append(hop)
        else:
            chains.append(RedirectChain(hops=tuple(current), chain_id=f"chain-{len(chains)}"))
            current = [hop]
    chains.append(RedirectChain(hops=tuple(current), chain_id=f"chain-{len(chains)}"))
    return chains


def analyze_redirects(capture: RedirectCapture) -> tuple[list[RedirectChain], list[RedirectIssue]]:
    chains = build_chains(capture.hops)
    issues: list[RedirectIssue] = []
    for chain in chains:
        for i, hop in enumerate(chain.hops):
            req_host = _host(hop.request_url)
            loc_host = _host(hop.location)
            if loc_host and req_host and loc_host != req_host:
                issues.append(
                    RedirectIssue(
                        chain_id=chain.chain_id,
                        issue="open_redirect",
                        severity="high",
                        confidence_score=0.90,
                        detail=f"Redirects to external host: {loc_host}",
                        hop_index=i,
                    )
                )
            if _scheme(hop.request_url) == "https" and _scheme(hop.location) == "http":
                issues.append(
                    RedirectIssue(
                        chain_id=chain.chain_id,
                        issue="https_downgrade",
                        severity="high",
                        confidence_score=0.88,
                        detail="HTTPS request redirected to HTTP",
                        hop_index=i,
                    )
                )
            if _scheme(hop.request_url) != _scheme(hop.location) and loc_host == req_host:
                issues.append(
                    RedirectIssue(
                        chain_id=chain.chain_id,
                        issue="mixed_scheme",
                        severity="medium",
                        confidence_score=0.80,
                        detail=f"Scheme change {_scheme(hop.request_url)} -> {_scheme(hop.location)}",
                        hop_index=i,
                    )
                )
    return chains, issues
