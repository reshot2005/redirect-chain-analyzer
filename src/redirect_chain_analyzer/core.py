"""Core redirect chain analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from secintel_core import (
    Classification,
    Confidence,
    Evidence,
    Finding,
    InputArtifact,
    Provenance,
    Report,
    Severity,
    build_environment_info,
    canonical_config_hash,
    deterministic_finding_id,
    reproducible_now,
    sha256_file,
)
from secintel_core.security import safe_resolve_path

from redirect_chain_analyzer.scanner import (
    RedirectCapture,
    RedirectChain,
    RedirectIssue,
    analyze_redirects,
    load_redirects,
)

TOOL_NAME = "redirect-chain-analyzer"
TOOL_VERSION = "0.1.0"
_SEV = {"high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW}


@dataclass
class AnalysisConfig:
    base_dir: Path = field(default_factory=lambda: Path.cwd())
    max_bytes: int = 50 * 1024 * 1024


@dataclass
class AnalysisResult:
    report: Report
    capture: RedirectCapture
    chains: list[RedirectChain]
    issues: list[RedirectIssue]


def _resolve(base: Path, p: Path | str) -> Path:
    up = Path(p)
    return up.resolve() if up.is_absolute() else safe_resolve_path(base, p)


def analyze_har(
    input_path: Path | str,
    *,
    config: AnalysisConfig | None = None,
    is_sample: bool = False,
) -> AnalysisResult:
    cfg = config or AnalysisConfig()
    resolved = _resolve(cfg.base_dir, input_path)
    if not resolved.is_file():
        raise ValueError(f"HAR file not found: {resolved}")

    input_hash = sha256_file(resolved, max_bytes=cfg.max_bytes)
    started = reproducible_now()
    capture = load_redirects(resolved)
    chains, issues = analyze_redirects(capture)
    findings = _emit_findings(chains, issues, input_hash=input_hash, source=str(resolved), started=started)

    ended = reproducible_now()
    report = Report(
        provenance=Provenance(
            tool_name=TOOL_NAME,
            tool_version=TOOL_VERSION,
            config_hash=canonical_config_hash({}),
            inputs=[InputArtifact(path=str(resolved), sha256=input_hash, size_bytes=resolved.stat().st_size)],
            analysis_started_at=started,
            analysis_ended_at=ended,
            environment=build_environment_info(),
        ),
        findings=findings,
        is_sample_data=is_sample,
        metadata={"hop_count": len(capture.hops), "chain_count": len(chains), "issue_count": len(issues)},
    )
    return AnalysisResult(report=report, capture=capture, chains=chains, issues=issues)


def _emit_findings(
    chains: list[RedirectChain],
    issues: list[RedirectIssue],
    *,
    input_hash: str,
    source: str,
    started: Any,
) -> list[Finding]:
    findings: list[Finding] = []
    findings.append(
        Finding(
            id=deterministic_finding_id("redirects-observed", input_hash, {"n": len(chains)}),
            title=f"Redirect chains traced: {len(chains)}",
            classification=Classification.OBSERVED,
            evidence=[Evidence(source=source, locator={"chains": len(chains)}, retrieved_at=started)],
            method="3xx Location header chain tracing",
            why_it_matters="Redirect visibility aids open-redirect detection.",
            plain_language=f"Traced {len(chains)} redirect chain(s).",
            severity=Severity.INFO,
            tags=["redirect"],
            timestamp=started,
        )
    )
    for issue in issues:
        findings.append(
            Finding(
                id=deterministic_finding_id("redirect-issue", input_hash, {"issue": issue.issue, "chain": issue.chain_id}),
                title=f"Redirect issue: {issue.issue}",
                classification=Classification.INFERRED,
                confidence=Confidence(score=issue.confidence_score, rationale=issue.detail, supporting_indicators=[issue.issue]),
                evidence=[Evidence(source=source, locator={"chain": issue.chain_id, "hop": issue.hop_index}, retrieved_at=started)],
                method="Redirect security heuristics",
                why_it_matters="Open redirects enable phishing and token theft.",
                plain_language=issue.detail,
                severity=_SEV.get(issue.severity, Severity.MEDIUM),
                tags=["redirect", issue.issue],
                timestamp=started,
            )
        )
    return findings
