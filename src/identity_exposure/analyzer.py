"""High-level orchestration for identity exposure analysis reports."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from identity_exposure.detection import analyze_snapshot
from identity_exposure.ingest import load_snapshot
from identity_exposure.models import Finding, IdentitySnapshot


def analyze_exports(ad_users: Path, ad_groups: Path, entra_export: Path) -> dict:
    snapshot = load_snapshot(ad_users=ad_users, ad_groups=ad_groups, entra_export=entra_export)
    findings = analyze_snapshot(snapshot)
    # Keep the public report schema small: summary data first, then normalized
    # findings that can be written to JSON, HTML or returned by the API.
    return {
        "summary": _summary(snapshot, findings),
        "findings": [_finding_to_dict(finding) for finding in findings],
    }


def _summary(snapshot: IdentitySnapshot, findings: list[Finding]) -> dict:
    severity_counts = Counter(finding.severity.value for finding in findings)
    # Counter returns zero for absent severities, which keeps the summary shape
    # stable for clean exports.
    return {
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
        "users": len(snapshot.users),
        "groups": len(snapshot.groups),
        "applications": len(snapshot.applications),
        "conditional_access_policies": len(snapshot.conditional_access_policies),
        "findings": len(findings),
        "critical": severity_counts["critical"],
        "high": severity_counts["high"],
        "medium": severity_counts["medium"],
        "low": severity_counts["low"],
    }


def _finding_to_dict(finding: Finding) -> dict:
    return {
        "rule_id": finding.rule_id,
        "title": finding.title,
        "severity": finding.severity.value,
        "description": finding.description,
        "affected_object": finding.affected_object,
        "evidence": finding.evidence,
        "remediation": finding.remediation,
    }
