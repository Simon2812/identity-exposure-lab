"""Detection rule tests for identity exposure findings."""

from __future__ import annotations

from pathlib import Path

from identity_exposure.detection import analyze_snapshot
from identity_exposure.ingest import load_snapshot


def test_detection_rules_find_expected_identity_risks():
    snapshot = load_snapshot(
        ad_users=Path("sample_data/ad_users.csv"),
        ad_groups=Path("sample_data/ad_groups.csv"),
        entra_export=Path("sample_data/entra_export.json"),
    )

    findings = analyze_snapshot(snapshot)
    rule_ids = {finding.rule_id for finding in findings}

    assert "ID-003" in rule_ids
    assert "ID-005" in rule_ids
    assert "ID-006" in rule_ids
    assert "ID-007" in rule_ids
    assert "ID-009" in rule_ids
    assert "ID-010" in rule_ids
