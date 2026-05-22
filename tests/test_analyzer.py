"""Analyzer integration tests for identity exposure reporting."""

from __future__ import annotations

from pathlib import Path

from identity_exposure.analyzer import analyze_exports
from identity_exposure.reporting import write_html_report, write_json_report


def test_analyzer_generates_report_files(tmp_path):
    report = analyze_exports(
        ad_users=Path("sample_data/ad_users.csv"),
        ad_groups=Path("sample_data/ad_groups.csv"),
        entra_export=Path("sample_data/entra_export.json"),
    )

    assert report["summary"]["findings"] > 0
    json_path = write_json_report(report, tmp_path / "report.json")
    html_path = write_html_report(report, tmp_path / "report.html")

    assert json_path.exists()
    assert html_path.exists()
    assert "Identity Exposure Report" in html_path.read_text(encoding="utf-8")
