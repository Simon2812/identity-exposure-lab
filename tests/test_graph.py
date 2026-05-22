"""Privilege path graph tests for identity relationships."""

from __future__ import annotations

from pathlib import Path

from identity_exposure.graph import find_paths_to_privilege
from identity_exposure.ingest import load_snapshot


def test_graph_finds_non_privileged_path_to_high_risk_permission():
    snapshot = load_snapshot(
        ad_users=Path("sample_data/ad_users.csv"),
        ad_groups=Path("sample_data/ad_groups.csv"),
        entra_export=Path("sample_data/entra_export.json"),
    )

    paths = find_paths_to_privilege(snapshot)

    assert any(
        path.start == "entra-u-202" and path.target == "Directory.ReadWrite.All" for path in paths
    )
