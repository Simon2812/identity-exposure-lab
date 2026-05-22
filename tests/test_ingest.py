"""Input parsing tests for identity snapshot loaders."""

from __future__ import annotations

from pathlib import Path

from identity_exposure.ingest import load_snapshot


def test_load_snapshot_from_sample_data():
    snapshot = load_snapshot(
        ad_users=Path("sample_data/ad_users.csv"),
        ad_groups=Path("sample_data/ad_groups.csv"),
        entra_export=Path("sample_data/entra_export.json"),
    )

    assert len(snapshot.users) == 10
    assert len(snapshot.groups) == 6
    assert len(snapshot.applications) == 2
    assert len(snapshot.conditional_access_policies) == 2
