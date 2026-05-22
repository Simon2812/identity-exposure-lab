"""API tests for identity exposure analysis uploads."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from identity_exposure.api.main import app


def test_health_endpoint():
    client = TestClient(app)

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_analyze_upload_endpoint():
    client = TestClient(app)
    with (
        Path("sample_data/ad_users.csv").open("rb") as ad_users,
        Path("sample_data/ad_groups.csv").open("rb") as ad_groups,
        Path("sample_data/entra_export.json").open("rb") as entra_export,
    ):
        response = client.post(
            "/analyze",
            files={
                "ad_users": ("ad_users.csv", ad_users, "text/csv"),
                "ad_groups": ("ad_groups.csv", ad_groups, "text/csv"),
                "entra_export": ("entra_export.json", entra_export, "application/json"),
            },
        )

    assert response.status_code == 200
    assert response.json()["summary"]["findings"] > 0
