"""HTTP API for uploading and analyzing identity snapshots."""

from __future__ import annotations

import tempfile
from pathlib import Path

from fastapi import FastAPI, File, UploadFile

from identity_exposure.analyzer import analyze_exports


app = FastAPI(
    title="Identity Exposure Lab",
    version="0.1.0",
    description="Analyze AD CSV and Microsoft Entra ID JSON exports for identity exposure.",
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/analyze")
async def analyze(
    ad_users: UploadFile = File(...),
    ad_groups: UploadFile = File(...),
    entra_export: UploadFile = File(...),
) -> dict:
    with tempfile.TemporaryDirectory() as temp_dir:
        base = Path(temp_dir)
        ad_users_path = base / "ad_users.csv"
        ad_groups_path = base / "ad_groups.csv"
        entra_path = base / "entra_export.json"
        # Persist uploads into a temporary snapshot so API analysis uses the
        # exact same file loaders as the CLI.
        ad_users_path.write_bytes(await ad_users.read())
        ad_groups_path.write_bytes(await ad_groups.read())
        entra_path.write_bytes(await entra_export.read())
        return analyze_exports(ad_users_path, ad_groups_path, entra_path)
