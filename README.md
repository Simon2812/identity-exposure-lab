# Identity Exposure Lab

Identity Exposure Lab analyzes small Active Directory-style CSV exports and Microsoft Entra ID-style JSON exports. It normalizes users, groups, applications, policies, and permissions, then reports risky identity configurations and privilege paths.

## Inputs

```text
sample_data/ad_users.csv
sample_data/ad_groups.csv
sample_data/entra_export.json
```

## Run

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
python -m identity_exposure.cli
pytest
```

Custom files:

```bash
identity-exposure --ad-users sample_data/ad_users.csv --ad-groups sample_data/ad_groups.csv --entra-export sample_data/entra_export.json
```

## Screenshots

These screenshots are from the real CLI run, generated JSON/HTML reports, the running FastAPI Swagger UI, and a real `/analyze` response created from the sample files.

To reproduce the same views:

```bash
PYTHONPATH=src python -m identity_exposure.cli
PYTHONPATH=src uvicorn identity_exposure.api.main:app --reload
curl \
  -F "ad_users=@sample_data/ad_users.csv;type=text/csv" \
  -F "ad_groups=@sample_data/ad_groups.csv;type=text/csv" \
  -F "entra_export=@sample_data/entra_export.json;type=application/json" \
  http://localhost:8000/analyze
```

Then open `artifacts/reports/identity_report.html`, `artifacts/reports/identity_report.json`, and `http://localhost:8000/docs`.

JSON findings:
(docs/screenshots/json-findings.png)

HTML report:
(docs/screenshots/html-report.png)

API upload response:
(docs/screenshots/upload-response.png)

FastAPI docs:(docs/screenshots/fastapi-docs.png)

## Findings Covered

- Disabled privileged accounts.
- Stale privileged identities.
- Privileged cloud accounts without MFA.
- Passwords set to never expire.
- SPN-backed service accounts.
- Guest identities with privileged access.
- High-risk application permissions.
- Stale application secrets.
- Missing tenant-wide MFA Conditional Access coverage.
- Non-privileged paths to privileged objects.

## API Mode

```bash
uvicorn identity_exposure.api.main:app --reload
```

Open `http://localhost:8000/docs` and upload the three sample files to `POST /analyze`.

## Layout

```text
src/identity_exposure/ingest/       CSV and JSON loaders
src/identity_exposure/detection/    identity risk rules
src/identity_exposure/graph/        exposure path traversal
src/identity_exposure/reporting/    report writers
artifacts/reports/                  generated JSON and HTML reports
```

Keywords: identity security, active directory, entra id, graph analysis, fastapi, pytest
