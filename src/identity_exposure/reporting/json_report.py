"""JSON report serialization for identity exposure findings."""

from __future__ import annotations

import json
from pathlib import Path


def write_json_report(report: dict, output_path: Path) -> Path:
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    # Keep indentation stable so diffs and screenshots are easy to read.
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return output_path
