"""Command-line interface for running identity exposure analysis."""

from __future__ import annotations

import argparse
from pathlib import Path

from identity_exposure.analyzer import analyze_exports
from identity_exposure.reporting import write_html_report, write_json_report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyze AD and Entra ID exports for identity exposure."
    )
    # Defaults point at the included sample snapshot, while every input path can
    # be replaced for a different directory export.
    parser.add_argument("--ad-users", type=Path, default=Path("sample_data/ad_users.csv"))
    parser.add_argument("--ad-groups", type=Path, default=Path("sample_data/ad_groups.csv"))
    parser.add_argument("--entra-export", type=Path, default=Path("sample_data/entra_export.json"))
    parser.add_argument(
        "--json-out", type=Path, default=Path("artifacts/reports/identity_report.json")
    )
    parser.add_argument(
        "--html-out", type=Path, default=Path("artifacts/reports/identity_report.html")
    )
    parser.add_argument("--no-html", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    # The analyzer returns one normalized report structure that both JSON and
    # HTML writers consume.
    report = analyze_exports(
        ad_users=args.ad_users,
        ad_groups=args.ad_groups,
        entra_export=args.entra_export,
    )
    json_path = write_json_report(report, args.json_out)
    print(f"JSON report written to: {json_path}")
    if not args.no_html:
        html_path = write_html_report(report, args.html_out)
        print(f"HTML report written to: {html_path}")
    summary = report["summary"]
    print(
        "Summary: "
        f"{summary['findings']} findings "
        f"({summary['critical']} critical, {summary['high']} high, "
        f"{summary['medium']} medium, {summary['low']} low)"
    )


if __name__ == "__main__":
    main()
