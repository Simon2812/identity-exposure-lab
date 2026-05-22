"""Report writer exports for identity exposure results."""

from identity_exposure.reporting.html import write_html_report
from identity_exposure.reporting.json_report import write_json_report

__all__ = ["write_html_report", "write_json_report"]
