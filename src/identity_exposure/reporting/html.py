"""HTML report rendering for identity exposure findings."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Template


TEMPLATE = Template(
    """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Identity Exposure Report</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 32px; background: #f8fafc; color: #1f2937; }
    h1, h2 { margin-bottom: 8px; }
    .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin: 20px 0; }
    .metric { background: white; border: 1px solid #dbe3ef; border-radius: 8px; padding: 14px; }
    .metric span { display: block; color: #64748b; font-size: 13px; }
    .metric strong { display: block; font-size: 26px; margin-top: 4px; }
    .finding { background: white; border-left: 6px solid #64748b; border-radius: 8px; padding: 16px; margin: 16px 0; }
    .critical { border-left-color: #991b1b; }
    .high { border-left-color: #dc2626; }
    .medium { border-left-color: #d97706; }
    .low { border-left-color: #2563eb; }
    .badge { display: inline-block; padding: 3px 8px; border-radius: 999px; font-size: 12px; text-transform: uppercase; background: #e2e8f0; }
    code { background: #e2e8f0; padding: 2px 5px; border-radius: 4px; }
  </style>
</head>
<body>
  <h1>Identity Exposure Report</h1>
  <p>Analyzed at {{ summary.analyzed_at }}</p>
  <section class="summary">
    <div class="metric"><span>Users</span><strong>{{ summary.users }}</strong></div>
    <div class="metric"><span>Groups</span><strong>{{ summary.groups }}</strong></div>
    <div class="metric"><span>Apps</span><strong>{{ summary.applications }}</strong></div>
    <div class="metric"><span>Findings</span><strong>{{ summary.findings }}</strong></div>
    <div class="metric"><span>Critical</span><strong>{{ summary.critical }}</strong></div>
    <div class="metric"><span>High</span><strong>{{ summary.high }}</strong></div>
  </section>
  <h2>Findings</h2>
  {% for finding in findings %}
    <article class="finding {{ finding.severity }}">
      <span class="badge">{{ finding.severity }}</span>
      <h3>{{ finding.rule_id }} - {{ finding.title }}</h3>
      <p>{{ finding.description }}</p>
      <p><strong>Affected object:</strong> {{ finding.affected_object or "n/a" }}</p>
      {% if finding.evidence %}
        <p><strong>Evidence:</strong></p>
        <ul>{% for item in finding.evidence %}<li><code>{{ item }}</code></li>{% endfor %}</ul>
      {% endif %}
      <p><strong>Remediation:</strong> {{ finding.remediation or "Review manually." }}</p>
    </article>
  {% endfor %}
</body>
</html>
"""
)


def write_html_report(report: dict, output_path: Path) -> Path:
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(TEMPLATE.render(**report), encoding="utf-8")
    return output_path
