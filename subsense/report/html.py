"""HTML (human-readable) report writer, rendered via Jinja2 from report/templates/report.html.j2."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from subsense.models import Finding, ScanState, Subdomain
from subsense.report.json_out import build_report_dict

_TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"


def write_html_report(out_dir: Path, state: ScanState, subdomains: list[Subdomain], findings: list[Finding]) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{state.target_domain}-{state.run_id[:8]}.html"

    env = Environment(loader=FileSystemLoader(_TEMPLATE_DIR), autoescape=select_autoescape(["html"]))
    template = env.get_template("report.html.j2")

    report = build_report_dict(state, subdomains, findings)
    path.write_text(template.render(report=report))
    return path
