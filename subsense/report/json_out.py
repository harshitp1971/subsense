"""JSON (machine-readable) report writer."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from subsense.models import SEVERITY_ORDER, Finding, ScanState, Subdomain


def build_report_dict(state: ScanState, subdomains: list[Subdomain], findings: list[Finding]) -> dict:
    sorted_findings = sorted(findings, key=lambda f: (SEVERITY_ORDER[f.severity], f.ai_priority or 0))
    return {
        "run_id": state.run_id,
        "target_domain": state.target_domain,
        "started_at": state.started_at.isoformat(),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "completed_stages": sorted(s.value for s in state.completed_stages),
        "summary": {
            "subdomains_total": len(subdomains),
            "subdomains_resolved": sum(1 for s in subdomains if s.resolved),
            "subdomains_in_scope": sum(1 for s in subdomains if s.in_scope),
            "findings_total": len(findings),
            "findings_by_severity": {
                sev.value: sum(1 for f in findings if f.severity == sev) for sev in SEVERITY_ORDER
            },
        },
        "subdomains": [json.loads(s.model_dump_json()) for s in subdomains],
        "findings": [json.loads(f.model_dump_json()) for f in sorted_findings],
    }


def write_json_report(out_dir: Path, state: ScanState, subdomains: list[Subdomain], findings: list[Finding]) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{state.target_domain}-{state.run_id[:8]}.json"
    report = build_report_dict(state, subdomains, findings)
    path.write_text(json.dumps(report, indent=2))
    return path
