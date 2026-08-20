"""nuclei vuln scan stage (opt-in, --nuclei): wraps the external `nuclei` binary against every
resolved, in-scope, HTTP-responsive subdomain. Exposures, misconfig, takeovers, CVE matches.

Per CLAUDE.md's vulnerability tiering, nuclei matches are always Tier 2 (tool flags as a lead;
human verifies) — template matches are heuristic/signature-based and need confirmation, unlike
the deterministic Tier 1 DNS checks in `dns_checks/`.
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
import tempfile
from pathlib import Path

from subsense.config import Config
from subsense.models import Finding, FindingTier, Severity, Subdomain

logger = logging.getLogger(__name__)

_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "unknown": Severity.INFO,
}


async def run_nuclei(subdomains: list[Subdomain], *, config: Config) -> list[Finding]:
    findings: list[Finding] = []

    nuclei_bin = config.nuclei.bin
    if shutil.which(nuclei_bin) is None:
        logger.warning("nuclei: '%s' not found on PATH, skipping vuln scan", nuclei_bin)
        return findings

    targets = [s for s in subdomains if s.resolved and s.in_scope and s.http_status is not None]
    if not targets:
        return findings

    with tempfile.TemporaryDirectory() as tmpdir:
        targets_path = Path(tmpdir) / "targets.txt"
        targets_path.write_text("\n".join(f"https://{s.hostname}" for s in targets) + "\n")
        out_path = Path(tmpdir) / "results.jsonl"

        cmd = [nuclei_bin, "-l", str(targets_path), "-jsonl", "-o", str(out_path), "-silent"]
        for template in config.nuclei.templates:
            cmd += ["-t", template]
        for severity in config.nuclei.severity:
            cmd += ["-severity", severity]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=3600)
        except asyncio.TimeoutError:
            logger.warning("nuclei: timed out after 3600s, killing process")
            proc.kill()
            await proc.wait()
            return findings
        except OSError as exc:
            logger.warning("nuclei: execution failed: %s", exc)
            return findings

        if proc.returncode not in (0, 1):  # nuclei exits 1 when matches are found in some versions
            logger.warning("nuclei: exited %s: %s", proc.returncode, stderr.decode(errors="replace"))

        if out_path.exists():
            for line in out_path.read_text().splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except ValueError:
                    continue
                findings.append(_finding_from_record(record))

    return findings


def _finding_from_record(record: dict) -> Finding:
    info = record.get("info", {})
    severity = _SEVERITY_MAP.get(str(info.get("severity", "unknown")).lower(), Severity.INFO)
    host = record.get("host", record.get("matched-at", ""))
    hostname = host.split("://", 1)[-1].split("/", 1)[0]

    return Finding(
        subdomain=hostname,
        check_name=f"nuclei:{record.get('template-id', 'unknown')}",
        tier=FindingTier.TIER_2,
        severity=severity,
        title=info.get("name", record.get("template-id", "nuclei match")),
        description=info.get("description", ""),
        evidence={
            "template_id": record.get("template-id"),
            "matched_at": record.get("matched-at"),
            "tags": info.get("tags", []),
        },
        remediation=info.get("remediation"),
    )
