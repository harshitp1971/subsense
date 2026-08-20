"""Subdomain takeover check: a CNAME pointing at a third-party service (GitHub Pages, Heroku,
S3, ...) whose corresponding resource was deleted lets an attacker claim that service slug and
serve content on the victim's subdomain. Matches against `config/fingerprints.json`.
Tier 1 — tool-confirmed (CNAME points at a known-vulnerable target AND the fingerprint's
error signature matches).
"""

from __future__ import annotations

import json
import logging

import httpx

from subsense.config import DEFAULT_FINGERPRINTS_PATH
from subsense.dns_checks.base import DnsCheck, DnsCheckContext
from subsense.models import Finding, FindingTier, RecordType, Severity
from subsense.registry import register_dns_check

logger = logging.getLogger(__name__)


def _load_fingerprints() -> list[dict]:
    with DEFAULT_FINGERPRINTS_PATH.open() as f:
        return json.load(f)["fingerprints"]


_FINGERPRINTS = _load_fingerprints()


@register_dns_check("takeover")
class TakeoverCheck(DnsCheck):
    name = "takeover"
    level = "subdomain"

    async def run(self, ctx: DnsCheckContext) -> list[Finding]:
        findings: list[Finding] = []
        sub = ctx.subdomain
        if sub is None:
            return findings

        cname_records = [r.value.rstrip(".").lower() for r in sub.records if r.record_type == RecordType.CNAME]
        if not cname_records:
            return findings

        for cname in cname_records:
            fp = _match_fingerprint(cname)
            if fp is None:
                continue

            if not sub.resolved:
                # CNAME present but the chain doesn't resolve at all -> classic dangling CNAME.
                findings.append(_finding(sub.hostname, fp, cname, evidence_extra={"reason": "cname_does_not_resolve"}))
                continue

            # Resolves, but may still render the service's "unclaimed" error page.
            body_match = await self._probe_body(ctx, sub.hostname, fp)
            if body_match:
                findings.append(_finding(sub.hostname, fp, cname, evidence_extra={"reason": "error_page_match", "matched_text": body_match}))

        return findings

    async def _probe_body(self, ctx: DnsCheckContext, hostname: str, fp: dict) -> str | None:
        guard = ctx.limiter.guard()
        async with guard:
            try:
                async with httpx.AsyncClient(
                    timeout=ctx.config.http.timeout_seconds,
                    follow_redirects=ctx.config.http.follow_redirects,
                    verify=False,
                ) as client:
                    resp = await client.get(f"https://{hostname}/", headers={"User-Agent": ctx.config.http.user_agent})
            except Exception:  # noqa: BLE001
                guard.failure()
                return None

            if fp["http_status"] and resp.status_code not in fp["http_status"]:
                return None

            body = resp.text
            for needle in fp["response_body"]:
                if needle.lower() in body.lower():
                    return needle
        return None


def _match_fingerprint(cname: str) -> dict | None:
    for fp in _FINGERPRINTS:
        if any(pattern in cname for pattern in fp["cname"]):
            return fp
    return None


def _finding(hostname: str, fp: dict, cname: str, evidence_extra: dict) -> Finding:
    severity = Severity.CRITICAL if fp["confidence"] == "high" else Severity.HIGH
    return Finding(
        subdomain=hostname,
        check_name="takeover",
        tier=FindingTier.TIER_1,
        severity=severity,
        title=f"Possible subdomain takeover via {fp['service']}",
        description=(
            f"{hostname} has a CNAME pointing at {cname} ({fp['service']}), which matches a "
            f"known takeover fingerprint."
        ),
        evidence={"cname": cname, "service": fp["service"], "confidence": fp["confidence"], **evidence_extra},
        remediation=f"Remove the dangling CNAME, or re-claim the {fp['service']} resource before it's claimed by an attacker.",
    )
