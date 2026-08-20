"""Dangling A-record check: an A record pointing into a cloud provider's IP space where the
corresponding resource (EC2 instance, ELB, GCP static IP, ...) has been released is a takeover
lead — the IP can potentially be reallocated to an attacker's account. Unlike CNAME takeovers
(dns_checks/takeover.py) this can't be confirmed by DNS + HTTP fingerprint alone, so it's always
Tier 2: the tool flags it, a human verifies against the cloud provider.
"""

from __future__ import annotations

import ipaddress
import logging

import httpx

from subsense.dns_checks.base import DnsCheck, DnsCheckContext
from subsense.models import Finding, FindingTier, RecordType, Severity
from subsense.registry import register_dns_check

logger = logging.getLogger(__name__)

# Coarse, well-known cloud provider ranges. Not exhaustive by design — this is a triage
# heuristic to prioritize human review, not an authoritative allocation database.
CLOUD_RANGES: dict[str, list[str]] = {
    "AWS": ["3.0.0.0/8", "13.32.0.0/15", "15.177.0.0/18", "18.130.0.0/16", "34.192.0.0/10", "52.0.0.0/8", "54.0.0.0/8"],
    "GCP": ["34.64.0.0/10", "35.184.0.0/13", "35.192.0.0/14"],
    "Azure": ["13.64.0.0/11", "20.33.0.0/16", "40.64.0.0/10", "52.224.0.0/11"],
    "DigitalOcean": ["104.131.0.0/16", "138.68.0.0/16", "159.65.0.0/16", "167.99.0.0/16"],
}
_PARSED_RANGES = {
    provider: [ipaddress.ip_network(cidr) for cidr in cidrs] for provider, cidrs in CLOUD_RANGES.items()
}


@register_dns_check("dangling")
class DanglingRecordCheck(DnsCheck):
    name = "dangling"
    level = "subdomain"

    async def run(self, ctx: DnsCheckContext) -> list[Finding]:
        findings: list[Finding] = []
        sub = ctx.subdomain
        if sub is None or not sub.resolved:
            return findings

        a_records = [r.value for r in sub.records if r.record_type in (RecordType.A, RecordType.AAAA)]
        if not a_records:
            return findings

        for ip_str in a_records:
            provider = _cloud_provider(ip_str)
            if provider is None:
                continue

            unreachable = await self._is_unreachable(ctx, sub.hostname)
            if not unreachable:
                continue

            findings.append(
                Finding(
                    subdomain=sub.hostname,
                    check_name=self.name,
                    tier=FindingTier.TIER_2,
                    severity=Severity.MEDIUM,
                    title=f"Possible dangling {provider} IP — manual verification needed",
                    description=(
                        f"{sub.hostname} resolves to {ip_str}, in {provider}'s IP space, but the "
                        f"host did not respond to an HTTP probe. If the underlying cloud resource "
                        f"was deprovisioned, this IP may be re-allocatable by an attacker."
                    ),
                    evidence={"ip": ip_str, "provider": provider},
                    remediation="Verify the cloud resource still exists and is owned by this org; remove the DNS record if not.",
                )
            )

        return findings

    async def _is_unreachable(self, ctx: DnsCheckContext, hostname: str) -> bool:
        guard = ctx.limiter.guard()
        async with guard:
            try:
                async with httpx.AsyncClient(timeout=5.0, verify=False) as client:
                    resp = await client.get(
                        f"http://{hostname}/", headers={"User-Agent": ctx.config.http.user_agent}
                    )
                    return resp.status_code >= 500
            except httpx.TransportError:
                return True
            except Exception:  # noqa: BLE001
                guard.failure()
                return False


def _cloud_provider(ip_str: str) -> str | None:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return None
    for provider, networks in _PARSED_RANGES.items():
        if any(ip in net for net in networks):
            return provider
    return None
