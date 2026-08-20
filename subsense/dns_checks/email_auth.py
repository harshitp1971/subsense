"""Email authentication gap check: missing/weak SPF and DMARC let attackers spoof mail from the
target domain (phishing, BEC). Tier 1 — tool-confirmed (DNS record presence/content is
deterministic, no probabilistic fingerprint involved).
"""

from __future__ import annotations

import asyncio
import logging

import dns.resolver

from subsense.dns_checks.base import DnsCheck, DnsCheckContext
from subsense.models import Finding, FindingTier, Severity
from subsense.registry import register_dns_check

logger = logging.getLogger(__name__)


@register_dns_check("email_auth")
class EmailAuthCheck(DnsCheck):
    name = "email_auth"
    level = "domain"

    async def run(self, ctx: DnsCheckContext) -> list[Finding]:
        findings: list[Finding] = []
        resolver = _resolver(ctx)

        spf_records = await _txt_lookup(resolver, ctx.root_domain)
        spf = next((r for r in spf_records if r.startswith("v=spf1")), None)

        if spf is None:
            findings.append(
                Finding(
                    subdomain=ctx.root_domain,
                    check_name=self.name,
                    tier=FindingTier.TIER_1,
                    severity=Severity.LOW,
                    title="No SPF record",
                    description=f"{ctx.root_domain} has no SPF (v=spf1) TXT record, allowing any host to spoof mail From this domain.",
                    evidence={},
                    remediation="Publish an SPF TXT record scoped to your legitimate sending infrastructure, ending in -all.",
                )
            )
        elif "+all" in spf or spf.rstrip().endswith(" all"):
            findings.append(
                Finding(
                    subdomain=ctx.root_domain,
                    check_name=self.name,
                    tier=FindingTier.TIER_1,
                    severity=Severity.LOW,
                    title="Overly permissive SPF record",
                    description=f"SPF record for {ctx.root_domain} uses '+all' or a bare 'all', which permits any sender.",
                    evidence={"spf": spf},
                    remediation="Use -all (hard fail) or at minimum ~all (soft fail) instead of +all.",
                )
            )

        dmarc_records = await _txt_lookup(resolver, f"_dmarc.{ctx.root_domain}")
        dmarc = next((r for r in dmarc_records if r.startswith("v=DMARC1")), None)

        if dmarc is None:
            findings.append(
                Finding(
                    subdomain=f"_dmarc.{ctx.root_domain}",
                    check_name=self.name,
                    tier=FindingTier.TIER_1,
                    severity=Severity.MEDIUM,
                    title="No DMARC record",
                    description=f"{ctx.root_domain} has no DMARC record, so spoofed/failing-SPF-or-DKIM mail is not rejected or quarantined by policy.",
                    evidence={},
                    remediation="Publish a DMARC TXT record at _dmarc with p=quarantine or p=reject.",
                )
            )
        elif "p=none" in dmarc:
            findings.append(
                Finding(
                    subdomain=f"_dmarc.{ctx.root_domain}",
                    check_name=self.name,
                    tier=FindingTier.TIER_1,
                    severity=Severity.LOW,
                    title="DMARC policy set to 'none' (monitor-only)",
                    description=f"DMARC for {ctx.root_domain} is p=none — failing mail is delivered anyway, not quarantined or rejected.",
                    evidence={"dmarc": dmarc},
                    remediation="Move DMARC policy to p=quarantine or p=reject once monitoring confirms no legitimate senders break.",
                )
            )

        return findings


async def _txt_lookup(resolver: dns.resolver.Resolver, name: str) -> list[str]:
    try:
        answer = await asyncio.to_thread(resolver.resolve, name, "TXT", raise_on_no_answer=False)
    except Exception as exc:  # noqa: BLE001
        logger.debug("email_auth: TXT lookup failed for %s: %s", name, exc)
        return []
    if answer is None or answer.rrset is None:
        return []
    records = []
    for rdata in answer:
        text = b"".join(rdata.strings).decode(errors="replace")
        records.append(text)
    return records


def _resolver(ctx: DnsCheckContext) -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ctx.config.dns.resolvers
    resolver.timeout = ctx.config.dns.timeout_seconds
    resolver.lifetime = ctx.config.dns.timeout_seconds
    return resolver
