"""AXFR zone transfer check: attempts a full zone transfer against every nameserver for the
target domain. A misconfigured nameserver that allows AXFR to anyone leaks the entire zone
(every subdomain, sometimes internal-only hosts) in one request. Tier 1 — tool-confirmed.
"""

from __future__ import annotations

import asyncio
import logging

import dns.query
import dns.resolver
import dns.zone

from subsense.dns_checks.base import DnsCheck, DnsCheckContext
from subsense.models import Finding, FindingTier, Severity
from subsense.registry import register_dns_check

logger = logging.getLogger(__name__)


@register_dns_check("axfr")
class AxfrCheck(DnsCheck):
    name = "axfr"
    level = "domain"

    async def run(self, ctx: DnsCheckContext) -> list[Finding]:
        findings: list[Finding] = []

        try:
            resolver = _resolver(ctx)
            ns_answer = await asyncio.to_thread(resolver.resolve, ctx.root_domain, "NS")
            nameservers = [str(rdata.target).rstrip(".") for rdata in ns_answer]
        except Exception as exc:  # noqa: BLE001
            logger.debug("axfr: NS lookup failed for %s: %s", ctx.root_domain, exc)
            return findings

        guard = ctx.limiter.guard()
        async with guard:
            for ns in nameservers:
                try:
                    ns_ip_answer = await asyncio.to_thread(resolver.resolve, ns, "A")
                    ns_ip = str(ns_ip_answer[0])
                except Exception:  # noqa: BLE001
                    continue

                try:
                    zone = await asyncio.wait_for(
                        asyncio.to_thread(
                            dns.zone.from_xfr,
                            dns.query.xfr(ns_ip, ctx.root_domain, timeout=ctx.config.dns.timeout_seconds),
                        ),
                        timeout=ctx.config.dns.timeout_seconds * 3,
                    )
                except Exception:  # noqa: BLE001
                    # Refused/timeout is the expected, correctly-configured case.
                    continue

                names = sorted(str(n) for n in zone.nodes.keys())
                findings.append(
                    Finding(
                        subdomain=ctx.root_domain,
                        check_name=self.name,
                        tier=FindingTier.TIER_1,
                        severity=Severity.HIGH,
                        title=f"AXFR zone transfer allowed by nameserver {ns}",
                        description=(
                            f"Nameserver {ns} ({ns_ip}) permitted an unauthenticated AXFR zone "
                            f"transfer for {ctx.root_domain}, leaking {len(names)} records."
                        ),
                        evidence={"nameserver": ns, "nameserver_ip": ns_ip, "record_count": len(names), "sample": names[:50]},
                        remediation="Restrict AXFR to authorized secondary nameservers only (ACL by IP + TSIG).",
                    )
                )
                guard.success()

        return findings


def _resolver(ctx: DnsCheckContext) -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ctx.config.dns.resolvers
    resolver.timeout = ctx.config.dns.timeout_seconds
    resolver.lifetime = ctx.config.dns.timeout_seconds
    return resolver
