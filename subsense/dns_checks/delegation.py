"""Lame delegation check: a nameserver listed in the domain's NS records that doesn't actually
answer authoritatively for the zone. If that NS is a third-party/cloud DNS host whose zone was
deleted (e.g. a decommissioned Route53 hosted zone still referenced by glue), an attacker who
claims the same NS hostname/zone can potentially answer authoritatively for the victim's domain.
Tier 1 — tool-confirmed (SOA-response absence/mismatch is deterministic).
"""

from __future__ import annotations

import asyncio
import logging

import dns.resolver

from subsense.dns_checks.base import DnsCheck, DnsCheckContext
from subsense.models import Finding, FindingTier, Severity
from subsense.registry import register_dns_check

logger = logging.getLogger(__name__)


@register_dns_check("delegation")
class DelegationCheck(DnsCheck):
    name = "delegation"
    level = "domain"

    async def run(self, ctx: DnsCheckContext) -> list[Finding]:
        findings: list[Finding] = []
        resolver = _resolver(ctx)

        try:
            ns_answer = await asyncio.to_thread(resolver.resolve, ctx.root_domain, "NS")
            nameservers = [str(rdata.target).rstrip(".") for rdata in ns_answer]
        except Exception as exc:  # noqa: BLE001
            logger.debug("delegation: NS lookup failed for %s: %s", ctx.root_domain, exc)
            return findings

        guard = ctx.limiter.guard()
        async with guard:
            for ns in nameservers:
                lame_reason = await self._check_lame(resolver, ns, ctx.root_domain)
                if lame_reason is None:
                    guard.success()
                    continue

                findings.append(
                    Finding(
                        subdomain=ctx.root_domain,
                        check_name=self.name,
                        tier=FindingTier.TIER_1,
                        severity=Severity.MEDIUM,
                        title=f"Lame delegation: nameserver {ns} does not answer authoritatively",
                        description=(
                            f"{ctx.root_domain} delegates to {ns}, but it {lame_reason}. If {ns} "
                            f"is a third-party/cloud DNS host, an attacker who can claim that "
                            f"nameserver's zone could potentially answer for this domain."
                        ),
                        evidence={"nameserver": ns, "reason": lame_reason},
                        remediation=f"Remove {ns} from the NS set if unused, or fix its zone configuration so it answers authoritatively.",
                    )
                )

        return findings

    async def _check_lame(self, resolver: dns.resolver.Resolver, ns: str, root_domain: str) -> str | None:
        try:
            ns_ip_answer = await asyncio.to_thread(resolver.resolve, ns, "A")
            ns_ip = str(ns_ip_answer[0])
        except Exception:  # noqa: BLE001
            return "does not resolve (NS hostname itself is unresolvable)"

        probe = dns.resolver.Resolver(configure=False)
        probe.nameservers = [ns_ip]
        probe.timeout = resolver.timeout
        probe.lifetime = resolver.lifetime

        try:
            answer = await asyncio.to_thread(probe.resolve, root_domain, "SOA")
            if not answer.response.flags & 0x0400:  # AA (authoritative answer) bit
                return "responded without the authoritative-answer flag set"
        except (dns.resolver.NoNameservers, TimeoutError, OSError):
            return "refused/timed out answering an SOA query for the zone"
        except dns.resolver.NXDOMAIN:
            return "returned NXDOMAIN for the zone it's supposed to serve"
        except Exception:  # noqa: BLE001
            return "failed to answer an SOA query for the zone"

        return None


def _resolver(ctx: DnsCheckContext) -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ctx.config.dns.resolvers
    resolver.timeout = ctx.config.dns.timeout_seconds
    resolver.lifetime = ctx.config.dns.timeout_seconds
    return resolver
