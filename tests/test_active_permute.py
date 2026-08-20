"""Tests for active/permute.py's generate -> resolve -> feedback loop (the mechanism, not
real-world hit-rate — that depends on an actual authorized target's naming conventions, which
this test suite deliberately doesn't touch). We fake the resolution boundary (_validate_candidates,
resolve_subdomains) so the loop's control flow — iteration, feedback, termination — is verified
deterministically and offline.
"""

from __future__ import annotations

import subsense.active.permute as permute_mod
from subsense.config import Config, ScopeConfig
from subsense.models import Subdomain
from subsense.ratelimit import RateLimiter
from subsense.scope import ScopeFilter


def _resolved_stub(hosts: set[str], root_domain: str) -> list[Subdomain]:
    return [
        Subdomain(hostname=h, root_domain=root_domain, sources={"ai_permute"}, resolved=True) for h in hosts
    ]


async def test_gap_fill_converges_and_stops_when_candidates_exhausted(monkeypatch):
    """CLAUDE.md's own example: payments-{dev,staging,prod} known, orders-dev known -> the loop
    should surface orders-staging and orders-prod, then stop once the prefix x suffix matrix is
    fully explained (no more unseen pairs to propose)."""
    root_domain = "example.com"
    real_targets = {f"orders-staging.{root_domain}", f"orders-prod.{root_domain}"}

    async def fake_validate(candidate_hosts, root_domain, *, config, scope):
        return candidate_hosts & real_targets

    async def fake_resolve_subdomains(subs, *, root_domain, config, limiter):
        return _resolved_stub({s.hostname for s in subs}, root_domain)

    monkeypatch.setattr(permute_mod, "_validate_candidates", fake_validate)
    monkeypatch.setattr(permute_mod, "resolve_subdomains", fake_resolve_subdomains)

    known = [
        Subdomain(hostname=f"payments-dev.{root_domain}", root_domain=root_domain),
        Subdomain(hostname=f"payments-staging.{root_domain}", root_domain=root_domain),
        Subdomain(hostname=f"payments-prod.{root_domain}", root_domain=root_domain),
        Subdomain(hostname=f"orders-dev.{root_domain}", root_domain=root_domain),
    ]

    config = Config.load()
    scope = ScopeFilter(ScopeConfig(), root_domain)
    limiter = RateLimiter(config.ratelimit)

    discovered = await permute_mod.run_permutation(
        known, root_domain=root_domain, config=config, scope=scope, limiter=limiter
    )

    discovered_hosts = {s.hostname for s in discovered}
    assert discovered_hosts == real_targets


async def test_loop_stops_on_diminishing_returns(monkeypatch):
    """If an iteration resolves fewer than _MIN_NEW_PER_ITERATION new hosts, the loop should
    stop even though more (unseen) candidates could theoretically still be generated."""
    root_domain = "example.com"
    # Only ONE of the possible gap-fills actually exists on the "target".
    real_targets = {f"orders-staging.{root_domain}"}

    call_count = {"n": 0}

    async def fake_validate(candidate_hosts, root_domain, *, config, scope):
        call_count["n"] += 1
        return candidate_hosts & real_targets

    async def fake_resolve_subdomains(subs, *, root_domain, config, limiter):
        return _resolved_stub({s.hostname for s in subs}, root_domain)

    monkeypatch.setattr(permute_mod, "_validate_candidates", fake_validate)
    monkeypatch.setattr(permute_mod, "resolve_subdomains", fake_resolve_subdomains)

    known = [
        Subdomain(hostname=f"payments-dev.{root_domain}", root_domain=root_domain),
        Subdomain(hostname=f"payments-staging.{root_domain}", root_domain=root_domain),
        Subdomain(hostname=f"orders-dev.{root_domain}", root_domain=root_domain),
    ]

    config = Config.load()
    scope = ScopeFilter(ScopeConfig(), root_domain)
    limiter = RateLimiter(config.ratelimit)

    discovered = await permute_mod.run_permutation(
        known, root_domain=root_domain, config=config, scope=scope, limiter=limiter
    )

    assert {s.hostname for s in discovered} == real_targets
    # exactly 1 new host < _MIN_NEW_PER_ITERATION(2) -> must stop after the first productive
    # iteration, not keep spinning through _MAX_ITERATIONS.
    assert call_count["n"] == 1


async def test_out_of_scope_candidates_never_reach_validation(monkeypatch):
    """A candidate landing outside scope.exclude must be filtered before validation is even
    called with it — scope enforcement happens before any active touch, not after."""
    root_domain = "example.com"
    seen_hosts: set[str] = set()

    async def fake_validate(candidate_hosts, root_domain, *, config, scope):
        seen_hosts.update(candidate_hosts)
        return set()

    monkeypatch.setattr(permute_mod, "_validate_candidates", fake_validate)

    known = [
        Subdomain(hostname=f"payments-dev.{root_domain}", root_domain=root_domain),
        Subdomain(hostname=f"payments-staging.{root_domain}", root_domain=root_domain),
        Subdomain(hostname=f"payments-prod.{root_domain}", root_domain=root_domain),
        Subdomain(hostname=f"internal-dev.{root_domain}", root_domain=root_domain),
    ]
    # Gap-fill matrix now proposes internal-staging and internal-prod (unseen prefix x suffix
    # pairs) alongside any payments-side gaps — exactly the case that must be scope-filtered.

    config = Config.load()
    # exclude anything starting with "internal" -> internal-{staging,prod} cross-fills should
    # never be sent to validation, even though the statistical permuter would happily propose them.
    scope = ScopeFilter(ScopeConfig(exclude=[r"^internal"]), root_domain)
    limiter = RateLimiter(config.ratelimit)

    await permute_mod.run_permutation(known, root_domain=root_domain, config=config, scope=scope, limiter=limiter)

    assert not any("internal" in h for h in seen_hosts)
