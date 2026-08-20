"""Stage orchestrator. Runs the 8-stage pipeline described in CLAUDE.md, checkpointing to
SQLite after every stage so `--resume` can pick up where a previous run left off.
"""

from __future__ import annotations

import asyncio
import logging

import httpx

from subsense.active.bruteforce import run_bruteforce
from subsense.active.permute import run_permutation
from subsense.active.resolve import resolve_subdomains
from subsense.ai.triage import triage_findings
from subsense.config import Config
from subsense.dns_checks.base import DnsCheck, DnsCheckContext
from subsense.models import Finding, ScanState, Stage, Subdomain
from subsense.probe.http import probe_subdomains
from subsense.ratelimit import RateLimiter
from subsense.registry import get_dns_checks, get_sources, load_all_plugins
from subsense.report.html import write_html_report
from subsense.report.json_out import write_json_report
from subsense.scope import ScopeFilter
from subsense.sources.base import SourceContext
from subsense.state import StateStore
from subsense.vuln.nuclei import run_nuclei

logger = logging.getLogger(__name__)


class Pipeline:
    def __init__(
        self,
        config: Config,
        target_domain: str,
        *,
        active: bool = False,
        nuclei: bool = False,
        ai: bool = False,
        resume: bool = False,
    ):
        self.config = config
        self.target_domain = target_domain.lower().strip(".")
        self.active_enabled = active
        self.nuclei_enabled = nuclei
        self.ai_enabled = ai
        self.resume = resume

        self.store = StateStore(config.state.db_path)
        self.limiter = RateLimiter(config.ratelimit)
        self.scope = ScopeFilter(config.scope, self.target_domain)

        self.subdomains: dict[str, Subdomain] = {}
        self.findings: list[Finding] = []
        self.state: ScanState | None = None
        self.report_paths: list = []

    async def run(self) -> tuple[ScanState, list[Subdomain], list[Finding]]:
        load_all_plugins()

        state = None
        if self.resume:
            state = await self.store.load_scan_state(self.target_domain)
        if state is None:
            state = ScanState(target_domain=self.target_domain)
            await self.store.save_scan_state(state)
        self.state = state

        for sub in await self.store.get_subdomains(state.run_id):
            self.subdomains[sub.hostname] = sub
        self.findings = await self.store.get_findings(state.run_id)

        await self._stage(Stage.PASSIVE_ENUM, self._run_passive_enum)
        await self._stage(Stage.ACTIVE_ENUM, self._run_active_enum, skip=not self.active_enabled)
        await self._stage(Stage.RESOLVE, self._run_resolve)
        await self._stage(Stage.DNS_CHECKS, self._run_dns_checks)
        await self._stage(Stage.HTTP_PROBE, self._run_http_probe)
        await self._stage(Stage.VULN_SCAN, self._run_vuln_scan, skip=not self.nuclei_enabled)
        await self._stage(Stage.AI_TRIAGE, self._run_ai_triage, skip=not self.ai_enabled)
        await self._stage(Stage.REPORT, self._run_report)

        state.finished = True
        await self.store.save_scan_state(state)
        return state, list(self.subdomains.values()), self.findings

    # -- stage runner -------------------------------------------------------

    async def _stage(self, stage: Stage, fn, *, skip: bool = False) -> None:
        assert self.state is not None
        if self.state.is_stage_complete(stage):
            logger.info("stage %s: already complete (resumed), skipping", stage.value)
            return

        self.state.current_stage = stage
        if skip:
            logger.info("stage %s: opt-in stage not enabled, skipping", stage.value)
        else:
            logger.info("stage %s: starting", stage.value)
            await fn()
            logger.info("stage %s: done", stage.value)

        self.state.mark_stage_complete(stage)
        await self.store.save_scan_state(self.state)

    def _merge(self, hostname: str, *, source: str) -> None:
        hostname = hostname.lower().strip(".")
        existing = self.subdomains.get(hostname)
        if existing is None:
            sub = Subdomain(hostname=hostname, root_domain=self.target_domain, sources={source})
            sub = self.scope.apply(sub)
            self.subdomains[hostname] = sub
        else:
            existing.sources.add(source)

    async def _persist_subdomains(self) -> None:
        assert self.state is not None
        for sub in self.subdomains.values():
            await self.store.upsert_subdomain(self.state.run_id, sub)

    async def _persist_findings(self, findings: list[Finding]) -> None:
        assert self.state is not None
        for finding in findings:
            await self.store.add_finding(self.state.run_id, finding)

    # -- stages ---------------------------------------------------------------

    async def _run_passive_enum(self) -> None:
        sources = get_sources()
        if not sources:
            logger.warning("passive_enum: no sources registered")
            return

        async with httpx.AsyncClient(
            headers={"User-Agent": self.config.http.user_agent}, proxy=self.limiter.proxy
        ) as http_client:
            ctx = SourceContext(
                root_domain=self.target_domain, config=self.config, limiter=self.limiter, http_client=http_client
            )
            results = await asyncio.gather(
                *(source_cls().discover(ctx) for source_cls in sources.values()), return_exceptions=True
            )

        for name, result in zip(sources.keys(), results):
            if isinstance(result, Exception):
                logger.warning("passive_enum: source '%s' raised: %s", name, result)
                continue
            for host in result:
                self._merge(host, source=f"passive:{name}")

        await self._persist_subdomains()

    async def _run_active_enum(self) -> None:
        bf_hosts = await run_bruteforce(self.target_domain, config=self.config, scope=self.scope)
        for host in bf_hosts:
            self._merge(host, source="active:bruteforce")
        await self._persist_subdomains()

        new_subs = await run_permutation(
            list(self.subdomains.values()),
            root_domain=self.target_domain,
            config=self.config,
            scope=self.scope,
            limiter=self.limiter,
        )
        for sub in new_subs:
            sub = self.scope.apply(sub)
            existing = self.subdomains.get(sub.hostname)
            if existing is None:
                self.subdomains[sub.hostname] = sub
            else:
                existing.merge(sub)
        await self._persist_subdomains()

    async def _run_resolve(self) -> None:
        unresolved = [s for s in self.subdomains.values() if not s.resolved]
        if unresolved:
            resolved = await resolve_subdomains(
                unresolved, root_domain=self.target_domain, config=self.config, limiter=self.limiter
            )
            for sub in resolved:
                self.subdomains[sub.hostname] = self.scope.apply(sub)
        await self._persist_subdomains()

    async def _run_dns_checks(self) -> None:
        checks = get_dns_checks()
        if not checks:
            logger.warning("dns_checks: no checks registered")
            return

        all_subs = list(self.subdomains.values())
        new_findings: list[Finding] = []

        domain_checks = [c for c in checks.values() if c.level == "domain"]
        subdomain_checks = [c for c in checks.values() if c.level == "subdomain"]

        domain_ctx = DnsCheckContext(
            root_domain=self.target_domain, config=self.config, limiter=self.limiter, all_subdomains=all_subs
        )
        domain_results = await asyncio.gather(
            *(self._run_one_check(check_cls, domain_ctx) for check_cls in domain_checks), return_exceptions=True
        )
        for check_cls, result in zip(domain_checks, domain_results):
            _collect(new_findings, check_cls, result)

        targets = [s for s in all_subs if s.resolved and s.in_scope]
        subdomain_tasks = [
            self._run_one_check(
                check_cls,
                DnsCheckContext(
                    root_domain=self.target_domain,
                    config=self.config,
                    limiter=self.limiter,
                    subdomain=sub,
                    all_subdomains=all_subs,
                ),
            )
            for sub in targets
            for check_cls in subdomain_checks
        ]
        subdomain_results = await asyncio.gather(*subdomain_tasks, return_exceptions=True)
        flat_checks = [check_cls for _ in targets for check_cls in subdomain_checks]
        for check_cls, result in zip(flat_checks, subdomain_results):
            _collect(new_findings, check_cls, result)

        self.findings.extend(new_findings)
        await self._persist_findings(new_findings)

    @staticmethod
    async def _run_one_check(check_cls: type[DnsCheck], ctx: DnsCheckContext) -> list[Finding]:
        return await check_cls().run(ctx)

    async def _run_http_probe(self) -> None:
        probed = await probe_subdomains(list(self.subdomains.values()), config=self.config, limiter=self.limiter)
        for sub in probed:
            self.subdomains[sub.hostname] = sub
        await self._persist_subdomains()

    async def _run_vuln_scan(self) -> None:
        new_findings = await run_nuclei(list(self.subdomains.values()), config=self.config)
        self.findings.extend(new_findings)
        await self._persist_findings(new_findings)

    async def _run_ai_triage(self) -> None:
        self.findings = await triage_findings(self.findings, config=self.config.ai)
        await self._persist_findings(self.findings)

    async def _run_report(self) -> None:
        assert self.state is not None
        subs = list(self.subdomains.values())
        json_path = write_json_report(self.config.report.out_dir, self.state, subs, self.findings)
        logger.info("report: wrote %s", json_path)
        self.report_paths.append(json_path)
        if "html" in self.config.report.formats:
            html_path = write_html_report(self.config.report.out_dir, self.state, subs, self.findings)
            logger.info("report: wrote %s", html_path)
            self.report_paths.append(html_path)


def _collect(sink: list[Finding], check_cls: type[DnsCheck], result) -> None:
    if isinstance(result, Exception):
        logger.warning("dns_checks: '%s' raised: %s", check_cls.name, result)
        return
    sink.extend(result)
