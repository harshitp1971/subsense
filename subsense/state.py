"""SQLite-backed checkpoint/resume state store. SQLite is the source of truth: every pipeline
stage writes through here, and `--resume` reconstructs in-memory state from the last checkpoint.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime
from pathlib import Path

from sqlmodel import Field as SQLField
from sqlmodel import Session, SQLModel, create_engine, select

from subsense.models import (
    DnsRecord,
    Finding,
    FindingTier,
    ScanState,
    Severity,
    Stage,
    Subdomain,
)


class SubdomainRow(SQLModel, table=True):
    __tablename__ = "subdomains"

    id: str = SQLField(primary_key=True)
    run_id: str = SQLField(index=True)
    hostname: str = SQLField(index=True)
    root_domain: str
    sources_json: str = "[]"
    records_json: str = "[]"
    resolved: bool = False
    wildcard_match: bool = False
    confidence: float = 0.0
    http_status: int | None = None
    http_title: str | None = None
    http_tech_json: str = "[]"
    in_scope: bool = True
    first_seen: datetime
    last_seen: datetime


class FindingRow(SQLModel, table=True):
    __tablename__ = "findings"

    id: str = SQLField(primary_key=True)
    run_id: str = SQLField(index=True)
    subdomain: str = SQLField(index=True)
    check_name: str
    tier: str
    severity: str
    title: str
    description: str = ""
    evidence_json: str = "{}"
    remediation: str | None = None
    created_at: datetime
    ai_priority: int | None = None
    ai_notes: str | None = None


class ScanStateRow(SQLModel, table=True):
    __tablename__ = "scan_state"

    run_id: str = SQLField(primary_key=True)
    target_domain: str
    current_stage: str
    completed_stages_json: str = "[]"
    started_at: datetime
    updated_at: datetime
    finished: bool = False


class StateStore:
    """Sync SQLite access wrapped for async callers via asyncio.to_thread.

    SQLite writes are fast and local; a thread-pool hop is enough to keep the event loop
    unblocked without needing a fully async DB driver for a single-writer CLI tool.
    """

    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.engine = create_engine(f"sqlite:///{self.db_path}")
        SQLModel.metadata.create_all(self.engine)

    # -- scan state -----------------------------------------------------

    def save_scan_state_sync(self, state: ScanState) -> None:
        row = ScanStateRow(
            run_id=state.run_id,
            target_domain=state.target_domain,
            current_stage=state.current_stage.value,
            completed_stages_json=json.dumps([s.value for s in state.completed_stages]),
            started_at=state.started_at,
            updated_at=state.updated_at,
            finished=state.finished,
        )
        with Session(self.engine) as session:
            session.merge(row)
            session.commit()

    async def save_scan_state(self, state: ScanState) -> None:
        await asyncio.to_thread(self.save_scan_state_sync, state)

    def load_scan_state_sync(self, target_domain: str) -> ScanState | None:
        with Session(self.engine) as session:
            stmt = (
                select(ScanStateRow)
                .where(ScanStateRow.target_domain == target_domain)
                .where(ScanStateRow.finished == False)  # noqa: E712
                .order_by(ScanStateRow.updated_at.desc())
            )
            row = session.exec(stmt).first()
            if row is None:
                return None
            return ScanState(
                run_id=row.run_id,
                target_domain=row.target_domain,
                current_stage=Stage(row.current_stage),
                completed_stages={Stage(s) for s in json.loads(row.completed_stages_json)},
                started_at=row.started_at,
                updated_at=row.updated_at,
                finished=row.finished,
            )

    async def load_scan_state(self, target_domain: str) -> ScanState | None:
        return await asyncio.to_thread(self.load_scan_state_sync, target_domain)

    # -- subdomains -------------------------------------------------------

    def upsert_subdomain_sync(self, run_id: str, sub: Subdomain) -> None:
        row = SubdomainRow(
            id=sub.id,
            run_id=run_id,
            hostname=sub.hostname,
            root_domain=sub.root_domain,
            sources_json=json.dumps(sorted(sub.sources)),
            records_json=json.dumps([r.model_dump(mode="json") for r in sub.records]),
            resolved=sub.resolved,
            wildcard_match=sub.wildcard_match,
            confidence=sub.confidence,
            http_status=sub.http_status,
            http_title=sub.http_title,
            http_tech_json=json.dumps(sub.http_tech),
            in_scope=sub.in_scope,
            first_seen=sub.first_seen,
            last_seen=sub.last_seen,
        )
        with Session(self.engine) as session:
            existing = session.exec(
                select(SubdomainRow)
                .where(SubdomainRow.run_id == run_id)
                .where(SubdomainRow.hostname == sub.hostname)
            ).first()
            if existing is not None:
                row.id = existing.id
            session.merge(row)
            session.commit()

    async def upsert_subdomain(self, run_id: str, sub: Subdomain) -> None:
        await asyncio.to_thread(self.upsert_subdomain_sync, run_id, sub)

    def get_subdomains_sync(self, run_id: str) -> list[Subdomain]:
        with Session(self.engine) as session:
            rows = session.exec(
                select(SubdomainRow).where(SubdomainRow.run_id == run_id)
            ).all()
            return [_row_to_subdomain(r) for r in rows]

    async def get_subdomains(self, run_id: str) -> list[Subdomain]:
        return await asyncio.to_thread(self.get_subdomains_sync, run_id)

    # -- findings -----------------------------------------------------------

    def add_finding_sync(self, run_id: str, finding: Finding) -> None:
        row = FindingRow(
            id=finding.id,
            run_id=run_id,
            subdomain=finding.subdomain,
            check_name=finding.check_name,
            tier=finding.tier.value,
            severity=finding.severity.value,
            title=finding.title,
            description=finding.description,
            evidence_json=json.dumps(finding.evidence),
            remediation=finding.remediation,
            created_at=finding.created_at,
            ai_priority=finding.ai_priority,
            ai_notes=finding.ai_notes,
        )
        with Session(self.engine) as session:
            session.merge(row)
            session.commit()

    async def add_finding(self, run_id: str, finding: Finding) -> None:
        await asyncio.to_thread(self.add_finding_sync, run_id, finding)

    def get_findings_sync(self, run_id: str) -> list[Finding]:
        with Session(self.engine) as session:
            rows = session.exec(select(FindingRow).where(FindingRow.run_id == run_id)).all()
            return [_row_to_finding(r) for r in rows]

    async def get_findings(self, run_id: str) -> list[Finding]:
        return await asyncio.to_thread(self.get_findings_sync, run_id)


def _row_to_subdomain(row: SubdomainRow) -> Subdomain:
    return Subdomain(
        id=row.id,
        hostname=row.hostname,
        root_domain=row.root_domain,
        sources=set(json.loads(row.sources_json)),
        records=[DnsRecord.model_validate(r) for r in json.loads(row.records_json)],
        resolved=row.resolved,
        wildcard_match=row.wildcard_match,
        confidence=row.confidence,
        http_status=row.http_status,
        http_title=row.http_title,
        http_tech=json.loads(row.http_tech_json),
        in_scope=row.in_scope,
        first_seen=row.first_seen,
        last_seen=row.last_seen,
    )


def _row_to_finding(row: FindingRow) -> Finding:
    return Finding(
        id=row.id,
        subdomain=row.subdomain,
        check_name=row.check_name,
        tier=FindingTier(row.tier),
        severity=Severity(row.severity),
        title=row.title,
        description=row.description,
        evidence=json.loads(row.evidence_json),
        remediation=row.remediation,
        created_at=row.created_at,
        ai_priority=row.ai_priority,
        ai_notes=row.ai_notes,
    )
