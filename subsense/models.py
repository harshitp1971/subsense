"""Core domain models: Subdomain, Finding, ScanState.

These are plain Pydantic models used throughout the pipeline in-memory. `state.py` maps them
to/from SQLModel table rows for SQLite persistence.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import StrEnum

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Stage(StrEnum):
    """The 8 pipeline stages, in order."""

    PASSIVE_ENUM = "passive_enum"
    ACTIVE_ENUM = "active_enum"
    RESOLVE = "resolve"
    DNS_CHECKS = "dns_checks"
    HTTP_PROBE = "http_probe"
    VULN_SCAN = "vuln_scan"
    AI_TRIAGE = "ai_triage"
    REPORT = "report"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# Sort key for report ordering: lower number = more severe = sorted first.
SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


class FindingTier(StrEnum):
    """Confidence tier per CLAUDE.md vulnerability detection scope."""

    TIER_1 = "tier_1"  # tool-confirmed, high confidence
    TIER_2 = "tier_2"  # tool-flagged lead, human verifies


class RecordType(StrEnum):
    A = "A"
    AAAA = "AAAA"
    CNAME = "CNAME"
    NS = "NS"
    MX = "MX"
    TXT = "TXT"


class DnsRecord(BaseModel):
    record_type: RecordType
    value: str
    ttl: int | None = None


class Subdomain(BaseModel):
    """A discovered hostname and everything learned about it as it moves through the pipeline."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    hostname: str
    root_domain: str

    # Provenance: every source/technique that surfaced this hostname.
    sources: set[str] = Field(default_factory=set)

    # Populated by the resolve stage.
    records: list[DnsRecord] = Field(default_factory=list)
    resolved: bool = False
    wildcard_match: bool = False
    confidence: float = 0.0  # 0.0-1.0, factors in wildcard filtering + source count

    # Populated by the HTTP probe stage.
    http_status: int | None = None
    http_title: str | None = None
    http_tech: list[str] = Field(default_factory=list)

    # Scope enforcement (scope.py) — set before any active stage touches this host.
    in_scope: bool = True

    first_seen: datetime = Field(default_factory=_utcnow)
    last_seen: datetime = Field(default_factory=_utcnow)

    def merge(self, other: "Subdomain") -> None:
        """Merge a re-discovery of the same hostname from another source into this one."""
        self.sources |= other.sources
        if other.records:
            self.records = other.records
        self.resolved = self.resolved or other.resolved
        self.last_seen = _utcnow()


class Finding(BaseModel):
    """A vulnerability / lead surfaced by a dns_checks or vuln plugin."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    subdomain: str
    check_name: str
    tier: FindingTier
    severity: Severity
    title: str
    description: str = ""
    evidence: dict = Field(default_factory=dict)
    remediation: str | None = None
    created_at: datetime = Field(default_factory=_utcnow)

    # Populated by the (opt-in) AI triage stage.
    ai_priority: int | None = None  # 1 (review first) .. N, relative to other findings in this run
    ai_notes: str | None = None


class ScanState(BaseModel):
    """Top-level state for one scan run, checkpointed to SQLite for --resume."""

    run_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    target_domain: str
    current_stage: Stage = Stage.PASSIVE_ENUM
    completed_stages: set[Stage] = Field(default_factory=set)
    started_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)
    finished: bool = False

    def mark_stage_complete(self, stage: Stage) -> None:
        self.completed_stages.add(stage)
        self.updated_at = _utcnow()

    def is_stage_complete(self, stage: Stage) -> bool:
        return stage in self.completed_stages
