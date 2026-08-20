"""Pydantic config models for subsense, loaded from config/default.yaml (+ optional user override)."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "default.yaml"
DEFAULT_FINGERPRINTS_PATH = Path(__file__).resolve().parent.parent / "config" / "fingerprints.json"


class ScopeConfig(BaseModel):
    include: list[str] = Field(default_factory=list)
    exclude: list[str] = Field(default_factory=list)


class RateLimitConfig(BaseModel):
    max_concurrency: int = 20
    requests_per_second: float = 10.0
    backoff_base_seconds: float = 1.0
    backoff_max_seconds: float = 60.0
    jitter_seconds: float = 0.5
    respect_retry_after: bool = True
    proxy: str | None = None
    # Adaptive block-detection: after this many consecutive failures, halve the rate
    # (down to a floor) rather than hammering a target that's actively blocking us.
    block_detect_threshold: int = 5


class DnsConfig(BaseModel):
    resolvers: list[str] = Field(default_factory=lambda: ["1.1.1.1", "8.8.8.8"])
    timeout_seconds: float = 5.0
    attempts: int = 2


class HttpConfig(BaseModel):
    timeout_seconds: float = 10.0
    user_agent: str = "subsense/0.1 (+authorized-security-testing)"
    follow_redirects: bool = True
    max_redirects: int = 5


class ActiveConfig(BaseModel):
    enabled: bool = False
    wordlist: Path | None = None
    puredns_bin: str = "puredns"
    massdns_bin: str = "massdns"
    resolvers_file: Path | None = None


class NucleiConfig(BaseModel):
    enabled: bool = False
    bin: str = "nuclei"
    templates: list[str] = Field(default_factory=list)
    severity: list[str] = Field(default_factory=list)


class AiConfig(BaseModel):
    enabled: bool = False
    provider: Literal["ollama"] = "ollama"
    host: str = "http://localhost:11434"
    model: str = "phi4-mini"
    json_mode: bool = True
    batch_size: int = 150


class StateConfig(BaseModel):
    db_path: Path = Path("./subsense_state.db")


class ReportConfig(BaseModel):
    out_dir: Path = Path("./subsense_report")
    formats: list[Literal["json", "html"]] = Field(default_factory=lambda: ["json", "html"])


class Config(BaseModel):
    scope: ScopeConfig = Field(default_factory=ScopeConfig)
    ratelimit: RateLimitConfig = Field(default_factory=RateLimitConfig)
    dns: DnsConfig = Field(default_factory=DnsConfig)
    http: HttpConfig = Field(default_factory=HttpConfig)
    active: ActiveConfig = Field(default_factory=ActiveConfig)
    nuclei: NucleiConfig = Field(default_factory=NucleiConfig)
    ai: AiConfig = Field(default_factory=AiConfig)
    state: StateConfig = Field(default_factory=StateConfig)
    report: ReportConfig = Field(default_factory=ReportConfig)

    @classmethod
    def load(cls, path: Path | None = None) -> "Config":
        """Load config from `path`, deep-merged over the built-in defaults.

        If `path` is None or equal to the default path, just the defaults are used.
        """
        data = _read_yaml(DEFAULT_CONFIG_PATH)
        if path is not None and path.resolve() != DEFAULT_CONFIG_PATH.resolve():
            override = _read_yaml(path)
            data = _deep_merge(data, override)
        return cls.model_validate(data)


def _read_yaml(path: Path) -> dict:
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")
    with path.open("r") as f:
        return yaml.safe_load(f) or {}


def _deep_merge(base: dict, override: dict) -> dict:
    merged = dict(base)
    for key, value in override.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged
