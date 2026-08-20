"""Plugin registry. Every passive source (`sources/`) and every DNS check (`dns_checks/`)
subclasses the relevant base class and registers itself here via a decorator.

Adding a new check/source = drop one file that imports its base class, subclasses it, and
decorates the class with `@register_source(...)` / `@register_dns_check(...)`. No other file
needs to change — `sources/__init__.py` and `dns_checks/__init__.py` import every module in
their package so the decorators run at startup.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, TypeVar

if TYPE_CHECKING:
    from subsense.dns_checks.base import DnsCheck
    from subsense.sources.base import Source

SourceT = TypeVar("SourceT", bound="Source")
DnsCheckT = TypeVar("DnsCheckT", bound="DnsCheck")

_SOURCE_REGISTRY: dict[str, type["Source"]] = {}
_DNS_CHECK_REGISTRY: dict[str, type["DnsCheck"]] = {}


def register_source(name: str):
    def decorator(cls: type[SourceT]) -> type[SourceT]:
        if name in _SOURCE_REGISTRY:
            raise ValueError(f"Source '{name}' is already registered")
        _SOURCE_REGISTRY[name] = cls
        return cls

    return decorator


def register_dns_check(name: str):
    def decorator(cls: type[DnsCheckT]) -> type[DnsCheckT]:
        if name in _DNS_CHECK_REGISTRY:
            raise ValueError(f"DNS check '{name}' is already registered")
        _DNS_CHECK_REGISTRY[name] = cls
        return cls

    return decorator


def get_sources() -> dict[str, type["Source"]]:
    return dict(_SOURCE_REGISTRY)


def get_dns_checks() -> dict[str, type["DnsCheck"]]:
    return dict(_DNS_CHECK_REGISTRY)


def load_all_plugins() -> None:
    """Import the sources/ and dns_checks/ packages so their `@register_*` decorators run."""
    import importlib
    import pkgutil

    import subsense.dns_checks as dns_checks_pkg
    import subsense.sources as sources_pkg

    for pkg in (sources_pkg, dns_checks_pkg):
        for _finder, module_name, _is_pkg in pkgutil.iter_modules(pkg.__path__, pkg.__name__ + "."):
            if module_name.endswith(".base"):
                continue
            importlib.import_module(module_name)
