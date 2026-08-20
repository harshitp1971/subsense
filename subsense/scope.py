"""Scope enforcement. Filters discovered hosts against in/out-of-scope regex BEFORE any active
stage touches them. Discovery != authorization to test — this module is what draws that line.
"""

from __future__ import annotations

import re

from subsense.config import ScopeConfig
from subsense.models import Subdomain


class ScopeFilter:
    """Compiles include/exclude regex once and evaluates hostnames against them.

    A hostname is in-scope if it matches at least one `include` pattern (when any are given,
    otherwise everything is a candidate) AND does not match any `exclude` pattern.
    """

    def __init__(self, config: ScopeConfig, root_domain: str):
        self.root_domain = root_domain.lower().strip(".")
        self._include = [re.compile(p, re.IGNORECASE) for p in config.include]
        self._exclude = [re.compile(p, re.IGNORECASE) for p in config.exclude]

    def is_in_scope(self, hostname: str) -> bool:
        host = hostname.lower().strip(".")

        # Always require the host to at least belong to the target's DNS namespace.
        if not (host == self.root_domain or host.endswith("." + self.root_domain)):
            return False

        if any(p.search(host) for p in self._exclude):
            return False

        if self._include and not any(p.search(host) for p in self._include):
            return False

        return True

    def apply(self, sub: Subdomain) -> Subdomain:
        """Return `sub` with `in_scope` set according to this filter (does not mutate input)."""
        return sub.model_copy(update={"in_scope": self.is_in_scope(sub.hostname)})

    def filter_in_scope(self, subs: list[Subdomain]) -> list[Subdomain]:
        """Convenience helper: apply scope and return only the subset that is in-scope.

        Active stages (bruteforce, permutation, nuclei, AI-guided probing) MUST call this
        (or check `.in_scope`) before touching a host.
        """
        return [s for s in (self.apply(s) for s in subs) if s.in_scope]
