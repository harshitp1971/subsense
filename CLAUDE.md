# CLAUDE.md — subsense

## What this tool is
**subsense** is a subdomain enumeration + DNS vulnerability discovery tool for **authorized
security testing** (own assets, scope-defined bug bounty, or client pentests). It maximizes
subdomain discovery (never claims "all" — that's impossible) and surfaces vulnerabilities as
prioritized leads.

Its differentiator vs a plain `subfinder` + `nuclei` chain: **custom DNS-layer vulnerability
checks** + **AI-powered pattern-understanding permutation** for discovering subdomains that have
no public footprint. The name reflects that "sense" — inferring naming patterns, not just brute force.

CLI invocation: `subsense -d target.com`

## Tech stack (Python primary — most work in Python)
- Language/core: Python 3.11+, asyncio (recon is I/O-bound; GIL is not a problem here)
- CLI: Typer
- Config/models: Pydantic v2 + PyYAML
- DNS (native): dnspython + aiodns  (AXFR, zone walk, SPF/DMARC, async resolution)
- HTTP (native): httpx / aiohttp   (crt.sh, takeover checks, probing)
- State: SQLite (stdlib) + SQLModel  (checkpoint / resume)
- Terminal UI: Rich | Reports: Jinja2 (HTML) + JSON
- AI: Ollama (local), model configurable — default Phi-4-mini, JSON mode, opt-in
- Packaging: uv + pyproject.toml
- Wrapped external tools (subprocess only, everything else native Python):
  subfinder (passive), puredns/massdns (bruteforce), nuclei (web vulns)

## Architecture principles (non-negotiable)
1. **Plugin architecture** — every source (`sources/`) and every DNS check (`dns_checks/`)
   implements a base class and registers via `registry.py`. Adding a new check = drop one file.
2. **Everything async, throttled by a shared semaphore** — the rate limiter enforces politeness
   AND scope at the code level.
3. **SQLite is source of truth** — every stage writes to it; `--resume` picks up from last checkpoint.
4. **Aggressive features are opt-in** — active enum (bruteforce/permutations), nuclei, and AI are
   behind explicit flags. Default run = passive + resolve + DNS checks + report (low-noise, safe).
5. **Scope enforcement is mandatory** — `scope.py` filters discovered hosts against in/out-of-scope
   regex BEFORE any active stage touches them. Discovery != authorization to test.

## Pipeline (8 stages, each stage's output feeds the next)
1. Passive enum      — crt.sh (native), subfinder (wrap), API sources        [always on]
2. Active enum       — puredns bruteforce + permutations                     [opt-in --active]
3. Resolve           — aiodns: A/AAAA/CNAME, wildcard filter, confidence score [always on]
4. DNS checks        — takeover, AXFR, NSEC/NSEC3 zonewalk, dangling record,  [always on]
                       SPF/DMARC gaps, lame delegation  ← core differentiator
5. HTTP probe        — aiohttp: status, title, tech-detect                    [always on]
6. Vuln scan         — nuclei: exposures, misconfig, takeovers, CVEs          [opt-in --nuclei]
7. AI triage         — Ollama: pattern-permute feedback, rank, categorize     [opt-in --ai]
8. Report            — JSON (machine) + HTML (human) + terminal (Rich)        [always on]

Cross-cutting on every stage: SQLite checkpoint · adaptive rate-limit + backoff + jitter ·
scope enforcement · Rich progress.

## Vulnerability detection scope
Tier 1 (tool confirms, high confidence): subdomain takeover (dangling CNAME + fingerprint match),
zone transfer (AXFR), SPF/DMARC/DKIM gaps, DNSSEC/NSEC zone walk.
Tier 2 (tool flags as leads, human verifies): dangling A-record / cloud IP takeover, exposed
panels (Jenkins/Grafana/GitLab/Swagger), exposed files (.git/.env/backups), misconfig (CORS,
headers), known CVEs (nuclei template match), dev/staging exposure, info disclosure (JS/sourcemaps).
Out of scope for the tool (manual only): business-logic bugs (IDOR, auth bypass, payment flaws),
novel vulns, chained exploits.

Report severity sort: takeover(critical) > exposed secrets/panels(high) > AXFR/zone leak(high)
> CVEs/misconfig(medium) > email-auth/delegation(low-med) > info disclosure(low).

## Pattern-understanding permutation (the advanced part — the "sense" in subsense)
Two techniques, used together:
- Statistical (pure Python, no model): token frequency analysis + Markov next-token prediction;
  re-rank wordlist by target-specific frequencies. Lives in `ai/permute.py`.
- LLM-based (Ollama, opt-in): feed discovered subs, infer naming convention, generate targeted
  candidates that fill gaps (e.g. saw payments-dev/staging/prod but only orders-dev → guess
  orders-staging, orders-prod). Batch 100-200 subs, JSON mode.
Feedback loop: generated candidates → puredns resolve (validate) → newly resolved feed back into
the analyzer (may reveal new tokens) → loop until diminishing returns. Guesses are NEVER trusted;
always validated by resolution. This is an active stage → scope + rate-limit apply.

## Project structure
```
subsense/
├── pyproject.toml
├── config/{default.yaml, fingerprints.json}
├── subsense/
│   ├── cli.py            # Typer entry point
│   ├── config.py         # Pydantic config models
│   ├── models.py         # Subdomain, Finding, ScanState (pydantic)
│   ├── state.py          # SQLite checkpoint/resume
│   ├── pipeline.py       # stage orchestrator
│   ├── scope.py          # in/out-of-scope enforcement
│   ├── ratelimit.py      # adaptive throttle + backoff + jitter + proxy + block-detect
│   ├── registry.py       # plugin registration
│   ├── sources/          # passive enum plugins (base.py + crtsh.py, subfinder.py, ...)
│   ├── active/           # bruteforce.py, permute.py, resolve.py
│   ├── dns_checks/       # base.py + takeover.py, axfr.py, zonewalk.py, dangling.py,
│   │                     #          email_auth.py, delegation.py
│   ├── probe/http.py
│   ├── vuln/nuclei.py
│   ├── ai/               # client.py, permute.py, triage.py, prompts.py
│   └── report/{json_out.py, html.py}
```

## Build order (phased — build + test each before next)
- **Phase 1 (core skeleton):** pyproject.toml, config.py + default.yaml, models.py, state.py,
  scope.py, ratelimit.py, cli.py (Typer skeleton), sources/base.py, sources/crtsh.py (native, no
  external dep). Goal: a runnable foundation that does passive crt.sh enum -> SQLite -> basic output.
- **Phase 2 (DNS depth):** resolve.py, then dns_checks/ (takeover, axfr, zonewalk, dangling,
  email_auth, delegation), probe/http.py, report/.
- **Phase 3 (intelligence + active):** active/bruteforce.py (puredns wrap), active/permute.py,
  ai/ (Ollama pattern permutation + triage), vuln/nuclei.py, feedback loop.

## Working style with Claude Code
- Build in small steps, test each. Prefer running a quick test after each module.
- Get plugin base classes + registry solid first — then new sources/checks are trivial.
- Keep secrets (API keys, resolver configs) out of git; add to .gitignore, chmod 600.

## Guardrails baked into the tool
- Global default rate ceiling (user-overridable) so an accidental run can't violate scope.
- Respect `Retry-After` on 429; adaptive backoff on block detection rather than hammering.
- Philosophy: avoid blocks by being polite, not by evading detection. Polite + adaptive gives
  more reliable results than aggressive evasion anyway.
