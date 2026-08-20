<!-- Title -->
# subsense

**A subdomain enumeration + DNS vulnerability discovery tool — built for authorized security
testing.** Point it at a domain you're allowed to test, and it finds subdomains (including ones
no public source has ever recorded) and flags real DNS-layer security problems, ranked by how
serious they are.

```bash
uv run subsense -d target.com
```

> ⚠️ **Authorized use only.** Only run this against domains you own, or are explicitly
> authorized to test (a scope-defined bug bounty, or a signed pentest engagement). Finding a
> subdomain is not permission to attack it — see [Responsible use](#-responsible-use) below.

---

## Table of contents

- [Why this tool, and not just subfinder + nuclei?](#why-this-tool-and-not-just-subfinder--nuclei)
- [What it actually finds](#what-it-actually-finds)
- [How to install it](#how-to-install-it)
- [How to use it](#how-to-use-it)
- [What's under the hood (tech stack, explained simply)](#whats-under-the-hood-tech-stack-explained-simply)
- [How the scan works, step by step](#how-the-scan-works-step-by-step)
- [Configuration](#configuration)
- [Reading the report](#reading-the-report)
- [Running the tests](#running-the-tests)
- [How to contribute / collaborate](#how-to-contribute--collaborate)
- [Found a bug? Here's how to report it](#found-a-bug-heres-how-to-report-it)
- [License](#license)
- [Responsible use](#-responsible-use)

---

## Why this tool, and not just subfinder + nuclei?

Most recon setups chain a passive-source tool (`subfinder`) into a vuln scanner (`nuclei`).
That's a good baseline — subsense includes both of those ideas — but it stops at "what's already
public" and "what has a known signature." subsense adds two things that chain doesn't do:

1. **Custom DNS-layer vulnerability checks.** Not web vulnerabilities — DNS *protocol-level*
   misconfigurations: zone transfers left open, DNSSEC zones that leak their entire contents,
   dangling CNAMEs pointing at claimable cloud services, missing email-spoofing protection,
   nameservers that don't actually answer for the zone they're delegated. These are checks a
   web-focused scanner simply doesn't do.

2. **Pattern-understanding subdomain guessing.** A wordlist bruteforce only finds subdomains
   someone already thought to name `admin` or `dev`. subsense looks at what it *has* found —
   say, `payments-dev`, `payments-staging`, `payments-prod`, and `orders-dev` — notices the
   `{service}-{environment}` pattern, and proposes `orders-staging` and `orders-prod` as
   candidates worth checking. It never trusts a guess — every candidate is actually resolved
   before being reported. This is how it finds subdomains that have **zero public footprint**:
   no certificate, no search-engine index, nothing — because it isn't looking things up, it's
   reasoning about naming conventions.

It also never claims to find "all" subdomains — no tool can promise that. It maximizes coverage
and is honest about the gap.

## What it actually finds

| Check | What it means if it fires |
|---|---|
| **Subdomain takeover** | A subdomain points (via CNAME) at a cloud service — GitHub Pages, Heroku, S3, Shopify, etc. — that no longer exists. Anyone can claim it and serve their own content on your domain. |
| **Zone transfer (AXFR)** | A misconfigured nameserver hands over your *entire* DNS zone to anyone who asks — every subdomain, including ones you never meant to be public. |
| **DNSSEC zone walk** | Your DNSSEC setup lets someone enumerate your whole zone just by chaining standard queries. |
| **Dangling cloud IP** | A subdomain points at an IP in AWS/GCP/Azure/DigitalOcean's range that looks unreachable — possible sign the underlying resource was deleted and the IP could be re-claimed by someone else. |
| **Missing/weak email auth** | No SPF or DMARC record (or a too-permissive one) — meaning attackers can send email that *looks* like it's from your domain. |
| **Lame delegation** | A nameserver your domain is delegated to doesn't actually answer for it — a subtle, often-missed misconfiguration. |

Findings are sorted by real-world severity: **takeover** (critical) → **exposed secrets/zone
leaks** (high) → **CVEs/misconfig** (medium) → **email auth gaps** (low–medium) → **info
disclosure** (low).

## How to install it

You need [uv](https://docs.astral.sh/uv/) (a fast Python package manager) and Python 3.11+.
uv will install the right Python version for you automatically.

```bash
# 1. Install uv (one-time, if you don't have it)
brew install uv          # macOS
# or: curl -LsSf https://astral.sh/uv/install.sh | sh   # Linux/macOS, no brew

# 2. From inside the project folder, install everything
uv sync
```

That's it for the core tool — passive scanning works right away with nothing else to install.

**Optional extras** (only needed if you use the matching flag):

| Flag | Needs | Install |
|---|---|---|
| `--active` | `puredns` (bruteforce/permutation resolving) | `brew install massdns && go install github.com/d3mondev/puredns/v2@latest` |
| `--nuclei` | `nuclei` (web vulnerability templates) | `brew install nuclei` |
| `--ai` | a local [Ollama](https://ollama.com) server | `brew install ollama && ollama pull phi4-mini` |

If a tool isn't installed, subsense logs a warning and skips just that piece — it won't crash
your scan.

## How to use it

The most basic command — this is all most people need:

```bash
uv run subsense -d target.com
```

This runs a **safe, passive-only** scan: it never sends anything that looks like an attack,
just standard DNS lookups and one polite HTTP request per host.

All the flags:

| Command | What it does |
|---|---|
| `uv run subsense -d target.com` | Basic passive scan (safe default) |
| `uv run subsense -d target.com --active` | Also bruteforce + smart pattern-guess subdomains (touches the target more) |
| `uv run subsense -d target.com --nuclei` | Also run web vulnerability templates against found hosts |
| `uv run subsense -d target.com --ai` | Also use local AI to guess smarter subdomains and rank findings by priority |
| `uv run subsense -d target.com --active --nuclei --ai` | Everything, all at once |
| `uv run subsense -d target.com --resume` | Continue a scan that got interrupted, from where it left off |
| `uv run subsense -d target.com -v` | Verbose mode — see exactly what's happening at each step |
| `uv run subsense -d target.com -o ./my-report` | Save the report somewhere other than the default folder |
| `uv run subsense -d target.com --config myconfig.yaml` | Use your own settings instead of the defaults |
| `uv run subsense --help` | Show all options |

## What's under the hood (tech stack, explained simply)

No need to know any of this to *use* the tool — it's here for anyone curious or contributing.

| Piece | What it's for, in plain terms |
|---|---|
| **Python 3.11+ / asyncio** | The whole engine. `asyncio` means it can do hundreds of DNS lookups and HTTP requests *at the same time* instead of one-by-one — this is why scans are fast even though DNS itself is slow. |
| **Typer** | Turns the tool into a friendly command-line program (`subsense -d ...`) with `--help` text generated automatically. |
| **Pydantic + PyYAML** | Reads and validates the settings file (`config/default.yaml`) — catches typos in config before a scan even starts, instead of failing halfway through. |
| **dnspython + aiodns** | The actual DNS toolkit — used for every lookup, zone transfer attempt, and DNSSEC check. |
| **httpx / aiohttp** | Talks to crt.sh (certificate search) and probes each website found (status code, page title, tech). |
| **SQLite + SQLModel** | A local database file that remembers scan progress. If a scan gets interrupted, `--resume` picks up exactly where it stopped instead of starting over. |
| **Rich** | Makes the terminal output readable — colors, progress spinners, tables — instead of a wall of plain text. |
| **Jinja2** | Builds the HTML report from a template, so the report looks like a real dashboard, not raw data. |
| **Ollama** | Runs a small AI model *on your own machine* (nothing leaves your computer) to spot subdomain naming patterns and help prioritize findings. Completely optional. |
| **subfinder / puredns / nuclei** | Three well-known external security tools, called only when you ask for them — subsense doesn't reinvent what they already do well, it wraps them and adds what they don't do. |

## How the scan works, step by step

```
1. Passive search   →  crt.sh + subfinder find subdomains from public records   [always runs]
2. Active guessing   →  wordlist bruteforce + smart pattern-guessing             [--active]
3. Resolve           →  check which subdomains are actually live                [always runs]
4. DNS security check → the 6 checks listed above                               [always runs]
5. Website probe     →  visit each live host, note status/title/tech            [always runs]
6. Vulnerability scan → run nuclei's templates against live websites            [--nuclei]
7. AI ranking        →  sort findings by what to look at first                  [--ai]
8. Report            →  write the JSON + HTML report                           [always runs]
```

Every step saves its progress to a local database as it goes, so `--resume` always works, even
if you close the terminal mid-scan.

## Configuration

Default settings live in [`config/default.yaml`](config/default.yaml) — rate limits, DNS
resolvers, timeouts, and (most importantly) **scope**:

```yaml
scope:
  include: []   # if you list patterns here, ONLY matching hosts are touched
  exclude: []   # hosts matching these are always skipped, even by --active
```

Set `exclude` for anything you don't want touched (e.g. `^internal\.` to skip internal hosts)
before running `--active`. This is enforced in code, not just documentation — excluded hosts
never reach a bruteforce/permutation/probe call.

Point at your own config file with `--config path/to/your.yaml` — you only need to include the
settings you want to change; everything else falls back to the default.

## Reading the report

Every scan writes to `subsense_report/` (or wherever `-o` points):

- **`<domain>-<id>.json`** — full machine-readable results, good for feeding into other tools
- **`<domain>-<id>.html`** — a readable dashboard: severity counts, a findings table with
  evidence you can expand, and the full subdomain list with what was found on each one

## Running the tests

```bash
uv run pytest -q
```

The test suite covers scope enforcement, config loading, the subdomain-guessing logic, rate
limiting, and each DNS check's edge cases — including regression tests for real bugs found while
testing this tool against live infrastructure (see the git history for details).

## How to contribute / collaborate

Contributions are welcome — this is early-stage and there's a lot of room to grow (more DNS
checks, more passive sources, better fingerprints).

1. **Fork/branch, make your change.** Follow the existing plugin pattern:
   - A new passive source? Add a file to `subsense/sources/`, subclass `Source`, and decorate it
     with `@register_source("your-name")`. It's picked up automatically — nothing else to wire up.
   - A new DNS check? Same idea in `subsense/dns_checks/`, subclassing `DnsCheck` and using
     `@register_dns_check("your-name")`.
2. **Write a test** for what you added — check `tests/` for the existing style. If your change
   touches network calls, fake the boundary (see `tests/test_resolve.py` for a pattern) rather
   than depending on live infrastructure in the test itself.
3. **Run the suite** before opening a PR: `uv run pytest -q`.
4. **Keep the guardrails intact.** Scope enforcement, rate limiting, and "aggressive stages are
   opt-in" are non-negotiable design decisions for this project (see `CLAUDE.md`) — a
   contribution that bypasses them won't be merged, even if it makes something faster.
5. Open a pull request describing *what* changed and *why*. Small, focused PRs are much easier
   to review than one big one.

## Found a bug? Here's how to report it

Open an issue (or, if you don't have write access, ask the maintainer to open one) with:

1. **The exact command you ran** (redact the target domain if it's sensitive).
2. **What you expected** vs. **what actually happened.**
3. **The relevant log output** — run with `-v` for verbose logs, and paste the warning/error,
   not just "it didn't work."
4. **Your environment**: OS, Python version (`python3 --version`), and whether you have
   `puredns`/`nuclei`/`ollama` installed if the bug involves one of those.

If the bug is a **security-relevant false positive or false negative** (a check flags something
that isn't real, or misses something that is), that's especially valuable to report — DNS
security checks are exactly the kind of code where a subtle logic error quietly produces wrong
results without ever crashing. Real-world DNS behavior is genuinely weird and varies a lot
between providers, so edge cases like this get found by running against real infrastructure —
if you hit one, it's worth writing up even if you're not sure it's a "real" bug.

## License

[MIT](LICENSE) — same license used by `subfinder`, `nuclei`, and `puredns`, the external tools
this project wraps.

## ⚠️ Responsible use

- Only scan domains you **own** or are **explicitly authorized** to test.
- `--active`, `--nuclei`, and `--ai`-driven permutation all send real traffic to the target —
  make sure your scope (`config/default.yaml`) is correct *before* using them.
- Finding a subdomain or a misconfiguration is not permission to exploit it. This tool surfaces
  leads for a human to verify and act on responsibly, within the bounds of your authorization.
- Be polite by default: the built-in rate limiter and backoff exist so a scan can't accidentally
  hammer a target — don't disable them unless you have a specific, authorized reason to.
