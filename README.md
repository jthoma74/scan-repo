# scan-repo — security-screen a git repo *before* you download or install it

A [Claude Code](https://claude.com/claude-code) agent skill that runs a thorough,
**non-executing** security screen on any open-source GitHub repository — so you can vet
a project before cloning, installing, or running it.

The screening methodology is derived from the
[OpenSSF Concise Guide for Evaluating Open Source Software](https://github.com/ossf/wg-best-practices-os-developers/blob/main/docs/Concise-Guide-for-Evaluating-Open-Source-Software.md)
plus red-flag patterns from real supply-chain attacks (tj-actions tag rewrite, Megalodon
workflow injection, repo-confusion clone campaigns, the xz-utils maintainer takeover).

## What it checks — five phases

| Phase | What happens |
|---|---|
| **0 — Preflight** | Verifies (and can install) the scanner toolchain: [osv-scanner](https://google.github.io/osv-scanner/), [trufflehog](https://github.com/trufflesecurity/trufflehog), [guarddog](https://github.com/DataDog/guarddog) |
| **1 — Remote intel** *(before any clone)* | Typosquat / repo-confusion detection, fake-star anomalies, fork masquerading, owner reputation, maintainer bus-factor, [OpenSSF Scorecard](https://scorecard.dev/), GitHub security advisories, [deps.dev](https://deps.dev/) registry advisories, SECURITY.md, license, suspicious release binaries |
| **2 — Safe acquire** | Shallow clone with git hooks disabled, into a throwaway scratch dir |
| **3 — Static scans** | 8-vector grep sweep (install hooks, exec primitives, obfuscation, pipe-to-shell, exfil endpoints, CI risks, secrets, hidden binaries) + osv-scanner (dependency CVEs) + trufflehog (secrets, passive mode) + guarddog (malicious-package heuristics) |
| **4 — Verdict** | Evidence table ending in **SAFE TO CLONE ✅ / CAUTION ⚠️ / DO NOT INSTALL 🛑** |

**Golden rule:** nothing from the target repository is ever executed during a screen. No
install hooks, no build steps, no scripts. Clone is download-only (hooks disabled).

## Install

```bash
git clone https://github.com/jthoma74/scan-repo ~/.claude/skills/scan-repo
```

Then in any Claude Code session, ask things like:

> security screen https://github.com/some/repo
> is this repo safe to install?

Claude picks up the skill automatically and runs the pipeline, then adjudicates the
findings into a verdict (a raw flag is a "look here", not a conviction).

## Use without Claude Code

The scripts are plain bash and work standalone:

```bash
bash scripts/security-screen.sh <github-url|owner/repo>   # full 5-phase screen
bash scripts/preflight-tools.sh --install                 # install the toolchain
bash scripts/intel-repo.sh owner/repo                     # reputation intel only (no clone)
bash scripts/scan-repo.sh <git-url|local-path>            # static pattern scan only
```

Exit codes: `0` = no flags, `1` = flags to review, `2` = usage/setup error. Each phase's
full output is saved to the scratch dir printed at the start of the run.

## Requirements

- `git`, `curl`, `jq`, and the [GitHub CLI](https://cli.github.com/) (`gh`, authenticated) — for the intel phase
- `osv-scanner`, `trufflehog`, `guarddog` — installed by `preflight-tools.sh --install`
  (via Homebrew / pipx; on Linux without brew, the script prints per-tool install pointers)
- macOS or Linux

## Files

- `SKILL.md` — the skill definition Claude Code loads (workflow + adjudication guidance)
- `REFERENCE.md` — the full OpenSSF-derived checklist, real-attack red-flag catalogue, API reference, per-tool interpretation notes
- `scripts/` — the four bash scripts above

## Honest limits

This is **static + metadata** screening. It cannot catch payloads that only activate at
runtime (environment-gated malware), and a clean result is not a guarantee. Always do a
first run of any untrusted project in a sandbox/VM without real credentials, review its
pinned dependencies, and pin what you install.

## License

MIT
