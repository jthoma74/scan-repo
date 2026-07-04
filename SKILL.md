---
name: scan-repo
description: Thorough security screen of an open-source git repo BEFORE downloading or installing it — identity/typosquat + reputation intel, OpenSSF Scorecard, known CVEs, maintenance health, plus a static non-executing malware scan (obfuscation, install hooks, exfil, secrets). Use when the user wants to "security screen" a repo, "scan a repo for malware/viruses", "check if this GitHub repo is safe", "vet/audit a repo before downloading, cloning, or running it", or pastes a repo URL and asks whether it's safe to install.
---

# Repo Security Screen

Vet an untrusted git repository **before** the user downloads, installs, or runs it.
Five phases: toolchain preflight → remote intel (no clone) → safe clone → static scans → verdict.
Everything is **read-only / non-executing** — cloning downloads text but runs nothing.

## Golden rule

**Never execute anything from the target repo during a screen.** No `pip install`, no
`npm install`, no running its scripts, no `make`, no opening it in a tool that auto-runs
tasks. Clone (download only) → read → report.

## Quick start

All paths are relative to this skill's directory (wherever it is installed).

```bash
# Full 5-phase screen (preferred):
bash scripts/security-screen.sh <github-url|owner/repo>

# Individual phases:
bash scripts/preflight-tools.sh [--install]    # toolchain check
bash scripts/intel-repo.sh <owner>/<repo>      # remote intel, no clone
bash scripts/scan-repo.sh <git-url|local-path> # static scan only
```

`security-screen.sh` saves every phase's output to a scratch dir and prints the path.
Exit `0` = no flags, `1` = flags to adjudicate. **A flag is a "look here", not a conviction**
— read the cited evidence before judging.

## The five phases

| Phase | What | How |
|---|---|---|
| 0 | **Toolchain preflight** | osv-scanner + trufflehog (brew), guarddog (pipx); gh + jq assumed. Auto-installs with `--install`. |
| 1 | **Remote intel — before any clone** | Identity/typosquat/fake-star/fork checks, owner reputation, maintenance health, OpenSSF Scorecard, GitHub advisories, deps.dev package advisories, SECURITY.md, license, release-asset signals. `gh api` + curl only. |
| 2 | **Safe acquire** | `git clone --depth 1 -c core.hooksPath=/dev/null` into `mktemp` — never into the working project. |
| 3 | **Static scans** | `scan-repo.sh` 8-vector grep sweep + `osv-scanner` (dependency CVEs) + `trufflehog --no-verification` (secrets) + `guarddog` (malicious-package heuristics, npm/PyPI/Go). |
| 4 | **Verdict** | You adjudicate all saved outputs into the verdict table below. |

The 8 static vectors: inventory/hidden binaries · install & build hooks · code-exec
primitives · obfuscation · pipe-to-shell · outbound endpoints · CI workflows · secrets.

## Workflow

1. Run `security-screen.sh`. If the user only wants a quick code check (or the repo is
   local-only), `scan-repo.sh` alone is fine — say the intel phase was skipped.
2. **Read every flagged line** in the saved outputs. The scripts grep and score; you
   adjudicate. See [REFERENCE.md](REFERENCE.md) for the full OpenSSF-derived checklist,
   real attack patterns (tj-actions tag rewrite, repo-confusion, xz takeover), API notes,
   and per-tool interpretation guidance.
3. If Phase 1 flagged release binary assets or moved tags, do the **release-integrity
   check**: diff a release tarball's file list against the tagged source tree.
4. **Report the verdict table** (below) with one of: SAFE TO CLONE ✅ / CAUTION ⚠️ /
   DO NOT INSTALL 🛑.
5. **Residual-risk note.** Static+intel screening can't catch everything. Always advise:
   review pinned deps, first run in a sandbox/VM, pin what you install.

## Adjudication notes (false positives are common)

- `re.compile` is not `compile()` exec; `curl|sh` to `astral.sh`/`sh.rustup.rs` in docs is
  normal, the same to a pastebin/IP is not; `subprocess` in a CLI tool is expected — judge
  *what* it runs.
- Scorecard 404 / no deps.dev entry = unindexed small project (WARN, not conviction).
- Low `Pinned-Dependencies`/`Code-Review` sub-scores are normal for small honest projects;
  a failing `Dangerous-Workflow` is serious at any size.
- Placeholder secrets (`your_api_key_here`, `sk-xxxx`) are fine.
- More depth: [REFERENCE.md](REFERENCE.md) § Adjudication.

## Verdict format

```
## Security screen: SAFE TO CLONE ✅ / CAUTION ⚠️ (N findings) / DO NOT INSTALL 🛑

| Area | Result |
|------|--------|
| Identity & typosquat   | … |
| Maintenance health     | … |
| OpenSSF Scorecard      | …/10 (low checks: …) |
| Known CVEs (deps)      | … |
| Build/install hooks    | … |
| Code-exec & obfuscation| … |
| Outbound network       | … |
| CI workflows           | … |
| Secrets                | … |
| Release integrity      | … |
| License                | … |

**Verdict:** <one-line judgment>. <residual risk: review deps, sandbox first, pin versions>.
```

## Scope & limits

- **Static + metadata only.** No dynamic analysis, no AV signatures, no binary decompilation.
  Conditional payloads that only fire at runtime can evade any static screen.
- **Best on** Python / JS-TS / shell / Go repos. Binary-heavy repos need extra manual care.
- Not a substitute for first-run isolation in a VM/container without real credentials.
