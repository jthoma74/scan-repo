# Security-screen reference — full checklist, red flags, APIs, tools

Deep material for the `scan-repo` skill. SKILL.md has the workflow; this file has the
*why*, the complete checklist (derived from the OpenSSF Concise Guide for Evaluating
Open Source Software + 2025-26 supply-chain incident writeups), and adjudication depth.

## The full evaluation checklist (OpenSSF-derived)

### 1. Necessity & authenticity
- [ ] Is the dependency needed at all? Every new dep expands attack surface.
- [ ] Is this the **canonical** repo? Cross-check the URL against the project's official
      website, docs, and package-registry homepage link. Attackers publish look-alike
      forks and "repo-confusion" clones (Snyk documented >100k cloned malicious repos).
- [ ] Name check: is a similarly-named project far more popular? (typosquat indicator)
- [ ] Repo creation date vs star count — thousands of stars on a weeks-old repo is a
      fake-star-farm signature.
- [ ] Owner account: age, other repos, org affiliation, followers.

### 2. Maintenance & sustainability
- [ ] Commits within the last 12 months; last release within 12 months.
- [ ] Multiple maintainers, ideally from more than one org (bus-factor + takeover risk).
- [ ] Issues/PRs get responses; abandoned issue trackers precede hostile takeovers
      (the xz/jia-tan pattern: a "helpful new maintainer" inherits a burned-out solo one).
- [ ] Version stability: `0.x`, `alpha`, `beta`, `rc` = expect breakage and less scrutiny.

### 3. Security posture
- [ ] OpenSSF Scorecard score and which checks fail (Branch-Protection, Code-Review,
      Pinned-Dependencies, Dangerous-Workflow, Token-Permissions are the load-bearing ones).
- [ ] Known CVEs in the version you'd install (OSV.dev / deps.dev / GitHub advisories).
- [ ] SECURITY.md + a working vulnerability-reporting channel.
- [ ] Any independent security audits? Were the findings fixed?
- [ ] Are its own dependencies reasonably current? A repo with 3-year-stale deps
      inherits 3 years of CVEs.
- [ ] Tests in CI; branch protection; signed releases if available.

### 4. Malicious-code static screen (never execute)
- [ ] Install-time hooks: npm `preinstall`/`postinstall`/`prepare`, `setup.py`,
      non-standard PEP-517 build backends, Makefile targets fetched in CI. **The #1 vector.**
- [ ] Obfuscation: base64/hex blobs, `eval(decode(...))`, `String.fromCharCode`,
      minified-only "source".
- [ ] Exfiltration primitives: env-var harvesting, reads of `~/.ssh`, `~/.aws`,
      keychains, browser profiles; outbound calls to raw IPs, pastebin, Discord
      webhooks, Telegram bot API, ngrok.
- [ ] Binary blobs committed to a source repo.
- [ ] GitHub Actions: unpinned third-party actions (`@main`/`@v1` instead of a SHA),
      `pull_request_target` with checkout of PR code, secrets echoed into logs.
- [ ] Recent-commit review: version tags retroactively moved, bot-disguised commits.
- [ ] Committed live secrets (also a hygiene proxy).

### 5. Release integrity
- [ ] Do release artifacts match the tagged source? The tj-actions/changed-files attack
      (CVE-2025-30066, 23k repos affected) worked by **retroactively re-pointing version
      tags** at malicious commits. Diff a release tarball's file list vs the tag if anything
      looks off.
- [ ] Binary release assets on a "source" project deserve a why.

### 6. License & adoption
- [ ] Clear OSI license compatible with intended use (check `LICENSE`, not just the
      README badge).
- [ ] Adoption signals: dependents count on deps.dev, packaged in distros, corporate use.

### 7. Post-screen hygiene (tell the user)
- Sandbox-first: first run in a container/VM without real credentials.
- Pin what you install (lockfile, exact version, or commit SHA for actions).
- Prefer registry packages with provenance/trusted-publishing over `pip install git+…`.

## Red-flag catalogue (real attack patterns)

| Pattern | Real-world example |
|---|---|
| Tag rewrite → CI secret exfil | tj-actions/changed-files (2025): all version tags re-pointed to a commit dumping CI secrets into logs |
| Mass workflow injection | "Megalodon" (2025): 5,500+ repos poisoned with credential-stealing Actions workflows |
| Repo-confusion clones | Snyk-documented campaigns: forked popular repos + injected payload + automated stars |
| Install-hook payload | Recurrent npm/PyPI pattern: `postinstall` fetches obfuscated 2nd-stage binary |
| Conditional payloads | Payload activates only under env checks (CI env vars, org scopes) — static scan sees the *check*, so grep for env-gated exec |
| Hostile maintainer takeover | xz-utils (2024): multi-year social engineering onto a solo-maintainer project |
| Fake stars / fake activity | Star-farms inflate credibility of days-old malware repos |

## API quick reference (all free, no auth except `gh`)

| What | Endpoint |
|---|---|
| Repo / owner / contributors / releases / advisories | `gh api repos/{o}/{r}`, `users/{o}`, `repos/{o}/{r}/contributors`, `…/releases`, `…/security-advisories`, `…/community/profile` |
| OpenSSF Scorecard | `https://api.securityscorecards.dev/projects/github.com/{o}/{r}` |
| deps.dev project → packages | `https://api.deps.dev/v3/projects/github.com%2F{o}%2F{r}:packageversions` |
| deps.dev package / version (advisories) | `https://api.deps.dev/v3/systems/{sys}/packages/{name}` → `…/versions/{v}` (`advisoryKeys`) |
| OSV by commit/version | `POST https://api.osv.dev/v1/query` |

Scorecard 404 = project simply isn't in the weekly scan set (common for small repos) — a
WARN, not a flag. deps.dev empty = not published to a registry.

## Scanner-tool notes

| Tool | Invocation | Interpreting output |
|---|---|---|
| osv-scanner | `osv-scanner scan source -r <dir>` (v2; v1: `osv-scanner -r <dir>`) | Reads lockfiles/manifests only — no code exec. Table rows = known CVEs in *dependencies*. Severity + whether a fixed version exists matter more than raw count. |
| trufflehog | `trufflehog filesystem <dir> --no-update --no-verification` | We deliberately pass `--no-verification` so it never *uses* found credentials (verification makes live API calls with them). Placeholder-looking hits are common; check entropy + context. |
| guarddog | `guarddog {npm\|pypi\|go} scan <dir>` | Heuristic YARA/semgrep rules for malicious-package patterns (install hooks, exfil, obfuscation). Its findings overlap scan-repo.sh vectors — treat agreement as signal amplification. |
| gitxray (optional, not required) | `gitxray -r {o}/{r}` | Contributor/repo forensics via GitHub API if you want deeper reputation analysis. |

## Adjudication depth (beyond SKILL.md notes)

- **Scorecard low sub-scores**: `Pinned-Dependencies` and `Code-Review` fail on most small
  honest projects — weigh against project size. `Dangerous-Workflow` failing is serious at
  any size.
- **Single maintainer** is the norm for small tools — it raises *takeover* risk, not
  present-malice probability. Combine with account age + activity pattern.
- **osv-scanner hits in devDependencies** of something you'll only *run* (not build) are
  lower risk than runtime-dependency hits.
- **trufflehog on someone else's repo**: a live-looking committed secret is a hygiene red
  flag about the maintainers even when it isn't a threat to *you*.
- **guarddog "suspicious install script"** on a repo whose README documents the same
  script is usually the documented behavior — read it anyway.
- Escalate to **DO NOT INSTALL 🛑** when you find: verified obfuscated payload, install
  hook fetching remote code from a non-canonical host, exfil endpoint wired to harvested
  data, or confirmed typosquat identity. Everything else is CAUTION ⚠️ with specifics.
