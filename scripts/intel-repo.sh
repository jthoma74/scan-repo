#!/usr/bin/env bash
# intel-repo — remote intelligence on a GitHub repo BEFORE any clone/download.
#
# Usage:
#   intel-repo.sh <owner>/<repo>          (or a github.com URL)
#
# Read-only: uses gh api + public curl APIs (OpenSSF Scorecard, deps.dev).
# Downloads nothing, executes nothing from the target.
#
# Exit codes: 0 = no flags   1 = flags raised   2 = usage/API error
#
# A [FLAG] is a "look here", not a conviction; [WARN] is context to weigh.

set -uo pipefail

RAW="${1:-}"
[ -z "$RAW" ] && { echo "usage: intel-repo.sh <owner>/<repo> | <github url>"; exit 2; }

# normalize URL → owner/repo
SLUG=$(printf '%s' "$RAW" | sed -E 's#^(https?://)?(www\.)?github\.com[:/]##; s#\.git$##; s#/$##')
OWNER="${SLUG%%/*}"; REPO="${SLUG#*/}"
[ -z "$OWNER" ] || [ -z "$REPO" ] || [ "$OWNER" = "$REPO" ] && { echo "cannot parse owner/repo from: $RAW"; exit 2; }

FINDINGS=0
note() { printf '  %s\n' "$1"; }
warn() { printf '  [WARN] %s\n' "$1"; }
flag() { printf '  [FLAG] %s\n' "$1"; FINDINGS=$((FINDINGS+1)); }
head2(){ printf '\n=== %s ===\n' "$1"; }

ghlist() { # gh api endpoint → JSON array, '[]' on any failure/error body
  local out; out=$(gh api "$1" 2>/dev/null)
  jq -e 'type=="array"' <<<"$out" >/dev/null 2>&1 && printf '%s' "$out" || printf '[]'
}

NOW=$(date +%s)
days_since() { # ISO date → integer days ago ("" → -1)
  [ -z "$1" ] || [ "$1" = "null" ] && { echo -1; return; }
  local t; t=$(date -j -u -f '%Y-%m-%dT%H:%M:%SZ' "$1" +%s 2>/dev/null || date -d "$1" +%s 2>/dev/null)
  [ -z "$t" ] && { echo -1; return; }
  echo $(( (NOW - t) / 86400 ))
}

echo "Remote intelligence: $OWNER/$REPO  (no clone, no execution)"

# --- 1. Repo identity ----------------------------------------------------------
head2 "1. Identity & authenticity"
META=$(gh api "repos/$OWNER/$REPO" 2>/dev/null) || { echo "  cannot fetch repo (bad slug? private? gh auth?)"; exit 2; }
FORK=$(jq -r .fork <<<"$META"); CREATED=$(jq -r .created_at <<<"$META")
PUSHED=$(jq -r .pushed_at <<<"$META"); STARS=$(jq -r .stargazers_count <<<"$META")
ARCHIVED=$(jq -r .archived <<<"$META"); DESC=$(jq -r '.description // ""' <<<"$META")
HOMEPAGE=$(jq -r '.homepage // ""' <<<"$META")
AGE_D=$(days_since "$CREATED")

note "created: $CREATED (${AGE_D}d ago) · stars: $STARS · homepage: ${HOMEPAGE:-—}"
note "description: ${DESC:-—}"
[ "$FORK" = "true" ] && flag "repo is a FORK of $(jq -r '.parent.full_name // "?"' <<<"$META") — verify you want the fork, not the original"
[ "$ARCHIVED" = "true" ] && flag "repo is ARCHIVED — unmaintained"
# fake-star anomaly: young repo, big stars
[ "$AGE_D" -ge 0 ] && [ "$AGE_D" -lt 90 ] && [ "$STARS" -gt 500 ] && \
  flag "star anomaly: ${STARS}★ on a ${AGE_D}-day-old repo — check for fake-star farming"

# owner reputation
UMETA=$(gh api "users/$OWNER" 2>/dev/null)
if [ -n "$UMETA" ]; then
  UTYPE=$(jq -r .type <<<"$UMETA"); UCREATED=$(jq -r .created_at <<<"$UMETA")
  UAGE_D=$(days_since "$UCREATED")
  note "owner: $OWNER ($UTYPE, account ${UAGE_D}d old, $(jq -r .followers <<<"$UMETA") followers, $(jq -r .public_repos <<<"$UMETA") public repos)"
  [ "$UAGE_D" -ge 0 ] && [ "$UAGE_D" -lt 90 ] && flag "owner account is only ${UAGE_D} days old"
fi

# typosquat / repo-confusion: same-named repos that are far more popular
SIM=$(gh search repos "$REPO" --sort stars --limit 5 --json fullName,stargazersCount 2>/dev/null)
if [ -n "$SIM" ] && [ "$SIM" != "[]" ]; then
  TOPNAME=$(jq -r '.[0].fullName' <<<"$SIM"); TOPSTARS=$(jq -r '.[0].stargazersCount' <<<"$SIM")
  if [ "$TOPNAME" != "$OWNER/$REPO" ] && [ "$TOPSTARS" -gt $(( (STARS + 1) * 10 )) ]; then
    BASETOP=$(printf '%s' "${TOPNAME#*/}" | tr '[:upper:]' '[:lower:]')
    BASEREPO=$(printf '%s' "$REPO" | tr '[:upper:]' '[:lower:]')
    if [ "$BASETOP" = "$BASEREPO" ]; then
      flag "possible typosquat/repo-confusion: '$TOPNAME' (${TOPSTARS}★) is a same-named, far more popular repo"
    else
      warn "similar name search: top result is '$TOPNAME' (${TOPSTARS}★) — eyeball for confusion"
    fi
  else note "name search: this repo is (or matches) the most popular of its name"; fi
fi

# --- 2. Maintenance health ------------------------------------------------------
head2 "2. Maintenance health"
PUSH_D=$(days_since "$PUSHED")
note "last push: $PUSHED (${PUSH_D}d ago) · open issues+PRs: $(jq -r .open_issues_count <<<"$META")"
[ "$PUSH_D" -gt 365 ] && flag "no pushes in >12 months"

CONTRIB=$(ghlist "repos/$OWNER/$REPO/contributors?per_page=30")
NC=$(jq 'length' <<<"$CONTRIB")
note "contributors (first page): $NC$([ "$NC" -eq 30 ] && echo '+') · top: $(jq -r '[.[0:5][].login] | join(", ")' <<<"$CONTRIB" 2>/dev/null)"
[ "$NC" -le 1 ] && warn "single-maintainer project (bus-factor / takeover risk)"

REL=$(ghlist "repos/$OWNER/$REPO/releases?per_page=5")
NREL=$(jq 'length' <<<"$REL")
if [ "$NREL" -gt 0 ]; then
  RDATE=$(jq -r '.[0].published_at' <<<"$REL"); RTAG=$(jq -r '.[0].tag_name' <<<"$REL")
  note "latest release: $RTAG ($RDATE, $(days_since "$RDATE")d ago)"
  case "$RTAG" in 0.*|v0.*|*alpha*|*beta*|*rc*) warn "version string signals pre-stable ($RTAG)";; esac
  # binary assets on releases of a source repo → verify against tagged source
  BIN=$(jq -r '[.[0].assets[]?.name | select(test("\\.(exe|dll|bin|so|dylib|apk|dmg|pkg|msi)$"))] | join(", ")' <<<"$REL")
  [ -n "$BIN" ] && warn "latest release ships binary assets ($BIN) — releases can differ from tagged source; verify"
else
  note "no GitHub releases (may release via package registry or tags only)"
fi

# --- 3. Security posture --------------------------------------------------------
head2 "3. Security posture"
SC=$(curl -sf --max-time 20 "https://api.securityscorecards.dev/projects/github.com/$OWNER/$REPO" 2>/dev/null)
if [ -n "$SC" ]; then
  SCORE=$(jq -r .score <<<"$SC")
  note "OpenSSF Scorecard: $SCORE / 10  (as of $(jq -r .date <<<"$SC"))"
  jq -r '.checks[] | select(.score >= 0 and .score < 5) | "    low check: \(.name) = \(.score)/10 — \(.reason)"' <<<"$SC" | head -8
  awk "BEGIN{exit !($SCORE < 4)}" && flag "Scorecard overall score is low ($SCORE/10)" || true
else
  warn "no OpenSSF Scorecard data (project not in weekly scan set — common for small repos)"
fi

ADV=$(ghlist "repos/$OWNER/$REPO/security-advisories?per_page=10")
NADV=$(jq 'length' <<<"$ADV")
if [ "$NADV" -gt 0 ]; then
  warn "$NADV published GitHub security advisories (check the current version is patched):"
  jq -r '.[0:5][] | "      \(.ghsa_id) [\(.severity)] \(.summary)"' <<<"$ADV"
else note "no published GitHub security advisories"; fi

PROFILE=$(gh api "repos/$OWNER/$REPO/community/profile" 2>/dev/null)
SECMD=$(jq -r '.files.security // "null"' <<<"${PROFILE:-{}}" 2>/dev/null)
if [ "$SECMD" = "null" ]; then
  # community/profile misses non-standard casing (e.g. express's Security.md) — check root listing
  gh api "repos/$OWNER/$REPO/contents" --jq '.[].name' 2>/dev/null | grep -qix 'security\.md' \
    && note "SECURITY.md present (root)" \
    || warn "no SECURITY.md / vulnerability-reporting policy"
else
  note "SECURITY.md present"
fi

# deps.dev: read the package name from the repo's own manifest, then check advisories
SYSTEM=""; PKG=""
fetch_root() { gh api "repos/$OWNER/$REPO/contents/$1" --jq .content 2>/dev/null | base64 -d 2>/dev/null; }
if PJSON=$(fetch_root package.json) && [ -n "$PJSON" ]; then
  SYSTEM="NPM"; PKG=$(jq -r '.name // empty' <<<"$PJSON")
elif PYTOML=$(fetch_root pyproject.toml) && [ -n "$PYTOML" ]; then
  SYSTEM="PYPI"; PKG=$(printf '%s' "$PYTOML" | grep -m1 -E '^\s*name\s*=' | sed -E 's/.*=\s*"([^"]+)".*/\1/')
elif GOMOD=$(fetch_root go.mod) && [ -n "$GOMOD" ]; then
  SYSTEM="GO"; PKG=$(printf '%s' "$GOMOD" | grep -m1 '^module ' | awk '{print $2}')
elif CARGO=$(fetch_root Cargo.toml) && [ -n "$CARGO" ]; then
  SYSTEM="CARGO"; PKG=$(printf '%s' "$CARGO" | grep -m1 -E '^\s*name\s*=' | sed -E 's/.*=\s*"([^"]+)".*/\1/')
fi
if [ -n "$SYSTEM" ] && [ -n "$PKG" ]; then
  PKG_ENC=$(jq -rn --arg p "$PKG" '$p|@uri')
  PKGINFO=$(curl -sf --max-time 20 "https://api.deps.dev/v3/systems/$SYSTEM/packages/$PKG_ENC" 2>/dev/null)
  if [ -n "$PKGINFO" ]; then
    note "published package (from manifest): $PKG ($SYSTEM)"
    LATEST=$(jq -r '[.versions[] | select(.isDefault == true)][0].versionKey.version // empty' <<<"$PKGINFO")
    if [ -n "$LATEST" ]; then
      VADV=$(curl -sf --max-time 20 "https://api.deps.dev/v3/systems/$SYSTEM/packages/$PKG_ENC/versions/$LATEST" 2>/dev/null \
        | jq -r '[.advisoryKeys[]?.id] | join(", ")')
      [ -n "$VADV" ] && flag "latest published version $LATEST has open advisories: $VADV" \
                     || note "latest published version $LATEST: no known advisories (deps.dev)"
    fi
  else
    note "manifest names '$PKG' but it isn't on the $SYSTEM registry (private/unpublished — or squat risk if you expected it published)"
  fi
else
  note "no npm/PyPI/Go/Cargo manifest at repo root — skipping registry advisory check"
fi

# --- 4. License ------------------------------------------------------------------
head2 "4. License"
LIC=$(jq -r '.license.spdx_id // "NONE"' <<<"$META")
case "$LIC" in
  NONE|NOASSERTION) warn "no clear OSI license detected (LICENSE file missing or non-standard)";;
  *) note "license: $LIC";;
esac

# --- Verdict ----------------------------------------------------------------------
head2 "INTEL SUMMARY"
if [ "$FINDINGS" -eq 0 ]; then
  echo "  No identity/posture flags. Proceed to static code scan before trusting."
else
  echo "  $FINDINGS flag(s) raised — read above before cloning. A flag is a 'look here', not a conviction."
fi
exit $([ "$FINDINGS" -eq 0 ] && echo 0 || echo 1)
