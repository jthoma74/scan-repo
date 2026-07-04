#!/usr/bin/env bash
# security-screen — full 5-phase security screen of a git repo before download/install.
#
#   Phase 0  toolchain preflight (auto-installs missing scanners)
#   Phase 1  remote intelligence — intel-repo.sh (NO clone)
#   Phase 2  safe shallow clone into a scratch dir (hooks disabled)
#   Phase 3  static scans — scan-repo.sh + osv-scanner + trufflehog + guarddog
#   Phase 4  summary (Claude adjudicates the saved outputs into a verdict)
#
# Usage:
#   security-screen.sh <github-url|owner/repo>
#
# NEVER executes anything from the target repo. Scanner outputs are written to
# the scratch dir for adjudication.
#
# Exit codes: 0 = no flags anywhere   1 = flags to adjudicate   2 = setup error

set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RAW="${1:-}"
[ -z "$RAW" ] && { echo "usage: security-screen.sh <github-url|owner/repo>"; exit 2; }

SLUG=$(printf '%s' "$RAW" | sed -E 's#^(https?://)?(www\.)?github\.com[:/]##; s#\.git$##; s#/$##')
OWNER="${SLUG%%/*}"; REPO="${SLUG#*/}"
[ -z "$OWNER" ] || [ -z "$REPO" ] || [ "$OWNER" = "$REPO" ] && { echo "cannot parse owner/repo from: $RAW"; exit 2; }
URL="https://github.com/$OWNER/$REPO"

OUT="$(mktemp -d -t secscreen-"$REPO")"
FLAGS=0
banner() { printf '\n########## PHASE %s — %s ##########\n' "$1" "$2"; }

echo "Security screen: $OWNER/$REPO"
echo "Outputs → $OUT"

# --- Phase 0: preflight ---------------------------------------------------------
banner 0 "toolchain preflight"
bash "$HERE/preflight-tools.sh" --install | tee "$OUT/preflight.txt"

# --- Phase 1: remote intelligence (no clone) --------------------------------------
banner 1 "remote intelligence (no clone)"
bash "$HERE/intel-repo.sh" "$OWNER/$REPO" | tee "$OUT/intel.txt"
[ "${PIPESTATUS[0]}" -eq 1 ] && FLAGS=$((FLAGS+1))

# --- Phase 2: safe acquire ---------------------------------------------------------
banner 2 "safe shallow clone (hooks disabled)"
DIR="$OUT/repo"
GIT_TERMINAL_PROMPT=0 git -c core.hooksPath=/dev/null clone --depth 1 "$URL" "$DIR" >/dev/null 2>&1 \
  || { echo "clone failed: $URL"; exit 2; }
echo "cloned → $DIR (download only; nothing executed)"

# --- Phase 3: static scans -----------------------------------------------------------
banner 3 "static pattern scan (scan-repo.sh)"
bash "$HERE/scan-repo.sh" "$DIR" | tee "$OUT/static.txt"
[ "${PIPESTATUS[0]}" -eq 1 ] && FLAGS=$((FLAGS+1))

banner 3b "known CVEs in dependencies (osv-scanner)"
if command -v osv-scanner >/dev/null 2>&1; then
  osv-scanner scan source -r "$DIR" >"$OUT/osv.txt" 2>&1; RC=$?
  if grep -q 'unknown command' "$OUT/osv.txt"; then  # v1 fallback
    osv-scanner -r "$DIR" >"$OUT/osv.txt" 2>&1; RC=$?
  fi
  if grep -q 'No package sources found' "$OUT/osv.txt"; then
    echo "no lockfiles osv-scanner can read — dependency CVE check limited (check the registry package instead)"
  elif [ "$RC" -eq 0 ]; then
    echo "no known vulnerabilities in scanned dependency sources"
  elif [ "$RC" -eq 1 ]; then
    tail -30 "$OUT/osv.txt"
    echo "[FLAG] known vulnerabilities found (full list: $OUT/osv.txt)"; FLAGS=$((FLAGS+1))
  else
    echo "osv-scanner error (rc=$RC) — see $OUT/osv.txt"
  fi
else echo "osv-scanner unavailable — SKIPPED"; fi

banner 3c "committed secrets (trufflehog, passive — no credential verification)"
if command -v trufflehog >/dev/null 2>&1; then
  trufflehog filesystem "$DIR" --no-update --no-verification 2>/dev/null | tee "$OUT/trufflehog.txt" | head -40
  [ -s "$OUT/trufflehog.txt" ] && { echo "[FLAG] potential secrets found (full list: $OUT/trufflehog.txt)"; FLAGS=$((FLAGS+1)); } \
                               || echo "no secrets detected"
else echo "trufflehog unavailable — SKIPPED"; fi

banner 3d "malicious-package heuristics (guarddog)"
if command -v guarddog >/dev/null 2>&1; then
  ECO=""
  [ -f "$DIR/package.json" ] && ECO="npm"
  { [ -f "$DIR/pyproject.toml" ] || [ -f "$DIR/setup.py" ]; } && ECO="pypi"
  [ -f "$DIR/go.mod" ] && ECO="${ECO:-go}"
  if [ -n "$ECO" ]; then
    guarddog "$ECO" scan "$DIR" 2>&1 | tee "$OUT/guarddog.txt" | tail -25
    grep -qiE 'found [1-9][0-9]* potentially malicious|issues? found' "$OUT/guarddog.txt" \
      && { echo "[FLAG] guarddog raised findings (full: $OUT/guarddog.txt)"; FLAGS=$((FLAGS+1)); }
  else echo "not an npm/PyPI/Go package — SKIPPED"; fi
else echo "guarddog unavailable — SKIPPED"; fi

# --- Phase 4: summary ------------------------------------------------------------------
banner 4 "summary"
echo "Phase outputs saved in $OUT:"
ls -1 "$OUT" | grep -v '^repo$' | sed 's/^/  /'
if [ "$FLAGS" -eq 0 ]; then
  echo "RESULT: no phase raised flags. Static+intel heuristics only — still sandbox-first."
else
  echo "RESULT: $FLAGS phase(s) raised flags. Adjudicate each saved output before any verdict."
fi
echo "(scratch dir left for review: $OUT — rm -rf when done)"
exit $([ "$FLAGS" -eq 0 ] && echo 0 || echo 1)
