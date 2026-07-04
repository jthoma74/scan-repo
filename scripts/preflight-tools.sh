#!/usr/bin/env bash
# preflight-tools — verify (and optionally install) the security-screen toolchain.
#
# Usage:
#   preflight-tools.sh            # report only
#   preflight-tools.sh --install  # install anything missing (brew / pipx / pip)
#
# Exit codes: 0 = all tools present   1 = something missing

set -uo pipefail

INSTALL=0
[ "${1:-}" = "--install" ] && INSTALL=1

MISSING=0
ok()   { printf '  [OK]      %-12s %s\n' "$1" "$2"; }
miss() { printf '  [MISSING] %-12s %s\n' "$1" "$2"; MISSING=$((MISSING+1)); }

check() { # name, version-cmd, install-hint
  local name="$1" vcmd="$2" hint="$3"
  if command -v "$name" >/dev/null 2>&1; then
    ok "$name" "$(eval "$vcmd" 2>/dev/null | head -1)"
  elif [ "$INSTALL" -eq 1 ] && [ -n "$hint" ]; then
    echo "  installing $name ($hint) ..."
    if eval "$hint" >/dev/null 2>&1 && command -v "$name" >/dev/null 2>&1; then
      ok "$name" "$(eval "$vcmd" 2>/dev/null | head -1) (just installed)"
    else
      miss "$name" "install failed — run manually: $hint"
    fi
  else
    miss "$name" "install: $hint"
  fi
}

echo "=== Security-screen toolchain preflight ==="

# Required base tools (never auto-installed — should already exist)
check git  "git --version"  ""
check gh   "gh --version"   "brew install gh   (then: gh auth login)"
check jq   "jq --version"   "brew install jq"
check curl "curl --version" ""

# Scanner toolchain (auto-install uses brew when available; otherwise shows alternatives)
if command -v brew >/dev/null 2>&1; then
  check osv-scanner "osv-scanner --version" "brew install osv-scanner"
  check trufflehog  "trufflehog --version"  "brew install trufflehog"
else
  check osv-scanner "osv-scanner --version" "see https://google.github.io/osv-scanner/installation/ (brew / go install / release binary)"
  check trufflehog  "trufflehog --version"  "see https://github.com/trufflesecurity/trufflehog#floppy_disk-installation (brew / install script / release binary)"
fi
if command -v guarddog >/dev/null 2>&1; then
  ok guarddog "$(guarddog --version 2>/dev/null | head -1)"
elif [ "$INSTALL" -eq 1 ]; then
  echo "  installing guarddog (pipx, falling back to pip --user) ..."
  (command -v pipx >/dev/null 2>&1 && pipx install guarddog >/dev/null 2>&1) \
    || python3 -m pip install --user guarddog >/dev/null 2>&1
  if command -v guarddog >/dev/null 2>&1; then ok guarddog "installed"
  else miss guarddog "install failed — try: pipx install guarddog"; fi
else
  miss guarddog "install: pipx install guarddog"
fi

# gh must be authenticated for the intel phase
if command -v gh >/dev/null 2>&1; then
  if gh auth status >/dev/null 2>&1; then ok "gh-auth" "authenticated"
  else miss "gh-auth" "run: gh auth login"; fi
fi

echo
if [ "$MISSING" -eq 0 ]; then echo "All tools present."; exit 0
else echo "$MISSING tool(s) missing (see above)."; exit 1; fi
