#!/usr/bin/env bash
# scan-repo — static, NON-EXECUTING safety sweep of a git repo.
#
# Usage:
#   scan-repo.sh <git-url|local-path>
#
# What it does: clones (shallow) to a scratch dir if given a URL, then runs a
# battery of read-only greps for the common malware / supply-chain vectors.
# It NEVER runs the repo's own code, install hooks, or build steps.
#
# Exit codes:  0 = no high-signal findings   1 = findings worth a human look
#
# Findings are heuristic. A hit is a "look here", not a conviction. Read the
# flagged lines before judging.

set -uo pipefail

TARGET="${1:-}"
[ -z "$TARGET" ] && { echo "usage: scan-repo.sh <git-url|local-path>"; exit 2; }

FINDINGS=0
note()  { printf '  %s\n' "$1"; }
flag()  { printf '  [FLAG] %s\n' "$1"; FINDINGS=$((FINDINGS+1)); }
head2() { printf '\n=== %s ===\n' "$1"; }

# --- 0. Acquire (clone is download-only; it executes nothing) -----------------
CLEANUP=""
if printf '%s' "$TARGET" | grep -qE '^(https?|git|ssh)://|@.*:'; then
  DIR="$(mktemp -d)/repo"
  echo "Cloning (shallow, no checkout hooks) → $DIR"
  GIT_TERMINAL_PROMPT=0 git -c core.hooksPath=/dev/null clone --depth 1 "$TARGET" "$DIR" >/dev/null 2>&1 \
    || { echo "clone failed"; exit 2; }
  CLEANUP="$DIR"
else
  DIR="$TARGET"
  [ -d "$DIR" ] || { echo "not a directory: $DIR"; exit 2; }
fi

EX=( -not -path '*/.git/*' )
SRC=( --include='*.py' --include='*.js' --include='*.ts' --include='*.mjs' --include='*.cjs' \
      --include='*.sh' --include='*.bash' --include='*.rb' --include='*.pl' --include='*.ps1' )

# --- 1. Inventory -------------------------------------------------------------
head2 "1. Inventory"
note "files: $(find "$DIR" -type f "${EX[@]}" | wc -l | tr -d ' ')"
find "$DIR" -type f "${EX[@]}" | sed 's/.*\.//' | sort | uniq -c | sort -rn | head -12 | sed 's/^/    /'
# binaries that could be disguised executables / hidden files
find "$DIR" -type f "${EX[@]}" -name '.*' | grep -vE '(\.(gitignore|gitattributes|gitmodules|gitkeep|dockerignore|npmrc|nvmrc|editorconfig|prettierrc|eslintrc.*|flake8|isort\.cfg|python-version|ruby-version|tool-versions|node-version)|env\.example|pre-commit-config\.yaml|github/.*|gitlab-ci\.yml|readthedocs\.ya?ml)$' \
  | head | while read -r f; do flag "hidden file: ${f#"$DIR"/}"; done

# --- 2. Install / build hooks (the #1 supply-chain vector) --------------------
head2 "2. Install & build hooks"
# npm lifecycle scripts that run on install
if [ -f "$DIR/package.json" ]; then
  if grep -qE '"(pre|post)?install"|"prepare"|"prepublish"' "$DIR/package.json"; then
    flag "package.json has install/prepare lifecycle scripts:"
    grep -nE '"(pre|post)?install"|"prepare"|"prepublish"' "$DIR/package.json" | sed 's/^/      /'
  else note "package.json: no install lifecycle scripts"; fi
fi
# python: setup.py runs arbitrary code at install; custom build backends do too
[ -f "$DIR/setup.py" ] && flag "setup.py present — runs arbitrary code on pip install; read it"
if [ -f "$DIR/pyproject.toml" ]; then
  BACKEND=$(grep -E 'build-backend' "$DIR/pyproject.toml" | head -1)
  case "$BACKEND" in
    *setuptools.build_meta*|*hatchling*|*flit_core*|*poetry.core*|*pdm.backend*|"") note "build backend: ${BACKEND:-default} (standard)";;
    *) flag "non-standard build backend: $BACKEND";;
  esac
fi

# --- 3. Code-execution primitives --------------------------------------------
head2 "3. Code-execution primitives (eval/exec/spawn)"
M=$(grep -rnE '\b(eval|exec|execfile|os\.system|os\.popen|subprocess\.(call|run|Popen|check_output)|child_process|spawnSync?|execSync?|Function\s*\(|marshal\.loads|pickle\.loads)\b' \
    "${SRC[@]}" "$DIR" 2>/dev/null | grep -vE '\bre\.(compile|escape|match|search|sub|findall)' | grep -v '/test' )
if [ -n "$M" ]; then flag "dynamic-exec call sites (review each):"; printf '%s\n' "$M" | head -25 | sed 's/^/      /'
else note "none in non-test source"; fi

# --- 4. Obfuscation -----------------------------------------------------------
head2 "4. Obfuscation"
O=$(grep -rnE 'b64decode|base64\s*\.\s*(b64)?decode|atob\(|fromCharCode|codecs\.decode|\.fromhex|String\.fromCharCode' \
    "${SRC[@]}" "$DIR" 2>/dev/null | grep -v '/test' )
[ -n "$O" ] && { flag "decode/obfuscation calls:"; printf '%s\n' "$O" | head -15 | sed 's/^/      /'; } || note "no base64/hex/char-code decoding in source"
# long inline base64/hex blobs (>200 chars) often hide payloads
B=$(grep -rnoE '[A-Za-z0-9+/]{200,}={0,2}' "${SRC[@]}" "$DIR" 2>/dev/null | head -5)
[ -n "$B" ] && { flag "long inline encoded blobs (possible payload):"; printf '%s\n' "$B" | cut -c1-100 | sed 's/^/      /'; } || note "no long inline encoded blobs"

# --- 5. Pipe-to-shell ---------------------------------------------------------
head2 "5. Pipe-to-shell installers"
P=$(grep -rnE '(curl|wget)[^|]*\|[[:space:]]*(sudo[[:space:]]+)?(ba)?sh' "$DIR" "${EX[@]}" 2>/dev/null | grep -vE '/\.git/')
[ -n "$P" ] && { flag "curl|sh style installers (verify the host):"; printf '%s\n' "$P" | head -10 | sed 's/^/      /'; } || note "none"

# --- 6. Network endpoints -----------------------------------------------------
head2 "6. Outbound network endpoints"
grep -rhoE 'https?://[a-zA-Z0-9._/-]+' "${SRC[@]}" "$DIR" 2>/dev/null \
  | sed -E 's#(https?://[^/]+).*#\1#' | sort | uniq -c | sort -rn | head -20 | sed 's/^/    /'
note "(review any non-obvious / raw-IP / pastebin / discord-webhook hosts)"
IP=$(grep -rnE 'https?://[0-9]{1,3}(\.[0-9]{1,3}){3}' "${SRC[@]}" "$DIR" 2>/dev/null | head)
[ -n "$IP" ] && { flag "hard-coded IP endpoints:"; printf '%s\n' "$IP" | sed 's/^/      /'; }
EX2=$(grep -rniE 'pastebin\.com|discord(app)?\.com/api/webhooks|ngrok\.io|telegram\.org/bot|raw\.githubusercontent' "${SRC[@]}" "$DIR" 2>/dev/null | head)
[ -n "$EX2" ] && { flag "known exfil-friendly hosts:"; printf '%s\n' "$EX2" | sed 's/^/      /'; }

# --- 7. CI / GitHub Actions ---------------------------------------------------
head2 "7. CI workflows"
if [ -d "$DIR/.github/workflows" ]; then
  UNPIN=$(grep -rnE 'uses:\s*[^@]+@(main|master|v?[0-9]+\s*$)' "$DIR/.github/workflows" 2>/dev/null | grep -vE '@v[0-9]+$' | head)
  [ -n "$UNPIN" ] && { flag "actions pinned to a moving ref (main/master):"; printf '%s\n' "$UNPIN" | sed 's/^/      /'; } || note "actions pinned to tags"
  CURLCI=$(grep -rnE 'curl|wget' "$DIR/.github/workflows" 2>/dev/null | head)
  [ -n "$CURLCI" ] && { note "downloads in CI (skim):"; printf '%s\n' "$CURLCI" | head -5 | sed 's/^/      /'; }
else note "no .github/workflows"; fi

# --- 8. Committed secrets -----------------------------------------------------
head2 "8. Committed secrets"
S=$(grep -rnE '(AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{36}|xox[baprs]-[A-Za-z0-9-]+|-----BEGIN (RSA|OPENSSH|EC) PRIVATE KEY-----)' \
    "$DIR" "${EX[@]}" 2>/dev/null | grep -vE 'example|sample|your_|placeholder|xxxx' | head)
[ -n "$S" ] && { flag "possible live secrets committed:"; printf '%s\n' "$S" | sed -E 's/(.{80}).*/\1.../' | sed 's/^/      /'; } || note "no live-looking secrets (placeholders ok)"

# --- Verdict ------------------------------------------------------------------
head2 "VERDICT"
if [ "$FINDINGS" -eq 0 ]; then
  echo "  CLEAN — no high-signal findings. Static heuristics only; still review deps + run in a sandbox first."
else
  echo "  $FINDINGS area(s) flagged for human review above. A flag is a 'look here', not proof of malice."
fi
[ -n "$CLEANUP" ] && echo "  (scratch clone left at: $CLEANUP — rm -rf when done)"
exit $([ "$FINDINGS" -eq 0 ] && echo 0 || echo 1)
