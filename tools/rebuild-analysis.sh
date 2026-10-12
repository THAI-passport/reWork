#!/usr/bin/env bash
# Rebuild a target's artifacts and decompiled tree from targets/<name>/SOURCES (or SOURCES.md). No sudo. Idempotent.
#
# Usage: tools/rebuild-analysis.sh <name> [options]
#   --local-file PATH   use this artifact instead of downloading it (hash is still verified)
#   --accept-new-hash   on a hash mismatch print the new hash and continue; never edits any file
#   --recover           after jadx, run tools/recover-failed-methods.sh (needs RECOVER_CLASS or --recover-class)
#   --recover-class C   fully qualified class for --recover (overrides RECOVER_CLASS)
#   --recover-dex D     dex name for --recover (overrides RECOVER_DEX, default classes.dex)
#   --force             redo every step; a tool version mismatch becomes a warning
#   --dry-run           print what would happen; no download, extraction or decompile
#   --root DIR          repository root (default: parent of tools/); used by tests
#   -h, --help          this text
# SOURCES fields (KEY=VALUE, one per line; in SOURCES.md only between <!-- rebuild:begin --> and <!-- rebuild:end -->):
#   required: NAME_FILE (artifact file name), SHA256, VERSION; URL unless --local-file is used
#   optional: KIND (apk, xapk or other; default apk), PACKAGE, INNER_APK + INNER_SHA256 (for xapk), ABI_APK + ABI_SHA256,
#             JADX_VERSION, JAVA_MAJOR, JADX_ARGS (default "-j 4"), RECOVER_CLASS, RECOVER_DEX
# Exit codes: 0 ok, 2 usage or SOURCES error, 3 hash mismatch, 4 missing tool or tool version, 5 step failed.
# Output (all git-ignored): targets/<name>/artifacts, work, decompiled, BUILD-INFO.txt.
set -euo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SELF_DIR/.." && pwd)"
TARGET="" LOCAL="" ACCEPT=0 RECOVER=0 FORCE=0 DRY=0 RCLASS="" RDEX=""

die() { echo "error: $2" >&2; exit "$1"; }
say() { echo "[rebuild] $*"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --local-file) [ $# -ge 2 ] || die 2 "--local-file needs a value"; LOCAL="$2"; shift 2 ;;
    --root) [ $# -ge 2 ] || die 2 "--root needs a value"; ROOT="$(cd "$2" && pwd)"; shift 2 ;;
    --recover-class) [ $# -ge 2 ] || die 2 "--recover-class needs a value"; RCLASS="$2"; shift 2 ;;
    --recover-dex) [ $# -ge 2 ] || die 2 "--recover-dex needs a value"; RDEX="$2"; shift 2 ;;
    --accept-new-hash) ACCEPT=1; shift ;;
    --recover) RECOVER=1; shift ;;
    --force) FORCE=1; shift ;;
    --dry-run) DRY=1; shift ;;
    -h|--help) sed -n 2,19p "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) die 2 "unknown option: $1 (try --help)" ;;
    *) [ -z "$TARGET" ] || die 2 "only one target name allowed (got '$TARGET' and '$1')"; TARGET="$1"; shift ;;
  esac
done
[ -n "$TARGET" ] || die 2 "target name required (try --help)"
[[ "$TARGET" =~ ^[a-z0-9][a-z0-9-]*$ ]] || die 2 "target name must be lowercase letters, digits and dashes: $TARGET"
[ -z "$LOCAL" ] || [ -f "$LOCAL" ] || die 2 "--local-file not found: $LOCAL"

T="$ROOT/targets/$TARGET"
[ -d "$T" ] || die 2 "no such target: targets/$TARGET (create it with: python tools/rw.py init $TARGET)"
SRC=""
for c in "$T/SOURCES" "$T/SOURCES.md"; do [ -f "$c" ] && { SRC="$c"; break; }; done
[ -n "$SRC" ] || die 2 "no SOURCES or SOURCES.md in targets/$TARGET"

# Parse KEY=VALUE lines without executing anything. If the file has rebuild markers, read only between them.
declare -A S
inblock=1; grep -q '<!-- rebuild:begin -->' "$SRC" && inblock=0
while IFS= read -r line || [ -n "$line" ]; do
  line="${line%$'\r'}"
  case "$line" in
    '<!-- rebuild:begin -->') inblock=1; continue ;;
    '<!-- rebuild:end -->') inblock=0; continue ;;
  esac
  [ "$inblock" = 1 ] || continue
  case "$line" in ''|'#'*|'```'*) continue ;; esac
  [[ "$line" =~ ^([A-Z0-9_]+)=(.*)$ ]] || die 2 "bad line in ${SRC#$ROOT/}: $line"
  S["${BASH_REMATCH[1]}"]="${BASH_REMATCH[2]}"
done < "$SRC"
for k in NAME_FILE SHA256 VERSION; do [ -n "${S[$k]:-}" ] || die 2 "${SRC#$ROOT/}: missing $k"; done
KIND="${S[KIND]:-apk}"
case "$KIND" in apk|xapk|other) ;; *) die 2 "KIND must be apk, xapk or other, got '$KIND'" ;; esac
if [ "$KIND" = xapk ]; then
  for k in INNER_APK INNER_SHA256; do [ -n "${S[$k]:-}" ] || die 2 "${SRC#$ROOT/}: KIND=xapk needs $k"; done
fi
for k in SHA256 INNER_SHA256 ABI_SHA256; do
  [ -z "${S[$k]:-}" ] || [[ "${S[$k]}" =~ ^[0-9a-f]{64}$ ]] || die 2 "${SRC#$ROOT/}: $k is not a lowercase 64-digit sha256"
done
[ -z "${S[ABI_APK]:-}" ] || [ -n "${S[ABI_SHA256]:-}" ] || die 2 "${SRC#$ROOT/}: ABI_APK needs ABI_SHA256"
case "${S[NAME_FILE]}${S[INNER_APK]:-}${S[ABI_APK]:-}" in */*|*..*) die 2 "file names in SOURCES must not contain / or .." ;; esac

ART="$T/artifacts/${S[NAME_FILE]}"; W="$T/work"; OUT="$T/decompiled"
JADX_ARGS="${S[JADX_ARGS]:--j 4}"

run() { if [ "$DRY" = 1 ]; then say "would run: $*"; else "$@"; fi; }
sha() { sha256sum "$1" | cut -d' ' -f1; }

# verify FILE EXPECTED LABEL: returns 0 on match (or accepted); exits 3 on mismatch
verify() {
  local got; got="$(sha "$1")"
  if [ "$got" = "$2" ]; then say "sha256 ok: $3"; return 0; fi
  echo "error: sha256 mismatch for $3" >&2
  echo "  expected: $2" >&2
  echo "  actual:   $got" >&2
  if [ "$ACCEPT" = 1 ]; then
    echo "  --accept-new-hash given: continuing. Record this hash yourself in SOURCES if it is the new reference; no file was edited." >&2
    return 0
  fi
  echo "  refusing to continue. If the source legitimately changed, inspect it, then re-run with --accept-new-hash." >&2
  exit 3
}

say "target $TARGET ${S[VERSION]} (${KIND})"
[ "$DRY" = 1 ] && say "dry run: nothing will be written"

# 1. acquire
if [ -n "$LOCAL" ]; then
  FILE="$LOCAL"; say "using local file $LOCAL"
elif [ -f "$ART" ] && [ "$FORCE" = 0 ]; then
  FILE="$ART"; say "artifact already present: targets/$TARGET/artifacts/${S[NAME_FILE]}"
else
  [ -n "${S[URL]:-}" ] || die 2 "${SRC#$ROOT/}: no URL and artifact not present (add URL or pass --local-file)"
  command -v curl >/dev/null || die 4 "curl is required to download (or pass --local-file)"
  say "download ${S[URL]}"
  run mkdir -p "$T/artifacts"
  run curl -fL --retry 3 -o "$ART.part" "${S[URL]}" || die 5 "download failed"
  [ "$DRY" = 1 ] || mv "$ART.part" "$ART"
  FILE="$ART"
fi
if [ -f "$FILE" ]; then
  verify "$FILE" "${S[SHA256]}" "artifact"
  if [ ! "$FILE" -ef "$ART" ] && [ "$DRY" = 0 ]; then mkdir -p "$T/artifacts"; cp -f "$FILE" "$ART"; fi
elif [ "$DRY" = 1 ]; then say "(artifact not present yet; hash would be checked after download)"
fi

# 2. extract (xapk only) and pick the APK to decompile
BASE=""
if [ "$KIND" = xapk ]; then
  BASE="$W/${S[INNER_APK]}"
  ok=0
  if [ "$FORCE" = 0 ] && [ -f "$BASE" ] && [ "$(sha "$BASE")" = "${S[INNER_SHA256]}" ]; then
    if [ -z "${S[ABI_APK]:-}" ] || { [ -f "$W/${S[ABI_APK]}" ] && [ "$(sha "$W/${S[ABI_APK]}")" = "${S[ABI_SHA256]}" ]; }; then ok=1; fi
  fi
  if [ "$ok" = 1 ]; then say "extracted APKs already present and verified"
  else
    command -v unzip >/dev/null || die 4 "unzip is required"
    [ "$DRY" = 1 ] || [ -f "$FILE" ] || die 5 "artifact missing"
    members=("${S[INNER_APK]}"); [ -z "${S[ABI_APK]:-}" ] || members+=("${S[ABI_APK]}")
    say "extract ${members[*]} into targets/$TARGET/work"
    run mkdir -p "$W"
    run unzip -oq -j "$FILE" "${members[@]}" -d "$W" || die 5 "could not extract ${members[*]} from the archive"
    if [ "$DRY" = 0 ]; then
      verify "$BASE" "${S[INNER_SHA256]}" "inner base APK"
      [ -z "${S[ABI_APK]:-}" ] || verify "$W/${S[ABI_APK]}" "${S[ABI_SHA256]}" "ABI split"
    fi
  fi
  BASE_SHA="${S[INNER_SHA256]}"
elif [ "$KIND" = apk ]; then
  BASE="$FILE"; BASE_SHA="${S[SHA256]}"
else
  BASE_SHA="${S[SHA256]}"; say "KIND=other: download and verify only, no decompile"
fi

# 3. tools and jadx (only for apk kinds)
JADX_V="" JAVA_V=""
if [ "$KIND" != other ]; then
  export JAVA_HOME="${JAVA_HOME:-$HOME/tools/jdk}"; export PATH="$JAVA_HOME/bin:$HOME/tools/jadx/bin:$PATH"
  tool_problem() { if [ "$FORCE" = 1 ]; then echo "warning: $1" >&2; else die 4 "$1 (re-run with --force to accept, or fix with tools/setup-tools.sh)"; fi; }
  if [ "$DRY" = 0 ]; then
    command -v java >/dev/null || die 4 "java not found; run tools/setup-tools.sh"
    command -v jadx >/dev/null || die 4 "jadx not found; run tools/setup-tools.sh"
    JADX_V="$(jadx --version 2>/dev/null | head -1 | tr -d '\r' || true)"
    JAVA_V="$(java -version 2>&1 | head -1 || true)"
    [ -z "${S[JADX_VERSION]:-}" ] || [ "$JADX_V" = "${S[JADX_VERSION]}" ] || tool_problem "jadx version is '$JADX_V', SOURCES pins ${S[JADX_VERSION]}"
    [ -z "${S[JAVA_MAJOR]:-}" ] || [[ "$JAVA_V" == *"\"${S[JAVA_MAJOR]}"* ]] || tool_problem "java is '$JAVA_V', SOURCES pins major ${S[JAVA_MAJOR]}"
  else
    say "tool check skipped in dry run (pins: jadx ${S[JADX_VERSION]:-any}, java ${S[JAVA_MAJOR]:-any})"
  fi

  # exit 0 and 3 are both usable (3 = some methods failed to decompile)
  MARK="$W/jadx.done"
  if [ "$FORCE" = 0 ] && [ -d "$OUT" ] && [ -f "$MARK" ] && grep -q "base_sha256=$BASE_SHA" "$MARK" 2>/dev/null \
     && grep -qE '^exit=(0|3) ' "$MARK"; then
    say "decompiled tree already built for this APK (use --force to redo)"
  else
    say "jadx $JADX_ARGS -> targets/$TARGET/decompiled"
    if [ "$DRY" = 1 ]; then say "would run: jadx $JADX_ARGS -d $OUT $BASE"
    else
      mkdir -p "$OUT" "$W"; start=$(date +%s); rc=0
      # shellcheck disable=SC2086
      jadx $JADX_ARGS -d "$OUT" "$BASE" > "$W/jadx.log" 2>&1 || rc=$?
      echo "exit=$rc seconds=$(( $(date +%s) - start )) base_sha256=$BASE_SHA" > "$MARK"
      case "$rc" in 0|3) say "jadx finished (exit $rc)" ;; *) die 5 "jadx failed with exit $rc, see targets/$TARGET/work/jadx.log" ;; esac
    fi
  fi

  # 4. optional recovery
  if [ "$RECOVER" = 1 ]; then
    RC="${RCLASS:-${S[RECOVER_CLASS]:-}}"; RD="${RDEX:-${S[RECOVER_DEX]:-classes.dex}}"
    [ -n "$RC" ] || die 2 "--recover needs RECOVER_CLASS in SOURCES or --recover-class"
    say "CFR recovery of $RC from $RD"
    run bash "$SELF_DIR/recover-failed-methods.sh" "$BASE" "$RD" "$RC" "$W/recover" || die 5 "recovery script failed"
  fi
fi

# 5. build info
if [ "$DRY" = 0 ]; then
  {
    echo "built_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "target=$TARGET"; echo "version=${S[VERSION]}"; echo "kind=$KIND"
    echo "artifact_sha256=$(sha "$FILE")"
    [ -z "$BASE" ] || [ ! -f "$BASE" ] || echo "base_apk_sha256=$(sha "$BASE")"
    echo "accepted_new_hash=$ACCEPT"; echo "recover=$RECOVER"
    echo "jadx=$JADX_V"; echo "java=$JAVA_V"; echo "jadx_args=$JADX_ARGS"
    echo "host=$(uname -sm)"
  } > "$T/BUILD-INFO.txt"
  say "wrote targets/$TARGET/BUILD-INFO.txt"
fi
say "done"
