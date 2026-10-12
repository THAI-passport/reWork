#!/usr/bin/env bash
# Recover methods jadx's default mode fails on: re-run jadx in simple mode, then dex2jar + CFR for one class.
# Usage: tools/recover-failed-methods.sh <base.apk> <dex name, e.g. classes2.dex> <fully.qualified.Class> [outdir]
# Output goes to outdir (default: ./recover-out). Keep it under targets/<slug>/work (git-ignored).
set -euo pipefail
APK="${1:?base apk}"; DEX="${2:?dex name}"; CLASS="${3:?class name}"; W="${4:-recover-out}"
export JAVA_HOME="${JAVA_HOME:-$HOME/tools/jdk}"; export PATH="$JAVA_HOME/bin:$HOME/tools/jadx/bin:$PATH"
mkdir -p "$W"
jadx -m simple --show-bad-code -j 4 -d "$W/jadx-simple" --no-res --log-level ERROR "$APK" || true
mkdir -p "$HOME/tools/cfr"; (cd "$HOME/tools/cfr"
  [ -f cfr.jar ] || curl -fsSL -o cfr.jar https://repo1.maven.org/maven2/org/benf/cfr/0.152/cfr-0.152.jar
  [ -d dex-tools-v2.4 ] || { curl -fsSL -o d2j.zip https://github.com/pxb1988/dex2jar/releases/download/v2.4/dex-tools-v2.4.zip && unzip -qo d2j.zip; })
unzip -p "$APK" "$DEX" > "$W/cls.dex"
"$HOME/tools/cfr/dex-tools-v2.4/d2j-dex2jar.sh" "$W/cls.dex" -o "$W/cls.jar" --force
java -jar "$HOME/tools/cfr/cfr.jar" "$W/cls.jar" --jarfilter "$CLASS" --outputdir "$W/cfr-out"
echo "CFR output under $W/cfr-out"
