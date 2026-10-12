#!/usr/bin/env bash
# Installs RE tools (JDK, jadx, apktool) into ~/tools without sudo, plus a venv at the repo root. Idempotent.
# jadx and apktool are pinned (JADX_VERSION, APKTOOL_VERSION); the JDK is the latest 17 at run time. Record versions in targets/<slug>/LOG.md via `python tools/rw.py doctor`.
# Usage: scripts/setup-tools.sh [--full | --emulation]
#   default      JDK, jadx, apktool, and a venv with pytest, bleak, pillow; never needs a compiler
#   --emulation  also install the emulation extras (unicorn, capstone, pyelftools); a failed build is reported, not fatal
#   --full       same as --emulation
set -euo pipefail
EMU=0
# Pinned versions (override with the environment); a target SOURCES file may pin the same jadx version
JADX_VERSION="${JADX_VERSION:-1.5.6}"; APKTOOL_VERSION="${APKTOOL_VERSION:-3.0.3}"
for a in "$@"; do
  case "$a" in
    --full|--emulation) EMU=1 ;;
    -h|--help) sed -n 2,6p "$0"; exit 0 ;;
    *) echo "unknown option: $a" >&2; exit 2 ;;
  esac
done
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
T="$HOME/tools"; mkdir -p "$T"; cd "$T"
if [ ! -d "$T/jdk" ]; then
  curl -fL "https://api.adoptium.net/v3/binary/latest/17/ga/linux/x64/jdk/hotspot/normal/eclipse" -o jdk.tgz
  mkdir jdk && tar xzf jdk.tgz -C jdk --strip-components=1 && rm jdk.tgz
fi
export JAVA_HOME="$T/jdk" PATH="$T/jdk/bin:$PATH"
if [ ! -d "$T/jadx" ]; then
  V="$JADX_VERSION"
  curl -fL "https://github.com/skylot/jadx/releases/download/v$V/jadx-$V.zip" -o jadx.zip
  mkdir jadx && unzip -q jadx.zip -d jadx && rm jadx.zip
fi
if [ ! -f "$T/apktool/apktool.jar" ]; then
  mkdir -p apktool
  U="https://github.com/iBotPeaches/Apktool/releases/download/v$APKTOOL_VERSION/apktool_$APKTOOL_VERSION.jar"
  curl -fL "$U" -o apktool/apktool.jar
  printf '#!/usr/bin/env bash\nexec "%s/jdk/bin/java" -jar "%s/apktool/apktool.jar" "$@"\n' "$T" "$T" > apktool/apktool
  chmod +x apktool/apktool
fi
LINE='export JAVA_HOME="$HOME/tools/jdk"; export PATH="$JAVA_HOME/bin:$HOME/tools/jadx/bin:$HOME/tools/apktool:$PATH"'
grep -qF 'tools/jadx/bin' ~/.bashrc || echo "$LINE" >> ~/.bashrc
cd "$ROOT"
[ -d .venv ] || python3 -m venv .venv
.venv/bin/pip install -q pytest bleak pillow
if [ "$EMU" = 1 ]; then
  if .venv/bin/pip install -q unicorn capstone pyelftools; then echo "emulation extras installed"
  else echo "emulation extras could not be installed (no wheel or no build chain); core and test are fine, emulation tests will skip" >&2; fi
fi
command -v tshark >/dev/null || (apt-get install -y tshark 2>/dev/null || echo "tshark unavailable without root")
