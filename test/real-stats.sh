#!/usr/bin/env bash
# Import every ELF of <workdir>/elf for <arch> (the ELF opinion picks the language), auto-analyse, decompile every function and
# report instructions / functions / bookmarks / decompile failures:  real-stats.sh <workdir> <arch>
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
W=$(readlink -m "$1") ARCH=$2
: "${GHIDRA_INSTALL_DIR:?}"
mkdir -p "$W/stats"
one() {
	local elf=$1 b
	b=$(basename "$elf" .elf)
	"$HERE/ghidra-script.sh" auto - "$elf" RealStats.java "$W/stats/$b.txt" > /dev/null 2>&1 || echo "$b: import failed"
	echo "$b: $(tail -1 "$W/stats/$b.txt")"
}
export -f one
export HERE W ARCH GHIDRA_INSTALL_DIR PROJ_DIR TMPDIR JAVA_HOME
ls "$W"/elf/*."$ARCH".*.elf | xargs -P "${JOBS:-4}" -I{} bash -c 'one {}'
