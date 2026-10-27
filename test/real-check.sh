#!/usr/bin/env bash
# Compare Ghidra's disassembly (language picked by the ELF opinion, no analysis) with JieLi's objdump at the oracle's own
# instruction addresses for every ELF in <workdir>/elf:  real-check.sh <workdir> <arch>
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
W=$(readlink -m "$1") ARCH=$2
: "${TC:?}" "${GHIDRA_INSTALL_DIR:?}"
mkdir -p "$W/cmp"
one() {
	local elf=$1 b
	b=$(basename "$elf" .elf)
	python3 "$HERE/oracle_elf.py" "$ARCH" "$elf" "$W/cmp/$b.or"
	cut -d' ' -f1 "$W/cmp/$b.or" > "$W/cmp/$b.addrs"
	"$HERE/ghidra-script.sh" auto-noanalysis - "$elf" DumpAt.java "$W/cmp/$b.addrs" "$W/cmp/$b.gh" > /dev/null
	python3 "$HERE/compare.py" --elf "$W/cmp/$b.gh" "$W/cmp/$b.or" --pairs "$W/cmp/$b.pairs" > "$W/cmp/$b.txt" || true
	echo "$b: $(wc -l < "$W/cmp/$b.or") instructions; $(grep -E '^(agree-shape|operands-differ|module-invalid|module-valid|length-differs|identical-shape)' "$W/cmp/$b.txt" | tr -s ' ' | tr '\n' ';')"
}
export -f one
export HERE W ARCH TC GHIDRA_INSTALL_DIR PROJ_DIR TMPDIR JAVA_HOME
ls "$W"/elf/*."$ARCH".*.elf | xargs -P "${JOBS:-4}" -I{} bash -c 'one {}'
