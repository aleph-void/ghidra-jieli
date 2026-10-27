#!/usr/bin/env bash
# Decode a corpus of fixed-size slots with the module, in 64 KB pieces (the address space is 16 bits wide).
#   decode-corpus.sh <language-id> <corpus.bin> <out.txt> <slot-size> [Script.java] [script-args...]
# Output: "<slot> <length> <text>" per slot (slot numbers are global).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
LANG_ID=$1 CORPUS=$2 OUT=$3 SLOT=$4
SCRIPT=${5:-DumpSlots.java}
shift $(( $# > 5 ? 5 : $# ))
JOBS=${JOBS:-4}
D=$(mktemp -d "${TMPDIR:-/tmp}/decode-corpus.XXXXXX")
trap 'rm -rf "$D"' EXIT
PIECE=$((1048576 / SLOT * SLOT))
split -b "$PIECE" -d -a 4 "$CORPUS" "$D/p."
ls "$D"/p.* | xargs -P "$JOBS" -I{} bash -c '"$0/ghidra-script.sh" raw "$1" "$2" '"$SCRIPT"' "$2.out" '"$SLOT"' "${@:3}"' "$HERE" "$LANG_ID" {} "$@"
if [[ $SCRIPT == Reach.java ]]; then
	cat "$D"/p.????.out | sort -un > "$OUT"
	exit 0
fi
n=0
: > "$OUT"
for f in $(ls "$D"/p.????); do
	python3 - "$f.out" "$n" >> "$OUT" <<'PY'
import sys
off = int(sys.argv[2])
for l in open(sys.argv[1]):
    if l.startswith('    '):
        sys.stdout.write(l)
        continue
    i, rest = l.split(' ', 1)
    sys.stdout.write(f'{int(i) + off} {rest}')
PY
	n=$((n + PIECE / SLOT))
done
