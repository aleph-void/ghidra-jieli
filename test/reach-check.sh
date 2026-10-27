#!/usr/bin/env bash
# Every-constructor check: decode a corpus and report the SLEIGH source lines of the constructors that appear in the parse trees,
# against the constructor lines of the language's .slaspec/.sinc files.   reach-check.sh <lang-id> <corpus.bin> <workdir> <slaspec>
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
LANG_ID=$1 CORPUS=$2 W=$3 SLASPEC=$4
"$HERE/decode-corpus.sh" "$LANG_ID" "$CORPUS" "$W/reach.txt" 8 Reach.java > /dev/null
python3 "$HERE/reach_check.py" "$SLASPEC" "$W/reach.txt"
