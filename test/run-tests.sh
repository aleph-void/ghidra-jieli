#!/usr/bin/env bash
# JieLi module tests.  Without arguments: everything that needs no third-party input:
#   1. the generators reproduce the checked-in SLEIGH (pi32v2: tools/pi32v2.toml; pi32, q32s: tools/*.forms.json)
#   2. the specs compile and load (Ghidra headless, all three languages)
#   3. p-code emulator cases (test/emu/*.cases: hand-computed expectations, one deliberately wrong one must be reported)
#   4. every constructor is reached by a decode corpus built from the tables
# With --real <workdir> it also downloads JieLi's public toolchain (pinned URL + SHA-256, run only as a black box) and
#   5. compares the decoding of every language with JieLi's objdump on random + structured corpora
#   6. builds freely licensed C projects (lz4, cJSON, miniz, Lua: pinned URLs + SHA-256) with that toolchain and imports them
#      (decode compare at objdump's addresses; instructions, functions, bookmarks and decompiler failures)
#
#   GHIDRA_INSTALL_DIR=/path/to/ghidra test/run-tests.sh [--real <workdir>]
#   GHIDRA_INSTALL_DIR must have Ghidra/Processors/JieLi pointing at this directory (a symlink is enough).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
MOD=$(cd "$HERE/.." && pwd)
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
REAL=
if [[ ${1:-} == --real ]]; then REAL=$(readlink -m "${2:?--real needs a work directory}"); fi
W=${REAL:-$(mktemp -d "${TMPDIR:-/tmp}/jieli-tests.XXXXXX")}
mkdir -p "$W"
export TMPDIR=$W PROJ_DIR=$W
fail=0
ok() { echo "   ok: $*"; }
bad() { echo "   FAILED: $*"; fail=1; }

echo "== 1. generators reproduce the checked-in SLEIGH"
python3 "$MOD/tools/gen_pi32v2.py" "$MOD/tools/pi32v2.toml" "$W/pi32v2_gen.sinc" > /dev/null
cmp -s "$W/pi32v2_gen.sinc" "$MOD/data/languages/pi32v2_gen.sinc" && ok pi32v2 || bad pi32v2
for a in pi32 q32s; do
	python3 "$MOD/tools/gen_jl.py" $a "$MOD/tools/$a.forms.json" "$W/${a}_gen.sinc" > /dev/null
	cmp -s "$W/${a}_gen.sinc" "$MOD/data/languages/${a}_gen.sinc" && ok $a || bad $a
done
cmp -s "$W/pi32_rep.sinc" "$MOD/data/languages/pi32_rep.sinc" && ok pi32_rep || bad pi32_rep

echo "== 2. the specs compile and load"
for a in pi32 pi32v2 q32s; do
	head -c 64 /dev/zero > "$W/zero.bin"
	if BASE_ADDR=0 "$HERE/ghidra-script.sh" raw $a:LE:32:default "$W/zero.bin" Reach.java "$W/zero.reach" 8 > /dev/null 2>&1; then ok $a; else bad "$a does not load"; fi
done

echo "== 3. p-code emulator cases"
for a in pi32v2 pi32 q32s; do
	python3 "$HERE/emu_build.py" "$HERE/emu/$a.cases" "$W/emu_$a" > /dev/null
	BASE_ADDR=0 "$HERE/ghidra-script.sh" raw $a:LE:32:default "$W/emu_$a/emu.bin" EmuCheck.java "$W/emu_$a/tests.txt" "$W/emu_$a/out.txt" > /dev/null 2>&1 || true
	last=$(tail -1 "$W/emu_$a/out.txt")
	echo "   $a: $last"
	grep -q ", 0 failed, 1 broken" <<< "$last" || { bad "$a emulator cases"; grep FAIL "$W/emu_$a/out.txt" || true; }
done

echo "== 4. every constructor is reached"
python3 "$HERE/gen_corpus.py" "$W/rand.bin" 2 20000 3 > /dev/null
python3 "$MOD/tools/gen_table_corpus.py" "$W/pi32v2.tab.bin" 1 24 > /dev/null
for a in pi32 q32s; do python3 "$MOD/tools/gen_forms_corpus.py" "$MOD/tools/$a.forms.json" "$W/$a.tab.bin" 1 16 > /dev/null; done
for a in pi32 q32s pi32v2; do
	cat "$W/rand.bin" "$W/$a.tab.bin" > "$W/$a.reach.bin"
	"$HERE/decode-corpus.sh" $a:LE:32:default "$W/$a.reach.bin" "$W/$a.reach.txt" 8 Reach.java > /dev/null 2>&1
	if out=$(python3 "$HERE/reach_check.py" "$MOD/data/languages/${a}_gen.sinc" "$W/$a.reach.txt"); then echo "   $a:${out#   }"; else echo "$out" | head -5; bad "$a: constructors not reached"; fi
done

if [[ -n $REAL ]]; then
	echo "== 5. decode compared with JieLi's objdump"
	eval "$("$HERE/fetch-toolchain.sh" "$W/tc")"
	export TC
	python3 "$HERE/gen_corpus.py" "$W/c.bin" 12 200000 7 > /dev/null
	for a in pi32 q32s pi32v2; do
		if [[ $a == pi32v2 ]]; then python3 "$HERE/oracle_union.py" $a "$W/c.bin" "$W/$a.or" 8 r3 r2v3 r3v3
		else python3 "$HERE/oracle.py" $a "$W/c.bin" "$W/$a.or" 8; fi
		"$HERE/decode-corpus.sh" $a:LE:32:default "$W/c.bin" "$W/$a.gh" 8 > /dev/null 2>&1
		SP_R15=$([[ $a == pi32 ]] && echo 1 || true) python3 "$HERE/compare.py" "$W/$a.gh" "$W/$a.or" --pairs "$W/$a.pairs" > "$W/$a.cmp.txt"
		echo "   $a: $(head -12 "$W/$a.cmp.txt" | tr -s ' ' | tr '\n' ';')"
	done
	echo "   (the explained classes are listed in GHIDRA-RARE.md; check '$W/*.cmp.txt' for anything else)"
	echo "== 6. real code"
	for a in pi32 q32s pi32v2; do
		"$HERE/real-build.sh" "$W/real" $a > /dev/null
		"$HERE/real-check.sh" "$W/real" $a
		"$HERE/real-stats.sh" "$W/real" $a
	done
fi
[[ $fail == 0 ]] && echo "ALL TESTS PASSED" || { echo "SOME TESTS FAILED"; exit 1; }
