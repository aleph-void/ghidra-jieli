#!/usr/bin/env bash
# Build freely licensed C projects with JieLi's own clang (a black box, not redistributed) into linked ELF files, one per
# project, architecture and optimisation level:  real-build.sh <workdir> <arch pi32|pi32v2|q32s> [extra clang flags]
#   projects: lz4 1.9.4 (BSD-2), cJSON 1.7.18 (MIT), miniz 3.0.2 (MIT), Lua 5.4.7 core (MIT)
# Sources are fetched by pinned URL + SHA-256 into <workdir>/src.  TC = the unpacked JieLi toolchain.
set -euo pipefail
export LC_ALL=C
W=$(readlink -m "$1") ARCH=$2
shift 2
: "${TC:?set TC to the unpacked JieLi toolchain (jieli-linux-toolchains-20260730.1)}"
mkdir -p "$W/src" "$W/elf"
fetch() { # name url sha256
	[[ -f $W/src/$1.tar.gz ]] || curl -sL -o "$W/src/$1.tar.gz" "$2"
	echo "$3  $W/src/$1.tar.gz" | sha256sum -c --quiet
	[[ -d $W/src/$1 ]] || { mkdir -p "$W/src/$1"; tar xf "$W/src/$1.tar.gz" -C "$W/src/$1" --strip-components=1; }
}
fetch lz4 https://github.com/lz4/lz4/archive/refs/tags/v1.9.4.tar.gz 0b0e3aa07c8c063ddf40b082bdf7e37a1562bda40a0ff5272957f3e987e0e54b
fetch cjson https://github.com/DaveGamble/cJSON/archive/refs/tags/v1.7.18.tar.gz 3aa806844a03442c00769b83e99970be70fbef03735ff898f4811dd03b9f5ee5
fetch miniz https://github.com/richgel999/miniz/archive/refs/tags/3.0.2.tar.gz c4b4c25a4eb81883448ff8924e6dba95c800094a198dc9ce66a292ac2ef8e018
fetch lua https://www.lua.org/ftp/lua-5.4.7.tar.gz 9fbf5e28ef86c69858f6d3d34eccc32e911c1a28b4120ff3e84aaa70cfbf1e30
mkdir -p "$W/stub"; echo "#define MINIZ_EXPORT" > "$W/stub/miniz_export.h"
CC=("$TC/$ARCH/bin/clang" -I"$W/stub" -target "$ARCH" -w -ffreestanding -I"$TC/$ARCH/include" "$@")
LD="$TC/$ARCH/bin/ld"
build() { # project files...
	local proj=$1; shift
	for opt in O0 O2 Os; do
		local objs=()
		for f in "$@"; do
			local o="$W/elf/$proj.$ARCH.$opt.$(basename "$f" .c).o"
			"${CC[@]}" -$opt -DLUA_USE_C89 -c "$f" -o "$o" 2>/dev/null || continue
			objs+=("$o")
		done
		# external functions (libc) become one-instruction stubs so that calls resolve inside the image
		local stub="$W/elf/$proj.$ARCH.$opt.stub"
		"$TC/$ARCH/bin/nm" -u "${objs[@]}" 2>/dev/null | awk '$1=="U"{print $2}' | sort -u > "$stub.u"
		"$TC/$ARCH/bin/nm" --defined-only "${objs[@]}" 2>/dev/null | awk 'NF==3{print $3}' | sort -u > "$stub.d"
		{ echo ".text"; comm -23 "$stub.u" "$stub.d" | while read -r s; do printf '.globl %s\n%s:\n rts\n' "$s" "$s"; done; } > "$stub.S"
		"${CC[@]}" -c "$stub.S" -o "$stub.o" 2>/dev/null && objs+=("$stub.o")
		"$LD" --unresolved-symbols=ignore-all -e 0 -o "$W/elf/$proj.$ARCH.$opt.elf" "${objs[@]}" 2>/dev/null || echo "link failed: $proj $opt" >&2
		rm -f "$stub.S" "$stub.o" "$stub.u" "$stub.d"
		rm -f "${objs[@]}"
	done
}
build lz4 "$W/src/lz4/lib/lz4.c" "$W/src/lz4/lib/lz4hc.c" "$W/src/lz4/lib/lz4frame.c" "$W/src/lz4/lib/xxhash.c"
build cjson "$W/src/cjson/cJSON.c" "$W/src/cjson/cJSON_Utils.c"
build miniz "$W/src/miniz/miniz.c" "$W/src/miniz/miniz_tdef.c" "$W/src/miniz/miniz_tinfl.c" "$W/src/miniz/miniz_zip.c"
build lua $(ls "$W"/src/lua/src/*.c | grep -v -E '/(lua|luac)\.c$')
ls "$W/elf"/*.$ARCH.*.elf
