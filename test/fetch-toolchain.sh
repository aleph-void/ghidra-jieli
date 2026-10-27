#!/usr/bin/env bash
# Download JieLi's public Linux toolchain (the reference "oracle": clang as assembler, objdump as disassembler) into <dir>, check
# its SHA-256 and unpack it.  It is only run as a black box (bytes in, text out); nothing of it is committed or redistributed.
#   test/fetch-toolchain.sh <dir>      then:  export TC=<dir>/jieli-linux-toolchains-20260730.1
set -euo pipefail
DIR=$(readlink -m "${1:?usage: fetch-toolchain.sh <dir>}")
REL=20260730.1
SHA=a1545cddbc451a06bac43eb5cd96d831470c42a97c5c0b1f98879a20fc7647bd
URL=https://jl-update.oss-cn-shenzhen.aliyuncs.com/jieli-linux-toolchains-$REL.tar.xz
mkdir -p "$DIR"
[[ -f $DIR/tc.tar.xz ]] || curl -sL -o "$DIR/tc.tar.xz" "$URL"
echo "$SHA  $DIR/tc.tar.xz" | sha256sum -c --quiet
[[ -d $DIR/jieli-linux-toolchains-$REL ]] || tar xf "$DIR/tc.tar.xz" -C "$DIR"
echo "export TC=$DIR/jieli-linux-toolchains-$REL"
