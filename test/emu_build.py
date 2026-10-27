#!/usr/bin/env python3
"""Build emu.bin and tests.txt from a committed test/emu/<arch>.cases file (no toolchain needed).
usage: emu_build.py <arch.cases> <outdir>"""
import os, sys
cases, out = sys.argv[1:3]
os.makedirs(out, exist_ok=True)
img = bytearray(0x100000)
lines = []
k = 0
for l in open(cases):
    if l.startswith('#') or not l.strip():
        continue
    name, asm, code, init, expect = l.rstrip('\n').split('\t')
    code = bytes.fromhex(code)
    base = 0x1000 * (k + 1) + 0x10000
    k += 1
    img[base:base + len(code)] = code
    lines.append('%s %x %x %s %s' % (name, base, base + len(code) - 2, init, expect))
open(out + '/emu.bin', 'wb').write(bytes(img))
open(out + '/tests.txt', 'w').write('\n'.join(lines) + '\n')
print(len(lines), 'cases')
