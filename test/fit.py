#!/usr/bin/env python3
"""Show how JieLi's objdump reads an instruction when each bit is flipped (field-layout discovery).
usage: fit.py <arch> <hex bytes, memory order>   e.g. fit.py q32s 80f30000"""
import os, re, subprocess, sys, tempfile
arch, hexs = sys.argv[1], sys.argv[2]
TC = os.environ['TC']
base = bytes.fromhex(hexs)
variants = [('base', base)]
for i in range(len(base) * 8):
    b = bytearray(base)
    b[i // 8] ^= 1 << (i % 8)
    variants.append(('byte%d.bit%d' % (i // 8, i % 8), bytes(b)))
d = tempfile.mkdtemp()
with open(d + '/a.s', 'w') as f:
    for k, (n, v) in enumerate(variants):
        f.write('.section s%d,"ax"\n.byte %s\n.byte 0,0,0,0,0,0\n' % (k, ','.join(map(str, v))))
subprocess.run([TC + '/' + arch + '/bin/clang', '-target', arch, '-c', d + '/a.s', '-o', d + '/a.o'], check=True)
txt = subprocess.run([TC + '/' + arch + '/bin/objdump', '-d', d + '/a.o'], capture_output=True, text=True).stdout
cur, res = None, {}
for l in txt.splitlines():
    m = re.match(r'Disassembly of section s(\d+):', l)
    if m: cur = int(m.group(1)); continue
    m = re.match(r'^\s*0:\s+((?:[0-9a-f]{2}\s)+)\s*(.*)$', l)
    if m and cur is not None and cur not in res:
        res[cur] = (len(m.group(1).split()), re.sub(r'\s+', ' ', m.group(2).strip()))
for k, (n, v) in enumerate(variants):
    ln, t = res.get(k, (0, '?'))
    print('%-14s %s len=%d  %s' % (n, v.hex(), ln, t))
