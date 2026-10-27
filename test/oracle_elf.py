#!/usr/bin/env python3
"""objdump -d of a linked ELF -> "<hex addr> <len> <text>" lines (instructions only), usage: oracle_elf.py <arch> <elf> <out> [mattr]"""
import os, re, subprocess, sys
arch, elf, out = sys.argv[1:4]
TC = os.environ['TC']
cmd = [TC + '/' + arch + '/bin/objdump', '-d', elf]
cmd[1:1] = [x for x in os.environ.get('OBJDUMP_ARGS', '').split() if x]
txt = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
ln = re.compile(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s)+)\s*(.*)$')
with open(out, 'w') as f:
    for l in txt.splitlines():
        m = ln.match(l)
        if not m: continue
        t = m.group(3).strip()
        n = len(m.group(2).split())
        if re.match(r'<\s*-?\d+ : 0x', t):      # a jump-table entry: data, not an instruction
            f.write('%s %d DATA\n' % (m.group(1), n))
            continue
        f.write('%s %d %s\n' % (m.group(1), 0 if t.startswith('<unk') else n, 'BAD' if t.startswith('<unk') else re.sub(r'\s+', ' ', t)))
