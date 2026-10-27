#!/usr/bin/env python3
"""Summarise the non-agreeing slots of compare.py by (module shape, oracle shape): diffsum.py <ghidra.txt> <oracle.txt> [top=40]"""
import collections, re, subprocess, sys, os
here = os.path.dirname(os.path.abspath(__file__))
out = subprocess.run([sys.executable, here + '/compare.py', sys.argv[1], sys.argv[2], '--show', '100000000'], capture_output=True, text=True).stdout
top = int(sys.argv[3]) if len(sys.argv) > 3 else 40
sect = None
cnt = collections.Counter(); ex = {}
def norm(t):
    t = re.sub(r'<[^>]*>', '<T>', t)
    t = re.sub(r'\b(r\d+|sp)\b', 'R', t)
    t = re.sub(r'\b(sfr|sr)\d+\b', 'S', t)
    t = re.sub(r'-?0x[0-9a-fA-F]+|-?\b\d+\b', '#', t)
    t = re.sub(r'\{[^{}]*\}', '{L}', t)
    return t
for l in out.splitlines():
    if l.startswith('-- '):
        sect = l[3:]; continue
    m = re.match(r'\s+(\d+)\s+x(\d+)\s+\[(.*)\]\s+<>\s+\[(.*)\]\s*$', l)
    if m and sect:
        k = (sect, norm(m.group(3)), norm(m.group(4)))
        cnt[k] += int(m.group(2)); ex.setdefault(k, (m.group(1), m.group(3), m.group(4)))
for k, v in cnt.most_common(top):
    print('%6d %-26s %-34s <> %-40s e.g. %s' % (v, k[0], k[1], k[2], ex[k]))
print(len(cnt), 'classes')
