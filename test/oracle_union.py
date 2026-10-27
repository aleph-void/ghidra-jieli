#!/usr/bin/env python3
"""Run oracle.py for several -mcpu values and merge: the -mcpu=r3 decode wins, a word it rejects takes the first other CPU's decode.
usage: oracle_union.py <arch> <corpus.bin> <out.txt> [slot=8] [cpu ...]   (pi32v2 only; the other archs have no -mcpu)"""
import os, subprocess, sys
arch, corpus, outp = sys.argv[1:4]
slot = sys.argv[4] if len(sys.argv) > 4 else '8'
cpus = sys.argv[5:] or ['r3', 'r1', 'r2', 'r4', 'r5', 'r2v3', 'r3v3', 'r4v3', 'r4v3s']
here = os.path.dirname(os.path.abspath(__file__))
merged = None
for cpu in cpus:
    tmp = '%s.%s' % (outp, cpu)
    env = dict(os.environ, OBJDUMP_ARGS='-mcpu=' + cpu)
    subprocess.run(['python3', here + '/oracle.py', arch, corpus, tmp, slot], check=True, env=env)
    lines = [l.rstrip('\n').split(' ', 2) for l in open(tmp)]
    os.remove(tmp)
    if merged is None:
        merged = lines
    else:
        for m, l in zip(merged, lines):
            if m[1] == '0' and l[1] != '0':
                m[1], m[2] = l[1], l[2]
with open(outp, 'w') as f:
    for m in merged:
        f.write(' '.join(m) + '\n')
