#!/usr/bin/env python3
"""Group the 'module invalid / oracle valid' and 'module valid / oracle invalid' words by oracle (resp. module) shape.
usage: classes.py <ghidra.txt> <oracle.txt> [N]"""
import collections, re, sys
sys.argv_save = sys.argv
exec(open(__file__.replace('classes.py', 'compare.py')).read().split("ap = argparse")[0])
G, O = load(sys.argv[1]), load(sys.argv[2])
a, b = collections.Counter(), collections.Counter()
ea, eb = {}, {}
for i in sorted(G):
    gl, gt = G[i]; ol, ot = O.get(i, (0, 'X'))
    if gl == 0 and ol > 0:
        k = split(ot, 0, False, ol)[0] + ' [len %d]' % ol; a[k] += 1; ea.setdefault(k, (i, ot))
    elif ol == 0 and gl > 0 and ot != 'CRASH':
        k = split(gt, i * 8, True)[0] + ' [len %d]' % gl; b[k] += 1; eb.setdefault(k, (i, gt))
print('== oracle valid, module invalid (%d shapes)' % len(a))
for k, v in sorted(a.items(), key=lambda x: -x[1]): print('%6d  %-50s e.g. %d %s' % (v, k, ea[k][0], ea[k][1]))
print('== module valid, oracle invalid (%d shapes)' % len(b))
for k, v in sorted(b.items(), key=lambda x: -x[1]): print('%6d  %-50s e.g. %d %s' % (v, k, eb[k][0], eb[k][1]))
