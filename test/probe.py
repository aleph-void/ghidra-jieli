#!/usr/bin/env python3
"""Decode byte strings with JieLi's objdump and with the module side by side.  usage: probe.py <arch> <hex> [<hex> ...]"""
import os, subprocess, sys
arch = sys.argv[1]
here = os.path.dirname(os.path.abspath(__file__))
w = os.environ.get('PROJ_DIR', '/tmp') + '/probe'
os.makedirs(w, exist_ok=True)
data = b''
for h in sys.argv[2:]:
    b = bytes.fromhex(h)
    data += b + bytes(8 - len(b))
open(w + '/p.bin', 'wb').write(data)
subprocess.run(['python3', here + '/oracle.py', arch, w + '/p.bin', w + '/p.or', '8'], check=True)
subprocess.run([here + '/decode-corpus.sh', arch + ':LE:32:default', w + '/p.bin', w + '/p.gh', '8'], check=True, capture_output=True)
o = [l.rstrip('\n').split(' ', 2) for l in open(w + '/p.or')]
g = [l.rstrip('\n').split(' ', 2) for l in open(w + '/p.gh')]
for h, a, b in zip(sys.argv[2:], o, g):
    print('%-14s oracle: %-44s module: %s' % (h, a[2], b[2]))
