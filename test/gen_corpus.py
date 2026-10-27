#!/usr/bin/env python3
"""Corpus of 8-byte slots: every 16-bit first word x TAILS tails (fixed patterns + random), plus RANDOM fully random slots.
usage: gen_corpus.py out.bin [tails=12] [random=200000] [seed=1]"""
import random, struct, sys
out = sys.argv[1]
tails = int(sys.argv[2]) if len(sys.argv) > 2 else 12
nrand = int(sys.argv[3]) if len(sys.argv) > 3 else 200000
rnd = random.Random(int(sys.argv[4]) if len(sys.argv) > 4 else 1)
fixed = [b'\0' * 6, b'\xff' * 6, b'\x55\xaa\xaa\x55\x55\xaa', b'\xaa\x55\x55\xaa\xaa\x55']
with open(out, 'wb') as f:
    for w in range(65536):
        ts = list(fixed)
        while len(ts) < tails:
            ts.append(bytes(rnd.randrange(256) for _ in range(6)))
        for t in ts[:tails]:
            f.write(struct.pack('<H', w) + t)
    for _ in range(nrand):
        f.write(bytes(rnd.randrange(256) for _ in range(8)))
