#!/usr/bin/env python3
"""Corpus of 8-byte slots from tools/<arch>.forms.json: for every instruction form and every operand token, every value of the
token's bits (at most 4096, sampled above that) with the other free bits random, plus random fillings of the whole form.
usage: gen_forms_corpus.py <forms.json> <out.bin> [seed=1] [fillings=16]"""
import json, random, struct, sys
d = json.load(open(sys.argv[1]))
out = sys.argv[2]
rnd = random.Random(int(sys.argv[3]) if len(sys.argv) > 3 else 1)
NFILL = int(sys.argv[4]) if len(sys.argv) > 4 else 16
words = []
for f in d['forms']:
    n, mask, val = f['n'], f['mask'], f['val']
    full = (1 << (8 * n)) - 1
    def fill():
        return (rnd.getrandbits(8 * n) & full & ~mask) | val
    for _ in range(NFILL):
        words.append((fill(), n))
    for t in f['tokens']:
        bits = t['bits']
        if not bits or len(bits) > 24:
            continue
        combos = list(range(1 << len(bits))) if len(bits) <= 12 else [rnd.getrandbits(len(bits)) for _ in range(4096)]
        # register lists: every single bit alone and every prefix of set bits (the "highest set bit" alternatives)
        combos += [1 << i for i in range(len(bits))] + [(1 << (i + 1)) - 1 for i in range(len(bits))]
        if t['fit']['type'] == 'sel':
            for sb in t['fit']['bits']:
                combos += [(1 << i) | (1 << bits.index(sb)) for i in range(len(bits)) if sb in bits]
        for combo in combos:
            w = fill()
            for i, b in enumerate(bits):
                w = (w & ~(1 << b)) | (((combo >> i) & 1) << b)
            words.append((w, n))
with open(out, 'wb') as fh:
    for w, n in words:
        fh.write((w & ((1 << (8 * n)) - 1)).to_bytes(n, 'little').ljust(8, b'\0'))
print(len(words), 'slots')
