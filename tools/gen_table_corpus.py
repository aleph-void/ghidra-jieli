#!/usr/bin/env python3
"""Corpus of 8-byte slots built from tools/pi32v2.toml: for every instruction form (including the parallel twins), every value of
each enum / small-set field in turn (others random), plus random operand fillings and the '-' bits set both ways.
usage: gen_table_corpus.py out.bin [seed=1] [random fillings per form=24]"""
import random, struct, sys, os, tomllib
HERE = os.path.dirname(os.path.abspath(__file__))
out = sys.argv[1]
rnd = random.Random(int(sys.argv[2]) if len(sys.argv) > 2 else 1)
NFILL = int(sys.argv[3]) if len(sys.argv) > 3 else 24
d = tomllib.load(open(os.path.join(HERE, 'pi32v2.toml'), 'rb'))

def letters_bits(enc):
    m = {}
    for wi, w in enumerate(enc):
        for bi, ch in enumerate(w):
            if ch not in '01-':
                m.setdefault(ch, []).append(16 * wi + 15 - bi)
    return m

def build(enc, assign, dash):
    v = 0
    for wi, w in enumerate(enc):
        for bi, ch in enumerate(w):
            bit = 16 * wi + 15 - bi
            if ch == '1': v |= 1 << bit
            elif ch == '-' and dash(): v |= 1 << bit
            elif ch in assign and (assign[ch] >> assign['_pos'][bit]) & 1: v |= 1 << bit
    return v

words = []
for e in d['insn']:
    enc = e['encoding']
    lb = letters_bits(enc)
    nbits = 16 * len(enc)
    def emit(vals):
        # vals: dict letter -> integer value spread over that letter's bits (msb first)
        v = 0
        for wi, w in enumerate(enc):
            for bi, ch in enumerate(w):
                if ch == '1': v |= 1 << (16 * wi + 15 - bi)
        for ch, bits in lb.items():
            x = vals[ch]
            n = len(bits)
            for k, b in enumerate(bits):
                if (x >> (n - 1 - k)) & 1: v |= 1 << b
        for wi, w in enumerate(enc):
            for bi, ch in enumerate(w):
                if ch == '-' and rnd.random() < 0.5: v |= 1 << (16 * wi + 15 - bi)
        words.append((v, len(enc)))
    def rand_vals(): return {ch: rnd.getrandbits(len(b)) for ch, b in lb.items()}
    # each letter group of width <= 5: every value in turn
    for ch, bits in lb.items():
        if len(bits) <= 5:
            for x in range(1 << len(bits)):
                vv = rand_vals(); vv[ch] = x; emit(vv)
        else:
            for x in (0, (1 << len(bits)) - 1, 1, 1 << (len(bits) - 1)):
                vv = rand_vals(); vv[ch] = x; emit(vv)
    for _ in range(NFILL): emit(rand_vals())
with open(out, 'wb') as f:
    for v, n in words:
        f.write((v & ((1 << (16 * n)) - 1)).to_bytes(6, 'little')[: 2 * n] + bytes(8 - 2 * n))
print(len(words), 'slots')
