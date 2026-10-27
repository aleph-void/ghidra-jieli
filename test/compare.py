#!/usr/bin/env python3
"""Compare Ghidra's decode of a slot corpus with JieLi's objdump (oracle.py).
The two print different syntaxes, so each text is cut into a *shape* (mnemonic and punctuation, registers -> R,
numbers -> N, branch targets -> T) and an ordered operand list.  Two decodes agree when the lengths agree and the
operand lists are a permutation of each other; for every (module shape, oracle shape) pair the permutation must
be the same for all samples.  Pairs are listed so each can be vetted once (accepted-<arch>.txt = vetted pairs).
usage: compare.py <ghidra.txt> <oracle.txt> [--slot 8] [--accepted file] [--pairs out] [--show N]"""
import os, argparse, collections, itertools, re, sys

REG = re.compile(r'\b(r\d+|pc|rets|reti|rete|retx|psr|icfg|usp|ssp|cnum|ie\d|sfr\d+|sr\d+|macc[lh]?|nzcv|sr\d+|cres|rep_\w+|mult_addr|r\d+_r\d+)\b')
NUM = re.compile(r'(?<![\w])-?(?:0x[0-9a-fA-F]+|\d+)\b|(?<=\w)(?<![\w.])-?(?:0x[0-9a-fA-F]+|\d+)\b')
M32 = (1 << 32) - 1

def split(text, slot_addr, ghidra, ilen=2, alt=False):
    t = text.strip()
    if not ghidra:
        # the data-address / rep-body annotations of objdump carry no operand (they restate the number or the body end)
        t = re.sub(r'(addr\(-?\d+\)[^<]*?|\{) <[^<>]*: [0-9a-f]+ ?>', r'\1', t)
        # an immediate that looks like an address gets a symbol annotation too ('r0 = 10904 <sym+0x2A98 : 2a98 >'): the value is the number
        t = re.sub(r'(^[\w.]+ = -?\d+)( #)? <[^<>]*: [0-9a-f]+ ?>$', r'\1\2', t)
    if ghidra:
        t = re.sub(r'((?:\br\d+|\.[lh]|\))) -(0x[0-9a-fA-F]+|\d+)', r'\1 - \2', t)
        t = re.sub(r'\|-(0x[0-9a-fA-F]+|\d+)', r'|- \1', t)
    def expand(m):
        regs = []
        for part in m.group(1).split(','):
            part = part.strip()
            r = re.fullmatch(r'(?:r|sp)(\d*)-r(\d+)', part)
            if r:
                x, y = (int(r.group(1)) if r.group(1) else 15), int(r.group(2))
                regs += ['r%d' % k for k in (range(x, y + 1) if x <= y else range(x, y - 1, -1))]
            elif part:
                regs.append('r15' if (part == 'sp' and os.environ.get('SP_R15')) else part)
        return '{' + ' '.join(regs) + '}'
    t = re.sub(r'\{([^}]*)\}', expand, t)
    par = t.endswith('#')
    if par: t = t[:-1].strip()
    toks = []
    t = re.sub(r'(-?\d+ )?(?:# )?<[^<>]*: ([0-9a-f]+) ?>', lambda m: (toks.append(('B', int(m.group(2), 16) & M32, (int(m.group(1)) & M32) if m.group(1) else int(m.group(2), 16) & M32)), '\0T\0')[1], t)
    if ghidra:
        def addr8(m):
            sgn = -1 if m.group(1) else 1
            v = sgn * int(m.group(2), 16)
            toks.append(('A', v & M32, (v - slot_addr) & M32, (v - slot_addr - ilen) & M32))
            return '\0T\0'
        t = re.sub(r'(-?)0x([0-9a-f]{8})\b', addr8, t)
    # sequential scan keeping order of T placeholders
    out, vals = [], []
    pos = 0
    pieces = re.split(r'(\0T\0)', t)
    ti = 0
    shape = ''
    for p in pieces:
        if p == '\0T\0':
            shape += 'T'; vals.append(toks[ti]); ti += 1; continue
        def rep(m):
            s = m.group(0)
            if REG.fullmatch(s):
                vals.append(('R', s)); return 'R'
            return s
        # tokenise word-wise
        q = ''
        i = 0
        for m in re.finditer(r'(?<![\w])-?(?:0x[0-9a-fA-F]+|\d+)(?![\w])|[A-Za-z_]\w*|\s+|.', p):
            s = m.group(0)
            if re.fullmatch(r'-?(?:0x[0-9a-fA-F]+|\d+)', s) and (m.start() == 0 or not (p[m.start()-1].isalnum() or p[m.start()-1] == '.')):
                v = int(s, 0) & M32
                vals.append(('A', v, (v - slot_addr) & M32, (v - slot_addr - ilen) & M32) if (alt and ghidra and (v >= 0x100 or slot_addr > 0)) else ('N', v)); q += 'N'
            elif REG.fullmatch(s):
                vals.append(('R', s)); q += 'R'
            else:
                q += s
        shape += q
    shape = re.sub(r'\s+', ' ', shape).strip()
    # numbers: some oracle texts print the same number as a register-like decimal, keep as is
    return shape + (' #' if par else ''), vals

IMPL = {('N', 0), ('N', 1)}
def _strip(l, d):
    d = dict(d); r = []
    for x in l:
        if d.get(x, 0) > 0: d[x] -= 1
        else: r.append(x)
    return r

def perms(a, b):
    if sorted(map(str, a)) != sorted(map(str, b)):
        ca, cb = collections.Counter(a), collections.Counter(b)
        d1, d2 = ca - cb, cb - ca
        if set(d1) <= IMPL and set(d2) <= IMPL:
            a, b = _strip(a, d1), _strip(b, d2)
    if sorted(map(str, a)) != sorted(map(str, b)): return None
    n = len(a)
    if n > 6:
        used, p = set(), []
        for x in a:
            j = next(j for j in range(n) if j not in used and b[j] == x)
            used.add(j); p.append(j)
        return {tuple(p)}
    res = set()
    for p in itertools.permutations(range(n)):
        if all(a[i] == b[p[i]] for i in range(n)): res.add(p)
    return res

def norm(x):
    return x.replace(' #', '').replace(' ', '').replace('T', 'N')

def load(fn):
    d = {}
    for l in open(fn):
        if l.startswith('    '): continue
        i, n, t = l.rstrip('\n').split(' ', 2)
        d[int(i, 16) if ELF else int(i)] = (int(n), t)
    return d

ELF = '--elf' in sys.argv
ap = argparse.ArgumentParser()
ap.add_argument('g'); ap.add_argument('o')
ap.add_argument('--slot', type=int, default=8)
ap.add_argument('--elf', action='store_true')
ap.add_argument('--piece', type=int, default=131072, help='slots per Ghidra import piece (decode-corpus.sh: 1 MB)')
ap.add_argument('--accepted'); ap.add_argument('--pairs'); ap.add_argument('--show', type=int, default=3)
a = ap.parse_args()
G, O = load(a.g), load(a.o)
acc = set()
if a.accepted:
    for l in open(a.accepted):
        l = l.rstrip('\n')
        if l and not l.startswith('#'): acc.add(l)
cls = collections.Counter(); ex = collections.defaultdict(list)
pairp = {}; pairn = collections.Counter(); pairex = {}
for i in sorted(G):
    gl, gt = G[i]; ol, ot = O.get(i, (0, 'MISSING'))
    if ot == 'CRASH': cls['oracle-crash'] += 1; continue
    if ot == 'DATA': cls['oracle-data (jump table entry, skipped)'] += 1; continue
    if gl == 0 and ol == 0: cls['both-invalid'] += 1; continue
    if gl == 0: cls['module-invalid-oracle-valid'] += 1; ex['module-invalid-oracle-valid'].append((i, gt, ot)); continue
    if ol == 0: cls['module-valid-oracle-invalid'] += 1; ex['module-valid-oracle-invalid'].append((i, gt, ot)); continue
    if gl != ol: cls['length-differs'] += 1; ex['length-differs'].append((i, gt, ot)); continue
    base = i if a.elf else (i % a.piece) * a.slot
    gs, gv = split(gt, base, True, alt=bool(re.search(r'\b(call|goto\w*|callns)\b', ot)), ilen=gl); os_, ov = split(ot, base, False, ol)
    p = None
    amb = [k for k, v in enumerate(gv) if v[0] == 'A']
    ambo = [k for k, v in enumerate(ov) if v[0] == 'B']
    for choice in itertools.product((1, 2, 3), repeat=len(amb)):
        g2 = list(gv)
        for k, c in zip(amb, choice): g2[k] = ('N', gv[k][c] if c < len(gv[k]) else gv[k][1])
        for oc in itertools.product((1, 2), repeat=len(ambo)):
            o2 = list(ov)
            for k, c in zip(ambo, oc): o2[k] = ('N', ov[k][c])
            p = perms(g2, o2)
            if p: break
        if p: break
    key = gs + '  <>  ' + os_
    if p is None or not p:
        cls['operands-differ'] += 1; ex['operands-differ'].append((i, gt, ot)); continue
    pairn[key] += 1
    pairex.setdefault(key, (i, gt, ot))
    pairp[key] = p if key not in pairp else pairp[key] & p
    cls['agree-shape'] += 1
    if norm(gs) == norm(os_): cls['identical-shape'] += 1
bad = [k for k, p in pairp.items() if not p]
for k in bad:
    cls['agree-shape'] -= pairn[k]; cls['order-inconsistent'] += pairn[k]
unvet = [k for k in pairn if k not in acc]
print('slots', len(G))
for k, v in sorted(cls.items()): print('%-34s %d' % (k, v))
print('distinct pairs', len(pairn), 'order-inconsistent pairs', len(bad), 'unvetted pairs', len(unvet))
for k in ex:
    print('--', k)
    seen = {}
    firsts = []
    for i, gt, ot in ex[k]:
        sk = (split(gt, 0, True)[0] if gt != 'BAD' else gt, split(ot, 0, False)[0] if ot != 'BAD' else ot)
        if sk in seen:
            seen[sk] += 1
            continue
        seen[sk] = 1
        firsts.append((sk, i, gt, ot))
    for n_, (sk, i, gt, ot) in enumerate(firsts):
        if n_ < a.show * 100: print('   %d  x%d  [%s]  <>  [%s]' % (i, seen[sk], gt, ot))
if a.pairs:
    with open(a.pairs, 'w') as f:
        for k in sorted(pairn): f.write('%s\n' % k)
    with open(a.pairs + '.detail', 'w') as f:
        for k in sorted(pairn): f.write('%6d  %s   e.g. %s  |  %s\n' % (pairn[k], k, pairex[k][1], pairex[k][2]))
for k in bad:
    print('ORDER-INCONSISTENT', k, pairex[k])
