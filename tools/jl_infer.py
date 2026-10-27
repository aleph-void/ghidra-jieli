#!/usr/bin/env python3
"""Infer an instruction table (the format of tools/pi32v2.toml) for JieLi's pi32 or q32s from JieLi's own objdump.

The toolchain is used strictly as a black box: bytes go in, text comes out; nothing is read from its binaries.

usage: jl_infer.py <arch pi32|q32s> <out.json> [--rounds N]

Stages
  1. sample: every 16-bit first word (zero tail) and random tails for the longer instructions;
  2. flip analysis: for a few samples per (length, text template) flip each bit; a bit whose flip changes the template is an
     opcode bit (a "cube" = opcode mask + value is one instruction form);
  3. cover check: every valid sample must lie in a cube with its own template, and every random word of a cube must decode to
     the cube's template; failures are analysed again (and cubes are split by a small decision tree if they overreach);
  4. fields: the non-opcode bits are grouped by the operand tokens they change; each token is fitted as a linear function of
     its bits (registers, numbers, branch targets) or as a bit->name map (register lists) or as a lookup table.
"""
import collections, json, os, pickle, random, re, struct, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from jl_oracle import decode_many
from jl_text import tokenize

ARCH = sys.argv[1]
OUT = sys.argv[2]
ROUNDS = int(sys.argv[sys.argv.index('--rounds') + 1]) if '--rounds' in sys.argv else 6
rnd = random.Random(12345)
CACHE_FILE = os.path.join(os.environ.get('TMPDIR', '/tmp'), 'jl_infer_cache_%s.pkl' % ARCH)
try:
    CACHE = pickle.load(open(CACHE_FILE, 'rb'))
except Exception:
    CACHE = {}


ZERO_OMIT = {'pi32': '[{R}+ {N}]', 'q32s': '[{R}+{N}]', 'pi32v2': '[{R}+{N}]'}
_ZO = re.compile(r'\[\{R\}\]')


def canon(tpl, toks):
    """objdump leaves out a zero offset ('[sp]' for '[sp+ 0]'); put it back so that the template does not depend on the value."""
    m = _ZO.search(tpl)
    while m:
        k = tpl[:m.start()].count('{')          # placeholders before the match
        k = len(re.findall(r'\{[RSNTL]\}', tpl[:m.start()]))
        # the R placeholder of the match is token k; the zero goes right after it
        toks = list(toks[:k + 1]) + [('N', 0)] + list(toks[k + 1:])
        tpl = tpl[:m.start()] + ZERO_OMIT[ARCH] + tpl[m.end():]
        m = _ZO.search(tpl)
    return tpl, tuple(toks)


def dec_raw(words):
    """words: list of (int value, nbytes<=6).  Returns [(len, tpl, toks)] (len 0: invalid)."""
    keys = [(w & ((1 << (8 * n)) - 1)).to_bytes(n, 'little').ljust(8, b'\0') for w, n in words]
    todo = sorted({k for k in keys if k not in CACHE})
    if todo:
        for k, r in zip(todo, decode_many(ARCH, list(todo))):
            n, text = r
            if n == 0:
                CACHE[k] = (0, text, ())
            else:
                tpl, toks = tokenize(text, ARCH == 'pi32')
                tpl, toks = canon(tpl, toks)
                CACHE[k] = (n, tpl, tuple(toks))
    return [CACHE[k] for k in keys]


def save_cache():
    pickle.dump(CACHE, open(CACHE_FILE, 'wb'))


def sig(r):
    """Form signature: length and the template with the branch-target annotation removed."""
    n, tpl, toks = r
    if n == 0:
        return None
    return (n, tpl.replace(' {T}', '').replace('{T}', ''))


def vtoks(r):
    return [t for t in r[2] if t[0] != 'T']


def ttok(r):
    for t in r[2]:
        if t[0] == 'T':
            return t[1]
    return None


# ---------------------------------------------------------------------------------------------------------------- stage 1
def stage1():
    first = [(w, 2) for w in range(65536)]
    r0 = dec_raw(first)
    samples = {}          # word -> (n, ...)
    for (w, _), r in zip(first, r0):
        if r[0]:
            samples[(w, r[0])] = r
    longs = [w for (w, _), r in zip(first, r0) if r[0] > 2]
    # first words whose zero-tail decode is invalid may still start a longer instruction (e.g. an empty register list is
    # rejected): probe them with random tails
    probe = []
    for (w, _), r in zip(first, r0):
        if r[0] == 0:
            for _ in range(10):
                probe.append((w | (rnd.getrandbits(32) << 16), 6))
    found = {}
    for x, r in zip(probe, dec_raw(probe)):
        if r[0] > 2:
            found.setdefault(x[0] & 0xffff, r[0])
            samples[(x[0] & ((1 << (8 * r[0])) - 1), r[0])] = r
    longs += [w for w in found if w not in set(longs)]
    r0len = {w: r[0] for (w, _), r in zip(first, r0) if r[0]}
    r0len.update(found)
    extra = []
    for w in longs:
        n = r0len[w]
        for _ in range(6):
            extra.append((w | (rnd.getrandbits(8 * (n - 2)) << 16), n))
    for x, r in zip(extra, dec_raw(extra)):
        if r[0] == x[1]:
            samples[x] = r
        elif r[0]:
            samples[(x[0] & 0xffff, r[0])] = r
    save_cache()
    return samples


# ---------------------------------------------------------------------------------------------------------------- stage 2
def flips(samples):
    """samples: list of (w, n).  Returns {(w,n): set of opcode bits}."""
    items = []
    for w, n in samples:
        for b in range(8 * n):
            items.append((w ^ (1 << b), n))
    res = dec_raw(items)
    out = {}
    k = 0
    base = dec_raw(samples)
    for (w, n), r0 in zip(samples, base):
        s0 = sig(r0)
        op = set()
        for b in range(8 * n):
            if sig(res[k]) != s0:
                op.add(b)
            k += 1
        out[(w, n)] = op
    return out


class Cube:
    def __init__(self, n, tpl, mask, val):
        self.n, self.tpl, self.mask, self.val = n, tpl, mask, val

    def key(self):
        return (self.n, self.tpl, self.mask, self.val)

    def has(self, w, n):
        return n == self.n and (w & self.mask) == self.val

    def rand(self):
        full = (1 << (8 * self.n)) - 1
        return (rnd.getrandbits(8 * self.n) & full & ~self.mask) | self.val


def build_cubes(cubes, samples_to_analyse, per=1):
    fl = flips(samples_to_analyse)
    base = dec_raw(samples_to_analyse)
    for (w, n), r in zip(samples_to_analyse, base):
        op = fl[(w, n)]
        mask = sum(1 << b for b in op)
        c = Cube(n, sig(r)[1], mask, w & mask)
        cubes.setdefault(c.key(), c)


def covered(cubes_by_sig, w, n, s):
    for c in cubes_by_sig.get(s, ()):
        if c.has(w, n):
            return True
    return False


def by_sig(cubes):
    d = collections.defaultdict(list)
    for c in cubes.values():
        d[(c.n, c.tpl)].append(c)
    return d


def gini(p, f):
    t = p + f
    return 0 if t == 0 else (2.0 * p * f) / t


def tree_pass_cubes(n, mask, val, probes, labels, bits):
    """Decision tree over `bits`; returns (mask, val) of the leaves that contain only passing probes."""
    out = []

    def rec(idx, m, v, free):
        p = sum(1 for i in idx if labels[i])
        f = len(idx) - p
        if f == 0:
            out.append((m, v))
            return
        if p == 0:
            return
        best, bb = None, None
        for b in free:
            a1 = [i for i in idx if (probes[i] >> b) & 1]
            p1 = sum(1 for i in a1 if labels[i])
            f1 = len(a1) - p1
            p0, f0 = p - p1, f - f1
            sc = gini(p1, f1) + gini(p0, f0)
            if bb is None or sc < best:
                best, bb = sc, b
        if bb is None:
            return
        rest = [b for b in free if b != bb]
        i1 = [i for i in idx if (probes[i] >> bb) & 1]
        i0 = [i for i in idx if not (probes[i] >> bb) & 1]
        if not i1 or not i0:
            return
        rec(i1, m | (1 << bb), v | (1 << bb), rest)
        rec(i0, m | (1 << bb), v, rest)

    rec(list(range(len(probes))), mask, val, bits)
    return out


def refine(cubes, nprobe=1500):
    """Split every cube that contains words of another template."""
    changed = False
    out = {}
    cl = list(cubes.values())
    allp, own = [], []
    for ci, c in enumerate(cl):
        for _ in range(nprobe if c.n > 2 else min(nprobe, 1 << max(0, 16 - bin(c.mask).count('1')))):
            allp.append((c.rand(), c.n))
            own.append(ci)
    rs = dec_raw(allp)
    per = collections.defaultdict(list)
    for x, r, ci in zip(allp, rs, own):
        per[ci].append((x[0], sig(r) == (cl[ci].n, cl[ci].tpl)))
    nbad = 0
    for ci, c in enumerate(cl):
        pr = per[ci]
        if all(ok for _, ok in pr):
            out[c.key()] = c
            continue
        nbad += 1
        changed = True
        bits = [b for b in range(8 * c.n) if not (c.mask >> b) & 1]
        leaves = tree_pass_cubes(c.n, c.mask, c.val, [w for w, _ in pr], [ok for _, ok in pr], bits)
        for m, v in leaves:
            d = Cube(c.n, c.tpl, m, v)
            out[d.key()] = d
    return out, nbad


def merge(cubes):
    """Quine-McCluskey style: cubes of one template with equal masks that differ in one value bit merge; nested cubes drop."""
    groups = collections.defaultdict(set)
    for c in cubes.values():
        groups[(c.n, c.tpl)].add((c.mask, c.val))
    res = {}
    for (n, tpl), s in groups.items():
        s = set(s)
        changed = True
        while changed:
            changed = False
            bymask = collections.defaultdict(set)
            for m, v in s:
                bymask[m].add(v)
            new = set()
            used = set()
            for m, vs in bymask.items():
                for v in vs:
                    for b in range(8 * n):
                        if (m >> b) & 1 and (v >> b) & 1:
                            o = v ^ (1 << b)
                            if o in vs:
                                new.add((m & ~(1 << b), v & ~(1 << b)))
                                used.add((m, v))
                                used.add((m, o))
            if new:
                s = (s - used) | new
                changed = True
        # drop cubes contained in another cube
        lst = sorted(s, key=lambda x: bin(x[0]).count('1'))
        keep = []
        for m, v in lst:
            if not any((m2 & m) == m2 and (v & m2) == v2 for m2, v2 in keep):
                keep.append((m, v))
        for m, v in keep:
            c = Cube(n, tpl, m, v)
            res[c.key()] = c
    return res


def stage23(samples):
    cubes = {}
    groups = collections.defaultdict(list)
    for (w, n), r in samples.items():
        groups[sig(r)].append((w, n))
    seed = []
    for s, lst in groups.items():
        rnd.shuffle(lst)
        seed += lst[:16]
    build_cubes(cubes, seed)
    print('seed cubes', len(cubes), 'templates', len(groups), flush=True)
    allw = list(samples)
    for rd in range(ROUNDS):
        cubes, nbad = refine(cubes)
        cubes = merge(cubes)
        idx = by_sig(cubes)
        unc = [x for x in allw if not covered(idx, x[0], x[1], sig(samples[x]))]
        print('round', rd, 'cubes', len(cubes), 'overreaching cubes split', nbad, 'uncovered corpus samples', len(unc), flush=True)
        if not unc and not nbad:
            break
        pick = collections.defaultdict(list)
        for x in unc:
            pick[sig(samples[x])].append(x)
        newsamp = []
        for s_, lst in pick.items():
            rnd.shuffle(lst)
            newsamp += lst[:12]
        if newsamp:
            build_cubes(cubes, newsamp)
        save_cache()
    return cubes


def add_seeds(samples):
    """Extra valid words found by differential tests (hex, memory order, one per line) join the corpus."""
    if '--seeds' not in sys.argv:
        return
    words = []
    for l in open(sys.argv[sys.argv.index('--seeds') + 1]):
        l = l.split()[0] if l.split() else ''
        if l:
            b = bytes.fromhex(l)
            words.append((int.from_bytes(b.ljust(6, b'\0')[:6], 'little'), 6))
    for x, r in zip(words, dec_raw(words)):
        if r[0]:
            samples[(x[0] & ((1 << (8 * r[0])) - 1), r[0])] = r
    save_cache()


def main():
    samples = stage1()
    add_seeds(samples)
    print('valid samples', len(samples), flush=True)
    cubes = stage23(samples)
    print('cubes', len(cubes))
    pickle.dump((samples, [c.key() for c in cubes.values()]), open(OUT + '.cubes.pkl', 'wb'))


if __name__ == '__main__':
    main()
