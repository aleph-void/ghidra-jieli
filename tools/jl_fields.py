#!/usr/bin/env python3
"""Stage 4 of the table inference: operand fields of every cube.  usage: jl_fields.py <arch> <prefix>  (reads <prefix>.cubes.pkl)"""
import collections, itertools, json, os, pickle, random, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
ARCH, PREFIX = sys.argv[1], sys.argv[2]
sys.argv = ['x', ARCH, PREFIX]
import jl_infer as J

rnd = random.Random(777)
NS = 64


def disjoint(cubes):
    """Make the cubes of one template disjoint (sharp operation)."""
    out = []
    for m, v in cubes:
        pieces = [(m, v)]
        for m2, v2 in out:
            nxt = []
            for pm, pv in pieces:
                common = pm & m2
                if (pv & common) != (v2 & common):
                    nxt.append((pm, pv))          # disjoint already
                    continue
                if (m2 & ~pm) == 0:
                    continue                       # (pm,pv) lies inside (m2,v2): gone
                cm, cv = pm, pv
                for b in range(64):
                    if (m2 >> b) & 1 and not (cm >> b) & 1:
                        nxt.append((cm | (1 << b), cv | ((~v2 >> b) & 1) << b))
                        cm |= 1 << b
                        cv |= ((v2 >> b) & 1) << b
            pieces = nxt
        out += pieces
    return out


M32 = 0xffffffff


def modimm(x):
    sel = (x >> 10) & 3
    if sel == 0:
        xy = x & 0xff
        t = (x >> 8) & 3
        return [xy, (xy << 16) | xy, (xy << 24) | (xy << 8), xy * 0x01010101][t]
    rot = (x >> 7) & 31
    b = 0x80 | (x & 0x7f)
    return ((b >> rot) | (b << (32 - rot))) & M32


def sample_cube(c, k=NS):
    free = [b for b in range(8 * c.n) if not (c.mask >> b) & 1]
    out, seen = [], set()
    tries = 0
    while len(out) < k and tries < 4 * k:
        w = c.rand()
        tries += 1
        if w not in seen:
            seen.add(w)
            out.append(w)
    return out, free


def token_obs(c, t, samples, free, base):
    """Which free bits change token t, with before/after values."""
    items = [(w ^ (1 << b), c.n) for w in samples for b in free]
    res = J.dec_raw(items)
    k = 0
    want = (c.n, c.tpl)
    obs = collections.defaultdict(list)
    cond = set()
    other = collections.defaultdict(set)
    for w, r0 in zip(samples, base):
        v0 = J.vtoks(r0)
        for b in free:
            r1 = res[k]
            k += 1
            if J.sig(r1) != want:
                cond.add(b)
                continue
            v1 = J.vtoks(r1)
            for u in range(len(v0)):
                if v0[u] != v1[u]:
                    other[b].add(u)
                    if u == t:
                        obs[b].append((v0[u][1], v1[u][1], (w >> b) & 1))
    return obs, other, cond


def fit_token(c, t, depth=0):
    """Fit token t of cube c.  Returns (fit, bits)."""
    samples, free = sample_cube(c)
    base = J.dec_raw([(w, c.n) for w in samples])
    want = (c.n, c.tpl)
    good = [(w, r) for w, r in zip(samples, base) if J.sig(r) == want]
    if len(good) < max(1, len(samples) // 2):
        raise ValueError('cube does not decode to its template (%d/%d)' % (len(good), len(samples)))
    samples = [w for w, r in good]
    base = [r for w, r in good]
    kind = J.vtoks(base[0])[t][0]
    obs, other, cond = token_obs(c, t, samples, free, base)
    bits = sorted(b for b in free if obs.get(b))
    vals = [J.vtoks(r)[t][1] for r in base]
    if not bits:
        if len(set(vals)) != 1:
            raise ValueError('token %d varies without bits' % t)
        return {'type': 'const', 'val': list(vals[0]) if kind == 'L' else vals[0]}, bits
    if kind == 'L':
        f = fit_list(c, t, bits, samples, base, obs)
        if f:
            return f, bits
        if len(bits) <= 10:
            return fit_table(c, t, bits, samples), bits
    # linear
    w = {}
    ok = kind != 'L'
    for b in bits:
        if not ok:
            break
        ds = {(after - before) * (1 if was == 0 else -1) for before, after, was in obs[b]}
        if len(ds) != 1:
            ok = False
            break
        w[b] = ds.pop()
    if ok:
        c0s = {J.vtoks(r)[t][1] - sum(w[b] for b in bits if (s >> b) & 1) for s, r in zip(samples, base)}
        if len(c0s) == 1:
            return {'type': 'lin', 'w': {str(b): w[b] for b in bits}, 'c0': c0s.pop()}, bits
    if len(bits) == 12 and kind != 'L':
        f = fit_modimm(c, t, bits, samples, base) or fit_modimm2(c, t, bits, samples, base)
        if f:
            return f, bits
    if len(bits) <= 10 and kind != 'L':
        return fit_table(c, t, bits, samples), bits
    if depth >= 1:
        raise ValueError('token %d: %d bits, not linear (depth)' % (t, len(bits)))
    # selector bits: fix one (or two) bit(s) and fit the rest
    cands = bits
    if kind == 'L':
        cands = []
        for b in bits:
            d = {frozenset(set(before) ^ set(after)) for before, after, was in obs[b]}
            if not (len(d) == 1 and len(next(iter(d))) == 1):
                cands.append(b)
    for k in (1, 2):
        for sel in itertools.combinations(cands, k):
            cases = {}
            try:
                for a in range(1 << k):
                    m, v = c.mask, c.val
                    for i, b in enumerate(sel):
                        m |= 1 << b
                        v |= ((a >> i) & 1) << b
                    sub = J.Cube(c.n, c.tpl, m, v)
                    f, _ = fit_token(sub, t, depth + 1)
                    cases[str(a)] = f
            except ValueError:
                continue
            if all(cc['type'] != 'table' for cc in cases.values()) or True:
                return {'type': 'sel', 'bits': list(sel), 'cases': cases}, bits
    raise ValueError('token %d: %d bits, not linear' % (t, len(bits)))


def fit_modimm(c, t, bits, samples, base):
    free_base = samples[0]
    z = free_base
    for b in bits:
        z &= ~(1 << b)
    r = J.dec_raw([(z, c.n)])[0]
    if J.sig(r) != (c.n, c.tpl):
        return None
    v0 = J.vtoks(r)[t][1]
    if v0 not in (0, M32, -1):
        return None
    inv = v0 != 0
    one = {}
    rs = J.dec_raw([(z ^ (1 << b), c.n) for b in bits])
    pos = {}
    for b, r1 in zip(bits, rs):
        if J.sig(r1) != (c.n, c.tpl):
            return None
        v = (J.vtoks(r1)[t][1] ^ (M32 if inv else 0)) & M32
        if v and v & (v - 1) == 0 and v < 256:
            pos[b] = v.bit_length() - 1
    if len(set(pos.values())) != 8:
        return None
    b0 = [b for b, p in pos.items() if p == 0][0]
    z1 = z | (1 << b0)
    rest = [b for b in bits if b not in pos]
    rs = J.dec_raw([(z1 ^ (1 << b), c.n) for b in rest])
    for b, r1 in zip(rest, rs):
        v = (J.vtoks(r1)[t][1] ^ (M32 if inv else 0)) & M32
        p = {0x00010001: 8, 0x01000100: 9, 0x81000000: 10, 0x00810000: 11}.get(v)
        if p is None:
            return None
        pos[b] = p
    if len(set(pos.values())) != 12:
        return None
    for s, r in zip(samples, base):
        x = sum(((s >> b) & 1) << p for b, p in pos.items())
        v = modimm(x) ^ (M32 if inv else 0)
        if (J.vtoks(r)[t][1] & M32) != v:
            return None
    return {'type': 'modimm', 'pos': {str(b): p for b, p in pos.items()}, 'inv': inv}


def modimm2(x):
    y = x >> 7
    lo = x & 0x7f
    if y < 18:
        m = 0x80 | lo
        r = 28 - y - (1 if y >= 4 else 0) - (1 if y >= 11 else 0)
        return ((m >> r) | (m << (32 - r))) & M32
    b = ((y & 1) << 7) | lo
    k = (y - 18) >> 1
    return [b, b << 8, b << 16, b << 24, b | (b << 16), (b << 8) | (b << 24), b * 0x01010101][k] & M32


def fit_modimm2(c, t, bits, samples, base):
    if bits != list(range(bits[0], bits[0] + 12)):
        return None
    for inv in (False, True):
        ok = True
        for s, r in zip(samples, base):
            x = sum(((s >> b) & 1) << i for i, b in enumerate(bits))
            if (J.vtoks(r)[t][1] & M32) != (modimm2(x) ^ (M32 if inv else 0)):
                ok = False
                break
        if ok:
            return {'type': 'modimm2', 'lo': bits[0], 'inv': inv}
    return None


def fit_table(c, t, bits, samples):
    if len(bits) > 10:
        raise ValueError('token %d: %d bits, table too large' % (t, len(bits)))
    s0 = samples[0]
    items = []
    for combo in range(1 << len(bits)):
        w = s0
        for i, b in enumerate(bits):
            w = (w & ~(1 << b)) | (((combo >> i) & 1) << b)
        items.append((w, c.n))
    rs = J.dec_raw(items)
    tab = {}
    for combo, r in enumerate(rs):
        if J.sig(r) != (c.n, c.tpl):
            tab[combo] = None
        else:
            v = J.vtoks(r)[t][1]
            tab[combo] = list(v) if isinstance(v, tuple) else v
    return {'type': 'table', 'bits': bits, 'map': {str(k): v for k, v in tab.items()}}


def fit_list(c, t, bits, samples, base, obs):
    names = {}
    for b in bits:
        d = {frozenset(set(before) ^ set(after)) for before, after, was in obs[b]}
        if len(d) != 1 or len(next(iter(d))) != 1:
            return None
        names[b] = next(iter(next(iter(d))))
    w = samples[0]
    for b in bits:
        w |= 1 << b
    w0 = samples[0]
    for b in bits:
        w0 &= ~(1 << b)
    r_all, r_none = J.dec_raw([(w, c.n), (w0, c.n)])
    if J.sig(r_all) != (c.n, c.tpl):
        return None
    allv = J.vtoks(r_all)[t][1]
    empty_invalid = False
    if J.sig(r_none) == (c.n, c.tpl):
        nonev = J.vtoks(r_none)[t][1]
    else:       # the empty list is not an instruction: the constant part is what no bit controls
        nonev = tuple(x for x in allv if x not in set(names.values()))
        empty_invalid = True
    for s, r in zip(samples, base):
        have = {names[b] for b in bits if (s >> b) & 1} | set(nonev)
        if have != set(J.vtoks(r)[t][1]):
            return None
    return {'type': 'mask', 'names': {str(b): names[b] for b in bits}, 'const': list(nonev), 'order': list(allv), 'nonempty': empty_invalid and not nonev}


def target_info(c):
    """If objdump annotates the form with a branch target <sym+off : addr>, find the number token it follows (T = N + delta)."""
    samples, _ = sample_cube(c, 200)
    rs = J.dec_raw([(w, c.n) for w in samples])
    pairs = [(J.vtoks(r), J.ttok(r)) for r in rs if J.sig(r) == (c.n, c.tpl) and J.ttok(r) is not None]
    if not pairs:
        return None
    ntok = len(pairs[0][0])
    for t in range(ntok):
        if pairs[0][0][t][0] != 'N':
            continue
        ds = {T - v[t][1] for v, T in pairs}
        if len(ds) == 1:
            return {'tok': t, 'delta': ds.pop(), 'samples': len(pairs)}
    return {'tok': None, 'samples': len(pairs)}


def fit_cube(c):
    base = J.dec_raw([(c.rand(), c.n)])[0]
    ntok = len(J.vtoks(base))
    toks = []
    for t in range(ntok):
        f, bits = fit_token(c, t)
        toks.append({'idx': t, 'kind': J.vtoks(base)[t][0], 'bits': bits, 'fit': f})
    return toks, target_info(c)


def main():
    samples, ck = pickle.load(open(PREFIX + '.cubes.pkl', 'rb'))
    bytpl = collections.defaultdict(list)
    for (n, tpl, m, v) in ck:
        bytpl[(n, tpl)].append((m, v))
    forms = []
    fails = []
    for (n, tpl), lst in sorted(bytpl.items()):
        for m, v in disjoint(sorted(lst, key=lambda x: bin(x[0]).count('1'))):
            c = J.Cube(n, tpl, m, v)
            try:
                toks, tinfo = fit_cube(c)
                cond = []
            except ValueError as e:
                fails.append((n, tpl, m, v, str(e)))
                continue
            forms.append({'n': n, 'tpl': tpl, 'mask': m, 'val': v, 'tokens': toks, 'cond': cond, 'target': tinfo})
    J.save_cache()
    json.dump({'arch': ARCH, 'forms': forms, 'fails': fails}, open(PREFIX + '.forms.json', 'w'))
    print('forms', len(forms), 'failed', len(fails))
    for f in fails[:30]:
        print('  FAIL', f[0], f[1], hex(f[2]), f[4])
    cc = collections.Counter(t['fit']['type'] for f in forms for t in f['tokens'])

    print(cc)
    print('forms with conditional opcode bits:', sum(1 for f in forms if f['cond']))


if __name__ == '__main__':
    main()
