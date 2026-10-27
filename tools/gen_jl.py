#!/usr/bin/env python3
"""Generate data/languages/<arch>_gen.sinc (tokens, operand tables and one constructor per instruction form) for JieLi's pi32 or
q32s from the instruction table inferred by jl_infer.py / jl_fields.py (tools/<arch>.forms.json).

usage: gen_jl.py <arch pi32|q32s> <forms.json> <out.sinc>

The forms are cubes of the instruction word (opcode mask and value) with operand tokens fitted from JieLi's objdump; the display
text is objdump's own template; the p-code comes from sem_jl.py.
"""
import collections, json, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
ARCH, FORMS, OUT = sys.argv[1:4]

GPR = {'pi32': ['r%d' % i for i in range(15)] + ['sp'], 'q32s': ['r%d' % i for i in range(16)]}[ARCH]
SFR = {
    'pi32': ['reti', 'rete', 'sfr2', 'sfr3', 'maccl', 'macch', 'rets', 'psr', 'sfr8', 'sfr9', 'ie1', 'ssp', 'ie0', 'icfg', 'pc', 'usp'],
    'q32s': ['reti', 'rete', 'retx', 'rets', 'sr4', 'psr', 'cnum', 'sr7', 'sr8', 'sr9', 'sr10', 'icfg', 'usp', 'ssp', 'sp', 'pc'],
}[ARCH]
M32 = 0xffffffff


class Gen:
    def __init__(self):
        self.fields = {2: {}, 4: {}, 6: {}}
        self.attach = collections.defaultdict(list)
        self.tables = collections.OrderedDict()
        self.cache = {}
        self.counter = 0

    def fld(self, n, lo, hi, variant='u'):
        suffix = {'u': '', 's': '_s', 'd': '_d', 'sd': '_sd', 'gpr': '_gpr', 'sfr': '_sfr'}[variant] if not variant.startswith('att') else '_' + variant
        name = 'f%d_%d_%d%s' % (n, lo, hi, suffix)
        if name not in self.fields[n]:
            attr = {'u': '', 's': ' signed', 'd': ' dec', 'sd': ' signed dec'}.get(variant, '')
            self.fields[n][name] = (lo, hi, attr)
        return name

    def sym(self, p):
        self.counter += 1
        return '%s%d' % (p, self.counter)


G = Gen()


class Op:
    def __init__(self):
        self.disp = None       # symbol or quoted literal printed
        self.val = None        # p-code expression (4 bytes) / register symbol
        self.pat = []          # pattern parts
        self.const = None      # python value for constant tokens
        self.reg = None        # register symbol (assignable) when the operand is a register
        self.names = None      # list operands: universe of register names
        self.kind = None
        self.is_target = False
        self.size = 4


def runs(bits):
    """Group sorted bit positions into adjacent runs."""
    out = []
    for b in sorted(bits):
        if out and out[-1][-1] + 1 == b:
            out[-1].append(b)
        else:
            out.append([b])
    return out


def lin_terms(n, fit):
    """Break a linear fit into field terms.  Returns (terms, c0, simple) where terms = [(field, weight)]."""
    w = {int(b): v for b, v in fit['w'].items()}
    terms = []
    cur = None
    for b in sorted(w):
        wb = w[b]
        if cur and cur['hi'] + 1 == b and wb == cur['last'] * 2:
            cur['hi'] = b
            cur['last'] = wb
        elif cur and cur['hi'] + 1 == b and wb == -cur['last'] * 2 and not cur['signed']:
            cur['hi'] = b
            cur['last'] = wb
            cur['signed'] = True
            cur['closed'] = True
        else:
            cur = {'lo': b, 'hi': b, 'w0': wb, 'last': wb, 'signed': False}
            terms.append(cur)
        if cur.get('closed'):
            cur = None
    out = []
    for t in terms:
        # a single bit with a negative weight is a plain bit scaled by it
        f = G.fld(n, t['lo'], t['hi'], 's' if t['signed'] else 'u')
        out.append((f, t['w0']))
    return out, fit['c0']


def expr_of(terms, c0):
    parts = []
    for f, w in terms:
        parts.append('(%s * %d)' % (f, w) if w != 1 else f)
    e = ' + '.join(parts) if parts else '0'
    if c0:
        e += ' + %d' % c0
    return e


def fixres(act):
    if act and act.startswith('off = '):
        return act
    return re.sub(r'^res = (.*);$', lambda m: 'res = (%s) + 0;' % m.group(1), act) if act else act


def tbl_lines(sym, alts):
    for a in alts:
        a['act'] = fixres(a.get('act'))
    return ['%s: %s is %s%s { %s }' % (sym, a['disp'], ' & '.join(a['pat']) if a['pat'] else 'epsilon',
                                         (' [ %s ]' % a['act']) if a.get('act') else '', a['body']) for a in alts]


def nm15(x):
    return 'sp' if (ARCH == 'pi32' and x == 'r15') else x


def pretty_list(names):
    names = [nm15(x) for x in names]
    """objdump style: runs of three or more consecutive descending r registers become r3-r0."""
    out = []
    i = 0
    nm = list(names)
    while i < len(nm):
        j = i
        m = re.fullmatch(r'r(\d+)', nm[i])
        if m:
            while j + 1 < len(nm) and re.fullmatch(r'r(\d+)', nm[j + 1]) and int(nm[j + 1][1:]) == int(nm[j][1:]) - 1:
                j += 1
        if m and j - i >= 2:
            out.append('%s-%s' % (nm[i], nm[j]))
            i = j + 1
        else:
            out.append(nm[i])
            i += 1
    return '{' + ', '.join(out) + '}'


# ------------------------------------------------------------------------------------------------------ operand builders
def bit_pat(n, bits, value):
    """Pattern parts fixing `bits` (list, combo bit i <-> bits[i]) to the combo `value`, grouped in runs."""
    parts = []
    i = 0
    bl = list(bits)
    while i < len(bl):
        j = i
        while j + 1 < len(bl) and bl[j + 1] == bl[j] + 1:
            j += 1
        v = (value >> i) & ((1 << (j - i + 1)) - 1)
        parts.append('%s=%d' % (G.fld(n, bl[i], bl[j], 'u'), v))
        i = j + 1
    return parts


def alts_for(n, fit, kind, ctx):
    """Alternatives (pattern parts, action, display, body) realising a fit.  ctx: dict(target=None|'next'|'start', names=...)."""
    t = fit['type']
    if t == 'lin':
        terms, c0 = lin_terms(n, fit)
        e = expr_of(terms, c0)
        if kind == 'R':
            return None      # handled by caller as register
        if ctx.get('target'):
            base = 'inst_next' if ctx['target'] == 'next' else 'inst_start'
            if ctx['target'] == 'start':
                return [{'pat': [f for f, _ in terms], 'act': 'off = (%s) + 0;' % e, 'disp': 'off',
                         'body': 'local v:4 = inst_start + off; export v;'}]
            return [{'pat': [f for f, _ in terms], 'act': 'res = %s + (%s);' % (base, e), 'disp': 'res',
                     'body': 'export *:4 res;'}]
        return [{'pat': [f for f, _ in terms], 'act': 'res = %s;' % e, 'disp': 'res', 'body': 'local v:4 = res; export v;'}]
    if t == 'table':
        bits = fit['bits']
        out = []
        for combo, v in sorted((int(k), v) for k, v in fit['map'].items()):
            if v is None:
                continue
            pat = bit_pat(n, bits, combo)
            if kind == 'L':
                out.append({'pat': pat, 'disp': '"%s"' % pretty_list(v), 'body': 'local m:4 = %d; export m;' % ctx['mask_of'](v)})
            elif ctx.get('target'):
                base = 'inst_next' if ctx['target'] == 'next' else 'inst_start'
                out.append({'pat': pat, 'act': 'res = %s + (%d);' % (base, v), 'disp': 'res',
                            'body': 'export *:4 res;' if ctx['target'] == 'next' else 'local v:4 = res; export v;'})
            else:
                out.append({'pat': pat, 'act': 'res = %d;' % (v & 0xffffffffffffffff if v >= 0 else v + (1 << 64)), 'disp': 'res', 'body': 'local v:4 = res; export v;'})
        return out
    if t == 'sel':
        out = []
        sel = fit['bits']
        for a, sub in sorted((int(k), v) for k, v in fit['cases'].items()):
            sp = bit_pat(n, sel, a)
            for alt in alts_for(n, sub, kind, ctx):
                alt = dict(alt)
                alt['pat'] = sp + alt['pat']
                out.append(alt)
        return out
    if t == 'modimm':
        pos = {int(b): p for b, p in fit['pos'].items()}
        inv = fit['inv']
        bit_of = {p: b for b, p in pos.items()}
        wrap = (lambda e: '(%s) ^ 0xffffffff' % e) if inv else (lambda e: e)
        out = []

        def mk(fixed, tmpl):
            # fixed: {position: value} constrained bits; the others are read as bare fields
            pat, parts = [], []
            for p in range(12):
                f = G.fld(n, bit_of[p], bit_of[p], 'u')
                if p in fixed:
                    pat.append('%s=%d' % (f, fixed[p]))
                    if fixed[p]:
                        parts.append('%d' % (1 << p))
                else:
                    pat.append(f)
                    parts.append('(%s << %d)' % (f, p))
            x = '(%s)' % ' + '.join(parts)
            return pat, x
        for hi, tmpl in ((0, '({xy})'), (1, '(({xy}) << 16) | ({xy})'), (2, '(({xy}) << 24) | (({xy}) << 8)'), (3, '(({xy}) << 24) | (({xy}) << 16) | (({xy}) << 8) | ({xy})')):
            pat, x = mk({11: 0, 10: 0, 9: (hi >> 1) & 1, 8: hi & 1}, tmpl)
            xy = '(%s & 0xff)' % x
            out.append({'pat': pat, 'act': 'res = %s;' % wrap('(' + tmpl.format(xy=xy) + ') & 0xffffffff'), 'disp': 'res', 'body': 'local v:4 = res; export v;'})
        for fixed in ({11: 1}, {11: 0, 10: 1}):
            pat, x = mk(fixed, None)
            rotexpr = '((%s >> 7) & 31)' % x
            bexpr = '(0x80 | (%s & 0x7f))' % x
            rot = '((((%s) >> %s) | ((%s) << (32 - %s))) & 0xffffffff)' % (bexpr, rotexpr, bexpr, rotexpr)
            out.append({'pat': pat, 'act': 'res = %s;' % wrap(rot), 'disp': 'res', 'body': 'local v:4 = res; export v;'})
        return out
    if t == 'modimm2':
        lo = fit['lo']
        fl = G.fld(n, lo, lo + 6, 'u')
        out = []
        for y in range(32):
            if y < 18:
                r = 28 - y - (1 if y >= 4 else 0) - (1 if y >= 11 else 0)
                e = '(((0x80 | %s) >> %d) | ((0x80 | %s) << %d)) & 0xffffffff' % (fl, r, fl, 32 - r)
            else:
                k = (y - 18) >> 1
                b = '(%d | %s)' % (((y & 1) << 7), fl)
                e = ['%s', '(%s << 8)', '(%s << 16)', '(%s << 24)', '(%s | (%s << 16))', '((%s << 8) | (%s << 24))',
                     '(%s | (%s << 8) | (%s << 16) | (%s << 24))'][k]
                e = e.replace('%s', b)
            if fit['inv']:
                e = '(%s) ^ 0xffffffff' % e
            out.append({'pat': [fl, '%s=%d' % (G.fld(n, lo + 7, lo + 11, 'u'), y)], 'act': 'res = (%s) & 0xffffffff;' % e, 'disp': 'res',
                        'body': 'local v:4 = res; export v;'})
        return out
    if t == 'mask':
        names = {int(b): nm for b, nm in fit['names'].items()}
        order = fit['order']
        const = set(fit['const'])
        uni = ctx['universe']
        bits = sorted(names)
        nonempty = fit.get('nonempty')
        if len(bits) <= 8:
            out = []
            for combo in range(1 << len(bits)):
                if nonempty and combo == 0:
                    continue
                have = set(const) | {names[bits[i]] for i in range(len(bits)) if (combo >> i) & 1}
                txt = [nm for nm in order if nm in have]
                out.append({'pat': [f'{G.fld(n, b, b, "u")}={(combo >> i) & 1}' for i, b in enumerate(bits)],
                            'disp': '"%s"' % pretty_list(txt), 'body': 'local m:4 = %d; export m;' % ctx['mask_of'](txt)})
            return out
        # many bits: one table per bit, the display is the chain
        pat, parts, mexpr = [], [], []
        disp = ['"{"']
        for nm in order:
            bsel = [b for b in bits if names[b] == nm]
            if not bsel:
                disp.append('"%s, "' % nm15(nm))
                mexpr.append('(1 << %d)' % uni.index(nm))
                continue
            b = bsel[0]
            fb = G.fld(n, b, b, 'u')
            tb = 'lbit_%s_%d' % (nm, b) if False else None
            sym = 'mb_%d_%d_%s' % (n, b, nm)
            if sym not in G.tables:
                G.tables[sym] = ['%s: "%s, " is %s=1 { }' % (sym, nm15(nm), fb), '%s: "" is %s=0 { }' % (sym, fb)]
            disp.append(sym)
            pat.append(sym)
            pat.append(fb)
            mexpr.append('(%s << %d)' % (fb, uni.index(nm)))
        disp.append('"}"')
        base = {'disp': '^'.join(disp), 'body': 'local m:4 = %s; export m;' % (' | '.join(mexpr) or '0')}
        if nonempty:
            # one alternative per highest set bit: the bits above it are zero (known, so they leave the mask expression)
            outs = []
            order_bits = sorted(bits, reverse=True)
            for k, b in enumerate(order_bits):
                fixed = {hb: 0 for hb in order_bits[:k]}
                fixed[b] = 1
                pat2 = [p for p in pat if not any(p == G.fld(n, hb, hb, 'u') for hb in fixed)]
                pat2 += ['%s=%d' % (G.fld(n, hb, hb, 'u'), v) for hb, v in fixed.items()]
                me = []
                for nm in order:
                    bsel = [bb for bb in bits if names[bb] == nm]
                    if not bsel:
                        me.append('(1 << %d)' % uni.index(nm))
                    elif bsel[0] in fixed:
                        if fixed[bsel[0]]:
                            me.append('(1 << %d)' % uni.index(nm))
                    else:
                        me.append('(%s << %d)' % (G.fld(n, bsel[0], bsel[0], 'u'), uni.index(nm)))
                outs.append(dict(base, pat=pat2, body='local m:4 = %s; export m;' % (' | '.join(me) or '0')))
            return outs
        return [dict(base, pat=pat)]
    raise SystemExit('unknown fit ' + t)


def build_op(form, tok, tpl_roles, universe):
    n = form['n']
    kind = tok['kind']
    fit = tok['fit']
    op = Op()
    op.kind = kind
    ctx = {'target': tpl_roles.get(tok['idx']), 'universe': universe,
           'mask_of': lambda names: sum(1 << universe.index(x) for x in names if x in universe)}
    if fit['type'] == 'const':
        op.const = fit['val']
        if kind == 'R':
            op.disp = '"%s"' % GPR[fit['val']]
            op.val = op.reg = GPR[fit['val']]
        elif kind == 'S':
            nm = SFR[fit['val']]
            op.disp = '"%s"' % nm
            op.val = op.reg = nm
        elif kind == 'N':
            op.disp = '"%d"' % fit['val']
            op.val = str(fit['val'] & M32)
        else:
            op.disp = '"%s"' % pretty_list(fit['val'])
            op.val = str(sum(1 << universe.index(x) for x in fit['val']))
        return op
    names = GPR if kind == 'R' else SFR if kind == 'S' else None
    if kind in ('R', 'S'):
        if fit['type'] != 'lin':
            raise SystemExit('register token with %s fit in %s' % (fit['type'], form['tpl']))
        w = {int(b): v for b, v in fit['w'].items()}
        bits = sorted(w)
        c0 = fit['c0']
        contiguous = bits == list(range(bits[0], bits[0] + len(bits)))
        if contiguous and all(w[b] == 1 << (b - bits[0]) for b in bits) and c0 + (1 << len(bits)) <= len(names):
            key = ('attach', n, bits[0], bits[-1], c0, kind)
            if key not in G.cache:
                f = G.fld(n, bits[0], bits[-1], 'att%s%d' % (kind, c0))
                G.fields[n][f] = (bits[0], bits[-1], '')
                G.attach[(kind, c0, len(bits))].append(f)
                G.cache[key] = f
            f = G.cache[key]
            op.disp = op.val = op.reg = f
            op.pat = [f]
            return op
        key = ('regtab', n, json.dumps(fit, sort_keys=True), kind)
        if key not in G.cache:
            sym = G.sym('reg')
            lines = []
            for combo in range(1 << len(bits)):
                v = c0 + sum(w[bits[i]] for i in range(len(bits)) if (combo >> i) & 1)
                if 0 <= v < len(names):
                    lines.append('%s: "%s" is %s { export %s; }' % (sym, names[v], ' & '.join(bit_pat(n, bits, combo)), names[v]))
            G.tables[sym] = lines
            G.cache[key] = sym
        sym = G.cache[key]
        op.disp = op.val = op.reg = sym
        op.pat = [sym]
        return op
    # numbers and lists
    if fit['type'] == 'lin' and kind == 'N' and not ctx['target']:
        terms, c0 = lin_terms(n, fit)
        if len(terms) == 1 and terms[0][1] in (1,) and c0 == 0:
            f = terms[0][0]
            m = re.match(r'f(\d+)_(\d+)_(\d+)(_s)?$', f)
            variant = 'sd' if f.endswith('_s') else 'd'
            lo, hi = int(m.group(2)), int(m.group(3))
            f2 = G.fld(n, lo, hi, variant)
            op.disp = op.val = f2
            op.pat = [f2]
            return op
    key = ('tab', n, json.dumps(fit, sort_keys=True), kind, ctx['target'], tuple(universe))
    if key not in G.cache:
        sym = G.sym('tgt' if ctx['target'] else 'lst' if kind == 'L' else 'num')
        alts = alts_for(n, fit, kind, ctx)
        G.tables[sym] = tbl_lines(sym, alts)
        G.cache[key] = sym
    sym = G.cache[key]
    op.disp = op.val = sym
    op.pat = [sym]
    op.is_target = ctx['target'] == 'next'
    return op


# ------------------------------------------------------------------------------------------------------ forms
def fixed_pattern(form):
    n = form['n']
    m, v = form['mask'], form['val']
    parts = []
    bits = [b for b in range(8 * n) if (m >> b) & 1]
    for r in runs(bits):
        lo, hi = r[0], r[-1]
        val = (v >> lo) & ((1 << (hi - lo + 1)) - 1)
        parts.append('%s=0x%x' % (G.fld(n, lo, hi, 'u'), val))
    return parts


def split_template(tpl):
    """-> list of ('lit', text) / ('tok', index)"""
    out = []
    k = 0
    for piece in re.split(r'(\{[RSNL]\})', tpl):
        if re.fullmatch(r'\{[RSNL]\}', piece):
            out.append(('tok', k))
            k += 1
        elif piece:
            out.append(('lit', piece))
    return out


def q(s):
    return '"%s"' % s.replace('"', '\\"')


def universe_of(form):
    names = []
    for tok in form['tokens']:
        if tok['kind'] != 'L':
            continue
        f = tok['fit']
        if f['type'] == 'const':
            cand = f['val']
        elif f['type'] == 'mask':
            cand = f['order']
        elif f['type'] == 'table':
            cand = [x for v in f['map'].values() if v for x in v]
        else:
            cand = []
        for x in cand:
            if x not in names:
                names.append(x)
    # sub-fits of selectors
    def walk(f):
        if f['type'] == 'sel':
            for c in f['cases'].values():
                walk(c)
        elif f['type'] == 'mask':
            for x in f['order']:
                if x not in names:
                    names.append(x)
        elif f['type'] == 'table':
            for v in f['map'].values():
                for x in (v or []):
                    if x not in names:
                        names.append(x)
    for tok in form['tokens']:
        if tok['kind'] == 'L':
            walk(tok['fit'])
    return names


def target_roles(form):
    """token index -> 'next'|'start' for operands that are branch / pc-relative addresses."""
    tpl = form['tpl']
    roles = {}
    toks = split_template(tpl)
    for i, (k, v) in enumerate(toks):
        if k != 'tok' or form['tokens'][v]['kind'] != 'N':
            continue
        before = ''.join(x[1] if x[0] == 'lit' else '' for x in toks[:i])
        if re.search(r'(goto|call) $', before):
            roles[v] = 'next'
        elif before.endswith('addr('):
            roles[v] = 'start'
    return roles


def dup_op(n, o):
    """A second use of one operand symbol in a constructor needs its own symbol."""
    nw = Op()
    nw.__dict__.update(o.__dict__)
    if o.disp in G.tables:
        G.counter += 1
        new = o.disp + '_%d' % G.counter
        G.tables[new] = [re.sub(r'^%s:' % re.escape(o.disp), new + ':', l) for l in G.tables[o.disp]]
        nw.disp = nw.val = nw.reg = new
        nw.pat = [new]
        return nw
    for key, fl in list(G.attach.items()):
        if o.disp in fl:
            new = o.disp + '_2'
            lo, hi, a = G.fields[n][o.disp]
            G.fields[n][new] = (lo, hi, a)
            if new not in G.attach[key]:
                G.attach[key].append(new)
            nw.disp = nw.val = nw.reg = new
            nw.pat = [new]
            return nw
    return nw


def sem_jl_extra():
    import sem_jl
    x = list(sem_jl.EXTRA_PATS)
    sem_jl.EXTRA_PATS.clear()
    return x


def drop_zero_offset(form):
    """'[sp]'-style forms have no offset field: undo the canonical '[R+ 0]' that jl_infer used to unify the zero-omitting forms."""
    tpl = form['tpl']
    toks = form['tokens']
    idx = [i for i, t in enumerate(toks) if t['kind'] == 'N' and t['fit']['type'] == 'const' and t['fit']['val'] == 0]
    if not idx:
        return form
    pieces = re.split(r'(\{[RSNL]\})', tpl)
    k = -1
    out = []
    drop = set()
    for p in pieces:
        if re.fullmatch(r'\{[RSNL]\}', p):
            k += 1
        out.append(p)
    # find the pattern '[{R}+ {N}]' / '[{R}+{N}]' and check that its N is a constant zero
    new = tpl
    for m in list(re.finditer(r'\[\{R\}\+ ?\{N\}\]', tpl)):
        before = len(re.findall(r'\{[RSNL]\}', tpl[:m.start()]))
        nk = before + 1
        if nk in idx:
            drop.add(nk)
    if not drop:
        return form
    new = tpl
    for m in reversed(list(re.finditer(r'\[\{R\}\+ ?\{N\}\]', tpl))):
        before = len(re.findall(r'\{[RSNL]\}', tpl[:m.start()]))
        if before + 1 in drop:
            new = new[:m.start()] + '[{R}]' + new[m.end():]
    f2 = dict(form)
    f2['tpl'] = new
    f2['tokens'] = [dict(t, idx=j) for j, t in enumerate(t for i, t in enumerate(toks) if i not in drop)]
    return f2


def gen_form(form, sem):
    form = drop_zero_offset(form)
    n = form['n']
    tpl = form['tpl']
    roles = target_roles(form)
    uni = universe_of(form)
    for t in form['tokens']:
        pass
    toks = form['tokens']
    if re.search(r'd\[\+\+ \{R\} = \{R\}\]', form['tpl']) and toks[0]['bits'] == toks[1]['bits']:
        # JieLi's objdump prints the base register twice for a doubleword pre-increment access (the increment register, bits
        # 24..27 in the kagaimiq documentation's layout, is never shown): decode the field as the documentation lays it out
        toks[1] = dict(toks[1], bits=[24, 25, 26, 27], fit={'type': 'lin', 'w': {'24': 1, '25': 2, '26': 4, '27': 8}, 'c0': 0})
    ops = [build_op(form, tok, roles, uni) for tok in toks]
    used = {}
    for i, o in enumerate(ops):
        if o.const is None and o.disp in used and o.pat:
            ops[i] = dup_op(n, o)
        used[o.disp] = i
    pats = fixed_pattern(form)
    disp = []
    for k, v in split_template(tpl):
        if k == 'lit':
            disp.append(q(v))
        else:
            disp.append(ops[v].disp)
    seen = set(pats)
    for o in ops:
        for p in o.pat:
            if p not in seen:
                seen.add(p)
                pats.append(p)
    # a register that appears twice through one attached field needs a second field object
    shown = collections.Counter()
    disp_text = '^'.join(disp) if disp else '""'
    if disp and not disp[0].startswith('"'):
        disp_text = '^' + disp_text
    for o in ops:
        shown[o.disp] += 1
    res = sem(form, ops, uni, G)
    if res is None:
        return None
    act, body = res
    for x in sem_jl_extra():
        if x not in pats:
            pats.append(x)
    head = ':'
    if ARCH == 'pi32':
        pats.insert(0, 'phase=1')
    return '%s%s is %s%s\n{\n%s}\n' % (head, disp_text, ' & '.join(pats) if pats else 'epsilon', ('\n[ %s ]' % act) if act else '', body)


def emit(sem):
    forms = json.load(open(FORMS))['forms']
    cons = []
    skipped = []
    for f in forms:
        if ARCH == 'q32s' and re.search(r'\{R\} \?\? ', f['tpl']):
            skipped.append(f['tpl'])
            continue
        c = gen_form(f, sem)
        if c is None:
            skipped.append(f['tpl'])
            continue
        cons.append('# %s  (%d bytes, mask %x value %x)\n%s' % (f['tpl'], f['n'], f['mask'], f['val'], c))
    out = ['# GENERATED by tools/gen_jl.py from tools/%s.forms.json; do not edit.\n' % ARCH]
    for n, tn in ((2, 'ins16'), (4, 'ins32'), (6, 'ins48')):
        out.append('define token %s(%d)\n' % (tn, 8 * n))
        for name in sorted(G.fields[n]):
            lo, hi, a = G.fields[n][name]
            out.append('\t%s = (%d,%d)%s\n' % (name, lo, hi, a))
        out.append(';\n')
    for (kind, c0, width), fl in G.attach.items():
        names = (GPR if kind == 'R' else SFR)[c0:c0 + (1 << width)]
        out.append('attach variables [ %s ] [ %s ];\n' % (' '.join(fl), ' '.join(names)))
    import sem_jl as S
    out.append(S.PRELUDE)
    for nm in sorted(S.USEROPS):
        out.append('define pcodeop %s;\n' % nm)
    for sym, lines in G.tables.items():
        out.extend(l + '\n' for l in lines)
    out.append('\n')
    out.extend(c + '\n' for c in cons)
    open(OUT, 'w').write(''.join(out))
    print('wrote', OUT, len(cons), 'constructors;', len(skipped), 'skipped;', len(S.FALLBACK), 'pcodeop fallbacks')
    return skipped


if __name__ == '__main__':
    import sem_jl
    sem_jl.setup(ARCH, GPR, SFR)
    sem_jl.ALL = json.load(open(FORMS))['forms']
    skipped = emit(sem_jl.sem)
    json.dump({'fallback': sem_jl.FALLBACK, 'why': sem_jl.WHY, 'skipped': skipped}, open(OUT + '.report.json', 'w'), indent=1)
