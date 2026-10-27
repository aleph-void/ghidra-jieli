#!/usr/bin/env python3
"""Generate data/languages/pi32v2_gen.sinc (token fields, operand tables and one constructor per instruction form)
from the pi32v2 instruction table (tools/pi32v2.toml, CC0-1.0, https://github.com/jvitkauskas/pi32v2-isa).

usage: gen_pi32v2.py [table.toml] [out.sinc]

Design
  * one SLEIGH token per instruction length (16/32/48 bit, little endian, so table word k bit b is token bit 16k+b);
  * parallel twins ('.p' entries) are not generated: pi32v2.slaspec's root tables decode prefix 6 and the
    bit-12 twins of group 7 by re-parsing the low bits; a form without a twin gets `parallel=0`;
  * operand kinds become attached fields (registers) or small tables (numbers, enums, lists);
  * semantics come from sem_pi32v2.py (statement-level compiler of the table's syntax strings).
"""
import collections, os, re, sys, tomllib

HERE = os.path.dirname(os.path.abspath(__file__))
TABLE = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, 'pi32v2.toml')
OUT = sys.argv[2] if len(sys.argv) > 2 else os.path.join(HERE, '..', 'data', 'languages', 'pi32v2_gen.sinc')

SRNAMES = ['reti', 'rete', 'retx', 'rets', 'sr4', 'psr', 'cnum', 'uspn', 'sspn', 'icfgn', 'icfgs', 'icfg', 'usp', 'ssp', 'sp', 'pc']
ATTACH = {
    'gpr': ['r%d' % i for i in range(16)],
    'lo': ['r%d' % i for i in range(8)],
    'hi': ['r%d' % i for i in range(8, 16)],
    'pair': ['r%d_r%d' % (2 * i + 1, 2 * i) for i in range(8)],
    'sr': SRNAMES,
}
KIND_ATTACH = {'gpr': 'gpr', 'gpr_lo': 'lo', 'gpr_hi': 'hi', 'pair': 'pair', 'sr': 'sr'}

table = tomllib.load(open(TABLE, 'rb'))
allins = table['insn']
entries = [e for e in allins if not e['id'].endswith('.p')]
def _canon(e):
    w = [re.sub(r'[^01]', 'x', x) for x in e['encoding']]
    if len(w) == 1:
        w[0] = ('000' if w[0][:3] == '110' else w[0][:3]) + w[0][3:]
    else:
        w[0] = w[0][:3] + w[0][4:]
    return (len(w),) + tuple(w)


twins = set()
_bycanon = collections.defaultdict(list)
for _e in entries:
    _bycanon[_canon(_e)].append(_e['id'])
_ids = {e['id'] for e in entries}
for _e in allins:
    if _e['id'].endswith('.p'):
        c = _bycanon.get(_canon(_e))
        if c:
            twins.update(c)
        elif _e['id'][:-2] in _ids:
            twins.add(_e['id'][:-2])


class Gen:
    def __init__(self):
        self.fields = {1: {}, 2: {}, 3: {}}   # words -> {name: (lo, hi, attrs)}
        self.attach = collections.defaultdict(list)   # attach type -> [field names]
        self.tables = collections.OrderedDict()   # symbol -> list of constructor text
        self.cons = []
        self.sym_cache = {}
        self.counter = 0

    # ---- token fields
    def fld(self, nw, lo, hi, variant='u'):
        """Field of the nw-word token covering bits lo..hi. variant: u, s (signed), or an ATTACH key."""
        name = 'f%d_%d_%d%s' % (nw, lo, hi, '' if variant == 'u' else '_' + variant)
        if name not in self.fields[nw]:
            attrs = {'u': '', 's': ' signed', 'd': ' dec', 'z': '', 'r': ''}.get(variant, '')
            self.fields[nw][name] = (lo, hi, attrs)
            if variant.rstrip('2') in ATTACH:
                self.attach[variant.rstrip('2')].append(name)
        return name

    def new_sym(self, prefix):
        self.counter += 1
        return '%s%d' % (prefix, self.counter)


G = Gen()


def runs_of(enc, letter):
    bits = []
    for wi, w in enumerate(enc):
        for bi, ch in enumerate(w):
            if ch == letter:
                bits.append(16 * wi + 15 - bi)
    return bits  # token bit indices, most significant first (appearance order)


def contiguous(bits):
    out = []
    for b in bits:
        if out and out[-1][-1] - 1 == b:
            out[-1].append(b)
        else:
            out.append([b])
    return out   # each: list of descending bit indices


def field_spec(v):
    if isinstance(v, str):
        return {'kind': v}
    return dict(v)


class Operand:
    """One field of an entry."""
    def __init__(self, name):
        self.name = name
        self.disp = None      # symbol printed
        self.val = None       # symbol/expression usable in p-code
        self.pat = []         # pattern parts to add
        self.kind = None
        self.ctx = None       # python expression text of disassembly-time value (single field only)


def hexc(n):
    return '0x%x' % n


def build_operand(G, e, name, nw, ops_cache):
    spec = field_spec(e['fields'][name])
    spec['target'] = bool(re.search(r'(?:goto|call|gotoss)\s+\{%s\}' % name, e['syntax']))
    kind = spec['kind']
    letters = spec.get('letters', name)
    bits = []
    for L in letters:
        bits += runs_of(e['encoding'], L)
    rs = contiguous(bits)
    op = Operand(name)
    op.kind = kind
    op.spec = spec
    op.runs = rs
    op.width = len(bits)
    key = (nw, kind, tuple(tuple(r) for r in rs), repr(sorted(spec.items(), key=lambda x: x[0])))
    if key in ops_cache:
        c = ops_cache[key]
        op.disp, op.val, op.pat, op.ctx = c.disp, c.val, c.pat, c.ctx
        op.sym = c.sym
        return op
    build_operand2(G, e, op, nw, spec, kind, rs)
    ops_cache[key] = op
    return op


def runfield(G, nw, run, variant='u'):
    return G.fld(nw, run[-1], run[0], variant)


def join_expr(G, nw, rs):
    """Disassembly-time expression joining runs (most significant first) and the total width."""
    parts = []
    total = sum(len(r) for r in rs)
    shift = total
    for r in rs:
        shift -= len(r)
        f = runfield(G, nw, r)
        parts.append('(%s << %d)' % (f, shift) if shift else f)
    return ' | '.join(parts), total


def build_operand2(G, e, op, nw, spec, kind, rs):
    if kind in KIND_ATTACH:
        att = KIND_ATTACH[kind]
        add = 8 if kind == 'gpr_hi' else 0
        if len(rs) == 1:
            f = runfield(G, nw, rs[0], att)
            op.disp = op.val = f
            op.pat = [f]
            op.sym = f
            return
        # split register field: enumerate
        sym = G.new_sym('rsplit')
        width = sum(len(r) for r in rs)
        names = ATTACH[att]
        lines = []
        for v in range(1 << width):
            conds = []
            sh = width
            for r in rs:
                sh -= len(r)
                part = (v >> sh) & ((1 << len(r)) - 1)
                conds.append('%s=%d' % (runfield(G, nw, r), part))
            reg = names[v]
            lines.append('%s: "%s" is %s { export %s; }' % (sym, reg, ' & '.join(conds), reg))
        G.tables[sym] = lines
        op.disp = op.val = sym
        op.pat = [sym]
        op.sym = sym
        return
    if kind == 'enum':
        vals = spec['values']
        sym = G.new_sym('enum')
        width = sum(len(r) for r in rs)
        lines = []
        for v in range(1 << width):
            conds = []
            sh = width
            for r in rs:
                sh -= len(r)
                part = (v >> sh) & ((1 << len(r)) - 1)
                conds.append('%s=%d' % (runfield(G, nw, r), part))
            txt = vals[v] if v < len(vals) else '?%d' % v
            disp = ' %s' % ('"%s"' % txt) if txt else ''
            lines.append('%s:%s is %s { local c:4 = %d; export c; }' % (sym, (' ' + '"%s"' % txt) if txt else '', ' & '.join(conds), v))
        G.tables[sym] = lines
        op.disp = op.val = sym
        op.pat = [sym]
        op.sym = sym
        return
    if kind in ('uimm', 'simm') and spec.get('target'):
        sym = G.new_sym('target')
        expr, width = join_expr(G, nw, rs)
        if kind == 'simm':
            half = 1 << (width - 1)
            expr = '((%s) ^ %d) - %d' % (expr, half, half)
        scale = spec.get('scale', 1)
        if scale != 1:
            expr = '(%s) * %d' % (expr, scale)
        names = [runfield(G, nw, r) for r in rs]
        G.tables[sym] = ['%s: res is %s [ res = inst_next + (%s); ] { export *:4 res; }' % (sym, ' & '.join(names), expr)]
        op.disp = op.val = sym
        op.pat = [sym]
        op.sym = sym
        op.is_target = True
        return
    if kind in ('uimm', 'simm'):
        scale = spec.get('scale', 1)
        add = spec.get('add', 0)
        zero_as = spec.get('zero_as')
        if len(rs) == 1 and scale == 1 and add == 0 and zero_as is None:
            f = runfield(G, nw, rs[0], 's' if kind == 'simm' else 'd')
            op.disp = f
            op.val = f
            op.pat = [f]
            op.sym = f
            op.ctx = f
            return
        sym = G.new_sym('num')
        expr, width = join_expr(G, nw, rs)
        if kind == 'simm':
            half = 1 << (width - 1)
            expr = '((%s) ^ %d) - %d' % (expr, half, half)
        if scale != 1:
            expr = '(%s) * %d' % (expr, scale)
        if add:
            expr = '(%s) + %d' % (expr, add)
        names = [runfield(G, nw, r) for r in rs]
        znames = [runfield(G, nw, r, 'z') for r in rs]
        lines = []
        if zero_as is not None:
            lines.append('%s: res is %s & %s [ res = (%s * 0) + %d; ] { local v:4 = res; export v; }' % (sym, ' & '.join(names), ' & '.join('%s=0' % n for n in znames), names[0], zero_as))
            lines.append('%s: res is %s & (%s) [ res = (%s) + 0; ] { local v:4 = res; export v; }' % (sym, ' & '.join(names), ' | '.join('%s!=0' % n for n in znames), expr))
        else:
            lines.append('%s: res is %s [ res = (%s) + 0; ] { local v:4 = res; export v; }' % (sym, ' & '.join(names), expr))
        G.tables[sym] = lines
        op.disp = op.val = sym
        op.pat = [sym]
        op.sym = sym
        return
    if kind in ('bit', 'invbit'):
        sym = G.new_sym('bit')
        names = [runfield(G, nw, r) for r in rs]
        expr, width = join_expr(G, nw, rs)
        if kind == 'invbit':
            expr = '(1 << (%s)) ^ 0xffffffff' % expr
        else:
            expr = '1 << (%s)' % expr
        G.tables[sym] = ['%s: res is %s [ res = %s; ] { local v:4 = res; export v; }' % (sym, ' & '.join(names), expr)]
        op.disp = op.val = sym
        op.pat = [sym]
        op.sym = sym
        return
    if kind == 'modimm':
        sym = G.new_sym('modimm')
        assert len(rs) == 1 and len(rs[0]) == 12, (e['id'], rs)
        lo = rs[0][-1]
        top = G.fld(nw, lo + 8, lo + 11, 'u')    # bits 11..8
        b7 = G.fld(nw, lo, lo + 7, 'u')            # XY
        sel = G.fld(nw, lo + 10, lo + 11, 'u')     # bits 11..10
        rot = G.fld(nw, lo + 7, lo + 11, 'u')      # bits 11..7
        b6 = G.fld(nw, lo, lo + 6, 'u')            # bits 6..0
        inv = spec.get('invert', False)
        wrap = (lambda x: '(%s) ^ 0xffffffff' % x) if inv else (lambda x: x)
        lines = []
        for t, ex in ((0, '%s'), (1, '(%s << 16) | %s'), (2, '(%s << 24) | (%s << 8)'), (3, '(%s << 24) | (%s << 16) | (%s << 8) | %s')):
            e_ = ex % tuple([b7] * ex.count('%s'))
            e_ = '(%s) | 0' % e_
            lines.append('%s: res is %s=%d & %s [ res = %s; ] { local v:4 = res; export v; }' % (sym, G.fld(nw, lo + 8, lo + 11, 'u'), t, b7, wrap(e_)))
        # rotated forms: bits 11..10 != 0: value = ror32(0x80 | b6, rot)
        lines.append('%s: res is %s!=0 & %s & %s [ res = ((((0x80 | %s) >> %s) | ((0x80 | %s) << (32 - %s))) & 0xffffffff); ] { local v:4 = res; export v; }'
                     % (sym, sel, b6, rot, b6, rot, b6, rot))
        if inv:
            lines[-1] = lines[-1].replace('[ res = (', '[ res = (0xffffffff ^ (').replace('& 0xffffffff); ]', '& 0xffffffff)); ]')
        G.tables[sym] = lines
        op.disp = op.val = sym
        op.pat = [sym]
        op.sym = sym
        return
    if kind == 'rlist4':
        sym = G.new_sym('rlist4')
        assert len(rs) == 1
        f = runfield(G, nw, rs[0])
        lines = []
        for v in range(16):
            if v < 4:
                regs = ['r%d' % i for i in range(3, v - 1, -1)]
            else:
                regs = ['r%d' % i for i in range(v, 3, -1)]
            mask = sum(1 << int(x[1:]) for x in regs)
            lines.append('%s: "%s" is %s=%d { local c:4 = %d; export c; }' % (sym, ' '.join(regs), f, v, mask))
        G.tables[sym] = lines
        op.disp = op.val = sym
        op.pat = [sym]
        op.sym = sym
        return
    if kind in ('rmask', 'srmask'):
        sym = G.new_sym(kind)
        assert len(rs) == 1
        w = len(rs[0])
        lo = rs[0][-1]
        f = runfield(G, nw, rs[0])
        names = ['r%d' % i for i in range(16)] if kind == 'rmask' else SRNAMES
        lead = spec.get('lead')
        # display: chain of per-bit tables, highest first
        for i in range(w - 1, -1, -1):
            bf = G.fld(nw, lo + i, lo + i, 'u')
            G.tables.setdefault('%s_b%d' % (sym, i), [
                '%s_b%d: "%s " is %s=1 { }' % (sym, i, names[i], bf),
                '%s_b%d: is %s=0 { }' % (sym, i, bf)])
        disp = '^'.join('%s_b%d' % (sym, i) for i in range(w - 1, -1, -1))
        if lead:
            disp = '"%s "^%s' % (lead, disp)
        chain = ' & '.join('%s_b%d' % (sym, i) for i in range(w - 1, -1, -1))
        G.tables[sym] = ['%s: %s is %s & %s { local m:4 = %s; export m; }' % (sym, disp, f, chain, f)]
        # a disp symbol whose text is the chain
        op.disp = op.val = sym
        op.pat = [sym]
        op.sym = sym
        return
    if kind == 'pair_regs':
        sym = G.new_sym('pairregs')
        lines = []
        width = sum(len(r) for r in rs)
        assert width == 5
        for v in range(32):
            conds = []
            sh = width
            for r in rs:
                sh -= len(r)
                conds.append('%s=%d' % (runfield(G, nw, r), (v >> sh) & ((1 << len(r)) - 1)))
            pn = v >> 2
            a, b = 2 * pn + ((v >> 1) & 1), 2 * pn + (v & 1)
            lines.append('%s: "r%d,r%d" is %s { }' % (sym, a, b, ' & '.join(conds)))
        G.tables[sym] = lines
        op.disp = sym
        op.val = None
        op.pat = [sym]
        op.sym = sym
        return
    raise SystemExit('unhandled kind %s in %s' % (kind, e['id']))


def parse_syntax(s):
    """Split a syntax string into ('lit', text) and ('fld', name, plus) pieces."""
    out = []
    i = 0
    lit = ''
    while i < len(s):
        if s.startswith('{{', i):
            lit += '{'
            i += 2
        elif s.startswith('}}', i):
            lit += '}'
            i += 2
        elif s[i] == '{':
            j = s.index('}', i)
            body = s[i + 1:j]
            if lit:
                out.append(('lit', lit))
                lit = ''
            plus = body.startswith('+')
            out.append(('fld', body.lstrip('+'), plus))
            i = j + 1
        else:
            lit += s[i]
            i += 1
    if lit:
        out.append(('lit', lit))
    return out


def q(s):
    return '"%s"' % s.replace('"', '\\"')


def gen_entry(e, sem):
    enc = e['encoding']
    nw = len(enc)
    w0 = enc[0]
    prefix = w0[:3]
    group = 7 if prefix == '111' else int(prefix, 2)
    fixed = {}
    for wi, w in enumerate(enc):
        for bi, ch in enumerate(w):
            if ch in '01':
                fixed[16 * wi + 15 - bi] = int(ch)
    # group bits
    for b in (13, 14, 15):
        fixed.pop(b, None)
    if group == 7 and enc[0][3:5] == '00':
        fixed.pop(12, None)
    # field letters: non-fixed letters
    ops = collections.OrderedDict()
    ops_cache = G.sym_cache
    for name in e.get('fields', {}):
        ops[name] = build_operand(G, e, name, nw, ops_cache)
    # fixed constraints as runs
    pats = ['parallel_phase=1', 'group=%d' % group]
    if e['id'] not in twins:
        pats.append('parallel=0')
    bits = sorted(fixed)
    runs = []
    for b in bits:
        if runs and runs[-1][-1] + 1 == b:
            runs[-1].append(b)
        else:
            runs.append([b])
    for r in runs:
        lo, hi = r[0], r[-1]
        val = 0
        for b in r:
            val |= fixed[b] << (b - lo)
        pats.append('%s=%s' % (G.fld(nw, lo, hi, 'u'), hexc(val)))
    for o in ops.values():
        for p in o.pat:
            if p not in pats:
                pats.append(p)
    # display
    disp = ''
    pieces = parse_syntax(e['syntax'])
    dparts = []
    used_disp = set()
    for p in pieces:
        if p[0] == 'lit':
            t = re.sub(r'\s+', ' ', p[1])
            dparts.append(q(t))
        else:
            o = ops.get(p[1])
            if o is None:
                raise SystemExit('syntax field %s not a field in %s' % (p[1], e['id']))
            if p[2]:
                psym = 'plus_' + o.disp
                if psym not in G.tables:
                    nz = 'ne0'
                    # sign-prefixed optional offset: needs the raw runs to test for zero
                    names = [runfield(G, nw, r) for r in o.runs]
                    zero = ' & '.join('%s=0' % n for n in names)
                    nzp = ' | '.join('%s!=0' % n for n in names)
                    G.tables[psym] = ['%s: is %s & %s { local v:4 = %s; export v; }' % (psym, zero, o.disp, o.disp),
                                      '%s: "+"^%s is (%s) & %s { local v:4 = %s; export v; }' % (psym, o.disp, nzp, o.disp, o.disp)]
                o_disp = psym
                o.val = psym
                if psym not in pats:
                    pats = [x for x in pats if x != o.disp]
                    pats.append(psym)
                dparts.append(psym)
            else:
                if o.disp in used_disp and o.kind in KIND_ATTACH and len(o.runs) == 1:
                    alias = runfield(G, nw, o.runs[0], KIND_ATTACH[o.kind] + '2')
                    dparts.append(alias)
                    pats.append(alias)
                else:
                    dparts.append(o.disp)
                    used_disp.add(o.disp)
    disp_text = '^'.join(dparts)
    if not dparts:
        disp_text = '^""'
    if not (dparts and dparts[0].startswith('"')) :
        disp_text = '^' + disp_text if not disp_text.startswith('^') else disp_text
    actions, body = sem(e, ops, G)
    for x in getattr(G, 'extra_pats', []):
        if x not in pats:
            pats.append(x)
    return ':%s is %s%s\n{\n%s}\n' % (disp_text, ' & '.join(pats), ('\n[ %s ]' % actions) if actions else '', body)


def emit(sem):
    cons = []
    for e in entries:
        cons.append('# %s: %s\n%s' % (e['id'], e['syntax'], gen_entry(e, sem)))
    out = []
    out.append('# GENERATED by tools/gen_pi32v2.py from tools/pi32v2.toml; do not edit.\n')
    # tokens
    out.append('define token instr(16)\n\tprefix = (13,15)\n\tins1112 = (11,12)\n')
    for n in sorted(G.fields[1]):
        lo, hi, a = G.fields[1][n]
        out.append('\t%s = (%d,%d)%s\n' % (n, lo, hi, a))
    out.append(';\n')
    for nw, tn in ((2, 'ins32'), (3, 'ins48')):
        out.append('define token %s(%d)\n' % (tn, 16 * nw))
        for n in sorted(G.fields[nw]):
            lo, hi, a = G.fields[nw][n]
            out.append('\t%s = (%d,%d)%s\n' % (n, lo, hi, a))
        out.append(';\n')
    for att, names in G.attach.items():
        out.append('attach variables [ %s ] [ %s ];\n' % (' '.join(names), ' '.join(ATTACH[att])))
    out.append('\n')
    import sem_pi32v2 as S
    out.append(S.FLAG_DEFS)
    for nm in ('Idle', 'CoreSynchronize', 'SystemSynchronize', 'BTBClear', 'Breakpoint', 'HBreakpoint', 'SystemCall', 'ClearLock', 'SetLock',
               'SendEventLocal', 'SendEventGlobal', 'WaitForEvent', 'Trigger', 'SoftwareInterrupt'):
        out.append('define pcodeop %s;\n' % nm)
    for nm in sorted(S.USEROPS):
        out.append('define pcodeop %s;\n' % nm)
    for sym, lines in G.tables.items():
        out.extend(l + '\n' for l in lines)
    out.append('\n')
    out.extend(c + '\n' for c in cons)
    return ''.join(out)


if __name__ == '__main__':
    try:
        from sem_pi32v2 import sem
    except ImportError:
        sys.path.insert(0, HERE)
        from sem_pi32v2 import sem
    text = emit(sem)
    open(OUT, 'w').write(text)
    print('wrote', OUT, len(entries), 'constructors')
