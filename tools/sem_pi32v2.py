"""P-code for the generated pi32v2 constructors, compiled from the table's syntax strings.

sem(entry, operands, gen) -> (disassembly actions, p-code body).  A form whose behaviour p-code cannot express or that
is not known (DSP lanes, FPU, hardware state) calls a user-defined operation named after its table id, with every
operand but the destination as arguments and the destination assigned from the result.

Behaviour comes from the table's own summaries (CC0, hardware-tested notes); see GHIDRA-RARE.md for what is modelled.
"""
import re

WHY = {}
FALLBACK = []          # ids that use a pcodeop
USEROPS = {}           # name -> (nargs) for the pcodeop definitions
M = 0xffffffff

NAMES_SR = ['reti', 'rete', 'retx', 'rets', 'sr4', 'psr', 'cnum', 'uspn', 'sspn', 'icfgn', 'icfgs', 'icfg', 'usp', 'ssp', 'sp', 'pc']

# ---- flags (psr bits: V=0, C=1, Z=2, N=3) ---------------------------------------------------------------------------

FLAG_DEFS = '''
macro setNZ(res) {
	psr = (psr & 0xfffffff3) | (zext(res == 0) << 2) | (zext(res s< 0) << 3);
}
macro setAdd(a, b, res) {
	psr = (psr & 0xfffffff0) | zext(((a ^ res) & (b ^ res)) s< 0) | (zext(res < a) << 1) | (zext(res == 0) << 2) | (zext(res s< 0) << 3);
}
macro setSub(a, b, res) {
	psr = (psr & 0xfffffff0) | zext(((a ^ b) & (a ^ res)) s< 0) | (zext(a >= b) << 1) | (zext(res == 0) << 2) | (zext(res s< 0) << 3);
}
'''


def sname(e):
    return 'pi32v2_' + re.sub(r'[^A-Za-z0-9]', '_', e['id'])


class Ctx:
    def __init__(self, e, ops):
        self.e = e
        self.ops = ops
        self.lines = []
        self.actions = []
        self.n = 0
        self.fail = False

    def tmp(self, size=4):
        self.n += 1
        return 't%d' % self.n

    def emit(self, s):
        self.lines.append('\t' + s)

    def op(self, name):
        if name not in self.ops:
            raise KeyError(name)
        return self.ops[name]

    # operand access
    def rd(self, name):
        o = self.op(name)
        if o.kind in ('gpr', 'gpr_lo', 'gpr_hi', 'pair', 'sr'):
            return o.val
        if o.kind in ('uimm', 'simm', 'bit', 'invbit', 'modimm', 'enum'):
            if o.ctx or o.val is None:
                return '(%s:4)' % o.val
            if re.fullmatch(r'f\d+_\d+_\d+\w*', o.val):
                return '(%s:4)' % o.val
            return o.val
        raise KeyError(name)

    def size(self, name):
        return 8 if self.op(name).kind == 'pair' else 4

    def isnum(self, name):
        return self.op(name).kind not in ('gpr', 'gpr_lo', 'gpr_hi', 'pair', 'sr')


class Unsupported(Exception):
    pass


BIN = {
    '+': '({a} + {b})', '-': '({a} - {b})', '*': '({a} * {b})', '&': '({a} & {b})', '|': '({a} | {b})', '^': '({a} ^ {b})',
}


def alu(c, op, a, b, size=4):
    """Expression string for a OP b."""
    if op in BIN:
        return BIN[op].format(a=a, b=b)
    if op == '<<':
        return '({a} << {b})'.format(a=a, b=b)
    if op == '>>':
        return '({a} >> {b})'.format(a=a, b=b)
    if op == '>>>':
        return '({a} s>> {b})'.format(a=a, b=b)
    raise Unsupported(op)


def mem_term(c, text):
    """Parse a memory operand 'b[...]' ... returns (size, pre_lines, addr_expr, post_lines)."""
    m = re.fullmatch(r'([bhd]?)\[(.*)\]', text.strip())
    if not m:
        raise Unsupported('mem ' + text)
    sz = {'': 4, 'b': 1, 'h': 2, 'd': 8}[m.group(1)]
    inner = m.group(2).strip()
    pre, post = [], []
    ph = PH
    mm = re.fullmatch(ph + r'\s*\+\s*' + ph, inner)
    if mm:
        return sz, pre, '(%s + %s)' % (c.rd(mm.group(1)), c.rd(mm.group(2))), post
    mm = re.fullmatch(ph + r'\s*\+\s*' + ph + r'<<(\d)', inner)
    if mm:
        return sz, pre, '(%s + (%s << %s))' % (c.rd(mm.group(1)), c.rd(mm.group(2)), mm.group(3)), post
    mm = re.fullmatch(r'sp\s*\+?\s*' + ph, inner)
    if mm:
        return sz, pre, '(sp + %s)' % c.rd(mm.group(1)), post
    if inner == 'sp':
        return sz, pre, 'sp', post
    mm = re.fullmatch(r'\+\+' + ph + '=' + ph, inner)
    if mm:
        b = c.rd(mm.group(1))
        pre.append('%s = %s + %s;' % (b, b, c.rd(mm.group(2))))
        return sz, pre, b, post
    mm = re.fullmatch(ph + r'\+\+=' + ph, inner)
    if mm:
        b = c.rd(mm.group(1))
        a = c.tmp()
        pre.append('local %s:4 = %s;' % (a, b))
        post.append('%s = %s + %s;' % (b, b, c.rd(mm.group(2))))
        return sz, pre, a, post
    mm = re.fullmatch(r'npc\s*\+\s*' + ph, inner)
    if mm:
        return sz, pre, '(((inst_start + 4 + 3) & 0xfffffffc) + %s)' % c.rd(mm.group(1)), post
    mm = re.fullmatch(ph, inner)
    if mm:
        return sz, pre, c.rd(mm.group(1)), post
    raise Unsupported('addr ' + inner)


def load_expr(sz, addr, sign):
    if sz == 4:
        return '*:4 %s' % addr
    if sz == 8:
        return '*:8 %s' % addr
    return ('sext' if sign == 's' else 'zext') + '(*:%d %s)' % (sz, addr)


def sem(e, ops, G):
    c = Ctx(e, ops)
    c.G = G
    G.extra_pats = []
    try:
        r = compile_entry(c, e, ops)
    except (Unsupported, KeyError, AttributeError, IndexError) as ex:
        import traceback
        WHY[e['id']] = repr(ex) + ' ' + traceback.format_exc().splitlines()[-3].strip()
        r = None
    if r is None:
        return fallback(c, e, ops)
    actions, body = r
    return actions, ''.join(l + '\n' for l in c.lines) if body is None else body


def fallback(c, e, ops):
    FALLBACK.append(e['id'])
    name = sname(e)
    syn = e['syntax']
    names = [m for m in re.findall(r'\{\+?(\w+)\}', syn)]
    names = list(dict.fromkeys(names))
    # destination: the first placeholder when the text starts with it
    first = re.match(r'\{(\w+)\}', syn)
    dest = None
    if first and first.group(1) in ops and ops[first.group(1)].kind in ('gpr', 'gpr_lo', 'gpr_hi', 'pair', 'sr'):
        dest = first.group(1)
    args = []
    for n in names:
        o = ops.get(n)
        if o is None or o.val is None:
            continue
        if o.kind in ('gpr', 'gpr_lo', 'gpr_hi', 'pair', 'sr'):
            args.append(o.val)
        else:
            args.append('%s:4' % o.val if not o.val.startswith(('num', 'enum', 'modimm', 'bit', 'plus', 'target', 'rlist', 'rmask', 'srmask')) else o.val)
    USEROPS[name] = len(args)
    ctxa = block_actions(e, ops)
    body = ''
    call = '%s(%s)' % (name, ', '.join(args))
    if dest and ops[dest].kind == 'pair':
        body = '\t%s = %s;\n' % (ops[dest].val, call)
    elif dest:
        body = '\t%s = %s;\n' % (ops[dest].val, call)
    else:
        body = '\t%s;\n' % call
    return ctxa, body


def block_actions(e, ops):
    return ''



PH = r'\{\+?(\w+)\}'
UNIT = {
    'nop': '', 'idle': 'Idle();', 'csync': 'CoreSynchronize();', 'ssync': 'SystemSynchronize();', 'btbclr': 'BTBClear();',
    'bkpt': 'Breakpoint();', 'hbkpt': 'HBreakpoint();', 'syscall': 'SystemCall();', 'lockclr': 'ClearLock();', 'lockset': 'SetLock();',
    'sevl': 'SendEventLocal();', 'sevg': 'SendEventGlobal();', 'wfe': 'WaitForEvent();', 'trigger': 'Trigger();',
    'cli': 'icfg = icfg & 0xfffffdff;', 'sti': 'icfg = icfg | 0x200;',
    'rts': 'return [rets];', 'rti': 'return [reti];', 'rtx': 'return [retx];', 'rte': 'return [rete];',
    'rtss': 'return [rets];', 'rtns': 'return [reti];', 'rthw': 'return [retx];',
    'cc = 0': 'psr = psr & 0xfffffffd;', 'cc = 1': 'psr = psr | 2;',
}


def flags_nz(c, res):
    c.emit('setNZ(%s);' % res)


def reg_assign(c, dname, expr, flags=None):
    d = c.op(dname).val
    c.emit('%s = %s;' % (d, expr))


def unescape(s):
    out, i = '', 0
    while i < len(s):
        if s.startswith('{{', i):
            out += '\x01'; i += 2
        elif s.startswith('}}', i):
            out += '\x02'; i += 2
        elif s[i] == '{':
            j = s.index('}', i); out += s[i:j + 1]; i = j + 1
        else:
            out += s[i]; i += 1
    return out


def compile_entry(c, e, ops):
    syn = re.sub(r'\s+#$', '', unescape(e['syntax'].rstrip()))
    eid = e['id']
    if syn in UNIT:
        if UNIT[syn]:
            c.emit(UNIT[syn])
        return '', None
    m = re.fullmatch(r'swi ' + PH, syn)
    if m:
        c.emit('SoftwareInterrupt(%s);' % c.rd(m.group(1)))
        return '', None
    if re.fullmatch(r'callns ' + PH, syn):
        return None
    # ---- branches
    m = re.fullmatch(r'(goto|call) ' + PH, syn)
    if m:
        o = c.op(m.group(2))
        if o.kind in ('simm', 'uimm'):
            tgt = o.val
            if m.group(1) == 'call':
                c.emit('rets = inst_next;')
            c.emit('%s %s;' % ('call' if m.group(1) == 'call' else 'goto', '[%s]' % tgt if False else tgt))
            return '', None
        # register target
        if m.group(1) == 'call':
            c.emit('local t:4 = %s;' % o.val)
            c.emit('rets = inst_next;')
            c.emit('call [t];')
        else:
            c.emit('goto [%s];' % o.val)
        return '', None
    if syn == 'pc = [sp++]':
        c.emit('local t:4 = *:4 sp;')
        c.emit('sp = sp + 4;')
        c.emit('return [t];')
        return '', None
    if syn == '[--sp] = rets':
        c.emit('sp = sp - 4;')
        c.emit('*:4 sp = rets;')
        return '', None
    m = re.fullmatch(r'if \(' + PH + r' (==|!=) 0\) goto ' + PH, syn)
    if m:
        cmp_ = '==' if m.group(2) == '==' else '!='
        c.emit('if (%s %s 0) goto %s;' % (c.rd(m.group(1)), cmp_, c.op(m.group(3)).val))
        return '', None
    m = re.fullmatch(r'if \(--' + PH + r' != 0\) goto ' + PH, syn)
    if m:
        r = c.op(m.group(1)).val
        c.emit('%s = %s - 1;' % (r, r))
        c.emit('if (%s != 0) goto %s;' % (r, c.op(m.group(2)).val))
        return '', None
    m = re.fullmatch(r'(if|ifs) \(' + PH + r' (==|!=|>=|<=|<|>) ' + PH + r'\) goto ' + PH, syn)
    if m:
        kind, a, op_, b, t = m.groups()
        a_, b_ = c.rd(a), c.rd(b)
        sg = 's' if kind == 'ifs' and op_ not in ('==', '!=') else ''
        opx = {'>=': sg + '>=', '<=': sg + '<=', '<': sg + '<', '>': sg + '>', '==': '==', '!=': '!='}[op_]
        c.emit('if (%s %s %s) goto %s;' % (a_, opx, b_, c.op(t).val))
        return '', None
    m = re.fullmatch(r'if \(\(' + PH + r' & ' + PH + r'\) (==|!=) 0\) goto ' + PH, syn)
    if m:
        c.emit('if ((%s & %s) %s 0) goto %s;' % (c.rd(m.group(1)), c.rd(m.group(2)), m.group(3), c.op(m.group(4)).val))
        return '', None
    m = re.fullmatch(r'if(eq|ne|cs|cc|hi|ls|ge|lt|gt|le) goto ' + PH, syn)
    if m:
        z, cy, v, n = '((psr >> 2) & 1)', '((psr >> 1) & 1)', '(psr & 1)', '((psr >> 3) & 1)'
        cond = {'eq': z + ' == 1', 'ne': z + ' == 0', 'cs': cy + ' == 1', 'cc': cy + ' == 0',
                'hi': '(%s == 1 && %s == 0)' % (cy, z), 'ls': '(%s == 0 || %s == 1)' % (cy, z),
                'ge': '%s == %s' % (n, v), 'lt': '%s != %s' % (n, v),
                'gt': '(%s == 0 && %s == %s)' % (z, n, v), 'le': '(%s == 1 || %s != %s)' % (z, n, v)}[m.group(1)]
        c.emit('if (%s) goto %s;' % (cond, c.op(m.group(2)).val))
        return '', None

    r = compile_block(c, e, ops, syn) or compile_stack(c, e, ops, syn) or compile_more(c, e, ops, syn) or compile_data(c, e, ops, syn)
    if r is not None:
        return r
    return None


FLAGTEXT = {}


def flagclass(e):
    t = (e.get('summary') or '') + ' ' + (e.get('notes') or '')
    if re.search(r'N, Z, C(?:,| and) ?(?:and )?V', t) or re.search(r'[Ww]rites N, Z, C and V', t) or re.search(r'Sets the carry', t):
        return 'NZCV'
    if re.search(r'N and Z follow', t):
        return 'NZ'
    return ''


def A(c, tok):
    """Operand token -> expression: {x} placeholder or literal sp."""
    if tok == 'sp':
        return 'sp'
    m = re.fullmatch(PH, tok)
    return c.rd(m.group(1))


def Dst(c, tok):
    if tok == 'sp':
        return 'sp'
    m = re.fullmatch(PH, tok)
    return c.op(m.group(1)).val


def apply_flags(c, fc, op_, a, b, res):
    if fc == 'NZCV' and op_ == '+':
        c.emit('setAdd(%s, %s, %s);' % (a, b, res))
    elif fc == 'NZCV' and op_ == '-':
        c.emit('setSub(%s, %s, %s);' % (a, b, res))
    elif fc in ('NZ', 'NZCV'):
        c.emit('setNZ(%s);' % res)


def width_of(c, tok):
    if tok == 'sp':
        return 4
    return c.size(re.fullmatch(PH, tok).group(1))


TOK = r'(\{\+?\w+\}|sp)'
OPS = r'(\+|-|\*|&|\||\^|<<|>>>|>>)'


def compile_data(c, e, ops, syn):
    fc = flagclass(e)
    # ---- plain moves
    m = re.fullmatch(TOK + r' = ' + TOK, syn)
    if m:
        if width_of(c, m.group(1)) != width_of(c, m.group(2)):
            return None
        c.emit('%s = %s;' % (Dst(c, m.group(1)), A(c, m.group(2))))
        return '', None
    m = re.fullmatch(r'(sp|usp|ssp|uspn|sspn) = (sp|usp|ssp|uspn|sspn)', syn)
    if m:
        c.emit('%s = %s;' % (m.group(1), m.group(2)))
        return '', None
    m = re.fullmatch(TOK + r' = 0', syn)
    if m:
        c.emit('%s = 0;' % Dst(c, m.group(1)))
        return '', None
    m = re.fullmatch(r'\{(\w+)\}\{(\w+)\} = \{(\w+)\}', syn)       # r.l / r.h / r.bK = constant
    if m and c.op(m.group(2)).kind == 'enum':
        r, n, v = m.groups()
        width = len(c.op(n).runs[0]) if c.op(n).runs else 1
        sh = 16 if e['id'].startswith('li.half') else 8
        bits = 16 if sh == 16 else 8
        c.emit('local sh:4 = %s * %d;' % (c.rd(n), sh))
        c.emit('local msk:4 = (%d << sh);' % ((1 << bits) - 1))
        c.emit('%s = (%s & ~msk) | ((%s << sh) & msk);' % (c.op(r).val, c.op(r).val, c.rd(v)))
        return '', None
    m = re.fullmatch(r'\{(\w+)\}\{(\w+)\} = \{(\w+)\}\{(\w+)\}', syn)  # mov.half
    if m and c.op(m.group(2)).kind == 'enum':
        r, n, s_, k = m.groups()
        c.emit('local half:4 = (%s >> (%s * 16)) & 0xffff;' % (c.op(s_).val, c.rd(k)))
        c.emit('local sh:4 = %s * 16;' % c.rd(n))
        c.emit('local msk:4 = (0xffff << sh);')
        c.emit('%s = (%s & ~msk) | (half << sh);' % (c.op(r).val, c.op(r).val))
        return '', None
    # ---- extensions
    m = re.fullmatch(TOK + r' = ' + TOK + r'\.(bv|l) \((u|s)\)', syn)
    if m:
        d, sr_, w, sg = m.groups()
        sz = 1 if w == 'bv' else 2
        c.emit('%s = %s(%s:%d);' % (Dst(c, d), 'zext' if sg == 'u' else 'sext', A(c, sr_), sz))
        if fc:
            c.emit('setNZ(%s);' % Dst(c, d))
        return '', None
    m = re.fullmatch(TOK + r' = ~' + TOK, syn)
    if m:
        c.emit('%s = ~%s;' % (Dst(c, m.group(1)), A(c, m.group(2))))
        if fc:
            c.emit('setNZ(%s);' % Dst(c, m.group(1)))
        return '', None
    # ---- ALU
    m = re.fullmatch(TOK + r' = ' + TOK + ' ' + OPS + ' ' + TOK, syn)
    if m and width_of(c, m.group(1)) == 4:
        d, a, op_, b = m.groups()
        if width_of(c, a) == 4 and not (c.op(re.fullmatch(PH, b).group(1)).kind == 'pair' if b != 'sp' else False):
            if op_ in ('<<', '>>', '>>>') and not c.isnum(re.fullmatch(PH, b).group(1)):
                bb = '(%s & 0x3f)' % A(c, b)
            else:
                bb = A(c, b)
            c.emit('local res:4 = %s;' % alu(c, op_, A(c, a), bb))
            apply_flags(c, fc, op_, A(c, a), bb, 'res')
            c.emit('%s = res;' % Dst(c, d))
            return '', None
    m = re.fullmatch(TOK + r' = ' + TOK + r' - ' + TOK, syn)
    m = re.fullmatch(TOK + r' ' + OPS + r'= ' + TOK, syn)
    if m and width_of(c, m.group(1)) == 4 and (m.group(3) == 'sp' or c.size(re.fullmatch(PH, m.group(3)).group(1)) == 4):
        d, op_, b = m.groups()
        bb = A(c, b)
        if op_ in ('<<', '>>', '>>>') and m.group(3) != 'sp' and not c.isnum(re.fullmatch(PH, b).group(1)):
            bb = '(%s & 0x3f)' % bb
        c.emit('local a:4 = %s;' % Dst(c, d))
        c.emit('local res:4 = %s;' % alu(c, op_, 'a', bb))
        apply_flags(c, fc, op_, 'a', bb, 'res')
        c.emit('%s = res;' % Dst(c, d))
        return '', None
    m = re.fullmatch(TOK + r' = ' + TOK + r' & ~' + TOK, syn)
    if m and width_of(c, m.group(1)) == 4:
        c.emit('%s = %s & ~%s;' % (Dst(c, m.group(1)), A(c, m.group(2)), A(c, m.group(3))))
        if fc:
            c.emit('setNZ(%s);' % Dst(c, m.group(1)))
        return '', None
    m = re.fullmatch(TOK + r' = ' + TOK + r' (\||\^|&|& ~) \(1 << ' + TOK + r'\)', syn)
    if m:
        d, a, op_, b = m.groups()
        bit = '(1 << (%s & 31))' % A(c, b)
        if op_ == '& ~':
            bit = '~' + bit
            op_ = '&'
        c.emit('%s = %s %s %s;' % (Dst(c, d), A(c, a), op_, bit))
        if fc:
            c.emit('setNZ(%s);' % Dst(c, d))
        return '', None
    m = re.fullmatch(TOK + r' = ' + TOK + r' & ~\(1 << ' + TOK + r'\)', syn)
    # reverse subtract: n - s
    m = re.fullmatch(TOK + r' = ' + TOK + r' / ' + TOK + r' \((u|s)\)', syn)
    if m and all(width_of(c, t) == 4 for t in m.groups()[:3]):
        d, a, b, sg = m.groups()
        c.emit('%s = %s %s %s;' % (Dst(c, d), A(c, a), '/' if sg == 'u' else 's/', A(c, b)))
        return '', None
    # ---- multiply into pairs
    m = re.fullmatch(r'\{(\w+)\} (=|\+=|-=) ' + TOK + r' \* ' + TOK + r' \((u|s)\)', syn)
    if m and c.op(m.group(1)).kind == 'pair':
        d, op_, a, b, sg = m.groups()
        ext = 'zext' if sg == 'u' else 'sext'
        prod = '(%s(%s) * %s(%s))' % (ext, A(c, a), ext, A(c, b))
        dd = c.op(d).val
        c.emit('%s = %s;' % (dd, prod if op_ == '=' else '%s %s %s' % (dd, '+' if op_ == '+=' else '-', prod)))
        return '', None
    # ---- bit counting and byte order
    m = re.fullmatch(TOK + r' = (popcnt|rev8|rev16|revs|clz|zcmp)\(' + TOK + r'(?:\.l)?\)', syn)
    if m and width_of(c, m.group(1)) == 4 and width_of(c, m.group(3)) == 4:
        d, fn, a = m.groups()
        a = A(c, a)
        D = Dst(c, d)
        if fn == 'popcnt':
            c.emit('%s = popcount(%s);' % (D, a))
        elif fn == 'clz':
            c.emit('%s = lzcount(%s);' % (D, a))
        elif fn == 'rev8':
            c.emit('%s = (%s << 24) | ((%s & 0xff00) << 8) | ((%s >> 8) & 0xff00) | (%s >> 24);' % (D, a, a, a, a))
        elif fn == 'rev16':
            c.emit('%s = ((%s & 0x00ff00ff) << 8) | ((%s >> 8) & 0x00ff00ff);' % (D, a, a))
        elif fn == 'revs':
            c.emit('local sw:2 = ((%s:2 & 0xff) << 8) | ((%s:2 >> 8) & 0xff);' % (a, a))
            c.emit('%s = sext(sw);' % D)
        elif fn == 'zcmp':
            c.emit('%s = zext(%s s> 0) - zext(%s s< 0);' % (D, a, a))
        if fc:
            c.emit('setNZ(%s);' % D)
        return '', None
    return compile_mem(c, e, ops, syn, fc)


def compile_mem(c, e, ops, syn, fc):
    # ---- loads / stores
    m = re.fullmatch(TOK + r' = ([bhd]?\[[^\]]*\])(?: \((u|s)\))?', syn)
    if m:
        d, mem, sg = m.groups()
        sz, pre, addr, post = mem_term(c, mem)
        if sz == 8 and width_of(c, d) != 8:
            return None
        if sz != 8 and width_of(c, d) != 4:
            return None
        for l in pre:
            c.emit(l)
        c.emit('local v:%d = %s;' % (4 if sz != 8 else 8, load_expr(sz, addr, sg)))
        for l in post:
            c.emit(l)
        c.emit('%s = v;' % Dst(c, d))
        return '', None
    m = re.fullmatch(r'([bhd]?\[[^\]]*\]) = ' + TOK + r'(\.h)?', syn)
    if m:
        mem, s_, hi = m.groups()
        sz, pre, addr, post = mem_term(c, mem)
        val = A(c, s_)
        if sz == 8 and width_of(c, s_) != 8:
            return None
        if hi:
            c.emit('local hv:4 = %s >> 16;' % val)
            val = 'hv'
        elif not re.fullmatch(r'[A-Za-z_]\w*', val):
            c.emit('local sv:%d = %s;' % (sz if sz == 8 else 4, val))
            val = 'sv'
        for l in pre:
            c.emit(l)
        if sz == 4 or sz == 8:
            c.emit('*:%d %s = %s;' % (sz, addr, val))
        else:
            c.emit('*:%d %s = %s:%d;' % (sz, addr, val, sz))
        for l in post:
            c.emit(l)
        return '', None
    m = re.fullmatch(r'(\[[^\]]*\]) (\+|-|\||\^|&|<<|>>|>>>)= (.+)', syn)
    if m:
        mem, op_, rhs = m.groups()
        sz, pre, addr, post = mem_term(c, mem)
        mm = re.fullmatch(TOK, rhs)
        if mm:
            val = A(c, rhs)
        elif rhs == '~' + '{s}' or re.fullmatch(r'~' + TOK, rhs):
            val = '~' + A(c, rhs[1:])
        elif re.fullmatch(r'1 << ' + TOK, rhs):
            val = '(1 << (%s & 31))' % A(c, rhs[5:])
        elif re.fullmatch(r'~\(1 << ' + TOK + r'\)', rhs):
            val = '~(1 << (%s & 31))' % A(c, rhs[7:-1])
        else:
            return None
        if op_ in ('<<', '>>', '>>>') and mm and not c.isnum(re.fullmatch(PH, rhs).group(1)):
            val = '(%s & 0x3f)' % val
        c.emit('local a:4 = *:4 %s;' % addr)
        c.emit('local res:4 = %s;' % alu(c, op_, 'a', val))
        c.emit('*:4 %s = res;' % addr)
        if fc:
            apply_flags(c, fc, op_, 'a', val, 'res')
        return '', None
    m = re.fullmatch(r'(\[[^\]]*\]) = \{(\w+)\}', syn)
    return None


FCMP = {'==': 'f==', 'u!=': 'f!=', 'u>=': 'f>=', '<': 'f<', 'u>': 'f>', '<=': 'f<=', '>=': 'f>=', 'u<': 'f<', 'u<=': 'f<=', '!=': 'f!=', '>': 'f>'}


def rawexpr(c, name):
    """Disassembly-time expression of a numeric operand built from its raw field (for context actions)."""
    o = c.op(name)
    assert len(o.runs) == 1, 'split operand in context action'
    r = o.runs[0]
    nw = len(c.e['encoding'])
    f = c.G.fld(nw, r[-1], r[0], 'r')
    c.G.extra_pats.append(f)
    spec = o.spec
    return '(%s * %d + %d)' % (f, spec.get('scale', 1), spec.get('add', 0))


def compile_block(c, e, ops, syn):
    # rep loops
    m = re.fullmatch(r'rep ' + PH + ' ' + PH + r' \x01', syn)
    if m:
        if e['id'] == 'rep':
            n, r_ = m.group(1), m.group(2)
            nbytes, cnt = n, c.op(r_).val
            c.emit('rep_count = %s;' % cnt)
            c.emit('if (%s != 0) goto <run>;' % cnt)
            c.emit('local endaddr:4 = inst_next + %s;' % c.rd(nbytes))
            c.emit('goto [endaddr];')
            c.emit('<run>')
        else:
            b, n = m.group(1), m.group(2)
            nbytes = b
            c.emit('rep_count = %s;' % c.rd(n))
        nb = rawexpr(c, nbytes)
        act = 'repblock_endaddr = inst_start + 2 + (%s); reploop=1; globalset(repblock_endaddr, reploop); replen=%s; globalset(repblock_endaddr, replen);' % (nb, nb)
        return act, None
    m = re.fullmatch(r'(if|ifs|iff) \((.*)\) \x01', syn)
    if not m:
        return None
    kind, cond = m.groups()
    blk = c.e.get('block')
    if not blk:
        return None
    act = ('thenbranch = %s; globalset(inst_next, thenbranch); elsebranch = %s; globalset(inst_next, elsebranch); '
           'ifblock = 1; globalset(inst_next, ifblock);') % (rawexpr(c, blk['then']), rawexpr(c, blk['else']))
    cm = re.fullmatch(PH + r' (==|!=|>=|<=|<|>|u!=|u>=|u>|u<|u<=) ' + PH, cond)
    if cm:
        a, op_, b = cm.groups()
        A_, B_ = c.rd(a), c.rd(b)
        if kind == 'iff':
            if c.e['id'].startswith('iff.ne.rr.') or op_ not in FCMP:
                return None
            if op_.startswith('u'):
                c.emit('cres = zext(nan(%s) || nan(%s) || (%s %s %s));' % (A_, B_, A_, FCMP[op_], B_))
            else:
                c.emit('cres = zext(%s %s %s);' % (A_, FCMP[op_], B_))
        else:
            sg = 's' if kind == 'ifs' and op_ not in ('==', '!=') else ''
            c.emit('cres = zext(%s %s %s);' % (A_, sg + op_ if op_ not in ('==', '!=') else op_, B_))
        return act, None
    cm = re.fullmatch(r'\(' + PH + r' & ' + PH + r'\) (==|!=) 0', cond)
    if cm:
        c.emit('cres = zext((%s & %s) %s 0);' % (c.rd(cm.group(1)), c.rd(cm.group(2)), cm.group(3)))
        return act, None
    return None


def push_pop_regs(c, maskexpr, pop, lead=None):
    """Emit unrolled push (highest register first) or pop (lowest first) for a 16-bit register mask."""
    c.emit('local m:4 = %s;' % maskexpr)
    order = list(range(15, -1, -1)) if not pop else list(range(16))
    for i in order:
        c.emit('if (((m >> %d) & 1) == 0) goto <skip%d>;' % (i, i))
        if pop:
            c.emit('r%d = *:4 sp;' % i)
            c.emit('sp = sp + 4;')
        else:
            c.emit('sp = sp - 4;')
            c.emit('*:4 sp = r%d;' % i)
        c.emit('<skip%d>' % i)


def compile_stack(c, e, ops, syn):
    m = re.fullmatch(r'\[--sp\] = \x01(?:(rets|pc), )?\{\+?(\w+)\}\x02(?: \(c\))?', syn)
    if m and c.op(m.group(2)).kind in ('rlist4', 'rmask'):
        lead, f = m.groups()
        # a push of the special register comes first (stored at the highest address)
        if lead == 'rets':
            c.emit('sp = sp - 4;')
            c.emit('*:4 sp = rets;')
        push_pop_regs(c, c.op(f).val, False)
        return '', None
    m = re.fullmatch(r'\x01(?:(rets|pc), )?\{\+?(\w+)\}\x02 = \[sp\+\+\]', syn)
    if m and c.op(m.group(2)).kind in ('rlist4', 'rmask'):
        lead, f = m.groups()
        push_pop_regs(c, c.op(f).val, True)
        if lead == 'rets':
            c.emit('rets = *:4 sp;')
            c.emit('sp = sp + 4;')
        elif lead == 'pc':
            c.emit('local t:4 = *:4 sp;')
            c.emit('sp = sp + 4;')
            c.emit('return [t];')
        return '', None
    m = re.fullmatch(r'\x01(?:(rets|pc), )?\{\+?(\w+)\}\x02 = \[sp\+\+\]', syn)
    return None


FOPS = {'==': 'f==', '!=': 'f!=', '<': 'f<', '<=': 'f<=', '>': 'f>', '>=': 'f>='}


def brev(c, src, dst):
    b = 'bv%s' % c.tmp()
    c.emit('local %s:4 = %s;' % (b, src))
    c.emit('%s = ((%s >> 1) & 0x55555555) | ((%s & 0x55555555) << 1);' % (b, b, b))
    c.emit('%s = ((%s >> 2) & 0x33333333) | ((%s & 0x33333333) << 2);' % (b, b, b))
    c.emit('%s = ((%s >> 4) & 0x0f0f0f0f) | ((%s & 0x0f0f0f0f) << 4);' % (b, b, b))
    c.emit('%s = ((%s >> 8) & 0x00ff00ff) | ((%s & 0x00ff00ff) << 8);' % (b, b, b))
    c.emit('%s = (%s >> 16) | (%s << 16);' % (dst, b, b))


def compile_more(c, e, ops, syn):
    fc = flagclass(e)
    m = re.fullmatch(r'cc = ' + PH, syn)
    if m:
        c.emit('psr = (psr & 0xfffffffd) | ((%s & 1) << 1);' % c.rd(m.group(1)))
        return '', None
    m = re.fullmatch(r'ifs2ns goto ' + PH + r' \((c|s)\)', syn)
    if m:
        c.emit('if ((r0 & 1) %s 0) goto %s;' % ('==' if m.group(2) == 'c' else '!=', c.op(m.group(1)).val))
        return '', None
    m = re.fullmatch(r'iff \(' + PH + r' (==|!=|<|<=|>|>=|u==|u!=|u<|u<=|u>|u>=|uno|ord) ' + PH + r'\) goto ' + PH, syn)
    if m:
        a, op_, b, t = m.groups()
        A_, B_ = c.rd(a), c.rd(b)
        if op_ == 'uno':
            cond = '(nan(%s) || nan(%s))' % (A_, B_)
        elif op_ == 'ord':
            cond = '!(nan(%s) || nan(%s))' % (A_, B_)
        elif op_.startswith('u'):
            cond = '(nan(%s) || nan(%s) || (%s %s %s))' % (A_, B_, A_, FOPS[op_[1:]], B_)
        else:
            cond = '(%s %s %s)' % (A_, FOPS[op_], B_)
        c.emit('if %s goto %s;' % (cond, c.op(t).val))
        return '', None
    m = re.fullmatch(r'gotoss ' + PH, syn)
    if m:
        c.emit('rets = inst_next;')
        c.emit('call %s;' % c.op(m.group(1)).val)
        return '', None
    m = re.fullmatch(r'(tbb|tbh) \[' + PH + r'\]', syn)
    if m:
        w = 1 if m.group(1) == 'tbb' else 2
        c.emit('local idx:4 = %s;' % c.rd(m.group(2)))
        c.emit('local ent:4 = zext(*:%d (inst_next + idx));' % w)
        c.emit('local tgt:4 = inst_next + (ent * 2);')
        c.emit('goto [tgt];')
        return '', None
    m = re.fullmatch(r'testset b\[' + PH + r'\]', syn)
    if m:
        c.emit('local old:1 = *:1 %s;' % c.rd(m.group(1)))
        c.emit('*:1 %s = 0xff;' % c.rd(m.group(1)))
        c.emit('psr = (psr & 0xfffffff0) | (zext(old) & 0xf);')
        return '', None
    m = re.fullmatch(r'cli ' + PH, syn)
    if m:
        c.emit('%s = icfg;' % c.op(m.group(1)).val)
        c.emit('icfg = icfg & 0xfffffdff;')
        return '', None
    m = re.fullmatch(r'sti ' + PH, syn)
    if m:
        c.emit('icfg = (icfg & 0xfffffdff) | (%s & 0x200);' % c.rd(m.group(1)))
        return '', None
    # add / sub with carry
    m = re.fullmatch(TOK + r' = ' + TOK + r' \+ ' + TOK + r' \+ c', syn)
    if m and e['id'].startswith('addc'):
        d, a, b = (Dst(c, m.group(1)), A(c, m.group(2)), A(c, m.group(3)))
        c.emit('local cin:4 = (psr >> 1) & 1;')
        c.emit('local w:8 = zext(%s) + zext(%s) + zext(cin);' % (a, b))
        c.emit('local res:4 = w:4;')
        c.emit('psr = (psr & 0xfffffff0) | zext(((%s ^ res) & (%s ^ res)) s< 0) | (zext((w >> 32) != 0) << 1) | (zext(res == 0) << 2) | (zext(res s< 0) << 3);' % (a, b))
        c.emit('%s = res;' % d)
        return '', None
    m = re.fullmatch(TOK + r' = ' + TOK + r' - ' + TOK + r' - !c', syn)
    if m:
        d, a, b = (Dst(c, m.group(1)), A(c, m.group(2)), A(c, m.group(3)))
        c.emit('local bin:4 = 1 - ((psr >> 1) & 1);')
        c.emit('local res:4 = %s - %s - bin;' % (a, b))
        c.emit('local ax:8 = zext(%s);' % a)
        c.emit('local bx:8 = zext(%s) + zext(bin);' % b)
        c.emit('psr = (psr & 0xfffffff0) | zext(((%s ^ %s) & (%s ^ res)) s< 0) | (zext(ax >= bx) << 1) | (zext(res == 0) << 2) | (zext(res s< 0) << 3);' % (a, b, a))
        c.emit('%s = res;' % d)
        return '', None
    m = re.fullmatch(TOK + r' \+= ' + TOK + r' \(brev\)', syn)
    if m:
        d, s_ = Dst(c, m.group(1)), A(c, m.group(2))
        c.emit('local ra:4 = 0;')
        brev(c, d, 'ra')
        c.emit('local rb:4 = 0;')
        brev(c, s_, 'rb')
        c.emit('local w:8 = zext(ra) + zext(rb);')
        c.emit('local sum:4 = w:4;')
        c.emit('local res:4 = 0;')
        brev(c, 'sum', 'res')
        c.emit('psr = (psr & 0xfffffff0) | zext(((ra ^ sum) & (rb ^ sum)) s< 0) | (zext((w >> 32) != 0) << 1) | (zext(res == 0) << 2) | (zext(res s< 0) << 3);')
        c.emit('%s = res;' % d)
        return '', None
    # rotates, saturating shifts, signed-count shift, carry rotate
    m = re.fullmatch(TOK + r' = ' + TOK + r' (<>|<<<|<c>|><) ' + TOK, syn)
    if m and width_of(c, m.group(1)) == 4 and width_of(c, m.group(2)) == 4:
        d, a, op_, b = m.groups()
        D, A_ = Dst(c, d), A(c, a)
        bnum = b != 'sp' and c.isnum(re.fullmatch(PH, b).group(1))
        n = A(c, b)
        if op_ == '<>':
            c.emit('local n:4 = %s;' % (n if bnum else '(%s & 31)' % n))
            c.emit('local res:4 = (%s >> n) | (%s << (32 - n));' % (A_, A_))
            c.emit('%s = res;' % D)
            if fc:
                c.emit('setNZ(res);')
            return '', None
        if op_ == '<<<':
            c.emit('local n:4 = %s;' % (n if bnum else '(%s & 63)' % n))
            c.emit('local w:8 = sext(%s) << n;' % A_)
            c.emit('local res:4 = w:4;')
            c.emit('if (w s> 0x7fffffff) goto <pos>;')
            c.emit('if (w s< -0x80000000) goto <neg>;')
            c.emit('goto <done>;')
            c.emit('<pos>')
            c.emit('res = 0x7fffffff;')
            c.emit('goto <done>;')
            c.emit('<neg>')
            c.emit('res = 0x80000000;')
            c.emit('<done>')
            c.emit('%s = res;' % D)
            if fc:
                c.emit('setNZ(res);')
            return '', None
        if op_ == '<c>':
            c.emit('local n:4 = %s;' % (n if bnum else '(%s & 63)' % n))
            c.emit('local c8:8 = zext((psr >> 1) & 1);')
            c.emit('local a8:8 = zext(%s);' % A_)
            c.emit('local x:8 = (c8 << 32) | a8;')
            c.emit('local y:8 = ((x >> n) | (x << (33 - n))) & 0x1ffffffff;')
            c.emit('local res:4 = y:4;')
            c.emit('%s = res;' % D)
            c.emit('local yh:8 = y >> 32;')
            c.emit('local cy:4 = yh:4 & 1;')
            c.emit('psr = (psr & 0xfffffff1) | (cy << 1) | (zext(res == 0) << 2) | (zext(res s< 0) << 3);')
            return '', None
        if op_ == '><':
            c.emit('local cnt:4 = %s & 0x3f;' % n)
            c.emit('local res:4 = 0;')
            c.emit('if (cnt s>= 32) goto <right>;')
            c.emit('res = %s << cnt;' % A_)
            c.emit('goto <done>;')
            c.emit('<right>')
            c.emit('res = %s >> (64 - cnt);' % A_)
            c.emit('<done>')
            c.emit('%s = res;' % D)
            if fc:
                c.emit('setNZ(res);')
            return '', None
    m = re.fullmatch(TOK + r' <<<= ' + TOK, syn)
    if m and width_of(c, m.group(1)) == 4:
        D = Dst(c, m.group(1))
        n = A(c, m.group(2))
        bnum = c.isnum(re.fullmatch(PH, m.group(2)).group(1))
        c.emit('local n:4 = %s;' % (n if bnum else '(%s & 63)' % n))
        c.emit('local w:8 = sext(%s) << n;' % D)
        c.emit('local res:4 = w:4;')
        c.emit('if (w s> 0x7fffffff) goto <pos>;')
        c.emit('if (w s< -0x80000000) goto <neg>;')
        c.emit('goto <done>;')
        c.emit('<pos>')
        c.emit('res = 0x7fffffff;')
        c.emit('goto <done>;')
        c.emit('<neg>')
        c.emit('res = 0x80000000;')
        c.emit('<done>')
        c.emit('%s = res;' % D)
        if fc:
            c.emit('setNZ(res);')
        return '', None
    m = re.fullmatch(TOK + r' = ' + TOK + r' & ~\(1 << ' + TOK + r'\)', syn)
    if m:
        c.emit('%s = %s & ~(1 << (%s & 31));' % (Dst(c, m.group(1)), A(c, m.group(2)), A(c, m.group(3))))
        if fc:
            c.emit('setNZ(%s);' % Dst(c, m.group(1)))
        return '', None
    m = re.fullmatch(TOK + r' = cls\(' + TOK + r'\)', syn)
    if m:
        c.emit('%s = lzcount(%s ^ (%s s>> 31));' % (Dst(c, m.group(1)), A(c, m.group(2)), A(c, m.group(2))))
        if fc:
            c.emit('setNZ(%s);' % Dst(c, m.group(1)))
        return '', None
    # bit fields
    m = re.fullmatch(TOK + r' (=|<=) (insert|uextra|sextra)\(' + TOK + r', p:(.+), l:(.+)\)', syn)
    if m:
        d, _, fn, sr_, pp, ll = m.groups()
        def fld(t):
            mm = re.fullmatch(PH + r'\[(\d+):(\d+)\]', t)
            if mm:
                hi, lo = int(mm.group(2)), int(mm.group(3))
                return '((%s >> %d) & %d)' % (c.rd(mm.group(1)), lo, (1 << (hi - lo + 1)) - 1)
            return c.rd(re.fullmatch(PH, t).group(1))
        p_, l_ = fld(pp), fld(ll)
        D, S_ = Dst(c, d), A(c, sr_)
        c.emit('local p:4 = %s;' % p_)
        c.emit('local l:4 = %s;' % l_)
        c.emit('local mask:4 = (1 << l) - 1;')
        if fn == 'insert':
            c.emit('%s = (%s & ~(mask << p)) | ((%s & mask) << p);' % (D, D, S_))
        elif fn == 'uextra':
            c.emit('%s = (%s >> p) & mask;' % (D, S_))
        else:
            c.emit('%s = (%s << (32 - p - l)) s>> (32 - l);' % (D, S_))
        if fc:
            c.emit('setNZ(%s);' % D)
        return '', None
    # pair shifts by an immediate
    m = re.fullmatch(r'\{(\w+)\} (<<|>>|>>>)= ' + PH, syn)
    if m and c.op(m.group(1)).kind == 'pair' and c.isnum(m.group(3)):
        d = c.op(m.group(1)).val
        c.emit('%s = %s %s %s;' % (d, d, {'<<': '<<', '>>': '>>', '>>>': 's>>'}[m.group(2)], c.rd(m.group(3))))
        return '', None
    m = re.fullmatch(r'\{(\w+)\} <>= ' + PH, syn)
    if m and c.op(m.group(1)).kind == 'pair' and c.isnum(m.group(2)):
        d = c.op(m.group(1)).val
        c.emit('local n:4 = %s;' % c.rd(m.group(2)))
        c.emit('%s = (%s >> n) | (%s << (64 - n));' % (d, d, d))
        return '', None
    m = re.fullmatch(r'\{(\w+)\} = \{(\w+)\} / \{(\w+)\} \((u|s)\)', syn)
    if m and c.op(m.group(1)).kind == 'pair' and c.op(m.group(2)).kind == 'pair':
        d, a, b, sg = m.groups()
        c.emit('local dv:8 = %s;' % ('zext(%s)' % c.rd(b) if sg == 'u' else 'sext(%s)' % c.rd(b)))
        c.emit('local q:8 = 0;')
        c.emit('if (dv == 0) goto <done>;')
        c.emit('q = %s %s dv;' % (c.rd(a), '/' if sg == 'u' else 's/'))
        c.emit('<done>')
        c.emit('%s = q;' % c.op(d).val)
        return '', None
    # ldm / stm
    m = re.fullmatch(r'(?:\x01(\{\+?\w+\})\x02 = \[(-|--)?\{\+?(\w+)\}(\+|\+\+)?\]|\[(-|--)?\{\+?(\w+)\}(\+|\+\+)?\] = \x01(\{\+?\w+\})\x02)', syn)
    if m:
        g = m.groups()
        if g[0]:
            load, mk, pre, base, post = True, re.fullmatch(PH, g[0]).group(1), g[1], g[2], g[3]
        else:
            load, mk, pre, base, post = False, re.fullmatch(PH, g[7]).group(1), g[4], g[5], g[6]
        if c.op(mk).kind != 'rmask':
            return None
        B = c.op(base).val
        update = pre == '--' or post == '++'
        c.emit('local m:4 = %s;' % c.op(mk).val)
        c.emit('local cnt4:4 = popcount(m) * 4;')
        c.emit('local a:4 = %s;' % B)
        if pre:
            c.emit('a = a - cnt4;')
        if update and load:
            c.emit('%s = %s;' % (B, 'a' if pre else '%s + cnt4' % B))
        for i in range(16):
            c.emit('if (((m >> %d) & 1) == 0) goto <skip%d>;' % (i, i))
            c.emit(('r%d = *:4 a;' if load else '*:4 a = r%d;') % i)
            c.emit('a = a + 4;')
            c.emit('<skip%d>' % i)
        if update and not load:
            c.emit('%s = %s;' % (B, 'a - cnt4' if pre else 'a'))
        return '', None
    # srmask push/pop
    m = re.fullmatch(r'\[--sp\] = \x01\{\+?(\w+)\}\x02(?: \(c\))?', syn)
    if m and c.op(m.group(1)).kind == 'srmask':
        c.emit('local m:4 = %s;' % c.op(m.group(1)).val)
        for i in range(15, -1, -1):
            c.emit('if (((m >> %d) & 1) == 0) goto <skip%d>;' % (i, i))
            c.emit('sp = sp - 4;')
            c.emit('*:4 sp = %s;' % NAMES_SR[i])
            c.emit('<skip%d>' % i)
        return '', None
    m = re.fullmatch(r'\x01\{\+?(\w+)\}\x02 = \[sp\+\+\]', syn)
    if m and c.op(m.group(1)).kind == 'srmask':
        c.emit('local m:4 = %s;' % c.op(m.group(1)).val)
        for i in range(16):
            if NAMES_SR[i] in ('pc',):
                c.emit('if (((m >> %d) & 1) == 0) goto <skip%d>;' % (i, i))
                c.emit('local t:4 = *:4 sp;')
                c.emit('sp = sp + 4;')
                c.emit('return [t];')
                c.emit('<skip%d>' % i)
                continue
            c.emit('if (((m >> %d) & 1) == 0) goto <skip%d>;' % (i, i))
            c.emit('%s = *:4 sp;' % NAMES_SR[i])
            c.emit('sp = sp + 4;')
            c.emit('<skip%d>' % i)
        return '', None
    return None
