#!/usr/bin/env python3
"""Split JieLi objdump text into a template and operand tokens.

tokenize(text) -> (template, [(kind, value), ...])

kinds
  R  general register  (value 0..15, 'sp' = 15)
  S  special register named sfrN / srN (value N)
  N  number            (value int)
  T  branch/data target printed as <sym+off : addr>   (value addr)
  L  register list     (value tuple of names, in printed order)
The template has {R} {S} {N} {T} {L} where the tokens were; everything else is literal text.
"""
import re

_TOK = re.compile(r'''
    (?P<T><[^<>]*?\ :\ (?P<ta>[0-9a-f]+)\ ?>)
  | (?P<L>\{[^{}]*\})
  | (?P<R>\b(?:r\d+|sp)\b)
  | (?P<S>\b(?:sfr|sr)\d+\b)
  | (?P<N>-?(?:0x[0-9a-fA-F]+|\d+)\b)
''', re.X)


def expand_list(body, sp_is_r15=True):
    names = []
    for part in body.split(','):
        part = part.strip()
        if not part:
            continue
        m = re.fullmatch(r'(?:r|sp)(\d*)-r(\d+)', part)
        if m:
            a, b = (int(m.group(1)) if m.group(1) else 15), int(m.group(2))
            names += ['r%d' % k for k in (range(a, b + 1) if a <= b else range(a, b - 1, -1))]
        else:
            names.append('r15' if (part == 'sp' and sp_is_r15) else part)
    return tuple(names)


def tokenize(text, sp_is_r15=True):
    toks = []
    out = []
    pos = 0
    for m in _TOK.finditer(text):
        k = m.lastgroup
        if k == 'R' and m.group(0) == 'sp' and not sp_is_r15:
            continue
        if k == 'ta':
            k = 'T'
        out.append(text[pos:m.start()])
        pos = m.end()
        s = m.group(0)
        if k == 'T':
            tv = int(m.group('ta'), 16)
            toks.append(('T', tv - (1 << 64) if tv >= 1 << 63 else tv))
        elif k == 'L':
            toks.append(('L', expand_list(s[1:-1], sp_is_r15)))
        elif k == 'R':
            toks.append(('R', 15 if s == 'sp' else int(s[1:])))
        elif k == 'S':
            toks.append(('S', int(re.sub(r'\D', '', s))))
        else:
            toks.append(('N', int(s, 16) if '0x' in s.lower() else int(s)))
        out.append('{%s}' % k)
    out.append(text[pos:])
    return ''.join(out), toks
