#!/usr/bin/env python3
"""Run JieLi's own objdump (LLVM 4.0.1 based, a black box) over a corpus of fixed-size slots.
usage: oracle.py <arch pi32|pi32v2|q32s> <corpus.bin> <out.txt> [slot=8] [mattr]
Each slot is assembled as .byte data in its own section; only the first instruction of the section is kept.
Output: "<slot> <length> <text>"  (length 0 = <unknown instruction>).  Env TC = unpacked toolchain dir."""
import os, re, subprocess, sys, tempfile
from multiprocessing import Pool
arch, corpus, outp = sys.argv[1:4]
slot = int(sys.argv[4]) if len(sys.argv) > 4 else 8
mattr = sys.argv[5] if len(sys.argv) > 5 else ''
TC = os.environ['TC']
CH = 20000
hdr = re.compile(r'^Disassembly of section s(\d+):')
ln = re.compile(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s)+)\s*(.*)$')

def work(args):
    base, data = args
    d = tempfile.mkdtemp(dir=os.environ.get('TMPDIR'))
    s, o = d + '/a.s', d + '/a.o'
    with open(s, 'w') as f:
        for i in range(len(data) // slot):
            f.write('.section s%d,"ax"\n.byte %s\n' % (i, ','.join(str(b) for b in data[i*slot:(i+1)*slot])))
    cc = [TC + '/' + arch + '/bin/clang', '-target', arch, '-c', s, '-o', o]
    if mattr: cc += ['-mattr=' + mattr] if False else []
    subprocess.run(cc, check=True)
    cmd = [TC + '/' + arch + '/bin/objdump', '-d', o]
    extra = [x for x in os.environ.get('OBJDUMP_ARGS', '').split() if x]
    cmd[1:1] = extra
    if mattr: cmd.insert(1, '-mattr=' + mattr)
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        os.system('rm -rf ' + d)
        n = len(data) // slot
        if n == 1:
            return base, {0: (0, 'CRASH')}
        h = n // 2 * slot
        _, a = work((base, data[:h]))
        _, b = work((base + h // slot, data[h:]))
        b = {k + h // slot: v for k, v in b.items()}
        a.update(b)
        return base, a
    txt = r.stdout
    res, cur, got = {}, None, False
    for l in txt.splitlines():
        m = hdr.match(l)
        if m:
            cur, got = int(m.group(1)), False
            continue
        if cur is None or got or ':' not in l:
            continue
        m = ln.match(l)
        if not m or int(m.group(1), 16) != 0:
            continue
        got = True
        nb = len(m.group(2).split())
        t = m.group(3).strip()
        if t.startswith('<unk'):
            res[cur] = (0, 'BAD')
        else:
            res[cur] = (nb, re.sub(r'\s+', ' ', t))
    os.system('rm -rf ' + d)
    return base, res

if __name__ == '__main__':
    data = open(corpus, 'rb').read()
    jobs = [(i // slot, data[i:i + CH * slot]) for i in range(0, len(data), CH * slot)]
    with Pool(int(os.environ.get('JOBS', '4'))) as p, open(outp, 'w') as out:
        for base, res in p.imap(work, jobs):
            for i in sorted(res):
                out.write('%d %d %s\n' % (base + i, res[i][0], res[i][1]))
