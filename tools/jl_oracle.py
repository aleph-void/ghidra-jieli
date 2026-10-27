#!/usr/bin/env python3
"""Batch front end to JieLi's own objdump (a black box; LLVM 4.0.1 based) for the table inference tools.

decode_many(arch, [bytes, ...]) -> [(length, text), ...]   (length 0 = unknown instruction, text 'BAD')

Each item is padded with zero bytes to SLOT bytes, placed alone in a section of an object file, and the first instruction of
the section is kept.  Environment: TC = the unpacked JieLi toolchain directory (jieli-linux-toolchains-*).
"""
import os, re, subprocess, tempfile
import multiprocessing
Pool = multiprocessing.get_context("fork").Pool

SLOT = 8
CHUNK = 12000
_HDR = re.compile(r'^Disassembly of section s(\d+):')
_LN = re.compile(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s)+)\s*(.*)$')


def _run(args):
    arch, items, mcpu = args
    tc = os.environ['TC']
    d = tempfile.mkdtemp(dir=os.environ.get('TMPDIR'))
    try:
        with open(d + '/a.s', 'w') as f:
            for i, b in enumerate(items):
                f.write('.section s%d,"ax"\n.byte %s\n' % (i, ','.join(str(x) for x in b)))
        cc = [tc + '/' + arch + '/bin/clang', '-target', arch]
        if mcpu:
            cc.append('-mcpu=' + mcpu)
        subprocess.run(cc + ['-c', d + '/a.s', '-o', d + '/a.o'], check=True, capture_output=True)
        r = subprocess.run([tc + '/' + arch + '/bin/objdump', '-d', d + '/a.o'], capture_output=True, text=True)
    finally:
        subprocess.run(['rm', '-rf', d])
    if r.returncode != 0:
        if len(items) == 1:
            return [(0, 'CRASH')]
        h = len(items) // 2
        return _run((arch, items[:h], mcpu)) + _run((arch, items[h:], mcpu))
    res, cur, got = {}, None, False
    for l in r.stdout.splitlines():
        m = _HDR.match(l)
        if m:
            cur, got = int(m.group(1)), False
            continue
        if cur is None or got:
            continue
        m = _LN.match(l)
        if not m or int(m.group(1), 16) != 0:
            continue
        got = True
        t = m.group(3).strip()
        if t.startswith('<unk'):
            res[cur] = (0, 'BAD')
        else:
            res[cur] = (len(m.group(2).split()), re.sub(r'\s+', ' ', t))
    return [res.get(i, (0, 'BAD')) for i in range(len(items))]


_pool = None


# JieLi's q32s objdump crashes when an instruction *starts* with the word 0xf34f.  Such a word inside a slot is hidden
# (the slot is cut there and zero padded); if the first instruction turns out to reach it, the slot is run alone.
CRASH_WORDS = {'q32s': (b'\x4f\xf3',)}


def decode_many(arch, items, mcpu=None, jobs=None):
    cw = CRASH_WORDS.get(arch, ())
    items = [bytes(b)[:SLOT].ljust(SLOT, b'\0') for b in items]
    cut = {}
    if cw:
        for i, b in enumerate(items):
            for j in range(0, SLOT, 2):
                if b[j:j + 2] in cw:
                    if j == 0:
                        cut[i] = (0, b)
                    else:
                        cut[i] = (j, b)
                        items[i] = b[:j].ljust(SLOT, b'\0')
                    break
    res = _decode(arch, items, mcpu, jobs)
    for i, (j, orig) in cut.items():
        if j == 0:
            res[i] = (0, 'CRASH')
        elif res[i][0] > j:
            res[i] = _run((arch, [orig], mcpu))[0]
    return res


def _decode(arch, items, mcpu=None, jobs=None):
    global _pool
    chunks = [(arch, items[i:i + CHUNK], mcpu) for i in range(0, len(items), CHUNK)]
    if len(chunks) == 1:
        return _run(chunks[0])
    if _pool is None:
        _pool = Pool(jobs or int(os.environ.get('JOBS', '4')))
    out = []
    for r in _pool.map(_run, chunks):
        out.extend(r)
    return out
