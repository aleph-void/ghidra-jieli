#!/usr/bin/env python3
"""Hand-computed p-code cases for pi32v2.  Each case: name, assembly (JieLi assembler syntax), initial state, expected state.
Expected values are worked out by hand from the instruction summaries in tools/pi32v2.toml (CC0) and the JieLi
documentation of the instruction set, never from this module's own output.  Memory items: n<size>:<addr>=<value> (little endian).
usage: emu_cases_pi32v2.py <outdir>   writes emu.bin and tests.txt (assembled with JieLi's own clang as a black box)."""
import os, subprocess, sys, tempfile

CASES = []
def case(name, asm, init='-', expect='-', archs=None):
    CASES.append((name, asm, init, expect, archs))

# psr bits: V=0, C=1, Z=2, N=3
case('add_rrr_flags_none', 'r8 = r9 + r10', 'r9=5,r10=7,psr=0', 'r8=c,psr=0')
case('add_carry_zero', 'r8 = r9 + r10', 'r9=ffffffff,r10=1,psr=0', 'r8=0,psr=6')
case('add_signed_overflow', 'r8 = r9 + r10', 'r9=7fffffff,r10=1,psr=0', 'r8=80000000,psr=9')
case('sub_borrow_negative', 'r8 = r9 - r10', 'r9=3,r10=5,psr=0', 'r8=fffffffe,psr=8')
case('sub_equal_no_borrow', 'r8 = r9 - r10', 'r9=5,r10=5,psr=0', 'r8=0,psr=6')
case('and_rrr', 'r8 = r9 & r10', 'r9=f0f0,r10=ff00', 'r8=f000')
case('or_xor', 'r8 = r9 | r10\nr7 = r9 ^ r10', 'r9=f0f0,r10=ff00', 'r8=fff0,r7=0ff0')
case('lsl_imm', 'r8 = r9 << 4', 'r9=12345678', 'r8=23456780')
case('lsr_imm', 'r8 = r9 >> 4', 'r9=12345678', 'r8=01234567')
case('asr_imm_negative', 'r8 = r9 >>> 4', 'r9=80000000', 'r8=f8000000')
case('ror_imm', 'r8 = r9 <> 8', 'r9=12345678', 'r8=78123456')
case('mul_low', 'r8 = r9 * r10', 'r9=10000,r10=10001', 'r8=10000')
case('mul_u64', 'r3_r2 = r4 * r5 (u)', 'r4=ffffffff,r5=ffffffff', 'r2=1,r3=fffffffe')
case('mul_s64', 'r3_r2 = r4 * r5 (s)', 'r4=ffffffff,r5=2', 'r2=fffffffe,r3=ffffffff')
case('div_u', 'r8 = r9 / r10 (u)', 'r9=64,r10=7', 'r8=e')
case('mov_imm_neg', 'r8 = -5', '-', 'r8=fffffffb')
case('half_h', 'r8.h = 0x1234', 'r8=ffffffff', 'r8=1234ffff')
case('half_l', 'r8.l = 0x1234', 'r8=ffffffff', 'r8=ffff1234')
case('ext_b_s', 'r8 = r9.b0 (s)', 'r9=1f0', 'r8=fffffff0')
case('ext_l_u', 'r8 = r9.l (u)', 'r9=abcd1234', 'r8=1234')
case('clz', 'r8 = clz(r9)', 'r9=10000', 'r8=f')
case('store_load_word', '[r1+4] = r2\nr3 = [r1+4]', 'r1=2000,r2=deadbeef', 'r3=deadbeef,n4:2004=deadbeef')
case('load_byte_signed', 'r3 = b[r1+1] (s)\nr4 = b[r1+1] (u)', 'r1=2000,n4:2000=00008000', 'r3=ffffff80,r4=80')
case('load_half_signed', 'r3 = h[r1+2] (s)\nr4 = h[r1+2] (u)', 'r1=2000,n4:2000=8001ffff', 'r3=ffff8001,r4=8001')
case('store_byte_half', 'b[r1+0] = r2\nh[r1+2] = r3', 'r1=2000,r2=12345678,r3=9abcdef0,n4:2000=ffffffff', 'n4:2000=def0ff78')
case('post_increment_load', 'r3 = [r1++=4]', 'r1=2000,n4:2000=cafebabe', 'r3=cafebabe,r1=2004')
case('sp_relative_store', '[sp+8] = r2\nr3 = [sp+8]', 'sp=3000,r2=11223344', 'r3=11223344,n4:3008=11223344')
case('push_pop_regs', '[--sp] = {r3-r0}\nr0 = 0\nr1 = 0\nr2 = 0\nr3 = 0\n{r3-r0} = [sp++]', 'sp=3000,r0=a,r1=b,r2=c,r3=d', 'r0=a,r1=b,r2=c,r3=d,sp=3000,n4:2ff0=a,n4:2ff4=b,n4:2ff8=c,n4:2ffc=d')
case('branch_taken', 'if (r1 == 0) goto L1\nr0 = 1\nL1:\nr2 = 2', 'r0=0,r1=0', 'r0=0,r2=2')
case('branch_not_taken', 'if (r1 == 0) goto L1\nr0 = 1\nL1:\nr2 = 2', 'r0=0,r1=5', 'r0=1,r2=2')
case('branch_cmp_unsigned', 'if (r1 < r2) goto L1\nr0 = 1\nL1:\nr3 = 3', 'r0=0,r1=1,r2=ffffffff', 'r0=0,r3=3')
case('branch_cmp_signed', 'ifs (r1 < r2) goto L1\nr0 = 1\nL1:\nr3 = 3', 'r0=0,r1=1,r2=ffffffff', 'r0=1,r3=3')
case('if_block_then', 'if (r1 == r2) {\nr0 = 1\n} else {\nr0 = 2\n}', 'r1=5,r2=5,r0=0', 'r0=1')
case('if_block_else', 'if (r1 == r2) {\nr0 = 1\n} else {\nr0 = 2\n}', 'r1=5,r2=6,r0=0', 'r0=2')
case('rep_imm', 'r0 = 0\nrep 3 {\nr0 += 1\n}', 'r0=77', 'r0=3')
case('bitfield', 'r8 = uextra(r9, p:8, l:4)\nr7 = sextra(r9, p:8, l:4)', 'r9=f00', 'r8=f,r7=ffffffff')
case('insert', 'r8 <= insert(r9, p:8, l:8)', 'r8=11223344,r9=ffffffaa', 'r8=1122aa44')
case('call_sets_rets', 'call L1\nr0 = 1\nL1:\nr2 = 2', 'r0=0', 'r0=0,r2=2')
case('stm_ldm', '[r1+] = {r5-r4}\n{r7-r6} = [r1+]', 'r1=2000,r4=aa,r5=bb', 'n4:2000=aa,n4:2004=bb,r6=aa,r7=bb,r1=2000')
# ---- pi32v2 only: parallel issue (A # B: B sees the registers as they were before A; B runs first in the p-code)
V = ('pi32v2',)
case('parallel_store_old', 'r0 = r1 * r2 #\n[r3+0] = r0', 'r0=7,r1=3,r2=4,r3=2000', 'r0=c,n4:2000=7', V)
case('parallel_load_overwritten', 'r0 = r1 * r2 #\nr0 = [r3+0]', 'r0=7,r1=3,r2=4,r3=2000,n4:2000=99', 'r0=c', V)
# ---- pi32 only (its own block, accumulator and carry forms; the flag layout V=0 C=1 Z=2 N=3 is carried over from pi32v2: unverified)
P = ('pi32',)
case('blk_then', 'cmp r1, r2\nifs (nzcv == 0) {\nr0 = 1\n} else {\nr0 = 2\n}', 'r1=5,r2=5,r0=0', 'r0=1', P)
case('blk_else', 'cmp r1, r2\nifs (nzcv == 0) {\nr0 = 1\n} else {\nr0 = 2\n}', 'r1=5,r2=6,r0=0', 'r0=2', P)
case('blk_then2_taken', 'cmp r1, r2\nifeq 2, 1\nr0 = 1\nr3 = 5\nr0 = 2', 'r1=5,r2=5,r0=0,r3=0', 'r0=1,r3=5', P)
case('blk_then2_else', 'cmp r1, r2\nifeq 2, 1\nr0 = 1\nr3 = 5\nr0 = 2', 'r1=5,r2=6,r0=0,r3=0', 'r0=2,r3=0', P)
case('rep_reg', 'r1 = 3\nrep r1 {\nr0 += 1\nr2 += 2\n}', 'r0=77,r2=0', 'r0=7a,r2=6,r1=0', P)
case('macc_signed', 'macc = r1 * r2 (s)\nr3 = maccl\nr4 = macch', 'r1=ffffffff,r2=2', 'r3=fffffffe,r4=ffffffff', P)
case('macc_unsigned', 'macc = r1 * r2\nr3 = maccl\nr4 = macch', 'r1=ffffffff,r2=2', 'r3=fffffffe,r4=1', P)
case('macc_accumulate', 'macc = r1 * r2\nmacc += r5 * r6\nr3 = maccl\nr4 = macch', 'r1=10000,r2=10000,r5=3,r6=4', 'r3=c,r4=1', P)
case('addc_no_carry', 'r0 += r1 + c', 'r0=5,r1=6,psr=2', 'r0=c,psr=0', P)
case('addc_carry_out', 'r0 += r1 + c', 'r0=ffffffff,r1=0,psr=2', 'r0=0,psr=6', P)
case('add_brev', 'r0 += r1 (brev)', 'r0=40000000,r1=40000000,psr=0', 'r0=20000000,psr=0', P)
case('cmp_jlt_taken', 'cmp r1, r2\njlt L1\nr0 = 1\nL1:\nr3 = 3', 'r0=0,r1=ffffffff,r2=1', 'r0=0,r3=3', P)
case('cmp_jlt_not_taken', 'cmp r1, r2\njlt L1\nr0 = 1\nL1:\nr3 = 3', 'r0=0,r1=1,r2=ffffffff', 'r0=1,r3=3', P)
case('shift_carry_out', 'r0 = r1 >> 4', 'r1=1f,psr=0', 'r0=1,psr=2', P)
# ---- q32s only
Q = ('q32s',)
case('q_addc', 'r8 = r1 + r2 + c', 'r1=ffffffff,r2=0,psr=2', 'r8=0,psr=6', Q)
case('q_mac', 'r0 += r1 * r2', 'r0=5,r1=3,r2=4', 'r0=11', Q)
case('q_cmpbr_taken', 'if (r1 < r2) goto L1\nr0 = 1\nL1:\nr3 = 3', 'r0=0,r1=1,r2=2', 'r0=0,r3=3', Q)
case('q_cmpbr_not_taken', 'if (r1 < r2) goto L1\nr0 = 1\nL1:\nr3 = 3', 'r0=0,r1=2,r2=1', 'r0=1,r3=3', Q)
case('q_cmpbr_signed', 'ifs (r1 < r2) goto L1\nr0 = 1\nL1:\nr3 = 3', 'r0=0,r1=ffffffff,r2=1', 'r0=0,r3=3', Q)
case('q_scaled_index', 'r0 = [r1+r2<<2]', 'r1=2000,r2=3,n4:200c=cafebabe', 'r0=cafebabe', Q)
case('q_cc_set', 'cc = 1', 'psr=0', 'psr=2', Q)
case('q_cc_clear', 'cc = 0', 'psr=f', 'psr=d', Q)
case('q_push_rets', '[--sp] = rets', 'rets=1234,sp=3000', 'sp=2ffc,n4:2ffc=1234', Q)
case('q_bit_test_branch', 'if ((r1 & r2) == 0) goto L1\nr0 = 1\nL1:\nr3 = 3', 'r0=0,r1=f0,r2=0f', 'r0=0,r3=3', Q)
case('XFAIL_add_wrong', 'r8 = r9 + r10', 'r9=5,r10=7', 'r8=d')

if __name__ == '__main__':
    out = sys.argv[1]
    TC = os.environ['TC']
    arch = sys.argv[2] if len(sys.argv) > 2 else 'pi32v2'
    os.makedirs(out, exist_ok=True)
    img = bytearray(0x100000)
    lines = []
    saved = []
    for k, (name, asm, init, expect, archs) in enumerate(CASES):
        if archs is not None and arch not in archs:
            continue
        base = 0x1000 * (k + 1) + 0x10000
        d = tempfile.mkdtemp(dir=out)
        src = d + '/a.S'
        open(src, 'w').write('.text\n' + asm + '\nnop\nnop\n')
        cmd = [TC + '/' + arch + '/bin/clang', '-target', arch] + (['-mcpu=r3'] if arch == 'pi32v2' else []) + ['-c', src, '-o', d + '/a.o']
        if subprocess.run(cmd, capture_output=True).returncode != 0:
            print('skipped (does not assemble for %s): %s' % (arch, name))
            os.system('rm -rf ' + d)
            continue
        subprocess.run([TC + '/' + arch + '/bin/objcopy', '-O', 'binary', '-j', '.text', d + '/a.o', d + '/a.bin'], check=True)
        code = open(d + '/a.bin', 'rb').read()
        img[base:base + len(code)] = code
        stop = base + len(code) - 2     # the final nop is the stop address
        lines.append('%s %x %x %s %s' % (name, base, stop, init, expect))
        saved.append('\t'.join([name, asm.replace('\n', ' ; '), code.hex(), init, expect]))
        os.system('rm -rf ' + d)
    open(out + '/emu.bin', 'wb').write(bytes(img))
    open(out + '/tests.txt', 'w').write('\n'.join(lines) + '\n')
    open(out + '/%s.cases' % arch, 'w').write('# name <TAB> assembly (; = newline) <TAB> machine code (hex, JieLi assembler output) <TAB> initial state <TAB> expected state\n' + '\n'.join(saved) + '\n')
    print(len(CASES), 'cases')
