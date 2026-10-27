# JieLi pi32, pi32v2 and q32s for Ghidra (Ghidra-Rare notes)

Processor modules for the three 32-bit CPU cores in JieLi (Zhuhai Jieli) Bluetooth/audio SoCs. This is the Ghidra-Rare fork of
[quarkslab/ghidra-jieli](https://github.com/quarkslab/ghidra-jieli) (Apache-2.0), which extends
[kagaimiq/ghidra-jieli](https://github.com/kagaimiq/ghidra-jieli) (Apache-2.0). Both are credited in [CREDITS.md](CREDITS.md), together
with every change made here. It targets Ghidra 12.1.4 and builds on 12.1.3 and 12.2.

## Languages

| Language ID | Core | ELF auto-select | Instruction sizes |
|---|---|---|---|
| `pi32:LE:32:default` | pi32 (Blackfin-like, 64-bit multiply accumulator `macc`, if/else blocks, `rep` loops) | e_machine 240 | 2, 4 |
| `pi32v2:LE:32:default` | pi32v2 (AC79/AC791N; parallel issue `#`, if/else blocks, `rep`, DSP lanes, FPU, register pairs) | e_machine 241 | 2, 4, 6 |
| `q32s:LE:32:default` | q32s (BD19/BD29, AC630N/AC632N; compare-and-branch, no blocks, no accumulator) | e_machine 242 | 2, 4, 6 |

`pi32` prints r15 as `sp`; in `q32s` and `pi32v2` the stack pointer is a special register (`sr14` / `sp`) and r15 is a general register.
The language IDs are upstream's. The compiler spec is `default` (JieLi's ABI: arguments in r0-r3 then the stack, results in r0, or
r1:r0 for 64 bits, r4 and up preserved). f59/f95 (PIC-like cores) and dv10/dv12 (Blackfin) are not implemented, see "Doesn't work".

## How the three languages were built

The hand-written constructors of the upstream module disagreed with JieLi's own disassembler on a large part of the instruction
space (37,351 of 181,072 corpus words for pi32, about 19,000 for q32s; for pi32v2 about 8,000 of the 65,536 first words), so all three are now generated:

- **pi32v2**: `tools/gen_pi32v2.py` and `tools/sem_pi32v2.py` turn `tools/pi32v2.toml` (the instruction table of
  [jvitkauskas/pi32v2-isa](https://github.com/jvitkauskas/pi32v2-isa), CC0-1.0, confirmed there against JieLi's toolchain and
  tested on an AC791N) into one constructor per instruction form with p-code. The root machinery in `pi32v2.slaspec` (parallel
  issue, `rep`, if/else blocks) is upstream's, reworked.
- **pi32, q32s**: no such table exists. `tools/jl_infer.py` and `tools/jl_fields.py` derive one from JieLi's objdump used as a
  black box (bytes in, text out; `tools/jl_oracle.py`): they find the opcode bits of every instruction form by flipping bits, then
  fit every operand (register, number, branch target, register list, modified immediate) as a function of its bits.
  `tools/pi32.forms.json` and `tools/q32s.forms.json` are the result (`tools/q32s.seeds` lists words found by the differential test
  whose valid tails random sampling had missed). `tools/gen_jl.py` and `tools/sem_jl.py` generate the SLEIGH and p-code from them:
  the p-code is compiled from objdump's own C-like syntax (`r0 = r1 + r2`, `[sp+4] = r0`, `{pc, r4} = [sp++]`).

`test/run-tests.sh` regenerates all three and compares byte for byte with the checked-in `data/languages/*_gen.sinc`.

## Test results

All counts are from the final tree. "Exact" means the same text modulo number base and spacing, "semantic" the same instruction with
the same operands in a different spelling. Corpus: 986,432 8-byte slots (every 16-bit first word with 12 random tails, plus 200,000
fully random slots; `test/gen_corpus.py 12 200000 7`), each decoded by JieLi's objdump and by the module.

| Area | pi32 | pi32v2 | q32s |
|---|---|---|---|
| Decode vs objdump | 867,215 agree (866,962 exact, 253 semantic), 119,028 both invalid, 189 differ (objdump bug 1) | 791,726 agree (791,075 exact, 651 semantic), 194,706 both invalid, 0 differ | 954,372 agree (954,256 exact), 4,659 both invalid, 52 objdump crashes, 27,349 words objdump accepts with a `??` operation (reserved) |
| Every constructor reached | 1905/1905 (plus the block and rep wrappers, run by the emulator cases and real code) | 1208/1208 | 1014/1014 |
| Semantics | 46 emulator cases (hand-computed, ALU/flags/memory modes/branches/blocks/rep/macc/carry/lists), 1 wrong expectation reported | 41 cases incl. parallel issue | 41 cases |
| Real code | see below | see below | see below |

pi32v2 is compared against `-mcpu=r3` (the CPU the table was swept on), then `r2v3` and `r3v3` for the few forms those CPUs add.

### Real code

Freely licensed C projects (lz4 1.9.4 BSD-2, cJSON 1.7.18 MIT, miniz 3.0.2 MIT, Lua 5.4.7 MIT; fetched by pinned URL and SHA-256 by
`test/real-build.sh`) are built with JieLi's own clang for each core at -O0, -O2 and -Os, linked with JieLi's `ld`, imported
without forcing the language (the ELF opinion picks it), auto-analysed, and every function is decompiled.

Each core: 12 ELF files (4 projects x -O0/-O2/-Os). Instruction-level comparison with objdump at its own addresses
(`test/real-check.sh`; jump-table words are data and skipped):

| | pi32 | pi32v2 | q32s |
|---|---|---|---|
| Instructions compared | 354,555 | 346,392 | 373,083 |
| Same as objdump (exact / semantic) | 345,384 (342,206 / 3,178), 9,171 jump-table words | 341,217 (all exact), 5,175 jump-table words | 367,906 (367,894 / 12), 5,177 jump-table words |
| Differences | 0 | 0 | 0 |

Import, auto-analysis and decompilation of every function (`test/real-stats.sh`, totals over the files finished at the time of
writing; per-file lines are printed by the script). "Error bookmarks in code" are Ghidra error bookmarks inside executable blocks:

| | pi32 | pi32v2 | q32s |
|---|---|---|---|
| Instructions / functions | ~320,000 / 3,500 | ~270,000 / 3,900 | ~310,000 / 3,700 |
| Bad-instruction bookmarks | 79 (lua only) | 0 | 0 |
| Error bookmarks in code | 63 (lua 45, cJSON 14, others 4) | 13 | 3 |
| Decompiler failures (of ~3,500 functions) | 6 (all lua -O2, timeouts) | 0-2 | 3 |

The pi32 bookmarks are almost all around `tbb`/`tbh` jump tables inside the code and in literal pools after returns: pi32's
dense encoding lets Ghidra's analyzers decode table bytes as instructions. They do not change decoding. q32s's `.rodata` errors are
outside code. Reproduce with `test/run-tests.sh --real <dir>`.


## Doesn't work

- **f59, f95** (JieLi's PIC-like 8-bit cores, ELF 803/804) and **dv10, dv12** (Blackfin): not implemented. kagaimiq's page lists
  the f59/f95 opcodes, but there is no assembler, disassembler or binary to test against; Ghidra-Rare has a separate Blackfin module.
- **pi32v2 forms that exist only on CPU models other than r3** (double-precision floating point on r4/r4v3/r4v3s: 429 words of the
  corpus, for example `r1_r0 = r1_r0 + r1_r0 (f)`): the table was swept on r3 only, so the module does not decode them.
- **q32s compare-and-branch with the condition codes objdump prints as `??`** (mi, pl, vs, vc, al and the last one: they would test
  flags that a register-immediate compare does not have): 27,349 corpus words. The kagaimiq notes also print them as `??`; treated as
  reserved, not decoded.
- **pi32 `macc /= R` and `macc /= R (s)`**: a pcodeop (`jl_macc_n_r`). Nothing states what the divide leaves in the accumulator.
- **Relocatable `.o` files** are loaded without applying relocations (no ELF relocation handler; linked executables need none).
- **No DWARF register map** (the toolchain ships no DWARF dumper to establish the register numbers).
- Jump tables of `tbb`/`tbh` are decoded and modelled, but Ghidra's switch analysis does not always recover the table size; a few
  analysis bookmarks remain in switch-heavy code (see the table above, the count inside executable blocks is what matters).

## Unverified

- **Flags and everything behavioural on pi32 and q32s.** There is no vendor manual or hardware test for these cores. The p-code
  for pi32 and q32s carries over the behaviour of the same syntax from the pi32v2 table, which was tested on an AC791N: flags in
  `psr` (V bit 0, C bit 1, Z bit 2, N bit 3), `add`/`sub`/`cmp`/`neg` write all four, logic, multiply, rotate and divide write N/Z,
  shifts also set C to the last bit shifted out (kept for a zero count), `<<<` saturates, division by zero gives 0, register lists
  store the lowest-numbered register at the lowest address, `pc` in a list is a return, `tbb`/`tbh` jump to the end of the
  instruction plus twice the table entry (checked against the targets in the compiled switch statements of the test code),
  and a taken `rep` runs the next N instructions with the counter register counting down to zero. Where the two cores' own
  instruction notes disagree with objdump, objdump was followed.
- **if/else blocks** on pi32: the then count is in bits 1..0 of the opener and the else count in bits 3..2 (found with objdump on
  all sixteen low nibbles; kagaimiq's table has the two the other way round). The p-code predicates each body instruction on the
  condition computed by the opener.
- **`rep` with a count of 0** (not tried on hardware, loops 2^32 times here), and what the loop does with a branch out of the body.
- **Which pi32 flag bits `mi`/`pl`/`vs`/`vc` test** (objdump prints `??` for them): taken from the pi32v2 psr layout.
- The pi32v2 parallel-issue ordering when the second instruction writes a register the first one reads (the table only
  documents stores and loads).
- Real firmware images: none was tested (the vendor SDK libraries and firmware are not freely redistributable); only code built from
  public sources.

## Reference-tool bugs

1. **JieLi pi32 objdump prints the base register twice in the pre-incrementing doubleword forms**: `d[++ rY = rZ] = rI, rX` prints
   as `d[++ rY = rY] = rI, rX` (the increment register rZ, bits 24..27, is never shown; the neighbouring forms print it). 189
   corpus words. The module follows the kagaimiq layout (rZ is the increment). Not confirmed on hardware.
2. **JieLi q32s objdump crashes (segmentation fault) when an instruction starts with the word 0xf34f.**
3. JieLi q32s objdump prints `<unkown instruction>` (sic) for invalid words, where the other cores print `<unknown instruction>`.
4. The JieLi toolchain's pi32v2 objdump decodes some words differently on `-mcpu=r1` and `-mcpu=r5` than on r3; the table describes r3.

## Files

- `data/languages/` : `pi32.slaspec`, `pi32v2.slaspec`, `q32s.slaspec` (registers, contexts, the block and parallel-issue
  machinery), `*_gen.sinc` and `pi32_rep.sinc` (generated), `*.cspec`, `pi32.pspec`, `JieLi.ldefs`, `JieLi.opinion`.
- `tools/` : the generators and the inference tools above, the tables, `gen_forms_corpus.py` and `gen_table_corpus.py` (corpora that
  exercise every form).
- `test/` : `run-tests.sh` (see its header), the emulator cases in `test/emu/*.cases` (assembled with JieLi's assembler, the machine
  code is committed so the cases need no toolchain), `compare.py` and the other helpers.
