# Credits: JieLi module (pi32, pi32v2, q32s)

This module is a community SLEIGH module that Ghidra-Rare imported, tested and rebuilt. The original processor specifications were
written by the authors below; Ghidra-Rare's changes and sources are listed after them.

## Upstream

| | |
|---|---|
| Source | [quarkslab/ghidra-jieli](https://github.com/quarkslab/ghidra-jieli), commit `e1bd0707874b77b759401555d24839ad43af1267` (2026-03-09, "First commit.", the only commit of that repository) |
| Ghidra-Rare fork | [aleph-void/ghidra-jieli](https://github.com/aleph-void/ghidra-jieli/tree/ghidra-rare), branch `ghidra-rare` |
| License | Apache-2.0 (`LICENSE`, unchanged) |
| Original authors | Damien Cauquil ([@virtualabs](https://github.com/virtualabs), Quarkslab): the pi32v2 work on top of kagaimiq's module (group 6/7 instructions, parallel issue, if/then/else blocks), q32s and pi32 additions. Andrey Grigoryev ([@kagaimiq](https://github.com/kagaimiq)): the original pi32, pi32v2 and q32s modules ([kagaimiq/ghidra-jieli](https://github.com/kagaimiq/ghidra-jieli), Apache-2.0, 48 commits 2023-2024, last `b5e60122b6cd3e6b615387035994b8bed0ea1a26`) and the documentation of the instruction sets at <https://kagaimiq.github.io/jielie/> |

Quarkslab's repository is a single squashed commit, so the history of the individual contributions is in kagaimiq's repository
(and in <https://github.com/virtualabs/ghidra-jieli>, Cauquil's fork, Apache-2.0).

The upstream files that survive unchanged are `LICENSE`, `Module.manifest`, `data/build.xml`, `data/sleighArgs.txt`,
`data/languages/JieLi.ldefs` (language ids), `pi32.pspec`, the register and special-register layouts, the pi32v2 conditional-block
and parallel-issue machinery in `data/languages/pi32v2.slaspec` (reworked, see below) and the original README text.  The hand-written
instruction constructors of all three languages (`*_ins_*.sinc`) are replaced; they remain in the git history of this branch.

## Other sources

| Source | License | What was taken |
|---|---|---|
| [jvitkauskas/pi32v2-isa](https://github.com/jvitkauskas/pi32v2-isa) `isa/pi32v2.toml` at commit `5ae97fd9259db923775d6b170ccc6efa41c1d8d7` (Julius Vitkauskas, 2026) | CC0-1.0 (the table; the repository's code is MIT-0) | the pi32v2 instruction table (`tools/pi32v2.toml`, unchanged, SPDX header kept, `LICENSES/CC0-1.0.txt`): every encoding, syntax and the behaviour notes (flags, saturation, register-list order, hardware results from an AC791N) that the p-code follows.  No GPL source or table went into it (its `docs/SOURCES.md` lists the sources; JieLi's toolchain was used as a black box) |
| kagaimiq's instruction set notes ([pi32](https://kagaimiq.github.io/jielie/cpu/pi32.html), [pi32v2](https://kagaimiq.github.io/jielie/cpu/pi32v2.html), [q32s](https://kagaimiq.github.io/jielie/cpu/q32s.html)) | none stated: facts only | register models and special-register names, which opcode groups exist, the syntax of the old classic mnemonics (read to cross-check bit layouts; the if-block and rep layouts in the notes are partly wrong, see GHIDRA-RARE.md) |
| JieLi's public Linux toolchain `jieli-linux-toolchains-20260730.1` (clang assembler, objdump) | no license text ships with it; LLVM 4.0.1 based | run only as a black box (bytes in, text out) to infer the pi32 and q32s instruction tables and to test all three languages; nothing is copied, nothing of it is redistributed.  **The lead should confirm that this use is acceptable** |

## Ghidra-Rare changes

1. `Stop tracking the compiled pi32v2.sla` (build artefacts do not belong in the tree); `pi32.cspec` named r15 as an unaffected
   register although pi32's r15 is `sp`, so Ghidra rejected the file.
2. **pi32v2 regenerated from the CC0 table** (`tools/gen_pi32v2.py`, `tools/sem_pi32v2.py`): 803 constructors, one per
   instruction form, with p-code.  Against JieLi's objdump the hand-written constructors left 6,048 decodable words undecoded and
   decoded 1,900 more with other operands.  The root machinery (parallel issue, rep, if/else blocks, contexts) was kept and fixed:
   the block context no longer leaves a closing-bracket state behind (flows from branches into the instruction after a block gave
   "inconsistent instruction prototype"), rep loops put the loop-back before the instruction after the body, and a register can
   be the rep count.
3. **pi32 and q32s regenerated** from tables inferred with JieLi's objdump (`tools/jl_infer.py`, `jl_fields.py`, `jl_oracle.py`,
   `jl_text.py`: find the opcode bits of every form by flipping bits, then fit every operand as a function of its bits;
   `tools/pi32.forms.json` and `tools/q32s.forms.json` are the result; `tools/gen_jl.py` and `tools/sem_jl.py` generate the
   SLEIGH and p-code).  pi32 gets if/else blocks and rep loops through context counters (`pi32.slaspec`, `pi32_rep.sinc`).
4. Per-language compiler specs (`pi32.cspec`, `pi32v2.cspec`, `q32s.cspec`: the Jieli ABI, arguments r0-r3, results r0/r1:r0).
5. The ELF opinion no longer lists the f59/f95 machine numbers (those languages do not exist).
6. `test/` (decode differential, constructor reach, emulator cases, real-code import), `build.gradle`, `extension.properties`,
   `GHIDRA-RARE.md`, this file, README status.
