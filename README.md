# ghidra-jieli

This is the improved Ghidra processor module for some JieLi's custom CPU architectures, derived from
[Kagaimiq](https://github.com/kagaimiq)'s [original implementation](https://github.com/kagaimiq/jielie/).

> **Ghidra-Rare fork.**  This copy is the `ghidra-rare` branch of a fork of
> [quarkslab/ghidra-jieli](https://github.com/quarkslab/ghidra-jieli) (Apache-2.0).  It targets Ghidra 12.1.4 and also builds on
> 12.1.3 and 12.2; prebuilt extension zips are on the fork's Releases page.  What was changed, what was tested and what is left is in
> [GHIDRA-RARE.md](GHIDRA-RARE.md); the original authors and every change are in [CREDITS.md](CREDITS.md).
> Install: unzip the release into `<ghidra>/Extensions/Ghidra/` (or File > Install Extensions), or copy this directory to
> `<ghidra>/Ghidra/Processors/JieLi`.  ELF files with `e_machine` 240, 241 and 242 select pi32, pi32v2 and q32s automatically.

- dv10 *(this is Blackfin, not implemented)*
- dv12 *(this is Blackfin, not implemented)*
- pi32 *(was: "not complete, but somewhat usable now."  Now: every instruction JieLi's objdump decodes is decoded, with p-code)*
- pi32v2 *(was: "covers most instructions, sone remain unknown".  Now: every form of the CC0 pi32v2 instruction table, with p-code)*
- q32s *(was: "very early stage".  Now: every instruction JieLi's objdump decodes, except the encodings its own disassembler prints as `??`, with p-code)*
- f59 *(not implemented yet; documented only by kagaimiq's notes, no assembler or disassembler to test against)*
- f95 *(not implemented yet; same)*

## TODO

Status in the Ghidra-Rare fork: **fixed**, **remaining** (with the reason).

- pi32
  - Stack-related instructions (currently only `push {rets}` and `pop {pc}` is handled): **fixed** (every register-list push/pop,
    with the pc pop as a return)
  - Remaining missing instructions: **fixed** (decoding agrees with objdump on all 181,072 corpus words except one objdump display bug)
  - rep loops and if-else blocks?: **fixed** (both are modelled; see GHIDRA-RARE.md)
  - Maybe refactor the mnemonics? (like the ones I'm using on q32s and pi32v2? or do it the other way around?): **fixed** (all three
    languages now print the syntax of JieLi's own objdump)
  - Change flags on instructions that change them (e.g. add, sub, rotc, etc.): **fixed**, but the flag rules are carried over from
    pi32v2 and are **unverified** on pi32 (no vendor manual or hardware test)
- pi32v2
  - Remaining missing instructions: **fixed** for everything in the pi32v2 table (CPU model r3); forms that exist only on the
    r4/r4v3/r4v3s models (double-precision floating point) are **remaining**: the table was swept on r3 only
  - Likely this is far more complicated than pi32, though: it is; the parallel issue (`#`) and if/else blocks are modelled
  - Mnemonics like in q32s or pi32?: **fixed** (objdump's syntax everywhere)
- q32s
  - Do the rest: Group7 instructions of course; Flags and stacks too: **fixed**
  - Make decisions about my new mnemonic standard... (or use pi32 one?): **fixed** (objdump's syntax)
  - (at least it's used on BD19 and BD29 - AC632N and AC630N resp.)
  - (It also seems to be simpler than pi32 or pi32v2!)
- dv10/dv12 (blackfin)
  - Maybe implement it too? Or leave it as a separate project?: **remaining**; Ghidra-Rare has a separate Blackfin module
