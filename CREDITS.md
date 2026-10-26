# Credits

## Upstream

This module is the IBM z/Architecture (s390x) processor module from
[paulovitorjp/ghidra-s390x](https://github.com/paulovitorjp/ghidra-s390x), imported at commit
`3f0cfcd12f23b13e9ff4266dfbd82ab1c63383e5` (2026-10-23, "Initial commit: ghidra-s390x, a
Ghidra processor module for IBM z/Architecture (s390x) with z/OS loaders"). License: Apache
License 2.0 (`LICENSE` and `NOTICE`, unchanged).

Original author: Paulo Pereira ([@paulovitorjp](https://github.com/paulovitorjp)). Upstream
wrote the SLEIGH specification, the z/OS loaders (classic load modules, GOFF, program
objects), the z/OS Language Environment and XPLINK compiler specs, the ELF relocation handler,
and the HLASM-assembled validation corpus (`hlasm_batches/`, `tests/`).

Upstream files keep their copyright and license headers. Changes made here are also licensed
under Apache-2.0 and exist as commits on top of the upstream history (branch `ghidra-rare` of
the fork [aleph-void/ghidra-s390x](https://github.com/aleph-void/ghidra-s390x/tree/ghidra-rare)).

## Reference material

Nothing from these was copied into the module; they were read or run as references.

- IBM *z/Architecture Principles of Operation*, SA22-7832-14 (15th edition, z17): the
  architecture definition every semantic follows.
- GNU binutils 2.45 `objdump` (decode oracle) and its s390 opcode and operand tables, read at
  test time from a local build (`test/dumpopc.c`). binutils is GPL and is not copied here; the
  tables drive the generator at build time only (`tools/gen_table.py` reads a dump of them).
- LLVM `llvm-objdump`/`llvm-mc` 21 (SystemZ, `-mcpu=arch15`): second decode check and the assembler for the
  emulator tests. LLVM's SystemZ instruction definitions were read for the LOAD INDEXED
  ADDRESS operand arithmetic.
- QEMU `qemu-s390x` 10.2 user-mode emulation: the reference for the p-code differential test.
- The Hercules emulator (SDL Hyperion: `float.c`, `dfp.c`, `zvector2.c`, `general1.c`,
  `general2.c`, `plo.c`, `nnpa.c`; Q Public License) was read as a second implementation of
  the hexadecimal and decimal floating point, vector packed decimal, PERFORM LOCKED OPERATION,
  CUSE, CFC, UPT and TRTE details. No Hercules code is used.
- IBM patents US 11360769 and US 11663004 (the scaling direction of VSCHP/VSCSHP/VCSPH).
- Python's `decimal` module (General Decimal Arithmetic) as the DFP reference model.

## Real-world test inputs

Downloaded at test time by `test/fetch-real-samples.sh` (pinned SHA-256), never committed:
Debian 13 s390x packages (glibc 2.41 `libc.so.6`, coreutils 9.7 `ls` and `sort`, zlib 1.3.1,
busybox-static 1.37.0) and Ubuntu 25.04 glibc 2.41 `libc.so.6`. Their licenses (LGPL-2.1+,
GPL-3+, Zlib, GPL-2) allow disassembly.

## Ghidra-Rare changes

Commits on branch `ghidra-rare` (upstream `3f0cfcd..`), oldest first:

1. `66d0cd4` Constructor displays rewritten into assembler syntax (repeated mnemonics,
   generator suffixes, bare register numbers, 12-bit-only 20-bit displacements, L-1 lengths).
2. `312f4b3` FPR/VR register overlays (f1 overlaid v0), GPR operands of int/BFP conversions,
   control registers.
3. `787abd4` Signed 32-bit relative offsets (BRCL/BRASL/LARL targets 4 GiB off), LDY/STDY/
   LEY/STEY displacement.
4. `55e29e8` `tools/gen_table.py`: the 1,463 opcode-table entries the module did not decode.
5. `bb4b74d` Builds as a Ghidra extension; ELF relocation handler and loaders always included.
6. `c86ae31` Register branches (BR/BCR/BASR... branched into register space), BASR/BALR,
   logical-immediate display, cspec.
7. `3529193` Integer semantics verified against qemu-s390x (most 32-bit operations wrote all
   64 bits); cc separated from the PSW mask.
8. `4e75225` Branch-on-index comparisons, BRCTH, BI/BIC.
9. `169f19f` Linux system calls; BRAS/BRASL used to skip inline literals.
10. `f077012` P-code for the integer vector facility.
11. `744ef32` Binary floating point, STOC and the rest of the vector facility; element loops to
    stay under Ghidra's 16 MiB `.sla` limit.
12. `17f1d28` Register ranges, LAE/LAEY, BSM/BASSM, constant zero register.
13. `151131e` General instructions that were pcodeops; wrong STM/STMH/PACK/UNPK/MVO/MVCIN/
    SRST/MVST/CLST fixed.
14. `2d12aac` NOPR, EFPC/SFPC: all 2,748 opcode-table entries agree with objdump.
15. `46225ef` Correctly rounded fused multiply-and-add.
16. `f6692b8` TROO/TROT/TRTO/TRTT with M3.
17. `b6104e8` CLZG/CTZG.
18. `f115040` ELF extension for the PLT; silent IRELATIVE.
19. `bf404c0` XPLINK returns.
20. `8276bf3` Condition flags (readable branch conditions); compare-and-trap fixes.
21. `77c0b66` One-off conversion scripts moved out of `data/languages`.
22. `3d80857` Packed-decimal arithmetic and EDIT/EDMK rewritten (upstream results were wrong).
23. `c968b96`, `3d51939`, `27c548e` Hexadecimal floating point with real HFP arithmetic,
    BFP/HFP conversions, unnormalized multiply(-and-add).
24. `3910d87`, `c2232bf` Decimal floating point (all 86 instructions), rounding modifiers.
25. `2e58917`, `5aac80a` Vector packed decimal (26 instructions, plus VSCHP/VSCSHP/VCSPH).
26. `633ec02` PLO, TRTE/TRTRE, CUSE, CFC, UPT, MVCOS, NTSTG, z17 LXA/LLXA, CAL, BDEPG/BEXTG.
27. `940a057` MVCK/MVCP/MVCS/MVCSK/MVCDK, TAM, SACF.
28. The tests (`test/`), these notes, and the README update.
