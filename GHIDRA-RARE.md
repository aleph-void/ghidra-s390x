# IBM z/Architecture (s390x) processor module for Ghidra

SLEIGH processor module for IBM z/Architecture: disassembly and p-code for the whole
z/Architecture instruction set as GNU binutils knows it (g5 through z17), Linux ELF loading
with relocations, and z/OS load module, GOFF and program object loaders. Target:
**Ghidra 12.1.4** (also builds for 12.1.3 and 12.2).

This is the community module [paulovitorjp/ghidra-s390x](https://github.com/paulovitorjp/ghidra-s390x)
by Paulo Pereira (Apache-2.0), verified and fixed by Ghidra-Rare. See [CREDITS.md](CREDITS.md)
for provenance and the full list of changes.

## Language and loading

One language, `s390x:BE:64:default`, with three compiler specs: `default` (Linux s390x ELF
ABI; the ELF opinion picks it), `zos` (z/OS Language Environment) and `zos_xplink` (XPLINK).

- **ELF.** `EM_S390` loads as `s390x:BE:64:default`. The relocation handler (part of the
  extension) applies the static and dynamic relocations; `R_390_IRELATIVE` is applied without
  a warning bookmark, TLS relocations are reported as unsupported as Ghidra does on x86-64.
  `S390_ElfExtension` disassembles each PLT entry and its lazy-binding path (s390x PLT0 and
  entries are 32 bytes; Ghidra's generic markup assumed 16).
- **z/OS.** Upstream's loaders: classic load modules (CESD/ESD/text/RLD with relocation),
  GOFF, and program objects (PM1/PM2). See `LOADERS.md`.
- **System calls.** `SVC` follows the Linux convention (number in the I field or r1,
  arguments r2-r7, result r2).
- **XPLINK.** Under `zos_xplink`, `BR 7` and `B 2(,7)`/`B 4(,7)` are returns.

## Instruction coverage

The binutils 2.45 opcode table has 2,748 entries (2,666 mnemonics). By the first CPU that has
them:

| Level | g5 | z900 | z990 | z9-109 | z9-ec | z10 | z196 | zEC12 | z13 | z14 | z15 | z16 | z17 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Entries | 500 | 210 | 132 | 68 | 66 | 381 | 255 | 48 | 636 | 195 | 140 | 22 | 95 |

All 2,748 decode, at every facility level; there is no per-CPU language (objdump also decodes
every entry regardless of CPU). Upstream decoded 1,159 of them correctly.

Semantics: every instruction whose result the architecture defines from program state is
p-code. That includes:

- **General instructions**, incl. the z14-z17 additions (MSC/MSGC, NCRK/NNRK/..., SELR,
  LOC/STOC, CLZG/CTZG, LOAD INDEXED ADDRESS, COMPARE AND LOAD, BIT DEPOSIT/EXTRACT), string and
  long operations (MVCLE/MVCLU/CLCLE/CLCLU, MVST, CLST, SRST/SRSTU, CUSE, TR/TRT/TRE/TRTE/
  TRTRE/TROO/TROT/TRTO/TRTT, CU12...CU42, CKSM), CDS/CSST/PLO (all 24 function codes),
  CFC/UPT, register ranges, LPQ/STPQ/LPD.
- **Decimal:** AP/SP/ZAP/CP/MP/DP/SRP/ED/EDMK, PACK/UNPK/PKA/PKU/UNPKA/UNPKU, CVB/CVD.
- **Binary floating point** (scalar and vector), incl. correctly rounded fused multiply-add
  and every rounding method.
- **Hexadecimal floating point:** all 104 HFP instructions with HFP arithmetic (guard digit,
  normalization, exponent underflow per the PSW mask), BFP/HFP conversions.
- **Decimal floating point:** all 86 DFP instructions with decimal arithmetic, the 8 DFP
  rounding methods and the rounding modifiers, quantum and clamp handling, NaN propagation.
- **Vector facility:** integer, BFP, string, z15-z17 additions, and the vector packed decimal
  instructions (VAP ... VTZ, VSCHP/VSCSHP/VCSPH).
- **PERFORM FLOATING-POINT OPERATION:** every radix conversion between BFP, HFP and DFP (short,
  long, extended) with the function-code and return-code handling, all rounding methods, the HFP
  overflow/underflow controls and NaN payloads, in exact big-integer arithmetic.
- **Message-security assist (CPACF), all functions the architecture defines from program state:**
  KIMD/KLMD (SHA-1, SHA-224/256/384/512, SHA3, SHAKE-128/256, GHASH), KM/KMC/KMF/KMO/KMCTR (DEA,
  TDEA, AES; KM also XTS and full XTS), KMA (AES-GCM), KMAC (CBC-MAC and HMAC-SHA-224/256/384/512
  with the IKP/IIMP/CCUP protocol), PCC (CMAC of the last block, the XTS parameter, scalar
  multiplication on P256/P384/P521/Ed25519/Ed448/X25519/X448), PRNO (the SHA-512 DRNG, seed and
  generate), KDSA (ECDSA and EdDSA verify and sign) and PCKMO. The protected-key (encrypted)
  functions of all of them work over the machine's wrapping keys, which are the registers `wka`,
  `wkavp`, `wkd`, `wkdvp` (hardware state no program can read; set them to test).
- **COMPRESSION CALL** (compression and expansion, symbol translation, order preservation,
  entropy encoding), **SORT LISTS** (SFLR and SVLR, merge mode 0 and 1) and the
  **DEFLATE CONVERSION CALL** query and expand functions (DEFLATE decoder with history, check
  value and resumable state).

The condition code is kept both as `cc` (0-3, for IPM/EPSW and the emulator) and as four
flags, so branches decompile to `if (a == b)` instead of condition-code bit arithmetic.

What stays a named pcodeop, and why:

- **Hardware and system state outside the program:** privileged control (control registers,
  address translation, storage keys, PSW key, linkage stack, SIE, SIGP, prefix), I/O
  (SSCH ... XSCH), clocks and timers (STCK*, STPT), configuration and model information (STSI,
  STIDP, STAP, STFL/STFLE, ECAG), CPU-measurement counters, guarded-storage controls
  (LGSC/STGSC, LLGFSG's shift).
- **Run-time events:** program exceptions (compare-and-trap and load-and-trap compare and load
  in p-code and then call a trap pcodeop; fixed-point divide exceptions; MONITOR CALL), transactional
  execution (TBEGIN's abort path), true random numbers (`s390_trng_byte()`: PRNO-TRNG output and the
  random number mixed into ECDSA signing when the deterministic bit is zero or the key is protected).
  EX/EXRL execute an instruction modified at run time, which a decompiler cannot follow.
- **Model-dependent results:** NNPA and the NNP-data-type-1 conversions (VCNF, VCFN, VCRNF,
  VCLFNH/L: the Principles of Operation leave the format to the model); DFLTCC-CMPR and DFLTCC-GDHT
  (`s390_dfltcc_cmpr`, `s390_dfltcc_gdht`: the duplicate-string search and the Huffman-table
  construction are left to the model, so there is no result to model).
- **Firmware identity:** the query-authentication-information functions (code 127) of the
  message-security-assist instructions return the model's firmware code level hash and version;
  they are reported as not installed (specification exception).

## Results

| Check | Result |
|---|---|
| SLEIGH | Compiles on Ghidra 12.1.3, 12.1.4 and 12.2 (extension zips built with each). `s390x.sla` is 1.7 MB and inflates to 13.7 MB, 81% of the 16 MiB Ghidra accepts |
| Decode vs GNU objdump 2.45, every opcode-table entry (8 encodings each, 21,984 instructions) | 100% exact+semantic (94.0% exact), 0 differences, 0 decoded by one side only; **2,748/2,748 entries** at every level g5-z17 |
| Decode vs objdump, 60,000 random words | objdump decodes 42,020: 100% agree (99.92% exact). 32 more decode only in Ghidra (nonzero reserved fields, e.g. DLR, VLR); 17,071 neither |
| Decode vs llvm-objdump 21 (`-mcpu=arch15`), opcode-table words | llvm decodes 17,303 of the 21,984 (it rejects nonzero reserved fields); 16,850 agree, the 453 others are llvm spellings (`%fN` for vector registers 0-15 of scalar FP instructions, an omitted zero base, RNSBG's test bit inside I3) |
| Emulator, hand-computed and library-checked (`emu_tests.py`) | 784/784, incl. PLO, CUSE, CFC, UPT, TRTE, z17, DFP, vector packed decimal, PFPO, and every CPACF function against `hashlib`/`hmac`/`cryptography` (SHA, AES/DES/TDES modes, GCM, XTS, CMAC, HMAC, ECDSA, EdDSA, X25519/X448, protected keys), PRNO, CMPSC (the manual's example plus a dictionary-builder model), SORTL (the manual's figures 26-108/109), DFLTCC expand against `zlib`. A deliberately wrong expectation fails |
| Emulator vs qemu-s390x 10.2 (random instructions of every entry qemu runs, plus hand-built specials) | 22,080/22,080 tests, 1,334 mnemonics, 0 differences, storage identical. Includes 9,000 random and 2,400 edge-case FMA tests in a separate run, all agreeing |
| Emulator vs reference models (qemu lacks these) | packed decimal 2,100/2,100 (7 mnemonics); HFP 6,240/6,240 (104); DFP 12,900/12,900 (86, Python `decimal`); vector packed decimal 5,250/5,250 (32); PFPO 1,500/1,500 |
| Debian 13 `libz.so.1.3.1`, `ls`, `sort`, `libc.so.6`, `busybox` (static); Ubuntu 25.04 `libc.so.6` | The ELF opinion picks the language for all. 1,007,254 instructions, 100% agree with objdump at the same addresses. 0 decompile failures, 0 timeouts (12,092 functions). libz 0 bad-instruction bookmarks; ls/sort 1 each and libc 3, busybox 4 in `.text`, all at a 0x0000 trap halfword that flow reaches after a non-returning call (e.g. `__libc_start_main`) or a branch analysis cannot prove dead; libc 240/244 and busybox 41 in `.rodata` from the generic Ghidra issues below. 1,176-1,297 relocations applied per libc; 13-14 TLS relocations unsupported, as on x86-64 |

Before these fixes the upstream module decoded 1,159 of the 2,748 table entries as objdump
does, wrote all 64 bits for most 32-bit operations (e.g. `LR`, `AR`), produced wrong packed
decimal results (`SP` lost the sign, `MP` 12 x -12 = 1000-), applied IEEE float operators to
HFP bit patterns, and left DFP, vector packed decimal, PLO and most vector instructions as
pcodeops. Its `.sla` would also have exceeded the 16 MiB limit with full vector semantics.

### Confirmed reference-tool bugs

QEMU 10.2 `qemu-s390x` (the differential test generates around these):

- CSST function code 0 writes the old value into R3 bits 0-31; function code 1 (sc 0) aborts
  (`extract32` with length 0).
- STMH stores zeros (shift left instead of right).
- UNPK ignores the leftmost source byte; PKA/PKU drop the leftmost character.
- TROT compares only 8 bits of the 16-bit test character.
- MVCOS with GR0 = 0 aborts (`extract32` assertion).
- No DFP, HFP arithmetic, packed-decimal arithmetic, vector packed decimal, PLO, CUSE, CFC,
  UPT, TRTE/TRTRE or z17 support: these are checked against reference models and
  hand-computed tests instead.

GNU objdump 2.45 prints EFPC/SFPC with a second register when the reserved R2 field is
nonzero; the module matches it.

Hercules (read as a second reference, not run) differs from the Principles of Operation in
places: HFP LDXR rounds at bit 56 where the architecture rounds at bit 55; RFSP (round for
shorter precision) is mapped to round-down; DFP TEST DATA CLASS classifies subnormals by the normalized instead of the
adjusted exponent; REROUND copies a signaling NaN; CONVERT TO LOGICAL treats a negative value
that rounds to zero as invalid (the Principles of Operation give 0, cc 1); VPSOP/VTP/VCVB
index slips. The module follows the Principles of Operation.

Generic Ghidra 12.1.4 issues seen on these samples (not module bugs):

- `GccExceptionAnalyzer` adds the image base twice to LSDA landing pads in position-
  independent objects (the same happens on x86-64 libc): the bad-instruction bookmarks in
  `.rodata` of libc.
- The decompiler's two-level byte-indexed switch recovery reads past the pointer table:
  the `.rodata` bookmarks of busybox.

## Testing

```sh
export GHIDRA_INSTALL_DIR=/path/to/scratch/ghidra_12.1.4_PUBLIC   # the module gets symlinked in
export OBJDUMP=/path/to/objdump-with-s390   # binutils 2.45 with the s390 target
test/run-tests.sh /tmp/s390x-tests          # SLEIGH + size, decode, emulator, qemu and model diffs
test/fetch-real-samples.sh samples          # Debian/Ubuntu s390x packages, pinned SHA-256
test/real-binaries.sh samples /tmp/s390x-real
```

- `test/run-decode.sh`: every opcode-table entry (8 encodings each) and 60,000 random words,
  Ghidra vs objdump, exact and semantic (`compare.py`); the table also against llvm-objdump.
- `test/emu_tests.py` + `EmuCheck.java`: hand-computed emulator tests (one deliberately wrong
  expectation was confirmed to fail).
- `test/qemu-check.sh` (`qemu_diff.py`, `qemu_special.py`, `QemuDiff.java`): random
  instructions of every entry qemu-s390x executes, plus hand-built tests for register pairs,
  long operations, valid decimal and Unicode data, FMA edge cases; registers, cc, FPRs, vector
  registers and a 256-byte storage window are compared.
- `test/model-check.sh` (`model_diff.py` with `hfp_model.py`, `dfp_model.py`, `pfpo_model.py`): decimal, HFP,
  DFP, vector packed decimal and PFPO against reference models.
- `test/pcode_defcheck.py`: static check that every temporary is written before it is read on every path.
- `test/real-binaries.sh` (`RealCheck.java`, `real_compare.py`): import with no processor
  flag, auto-analysis, every instruction compared with objdump, every function decompiled.

Regenerating the SLEIGH after editing a generator:

```sh
python3 tools/strip_constructors.py data/languages tools/core_replace.txt
python3 tools/gen_table.py s390-opc.txt s390-operands.txt tools/table_skip.txt \
    data/languages/s390x_table_gen.sinc     # tables from test/dumpopc (run-decode.sh writes them)
$GHIDRA_INSTALL_DIR/support/sleigh data/languages/s390x.slaspec
```
