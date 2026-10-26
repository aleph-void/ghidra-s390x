# s390x Ghidra processor module for IBM Z / z/Architecture

A from-scratch Ghidra processor module for IBM z/Architecture (s390x),
built because no public SLEIGH specification for this architecture existed.
It covers the instruction set, Linux ELF importing, and loaders for z/OS load modules.

Licensed under the Apache License, Version 2.0. See `LICENSE` and `NOTICE`.

## Why

Companies run mainframe programs whose source code was lost long ago. The
authors retired, the source libraries are gone, all that remains is a load
module. Until now, you couldn't open that binary in a modern
reverse-engineering tool.

This module lets you import z/OS load modules and Linux s390x binaries into
Ghidra and get back disassembly and decompiled C:

- **Recover lost logic** — import a load module with no source and read what
  it actually does, recovered as structured C.
- **Audit undocumented code** — inspect third-party or legacy modules for
  behavior the documentation never described.
- **Analyze before migrating** — understand a legacy module's real behavior
  before rewriting or moving it off the mainframe.

> **Ghidra-Rare fork.** This branch (`ghidra-rare`) is the upstream module after verification
> and fixes by [Ghidra-Rare](https://github.com/aleph-void/ghidra-s390x/tree/ghidra-rare):
> every entry of the GNU binutils z/Architecture opcode table (g5 to z17) decodes as objdump
> does, and the instruction semantics are checked against qemu-s390x, reference models and
> the Principles of Operation. See [GHIDRA-RARE.md](GHIDRA-RARE.md) for what was verified, the
> results, the remaining gaps, and how to run the tests, and [CREDITS.md](CREDITS.md) for
> provenance. Prebuilt extension zips for Ghidra 12.1.3, 12.1.4 and 12.2 are on the
> [Releases page](https://github.com/aleph-void/ghidra-s390x/releases).

## Status

- **Language ID:** `s390x:BE:64:default` (cspecs: Linux ELF ABI, z/OS Language Environment,
  z/OS XPLINK). Target: Ghidra 12.1.4; extension zips build for 12.1.3, 12.1.4 and 12.2.
- **Decoding:** all 2,748 entries of the binutils 2.45 opcode table (z/Architecture g5 through
  z17) agree with GNU objdump, 8 encodings each (llvm-objdump as a second check); random words agree
  100%. Upstream's HLASM corpus (4,308 encodings assembled with IBM HLASM R6.0 on z/OS) is
  kept in `tests/`.
- **Semantics:** p-code for the general, binary/hexadecimal/decimal floating-point, decimal,
  vector (integer, BFP, packed decimal, string) instructions, checked by differential tests
  against qemu-s390x and against reference models for what qemu lacks (decimal, HFP, DFP,
  vector packed decimal). Privileged, I/O and hardware-state instructions stay named pcodeops.
- **Loaders:** Linux s390x ELF (opinion, relocations, PLT), z/OS classic load modules
  (CESD/ESD/text/RLD with relocation), GOFF and program objects, all included in the
  extension.

## Layout

```
data/languages/      SLEIGH sources (s390x.slaspec + *.sinc), compiled s390x.sla,
                     s390x.ldefs, pspec/cspec (Linux, z/OS LE, XPLINK), opinion file
src/main/java/         Java sources: z/OS loaders (ZosLoadModuleLoader, ZosGoffLoader,
                     ZosProgramObjectLoader, ZosUtil) and the s390x ELF
                     relocation handler
tools/               Generators, validators, loader build scripts
tests/               Differential corpora, decoder/p-code harness sources,
                     Ghidra headless smoke scripts and fixtures
hlasm_batches/       HLASM source batches used to build the z/OS corpus
CONVENTIONS.md       SLEIGH authoring conventions (read before editing the spec)
CHANGELOG.md         Dated history of fixes
LOADERS.md           Loader design, formats, validation, limits
```

## Install

Download the zip for your Ghidra version from the
[Releases page](https://github.com/aleph-void/ghidra-s390x/releases) and install it with
**File > Install Extensions** (or unzip it into `$GHIDRA_INSTALL_DIR/Ghidra/Extensions`), then
restart Ghidra. Linux s390x ELF files import with the stock ELF loader (the opinion picks
`s390x:BE:64:default`), raw binaries with `-processor s390x:BE:64:default`, and classic load
modules, GOFF or program objects with `ZosLoadModuleLoader`, `ZosGoffLoader` or
`ZosProgramObjectLoader` (picked automatically by file signature).

## Build

Requires Ghidra 12.1.x or 12.2 with its JDK, Gradle and Python 3.

```sh
export GHIDRA_INSTALL_DIR=/path/to/ghidra_12.1.4_PUBLIC
gradle buildExtension           # dist/ghidra_12.1.4_PUBLIC_<date>_s390x.zip
```

`data/languages/s390x.sla` is committed; to rebuild it after editing the SLEIGH sources run
`$GHIDRA_INSTALL_DIR/support/sleigh data/languages/s390x.slaspec`. Most of
`s390x_table_gen.sinc` is generated: `tools/gen_table.py` with the semantics of
`tools/gen_semantics.py` (and `gen_vector.py`, `gen_fp.py`, `gen_hfp.py`, `gen_dfp.py`,
`gen_vpd.py`, `gen_misc.py`); `GHIDRA-RARE.md` has the command. The compiled `.sla` must
inflate to less than 16 MiB or Ghidra refuses it with a misleading "Decoding error"
(`test/run-tests.sh` checks this).

## Validation

`test/run-tests.sh` runs the Ghidra-Rare test suite (SLEIGH compile and size, decode against
objdump and llvm-objdump, hand-computed emulator tests, the qemu-s390x differential and the
reference-model differentials); `test/fetch-real-samples.sh` and `test/real-binaries.sh` run
the Debian/Ubuntu binaries. `GHIDRA-RARE.md` has the details and current results.

The upstream harness (`tests/sleigh_diff.py` against recorded Capstone output, the
`tests/validate_*.py` p-code validators and the headless smoke scripts) is unchanged; it
predates the fixes, so some of its recorded expectations reflect the old decoding. The HLASM
corpus (`tests/corpus_zos_hlasm_full.json`, 4,326 entries) was built by assembling
`hlasm_batches/*.asm` with IBM HLASM R6.0 on z/OS.

## Known limitations

Upstream's list, with what changed (details in `GHIDRA-RARE.md`):

- ~~41 instructions are ARCH-gated at HLASM R6.0's default ARCH level and checked against the
  Principles of Operation only~~ **Fixed:** they decode as GNU objdump does, and their
  semantics are covered by the qemu and model differentials.
- ~~29 mnemonics are deliberately not decoded~~ **Fixed:** every opcode-table entry decodes.
- ~~XPLINK returns are a known gap~~ **Fixed:** `BR 7` and `B 2(,7)`/`B 4(,7)` are returns
  under the XPLINK compiler spec.
- ~~Some privileged/crypto operations use opaque semantics; vector semantics are incomplete;
  approximate HFP semantics~~ **Fixed** for everything the architecture defines from program
  state: all vector, BFP, HFP, DFP and decimal instructions, PLO, CUSE, TRTE and the z17
  additions have real p-code. **Remaining**, with reasons: privileged, I/O, timing and
  configuration instructions (hardware state outside the program), transactional execution
  (the abort outcome is a run-time event), NNPA and the NNP-data-type conversions (the
  Principles of Operation leave the format model-dependent), the CPACF crypto, CMPSC, SORTL,
  DFLTCC and PFPO instructions (not implemented; see `GHIDRA-RARE.md`).
- ~~ELF relocations are handled only by the optional handler~~ **Fixed:** the relocation
  handler and the loaders are part of the extension.
- ~~Decompiled branch conditions show condition-code bit manipulation~~ **Fixed:** branches
  decompile to `if (a == b)`, `if (a < b)`, `if ((x & 0x10) == 0)`.
- Fixed-point divide and other program exceptions are not modelled (a trap pcodeop or no
  effect): an exception is a run-time event.
- **Remaining (no samples):** modern PM3+ program objects are detected but refused; CTL+RLD,
  overlay/scatter and continued records are refused; full PDS-image parsing is not
  implemented. No legally usable z/OS load modules exist to validate against.

## References

- IBM *z/Architecture Principles of Operation*, SA22-7832 (15th ed.)
  https://publibfp.dhe.ibm.com/epubs/pdf/dz9zr003.pdf
- IBM s390x ABI: https://github.com/IBM/s390xabi
- IBM *MVS Program Management: Advanced Facilities*: SA22-7644
  (load module / GOFF record layouts, Appendices B and C)
