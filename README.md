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

## Status

- **Processor spec:** `data/languages/s390x.slaspec` + extension `.sinc` files,
  ~4,356 constructors, compiles with Ghidra's SLEIGH compiler with 0 errors.
- **Language ID:** `s390x:BE:64:default`
- **HLASM validation on real z/OS:** 4,308 instruction encodings assembled
  with IBM HLASM R6.0 and validated against the SLEIGH decoder — every
  correctly-extracted byte sequence decodes.
  Plus 18 EBCDIC-sensitive vectors. See `tests/VALIDATION.md`.
- **Semantic validation:** 303/303 p-code vectors green (branches, TM,
  division, TRTT, FP, decimal, vector, load/store).
- **Differential fuzzing:** 20,000 inputs, 0 crashes, 0 misdecodes.
- **Smoke-tested in Ghidra 12.1.3:** module loads, raw and ELF binaries import,
  disassembly matches Capstone, and the decompiler produces structured C
  (recovered `do/while` loops, if/else, function calls/returns).
- **z/OS loaders:** classic MVS load modules (CESD/ESD/text/RLD parsing with
  relocation) and GOFF, each validated in headless Ghidra against synthetic
  test files. Plus a z/OS Language Environment ABI compiler spec (`zos`)
  auto-selected by both loaders.

See `LOADERS.md` for the loader design, `tests/VALIDATION.md` for validation
results, `CHANGELOG.md` for history, and `CONVENTIONS.md` for the authoring
conventions used throughout the spec.

## Layout

```
data/languages/      SLEIGH sources (s390x.slaspec + *.sinc), compiled s390x.sla,
                     s390x.ldefs, pspec/cspec (Linux, z/OS LE, XPLINK), opinion file
loaders/src/         Java sources: z/OS loaders (ZosLoadModuleLoader, ZosGoffLoader,
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

## Build

Requires Ghidra 12.1.3 (OpenJDK 21) and Python 3. The validators also need
Capstone (`pip install capstone`).

```sh
export GHIDRA_INSTALL_DIR=<path-to-ghidra_12.1.3_PUBLIC>

# Rebuild the .sla from sources (the SLEIGH compiler ships with Ghidra)
$GHIDRA_INSTALL_DIR/support/sleigh -a data/languages   # writes data/languages/s390x.sla
```

## Install

The module goes in `$GHIDRA_INSTALL_DIR/Ghidra/Processors/s390x/`. Ghidra
needs `Module.manifest` and `data/languages/` there:

```sh
DEST=$GHIDRA_INSTALL_DIR/Ghidra/Processors/s390x
mkdir -p "$DEST"
cp Module.manifest "$DEST"/
cp -r data "$DEST"/

# Optional: compile and install the z/OS loaders and the ELF relocation
# handler (each script writes a jar to $DEST/lib/)
tools/build_zos_loaders.sh
tools/build_elf_reloc.sh
```

Restart Ghidra after installing. Raw binaries import with the stock Raw
Binary loader (`-processor s390x:BE:64:default`), Linux s390x ELF with the
stock ELF loader, and classic load modules or GOFF with `ZosLoadModuleLoader`
or `ZosGoffLoader` (picked automatically by file signature).

## Validation

The differential harness decodes every vector in `tests/corpus.json` with the
compiled `.sla` and compares against recorded Capstone output. It needs the
`tests/s390x_decode` helper, built from Ghidra's decompiler C++ sources:

```sh
git clone --depth 1 --branch Ghidra_12.1.3_build --filter=blob:none --sparse \
  https://github.com/NationalSecurityAgency/ghidra.git ~/ghidra-src
git -C ~/ghidra-src sparse-checkout set Ghidra/Features/Decompiler/src/decompile/cpp
export GHIDRA_CPP_SRC=~/ghidra-src/Ghidra/Features/Decompiler/src/decompile/cpp

SRCS="xml marshal space float address pcoderaw translate opcodes globalcontext \
  sleigh pcodeparse pcodecompile sleighbase slghsymbol slghpatexpress \
  slghpattern semantics context slaformat compression filemanage loadimage"
g++ -O2 -std=c++17 -I "$GHIDRA_CPP_SRC" \
  $(for f in $SRCS; do echo "$GHIDRA_CPP_SRC/$f.cc"; done) \
  tests/s390x_decode.cc -lz -o tests/s390x_decode

python3 tests/sleigh_diff.py
```

The p-code validators (`tests/validate_cond2.py`, `tests/validate_vector2.py`)
build their own helper from `$GHIDRA_CPP_SRC`. The `tools/validate_*.py`
scripts that recompile the spec need Ghidra's `sleigh_opt` binary (build it
with `make sleigh_opt` in `$GHIDRA_CPP_SRC`) on `PATH` or in `$SLEIGH_OPT`.

The Ghidra smoke tests (`tests/*.java`, `tests/ghidra_smoke.py`,
`tests/elf_smoke_test.py`) run inside headless Ghidra; `LOADERS.md` has the
exact `analyzeHeadless` commands. They write output to `$S390X_TESTS_DIR`
(default `tests`).

The HLASM corpus (`tests/corpus_zos_hlasm_full.json`, 4,326 entries) was
built by assembling `hlasm_batches/*.asm` with IBM HLASM R6.0 on z/OS and
checking the listings with `tools/validate_hlasm_corpus.py`.

## Known limitations

- 41 instructions are ARCH-gated at HLASM R6.0's default ARCH level
  (SELECT family, MG/MGH, KMA, DFP convert variants). They are checked
  against the Principles of Operation text only.
- 29 mnemonics are deliberately not decoded (privileged/system, DFP, and
  unimplemented families). They are listed in `tests/VALIDATION.md` with
  the bytes HLASM produced.
- Modern PM3+ program objects are detected but refused (IBM's binder layout is
  not publicly documented; no samples available to validate against).
- CTL+RLD, overlay/scatter, and continued records are refused, not half-parsed.
- Full PDS-image parsing is not implemented.
- XPLINK support is limited to the `zos_xplink` compiler spec; XPLINK
  returns are a known gap (see `CHANGELOG.md`).
- Some privileged/crypto operations use intentionally opaque semantics; vector
  semantics are incomplete in places; fixed-point divide exceptions are not
  modeled.
- ELF relocations are handled only by the optional handler from
  `tools/build_elf_reloc.sh`; without it, only static ET_EXEC binaries import
  cleanly.
- Decompiled branch conditions show Ghidra-style condition-code bit manipulation.

## References

- IBM *z/Architecture Principles of Operation*, SA22-7832 (15th ed.)
  https://publibfp.dhe.ibm.com/epubs/pdf/dz9zr003.pdf
- IBM s390x ABI: https://github.com/IBM/s390xabi
- IBM *MVS Program Management: Advanced Facilities*: SA22-7644
  (load module / GOFF record layouts, Appendices B and C)
