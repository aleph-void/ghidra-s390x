#!/usr/bin/env bash
# Build dumpopc (GNU binutils opcode-table dumper) against an installed binutils.
#   test/build-dumpopc.sh <out-binary>
# BINUTILS_SRC: binutils source tree (for include/opcode/*.h)
# BINUTILS_LIB: directory with the installed libopcodes.a, libbfd.a, libsframe.a
# LIBIBERTY:    a host libiberty.a
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
: "${BINUTILS_SRC:=$HOME/.cache/ghidra-rare-scratch/tools/bu/binutils-2.45}"
: "${BINUTILS_LIB:=$HOME/.cache/ghidra-rare-scratch/tools/binutils-all/lib}"
: "${LIBIBERTY:=$HOME/.cache/ghidra-rare-scratch/tools/bu/build/libiberty/libiberty.a}"
gcc -I"$BINUTILS_SRC/include" "$HERE/dumpopc.c" "$BINUTILS_LIB/libopcodes.a" "$BINUTILS_LIB/libbfd.a" \
	"$LIBIBERTY" "$BINUTILS_LIB/libsframe.a" -lz -lzstd -o "$1"
