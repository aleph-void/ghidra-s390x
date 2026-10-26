#!/usr/bin/env bash
# Ghidra p-code vs qemu-s390x on random instructions (qemu_diff.py, QemuDiff.java).
#   test/qemu-check.sh <s390-opc.txt> <s390-operands.txt> <workdir> [tests-per-entry] [seed]
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
OPC=$1 OPERANDS=$2 W=$(readlink -m "$3") PER=${4:-24} SEED=${5:-1}
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
mkdir -p "$W"
[[ -s $W/ok-entries.txt && -z ${REPROBE:-} ]] || python3 "$HERE/qemu_diff.py" probe "$OPC" "$OPERANDS" "$W" "$PER" "$SEED"
python3 "$HERE/qemu_diff.py" gen "$OPC" "$OPERANDS" "$W/ok-entries.txt" "$W" "$PER" "$SEED"
"${QEMU_S390X:-qemu-s390x}" "$W/qd.elf" >"$W/q.bin"
P=$(mktemp -d "${PROJ_DIR:-${TMPDIR:-/tmp}}/s390x-qd.XXXXXX")
trap 'rm -rf "$P"' EXIT
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$P" p -import "$W/qd.elf" -loader BinaryLoader \
	-loader-baseAddr 0x10000000 -processor s390x:BE:64:default -noanalysis -scriptPath "$HERE" \
	-postScript QemuDiff.java "$W/qd.txt" "$W/g.bin" -deleteProject >"$W/ghidra.log" 2>&1
python3 "$HERE/qemu_diff.py" cmp "$W" "$W/q.bin" "$W/g.bin" 3 >"$W/cmp.txt"
head -1 "$W/cmp.txt"
