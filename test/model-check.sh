#!/usr/bin/env bash
# Ghidra p-code vs the reference models of model_diff.py (instructions qemu-s390x lacks).
#   test/model-check.sh decimal <workdir> [tests-per-mnemonic] [seed]
#   test/model-check.sh hfp|dfp <workdir> <s390-opc.txt> <s390-operands.txt> [tests-per-mnemonic] [seed]
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
MODE=$1 W=$(readlink -m "$2")
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
mkdir -p "$W"
if [[ $MODE == decimal ]]; then
	python3 "$HERE/model_diff.py" gen "$W" "${3:-200}" "${4:-1}"
else
	python3 "$HERE/model_diff.py" "$MODE" "$W" "$3" "$4" "${5:-100}" "${6:-1}"
fi
P=$(mktemp -d "${PROJ_DIR:-${TMPDIR:-/tmp}}/s390x-md.XXXXXX")
trap 'rm -rf "$P"' EXIT
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$P" p -import "$W/qd.elf" -loader BinaryLoader \
	-loader-baseAddr 0x10000000 -processor s390x:BE:64:default -noanalysis -scriptPath "$HERE" \
	-postScript QemuDiff.java "$W/qd.txt" "$W/g.bin" -deleteProject >"$W/ghidra.log" 2>&1
python3 "$HERE/model_diff.py" cmp "$W" "$W/g.bin" 3 >"$W/cmp.txt"
head -1 "$W/cmp.txt"
