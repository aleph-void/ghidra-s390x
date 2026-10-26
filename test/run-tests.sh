#!/usr/bin/env bash
# IBM z/Architecture (s390x) module test suite: everything that needs no downloaded inputs.
#
#   test/run-tests.sh [workdir]
#
# Environment:
#   GHIDRA_INSTALL_DIR  Ghidra 12.1.x/12.2 to test with. The module is symlinked into its
#                       Ghidra/Processors/s390x (a different existing entry is left alone) and
#                       lib/s390x.jar is rebuilt; use a scratch copy, not your real install.
#   OBJDUMP             GNU binutils objdump with the s390 target (default: the Ghidra-Rare
#                       all-targets 2.45 build; /usr/bin/objdump of a recent binutils also works)
#   LLVM_MC             llvm-mc with the SystemZ target (default: llvm-mc on PATH)
#   JAVA_HOME           a JDK with javac (for lib/s390x.jar)
#   QEMU_S390X          qemu-s390x user-mode emulator (default: qemu-s390x on PATH; skipped
#                       when missing)
#   PROJ_DIR            where throw-away Ghidra projects go (no "." directories in the path)
# Real binaries (Debian/Ubuntu s390x packages) are separate: test/fetch-real-samples.sh and
# test/real-binaries.sh.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
MOD=$(cd "$HERE/.." && pwd)
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR to a scratch Ghidra 12.1.x}"
: "${OBJDUMP:=$HOME/.cache/ghidra-rare-scratch/tools/binutils-all/bin/objdump}"
QEMU_S390X=${QEMU_S390X:-qemu-s390x}
W=$(readlink -m "${1:-${TMPDIR:-/tmp}/s390x-tests}")
mkdir -p "$W"
export OBJDUMP
if [[ -z ${JAVA_HOME:-} && -x /usr/lib/jvm/java-25-openjdk-amd64/bin/javac ]]; then
	export JAVA_HOME=/usr/lib/jvm/java-25-openjdk-amd64
fi

echo "== compiling SLEIGH"
"$GHIDRA_INSTALL_DIR/support/sleigh" "$MOD/data/languages/s390x.slaspec" 2>&1 | grep -E "^ERROR" && exit 1 || true
# Ghidra refuses (with a misleading decode error) a .sla that inflates to 16 MiB or more
python3 - "$MOD/data/languages/s390x.sla" <<'EOF'
import sys, zlib
d = open(sys.argv[1], "rb").read()
n = len(zlib.decompress(d[4:]))
print(f"   s390x.sla: {len(d)} bytes, {n} decoded ({100 * n / (1 << 24):.1f}% of the 16 MiB limit)")
sys.exit(n >= 1 << 24)
EOF
P="$GHIDRA_INSTALL_DIR/Ghidra/Processors/s390x"
if [[ ! -e $P ]]; then ln -s "$MOD" "$P"; elif [[ $(readlink -f "$P") != "$MOD" ]]; then
	echo "warning: $P exists and is not this module" >&2; fi
"$HERE/build-jar.sh"

echo "== decode: every opcode-table entry and 60,000 random instructions vs GNU objdump"
"$HERE/run-decode.sh" "$W/decode"

echo "== p-code: hand-computed emulator tests (emu_tests.py / EmuCheck.java)"
python3 "$HERE/emu_tests.py" "$W"
"$HERE/ghidra-script.sh" raw s390x:BE:64:default "$W/emu.bin" EmuCheck.java "$W/emu.txt" "$W/emu_out.txt"
grep -v "^PASS" "$W/emu_out.txt"

echo "== p-code: random instructions of every opcode-table entry, Ghidra emulator vs qemu-s390x"
if command -v "$QEMU_S390X" >/dev/null; then
	"$HERE/qemu-check.sh" "$W/decode/s390-opc.txt" "$W/decode/s390-operands.txt" "$W/qemu" 16
else
	echo "   (skipped: $QEMU_S390X not found)"
fi

echo "== p-code: instructions qemu-s390x lacks, Ghidra emulator vs reference models (model_diff.py)"
"$HERE/model-check.sh" decimal "$W/model-decimal" 300
"$HERE/model-check.sh" hfp "$W/model-hfp" "$W/decode/s390-opc.txt" "$W/decode/s390-operands.txt" 60
"$HERE/model-check.sh" dfp "$W/model-dfp" "$W/decode/s390-opc.txt" "$W/decode/s390-operands.txt" 150
"$HERE/model-check.sh" vpd "$W/model-vpd" "$W/decode/s390-opc.txt" "$W/decode/s390-operands.txt" 150
"$HERE/model-check.sh" pfpo "$W/model-pfpo" "$W/decode/s390-opc.txt" "$W/decode/s390-operands.txt" 1500

echo "== p-code: every temporary is written before it is read, on every path (all table instructions)"
"$HERE/ghidra-dis.sh" s390x:BE:64:default "$W/decode/table.bin" "$W/decode/pc_table.txt" 8 pcode
python3 "$HERE/pcode_defcheck.py" "$W/decode/pc_table.txt"
