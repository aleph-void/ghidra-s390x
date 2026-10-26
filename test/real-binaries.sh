#!/usr/bin/env bash
# Real-world binary check: import each sample headless with NO -processor flag (the ELF opinion
# must pick the language), auto-analyze, decompile every function (RealCheck.java), and diff
# Ghidra's disassembly of every instruction it found against GNU objdump at the same addresses.
#
#   test/fetch-real-samples.sh <samples>     # download the pinned Debian/Ubuntu s390x samples once
#   test/real-binaries.sh <samples> <workdir>
#
# GHIDRA_INSTALL_DIR: Ghidra with this module under Ghidra/Processors/s390x and lib/s390x.jar
# built (test/build-jar.sh). OBJDUMP: binutils with the s390 target. DECOMP_TIMEOUT: seconds
# per function (default 60; 0 skips decompiling). PROJ_DIR: where the throw-away Ghidra projects go.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
: "${OBJDUMP:=$HOME/.cache/ghidra-rare-scratch/tools/binutils-all/bin/objdump}"
TMO=${DECOMP_TIMEOUT:-60}
SAMPLES=$(readlink -f "$1")
W=$(readlink -m "$2")
mkdir -p "$W"
files=(libz.so.1.3.1 ls sort libc.so.6 libc-ubuntu.so.6 busybox)
# binutils' opcode/operand tables let real_compare.py accept objdump's extended mnemonics
# (jg for brcl 15, vzero for vgbm 0, ...) as the same instruction
if [[ -z ${S390_OPC:-} ]]; then
	"$HERE/build-dumpopc.sh" "$W/dumpopc"
	"$W/dumpopc" s390 >"$W/s390-opc.txt"
	"$W/dumpopc" operands >"$W/s390-operands.txt"
	S390_OPC=$W/s390-opc.txt S390_OPERANDS=$W/s390-operands.txt
fi

run_one() { # file
	local f=$1 n p
	n=$(basename "$f")
	# Ghidra rejects project paths with a dot-directory (e.g. ~/.cache); PROJ_DIR may point at
	# a symlink to disk instead (default: $TMPDIR).
	p=$(mktemp -d "${PROJ_DIR:-${TMPDIR:-/tmp}}/s390x-real.XXXXXX")
	"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$p" p -import "$f" -scriptPath "$HERE" \
		-postScript RealCheck.java "$W/$n.sum" "$W/$n.lst" "$W/$n.c" "$TMO" \
		-deleteProject >"$W/$n.log" 2>&1 || { tail -20 "$W/$n.log" >&2; }
	rm -rf "$p"
}
echo "== headless import + analysis + decompile (${#files[@]} files)"
for f in "${files[@]}"; do run_one "$SAMPLES/$f" & done
wait
echo "== results"
for n in "${files[@]}"; do
	f=$SAMPLES/$n
	etype=$(python3 -I -c 'import sys; print(int.from_bytes(open(sys.argv[1],"rb").read(18)[16:18],"big"))' "$f")
	delta=0
	[[ $etype == 3 ]] && delta=$(sed -n 's/^image base: //p' "$W/$n.sum")
	"$OBJDUMP" -d "$f" >"$W/$n.od"
	echo "-- $n (e_type $etype)"
	grep -E "^(language|functions|instructions|fallthrough|bad-instruction|error bookmarks|relocations|decompile|functions whose)" "$W/$n.sum" | sed 's/^/   /'
	echo "   vs objdump: $(python3 "$HERE/real_compare.py" "$W/$n.lst" "$W/$n.od" 10 "$delta" "${S390_OPC:-}" "${S390_OPERANDS:-}" | tee "$W/$n.cmp" | head -1)"
done
echo "(full outputs: $W/<file>.{sum,lst,c,cmp,log})"
