#!/usr/bin/env bash
# Decode diff of s390x:BE:64:default against GNU objdump (-m s390:64-bit) on every
# opcode-table entry (8 encodings each) and 60,000 random instructions; the table also against
# llvm-objdump (-mcpu=arch15) when it is installed.
#   test/run-decode.sh <workdir>
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
W=$(readlink -m "$1"); mkdir -p "$W"; cd "$W"
: "${OBJDUMP:=$HOME/.cache/ghidra-rare-scratch/tools/binutils-all/bin/objdump}"
: "${LLVM_OBJDUMP:=llvm-objdump}" : "${LLVM_OBJCOPY:=llvm-objcopy}"
# GNU binutils' s390 opcode and operand tables, dumped from the installed libopcodes
# (generated here rather than committed: binutils is GPL)
if [[ -z ${S390_OPC:-} ]]; then
	"$HERE/build-dumpopc.sh" "$W/dumpopc"
	"$W/dumpopc" s390 >"$W/s390-opc.txt"
	"$W/dumpopc" operands >"$W/s390-operands.txt"
	S390_OPC=$W/s390-opc.txt S390_OPERANDS=$W/s390-operands.txt
fi
python3 "$HERE/gen_corpus.py" "$S390_OPC" .
for b in table fuzz; do
	"$OBJDUMP" -z -D -b binary -m s390:64-bit $b.bin > o_$b.txt
	"$HERE/ghidra-dis.sh" s390x:BE:64:default $b.bin g_$b.txt &
done
wait
python3 "$HERE/compare.py" g_table.txt o_table.txt 3 --idx table.idx --opc "$S390_OPC" \
	--operands "$S390_OPERANDS" --status st_table.txt > cmp_table.txt
python3 "$HERE/compare.py" g_fuzz.txt o_fuzz.txt 3 --opc "$S390_OPC" --operands "$S390_OPERANDS" > cmp_fuzz.txt
echo "table: $(head -1 cmp_table.txt)"
echo "fuzz:  $(head -1 cmp_fuzz.txt)"
sed -n '/^opcode-table entries/,$p' cmp_table.txt

# second oracle: llvm-objdump. It rejects encodings with nonzero reserved fields that binutils
# accepts, and spells some operands differently (%fN for vector registers 0-15 of scalar FP
# instructions, an omitted zero base, RNSBG's test bit as part of I3).
if command -v "$LLVM_OBJDUMP" >/dev/null; then
	"$LLVM_OBJCOPY" -I binary -O elf64-s390 --rename-section=.data=.text,code table.bin l_table.o
	"$LLVM_OBJDUMP" -d -z --mcpu=arch15 l_table.o | sed -E 's/^( *[0-9a-f]+): /\1:\t/; s/, /,/g; s/ +\t/ \t/' > l_table.txt
	python3 "$HERE/compare.py" g_table.txt l_table.txt 3 --idx table.idx --opc "$S390_OPC" \
		--operands "$S390_OPERANDS" > cmp_table_llvm.txt
	echo "table vs llvm-objdump: $(head -1 cmp_table_llvm.txt)"
fi
