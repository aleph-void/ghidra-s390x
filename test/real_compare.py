#!/usr/bin/env python3
"""Compare Ghidra's disassembly of a real binary (RealCheck.java listing) with objdump -d.

  real_compare.py <ghidra.lst> <objdump-d.txt> [examples] [address-delta] [s390-opc.txt s390-operands.txt]

Every instruction Ghidra found is looked up at the same address (minus address-delta, the image
base Ghidra rebased a shared object to) and compared with compare.py's normalization; with the
opcode-table dumps, extended mnemonics and aliases count as semantic agreement.
"""
import os, re, sys
from collections import Counter, defaultdict
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import compare as C

gfile, ofile = sys.argv[1], sys.argv[2]
nex = int(sys.argv[3]) if len(sys.argv) > 3 else 5
delta = int(sys.argv[4], 0) if len(sys.argv) > 4 else 0
if len(sys.argv) > 6 and sys.argv[5]:
    C.CANON = C.Canon(sys.argv[5], sys.argv[6])
o = {}
for line in open(ofile):
    m = re.match(r"\s*([0-9a-f]+):\t([0-9a-f ]+)\t(.*)$", line)
    if m:
        o[int(m.group(1), 16)] = re.sub(r"\s*<[^>]*>", "", m.group(3).replace("\t", " ")).strip()

def fix_targets(text, objdump):
    """objdump prints PC-relative targets as bare hex in ELF mode; Ghidra prints rebased
    0x addresses. Any operand that looks like an address is rewritten as decimal."""
    parts = text.split(None, 1)
    if len(parts) < 2:
        return text
    ops = re.split(r"(,)", parts[1])
    out = []
    for t in ops:
        s = t.strip()
        if objdump and re.fullmatch(r"[0-9a-f]+", s):
            t = str(int(s, 16))
        elif not objdump and re.fullmatch(r"0x[0-9a-f]{5,}", s) and delta:
            v = int(s, 16) - delta
            t = str(v) if v >= 0 else s
        out.append(t)
    return parts[0] + " " + "".join(out)

cnt = Counter()
classes = defaultdict(list)
for line in open(gfile):
    addr, hexb, text = line.rstrip("\n").split(" ", 2)
    a = int(addr, 16) - delta
    ot = o.get(a)
    if ot is None:
        cnt["not in objdump -d"] += 1
        continue
    if re.match(r"\.(long|short|byte)", ot):
        cnt["objdump undefined"] += 1
        classes[("objdump-undefined", text.split()[0].lower())].append((addr, text, ot))
        continue
    # objdump prints a PC-relative target as bare hex but immediates as decimal: try both
    gn = C.norm(fix_targets(text, False))
    on_hex, on_dec = C.norm(fix_targets(ot, True)), C.norm(ot)
    on = on_hex if gn == on_hex else on_dec
    if gn == on:
        cnt["exact"] += 1
    elif any(C.signed_equal(gn, x) or (C.CANON and (C.CANON.canon(gn) == C.CANON.canon(x) or
                                                     C.signed_equal(C.CANON.canon(gn), C.CANON.canon(x))))
             for x in (on_hex, on_dec)):
        cnt["semantic"] += 1
    else:
        cnt["differ"] += 1
        classes[("differ", text.split()[0].lower() + " / " + ot.split()[0])].append((addr, text, ot))
n = cnt["exact"] + cnt["semantic"] + cnt["differ"]
print(f"instructions {n}: exact {cnt['exact']}, semantic {cnt['semantic']}, differ {cnt['differ']} "
      f"({100 * (cnt['exact'] + cnt['semantic']) / max(1, n):.3f}% agree); "
      f"objdump undefined {cnt['objdump undefined']}, not in objdump -d {cnt['not in objdump -d']}")
for k, v in sorted(classes.items(), key=lambda kv: -len(kv[1])):
    print(f"  [{len(v):5d}] {k[0]}: {k[1]}")
    for a, gt, ot in v[:nex]:
        print(f"           {a}  ghidra: {gt:40s} objdump: {ot}")
