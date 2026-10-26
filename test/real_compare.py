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

def fix_targets(text, objdump, delta=delta):
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

def objdump_variants(text):
    """objdump's text with each bare number read as decimal (an immediate) or as hex (a
    PC-relative target, rewritten in decimal): every combination, all-decimal first."""
    parts = text.split(None, 1)
    if len(parts) < 2:
        return [text]
    ops = re.split(r"(,)", parts[1])
    idx = [i for i, t in enumerate(ops) if re.fullmatch(r"[0-9a-f]+", t.strip())]
    out = []
    for mask in range(1 << min(len(idx), 4)):
        o = list(ops)
        for k, i in enumerate(idx[:4]):
            if mask >> k & 1:
                o[i] = str(int(o[i].strip(), 16))
        out.append(parts[0] + " " + "".join(o))
    return out

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
    # objdump prints a PC-relative target as bare hex but immediates as decimal: try both. In a
    # rebased shared object only targets move by delta, so try Ghidra's text with and without it
    # (a 32-bit immediate such as LLIHF's looks like an address).
    gns = [C.norm(fix_targets(text, False))] + ([C.norm(fix_targets(text, False, 0))] if delta else [])
    ons = [C.norm(x) for x in objdump_variants(ot)]
    on_hex, on_dec = ons[-1], ons[0]
    if any(gn in ons for gn in gns):
        cnt["exact"] += 1
    elif any(C.signed_equal(gn, x) or (C.CANON and (C.CANON.canon(gn) == C.CANON.canon(x) or
                                                     C.signed_equal(C.CANON.canon(gn), C.CANON.canon(x))))
             for x in ons for gn in gns):
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
