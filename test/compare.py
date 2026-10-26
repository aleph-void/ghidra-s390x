#!/usr/bin/env python3
"""Compare Ghidra's s390x disassembly with GNU objdump's (or llvm-mc's), slot by slot.

  compare.py <ghidra.txt> <objdump.txt> [examples] [--opc s390-opc.txt --operands s390-operands.txt]
             [--idx table.idx] [--status out]

ghidra.txt: DumpDisasm.java output ("<offset> <bytes> <text>") for 8-byte slots.
objdump.txt: `objdump -z -D -b binary -m s390:64-bit` output (only lines at slot starts count).
Prints exact / semantic agreement and every difference class with examples. With --idx/--opc
(table corpus), also reports per-entry and per-facility (min_cpu) coverage.
"""
import os, re, sys
from collections import Counter, defaultdict

def num(t):
    try:
        return int(t, 0)
    except ValueError:
        return None

def norm_tok(t):
    t = t.strip().lower()
    t = re.sub(r"^%([rfavc])(\d+)$", r"\1\2", t)
    if t in ("zero",):
        return "0"
    n = num(t)
    return str(n & 0xffffffffffffffff) if n is not None else t

def split_ops(ops):
    return [x for x in re.split(r"([,()])", ops) if x.strip()]

def norm(text):
    parts = text.strip().split(None, 1)
    mn = parts[0].lower()
    ops = parts[1] if len(parts) > 1 else ""
    toks = [norm_tok(t) for t in split_ops(ops)]
    return " ".join([mn] + toks)

def load_ghidra(p):
    d = {}
    for line in open(p):
        off, h, text = line.rstrip("\n").split(" ", 2)
        d[int(off, 16)] = (h, None if text.startswith("BAD") else text)
    return d

def load_objdump(p):
    d = {}
    for line in open(p):
        m = re.match(r"\s*([0-9a-f]+):\t([0-9a-f ]+)\t(.*)$", line)
        if not m:
            continue
        text = re.sub(r"\s*<[^>]*>", "", m.group(3).replace("\t", " ")).strip()
        # undefined: objdump's .long/.short/.byte, llvm-objdump's <unknown> (empty after the strip)
        d[int(m.group(1), 16)] = None if not text or re.match(r"\.(long|short|byte)", text) else text
    return d

class Canon:
    """Semantic canonical form from the opcode table: aliases (identical opcode and mask) map to
    one name, and extended mnemonics (an operand fixed by the mask, e.g. jgnh, selgrhe, vzero,
    nop) expand to their base instruction with that operand written out. Trailing optional
    operands are padded with 0."""
    def __init__(self, opc, operands):
        self.ops = {}
        for line in open(operands):
            i, b, sh, fl = line.split()
            self.ops[int(i)] = (int(b), int(sh), int(fl, 16))
        self.ent = []
        first = {}
        self.byname = {}
        for line in open(opc):
            f = line.split()
            e = dict(name=f[0], op=int(f[1], 16), mask=int(f[2], 16), len=int(f[3]),
                     flags=int(f[6], 16), ops=[int(x) for x in f[7:]])
            if int(f[6], 16) & 0x100:
                continue
            key = (e["op"], e["mask"])
            e["alias"] = first.setdefault(key, e["name"])
            self.ent.append(e)
            self.byname.setdefault(e["name"], e)
        self.base = {}
        for e in self.ent:
            best = None
            for b in self.ent:
                if b is e or b["len"] != e["len"] or b["mask"] & ~e["mask"] or b["mask"] == e["mask"]:
                    continue
                if (e["op"] & b["mask"]) != (b["op"] & b["mask"]):
                    continue
                if not set(e["ops"]) <= set(b["ops"]):
                    continue
                if best is None or bin(b["mask"]).count("1") > bin(best["mask"]).count("1"):
                    best = b
            self.base[e["name"]] = best

    def groups(self, ops):
        """Operand ids grouped as displayed: D(X,B), D(B), D(L,B) count as one."""
        out, cur = [], None
        for o in ops:
            fl = self.ops[o][2]
            if fl & 0x10:
                cur = [o]
                continue
            if cur is not None:
                cur.append(o)
                if fl & 0x20:
                    out.append(tuple(cur)); cur = None
                continue
            out.append((o,))
        return out

    def value(self, e, o):
        bits, shift, fl = self.ops[o]
        v = (e["op"] >> (48 - shift - bits)) & ((1 << bits) - 1)
        if fl & 0x100 and v >= 1 << (bits - 1):
            v -= 1 << bits
        return str(v & 0xffffffffffffffff)

    def canon(self, text):
        f = text.split()
        mn, toks = f[0], f[1:]
        mn = HLASM.get(mn, mn)
        if re.match(r"jl", mn) and ("jg" + mn[2:]) in self.byname:
            mn = "jg" + mn[2:]
        toks = [re.sub(r"^f(\d+)h$", r"f\1", t) for t in toks]
        e = self.byname.get(mn)
        if e is None:
            return text
        # split operand tokens into display groups at top-level commas
        grp, depth, cur = [], 0, []
        for t in toks:
            if t == "," and depth == 0:
                grp.append(cur); cur = []
                continue
            depth += t == "("
            depth -= t == ")"
            cur.append(t)
        if cur:
            grp.append(cur)
        name = e["alias"]
        b = self.base.get(e["name"])
        if b is not None:
            eg, bg = self.groups(e["ops"]), self.groups(b["ops"])
            it = iter(grp)
            new = []
            for g in bg:
                if g in eg:
                    new.append(next(it, ["0"]))
                else:
                    new.append([self.value(e, g[0])])
            grp = new
            name = b["alias"]
            e = b
        n = len(self.groups(e["ops"]))
        while len(grp) < n:
            grp.append(["0"])
        return " ".join([name] + [" , ".join(" ".join(g) for g in grp)])

# HLASM spellings the module uses that the GNU table lacks
HLASM = {"jlu": "jg", "jlnop": "jgnop"}
CANON = None

def signed_equal(gn, on):
    """Same tokens except immediates that agree modulo 2^8/16/32 (signed vs unsigned)."""
    g, o = gn.split(), on.split()
    if len(g) != len(o) or g[0] != o[0]:
        return False
    for a, b in zip(g, o):
        if a == b:
            continue
        x, y = num(a), num(b)
        if x is None or y is None:
            return False
        # one side must read as negative (two's complement) for a signedness difference;
        # two positive values that differ by 2^32 are a real error (e.g. a branch target)
        if (x >= 1 << 63) == (y >= 1 << 63):
            return False
        if not any((x - y) % (1 << k) == 0 for k in (8, 16, 32, 64)):
            return False
    return True

def main():
    args = [a for a in sys.argv[1:]]
    idx = opc = None
    if "--idx" in args:
        i = args.index("--idx"); idx = args[i + 1]; del args[i:i + 2]
    stout = None
    if "--status" in args:
        i = args.index("--status"); stout = args[i + 1]; del args[i:i + 2]
    if "--opc" in args:
        i = args.index("--opc"); opc = args[i + 1]; del args[i:i + 2]
    global CANON
    operands = None
    if "--operands" in args:
        i = args.index("--operands"); operands = args[i + 1]; del args[i:i + 2]
    if opc and operands:
        CANON = Canon(opc, operands)
    nex = int(args[2]) if len(args) > 2 else 5
    g, o = load_ghidra(args[0]), load_objdump(args[1])
    cnt = Counter()
    classes = defaultdict(list)
    status = {}
    for off in sorted(g):
        h, gt = g[off]
        if off not in o:
            # objdump printed an undecodable 6-byte word as .long (4 bytes) and decoded the
            # rest into this slot: no line starts here, so the slot is not comparable
            cnt["objdump out of sync"] += 1
            status[off // 8] = "skip"
            continue
        ot = o.get(off)
        st = "ok"
        if gt is None and ot is None:
            cnt["both undefined"] += 1
            st = "undef"
        elif gt is None:
            cnt["objdump only"] += 1
            classes[("objdump-only", ot.split()[0])].append((off, h, "-", ot))
            st = "bad"
        elif ot is None:
            cnt["ghidra only"] += 1
            classes[("ghidra-only", gt.split()[0].lower())].append((off, h, gt, "-"))
            st = "bad"
        else:
            gn, on = norm(gt), norm(ot)
            if gn == on:
                cnt["exact"] += 1
            elif signed_equal(gn, on) or (CANON and (CANON.canon(gn) == CANON.canon(on) or
                                                      signed_equal(CANON.canon(gn), CANON.canon(on)))):
                cnt["semantic"] += 1
                classes[("semantic", gt.split()[0].lower() + " / " + ot.split()[0])].append((off, h, gt, ot))
            else:
                cnt["differ"] += 1
                classes[("differ", gt.split()[0].lower() + " / " + ot.split()[0])].append((off, h, gt, ot))
                st = "bad"
        status[off // 8] = st
    if stout:
        with open(stout, "w") as fh:
            for k in sorted(status):
                fh.write(f"{k} {status[k]}\n")
    ref = cnt["exact"] + cnt["semantic"] + cnt["differ"] + cnt["objdump only"]
    print(f"compared {len(g)} slots: objdump decodes {ref}; exact {cnt['exact']} "
          f"({100 * cnt['exact'] / max(1, ref):.2f}%), exact+semantic {cnt['exact'] + cnt['semantic']} "
          f"({100 * (cnt['exact'] + cnt['semantic']) / max(1, ref):.2f}%), differ {cnt['differ']}, "
          f"objdump-only {cnt['objdump only']}, ghidra-only {cnt['ghidra only']}, "
          f"both undefined {cnt['both undefined']}, not comparable {cnt['objdump out of sync']}")
    for k, v in sorted(classes.items(), key=lambda kv: (kv[0][0] == "semantic", -len(kv[1]))):
        print(f"  [{len(v):5d}] {k[0]}: {k[1]}")
        for off, h, gt, ot in v[:nex]:
            print(f"           {h:12s} ghidra: {gt:40s} objdump: {ot}")
    if idx and opc:
        ent = [l.split() for l in open(opc)]
        cpus = ["g5", "g6", "z900", "z990", "z9-109", "z9-ec", "z10", "z196", "zEC12", "z13",
                "z14", "z15", "z16", "z17"]
        per = defaultdict(list)
        for s, i in enumerate(int(x) for x in open(idx)):
            per[i].append(status.get(s))
        tot, full = Counter(), Counter()
        missing = defaultdict(list)
        for i, sts in per.items():
            c = cpus[int(ent[i][5], 16)]
            tot[c] += 1
            if all(x == "ok" for x in sts):
                full[c] += 1
            else:
                missing[c].append(ent[i][0])
        print("opcode-table entries whose 8 encodings all decode and agree, by facility level:")
        for c in cpus:
            if tot[c]:
                print(f"  {c:7s} {full[c]:4d}/{tot[c]:4d}  " + " ".join(missing[c][:15]) +
                      (" ..." if len(missing[c]) > 15 else ""))
        print(f"  total   {sum(full.values())}/{sum(tot.values())}")

if __name__ == "__main__":
    main()
