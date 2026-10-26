#!/usr/bin/env python3
"""Generate SLEIGH constructors for z/Architecture opcode-table entries that the hand-written
and earlier generated .sinc files do not decode.

  tools/gen_table.py <s390-opc.txt> <s390-operands.txt> <skip-list> <out.sinc>

Inputs are text dumps of the instruction format facts of the opcode table (mnemonic, opcode
bits, opcode mask, length, operand layout; see Ghidra-Rare s390x/test/dumpopc.c):
  s390-opc.txt       name opcode(12 hex) mask(12 hex) length modes min_cpu flags operand-ids...
  s390-operands.txt  id bits shift flags        (shift counts from the most significant bit)
skip-list: entries already decoded correctly by the other .sinc files, one per line as
"<name> <opcode> <mask>" (or just "<name>" for every entry of that name).

Every generated constructor decodes exactly the bits fixed by its mask and prints operands in
GNU/IBM assembler order and syntax:
  registers r/f/a/c/v, D(X,B) / D(B) / D(L,B) / D(V,B) address operands (index 0 and base 0
  omitted as the assembler does), signed or unsigned immediates, PC-relative targets, optional
  trailing operands omitted when zero.
Semantics come from templates in gen_semantics.py when the mnemonic has one; otherwise a named
pcodeop (s390_<mnemonic>) that takes the operand values and, for instructions whose first
operand is a register they write, assigns its result to it. Branch-class entries always get
correct flow (goto/call) with a pcodeop deciding the condition.
"""
import re, sys
from collections import OrderedDict

GPR, FPR, AR, CR, DISP, BASE, INDEX, PCREL, SIGNED, LENGTH, PAIR, VR, CP16 = (
    0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80, 0x100, 0x200, 0x400, 0x800, 0x1000)
OPTPARM, OPTPARM2 = 0x1, 0x2
BRANCH, RELATIVE, CONDITIONAL, SUBROUTINE = 0x10, 0x20, 0x40, 0x80
PSEUDO = 0x100

opc_file, operand_file, skip_file, out_file = sys.argv[1:5]
OPS = {}
for line in open(operand_file):
    i, bits, shift, flags = line.split()
    OPS[int(i)] = (int(bits), int(shift), int(flags, 16))
# skip-list lines: "<name>" (every entry of that name) or "<name> <opcode> <mask>"
SKIP = set(tuple(l.split()) for l in open(skip_file) if l.strip() and not l.startswith("#"))

import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gen_semantics

fields = OrderedDict()      # name -> (token bits, lo, hi, signed)
pairs = {}                  # operand index -> field naming the odd register of its pair
ors = {}                    # operand index -> field naming register R|1
attaches = OrderedDict()    # field -> register list name
subtables = OrderedDict()   # name -> text
pcodeops = set()
REGS = {
    "gpr": [f"r{i}" for i in range(16)],
    "fpr": [f"f{i}" for i in range(16)],
    "ar": [f"a{i}" for i in range(16)],
    "cr": [f"c{i}" for i in range(16)],
    "vlo": [f"v{i}" for i in range(16)],
    "vhi": [f"v{i}" for i in range(16, 32)],
    "gpro": [f"r{i + 1}" for i in range(15)] + ["r0"],   # odd register of an even/odd pair
    "gpror": [f"r{i | 1}" for i in range(16)],           # R|1 (BXH/BXLE comparand)
    "fprp2": [f"f{(i + 2) % 16}" for i in range(16)],    # FPR n+2: low half of an extended pair
    "fprlo": [f"f{i & 13}" for i in range(16)],          # either register of a pair -> its low-numbered one
    "fprlo2": [f"f{(i & 13) + 2}" for i in range(16)],
}

def field(L, shift, bits, kind="u"):
    """Token field covering <bits> bits at MSB-relative <shift> of an L-bit token."""
    name = f"g{L}_{kind}{shift}_{bits}"
    lo, hi = L - shift - bits, L - shift - 1
    if name not in fields:
        fields[name] = (L, lo, hi, kind == "s")
        if kind in REGS:
            attaches[name] = kind
    return name

def rxb_bit(L, shift):
    vr = 3 if shift == 32 else shift // 4 - 2
    return field(L, 36 + vr, 1, "u")

def addr_subtable(L, items):
    """items: list of (opid, bits, shift, flags) for D, [X|L|V|R], B. Returns subtable name
    (exports the effective address) and the raw-length field if any."""
    d = items[0]
    mid = items[1] if len(items) == 3 else None
    b = items[-1]
    dbits, dshift = d[1], d[2]
    key = f"a{L}_{dshift}_{dbits}" + (f"_{mid[3]:x}_{mid[2]}_{mid[1]}" if mid else "") + f"_{b[2]}"
    if key in subtables:
        return key, (field(L, mid[2], mid[1], "u") if mid and mid[3] & LENGTH else None)
    if dbits == 20:
        dl = field(L, 20, 12, "u")
        dh = field(L, 32, 8, "s")
        dpat = f"{dl} & {dh}"
        dact = f"d20 = ({dh} << 12) | {dl};"
        dsym, dval = "d20", "d20"
    else:
        dl = field(L, dshift, dbits, "u")
        dpat, dact, dsym, dval = dl, "", dl, dl
    bg = field(L, b[2], b[1], "gpr")
    braw = field(L, b[2], b[1], "u")
    cases = []
    lenfld = None
    if mid is None:
        cases.append((f"{dsym}", f"{braw}=0", "0:8"))
        cases.append((f"{dsym}({bg})", f"{braw}!=0 & {bg}", f"{bg}"))
    elif mid[3] & INDEX and not mid[3] & VR:
        xg = field(L, mid[2], mid[1], "gpr")
        xraw = field(L, mid[2], mid[1], "u")
        cases.append((f"{dsym}", f"{xraw}=0 & {braw}=0", "0:8"))
        cases.append((f"{dsym}({bg})", f"{xraw}=0 & {braw}!=0 & {bg}", f"{bg}"))
        cases.append((f"{dsym}({xg},0)", f"{xraw}!=0 & {xg} & {braw}=0", f"{xg}"))
        cases.append((f"{dsym}({xg},{bg})", f"{xraw}!=0 & {xg} & {braw}!=0 & {bg}", f"{xg} + {bg}"))
    elif mid[3] & LENGTH:
        lenfld = field(L, mid[2], mid[1], "u")
        lact = f"len = {lenfld} + 1;"
        cases.append((f"{dsym}(len,0)", f"{lenfld} & {braw}=0", "0:8", lact))
        cases.append((f"{dsym}(len,{bg})", f"{lenfld} & {braw}!=0 & {bg}", f"{bg}", lact))
    elif mid[3] & VR:
        vsub = vr_subtable(L, mid[2])
        cases.append((f"{dsym}({vsub},0)", f"{vsub} & {braw}=0", "0:8"))
        cases.append((f"{dsym}({vsub},{bg})", f"{vsub} & {braw}!=0 & {bg}", f"{bg}"))
    elif mid[3] & GPR:   # D(R,B): register length operand (e.g. MVCK)
        rg = field(L, mid[2], mid[1], "gpr")
        cases.append((f"{dsym}({rg},0)", f"{rg} & {braw}=0", "0:8"))
        cases.append((f"{dsym}({rg},{bg})", f"{rg} & {braw}!=0 & {bg}", f"{bg}"))
    else:
        raise ValueError(f"address form {mid}")
    text = []
    for c in cases:
        disp, pat, base = c[0], c[1], c[2]
        acts = dact + (" " + c[3] if len(c) > 3 else "")
        act = f"[ {acts.strip()} ]" if acts.strip() else ""
        text.append(f"{key}: {disp} is {dpat} & {pat} {act} {{ local ea:8 = {base} + {dval}; export ea; }}")
    subtables[key] = "\n".join(text) + "\n"
    return key, lenfld

def vr_subtable(L, shift):
    key = f"v{L}_{shift}"
    if key not in subtables:
        lo = field(L, shift, 4, "vlo")
        hi = field(L, shift, 4, "vhi")
        x = rxb_bit(L, shift)
        subtables[key] = (f"{key}: {lo} is {lo} & {x}=0 {{ export {lo}; }}\n"
                          f"{key}: {hi} is {hi} & {x}=1 {{ export {hi}; }}\n")
    return key

def rel_subtable(L, shift, bits):
    key = f"rel{L}_{shift}_{bits}"
    if key not in subtables:
        f = field(L, shift, bits, "s")
        subtables[key] = (f"{key}: tgt is {f} [ tgt = inst_start + 2 * {f}; ] "
                          f"{{ export *[ram]:8 tgt; }}\n")
    return key

def mask_constraints(L, opcode, mask):
    cons = []
    nb = L // 4
    for k in range(nb):
        byte, hi = k // 2, k % 2 == 0
        m = (mask[byte] >> 4) if hi else (mask[byte] & 15)
        v = (opcode[byte] >> 4) if hi else (opcode[byte] & 15)
        if m == 15:
            cons.append(f"{field(L, 4 * k, 4, 'u')}=0x{v:x}")
        elif m:
            for j in range(4):
                if m & (8 >> j):
                    cons.append(f"{field(L, 4 * k + j, 1, 'u')}={(v >> (3 - j)) & 1}")
    return cons

def fixed_bits(opcode, mask, bits, shift):
    """(mask, value) of the bits of an operand that the opcode mask fixes."""
    m = v = 0
    for i in range(bits):
        pos = shift + i
        byte, bit = pos // 8, 7 - pos % 8
        m = (m << 1) | ((mask[byte] >> bit) & 1)
        v = (v << 1) | ((opcode[byte] >> bit) & 1)
    return m, v

def ident(name):
    return re.sub(r"[^A-Za-z0-9_]", "_", name)

VINDEX = [None]

# register-range instructions: one constructor per register range, unrolled
RANGE = {   # name: (register kind, bytes per register, load/store/lmd)
    "lmy": ("r", 4, "l"), "lamy": ("a", 4, "l"), "stamy": ("a", 4, "s"),
    "lctl": ("c", 4, "l"), "stctl": ("c", 4, "s"), "lctlg": ("c", 8, "l"), "stctg": ("c", 8, "s"),
    "vlm": ("v", 16, "l"), "vstm": ("v", 16, "s"), "lmd": ("r", 4, "d"),
    "lam": ("a", 4, "l"), "stam": ("a", 4, "s"), "stmy": ("r", 4, "s"),
    "lm": ("r", 4, "l"), "stm": ("r", 4, "s"), "lmg": ("r", 8, "l"), "stmg": ("r", 8, "s"),
    "lmh": ("h", 4, "l"), "stmh": ("h", 4, "s"),     # h: bits 0-31 of the GPRs
}

# Ranges are emitted as one constructor per mnemonic: a guarded block per register, whose
# guard depends only on the R1/R3 fields. The guards are constants for each decoded instruction
# (the decompiler folds them away); one constructor per register range would cost about 6 MB of
# the 16 MiB a .sla may decode to (SlaFormat.MAX_FILE_SIZE).
COMPACT_RANGE = True

def build_range_compact(e, items, cons):
    name, L = e["name"], e["len"]
    kind, w, op = RANGE[name]
    vec = kind == "v"
    addrs = [it[1] for it in items if it[0] == "addr"]
    u1, u3 = field(L, 8, 4, "u"), field(L, 12, 4, "u")
    pat = list(cons)
    if vec:
        x1, x3 = rxb_bit(L, 8), rxb_bit(L, 12)
        d1, d3 = vr_subtable(L, 8), vr_subtable(L, 12)
        m4 = field(L, 32, 4, "u")
        st = f"optm{L}_32"
        if st not in subtables:
            subtables[st] = f"{st}: is {m4}=0 {{ }}\n{st}: \",\"{m4} is {m4} {{ }}\n"
        disp = f"{d1},{d3},{','.join(addrs)}^{st}"
        pat += [d1, d3, u1, u3, x1, x3] + addrs + [st]
        first, nreg = f"({u1} + 16 * {x1})", 32
        last = f"({u3} + 16 * {x3})"
    else:
        rk = {"r": "gpr", "h": "gpr", "a": "ar", "c": "cr"}[kind]
        d1, d3 = field(L, 8, 4, rk), field(L, 12, 4, rk)
        disp = f"{d1},{d3},{','.join(addrs)}"
        pat += [d1, d3, u1, u3] + addrs
        first, last, nreg = u1, u3, 16
    t = uid_range()
    body = [f"  local ea:8 = {addrs[0]};"]
    if op == "d":
        body.append(f"  local eb:8 = {addrs[1]};")
    if vec:
        body.append(f"  local n:8 = {last} - {first};")
    else:
        body.append(f"  local n:8 = ({last} - {first}) & 15;")
    for r in range(nreg):
        reg = f"{'r' if kind == 'h' else kind}{r}"
        k = f"k{r}"
        body.append(f"  local {k}:8 = ({r} - {first})" + ("" if vec else " & 15") + ";")
        body.append(f"  if ({k} > n) goto <s{t}_{r}>;")
        a = f"(ea + {k} * {w})"
        if op == "l":
            if kind == "h":
                body.append(f"  {reg} = ({reg} & 0xffffffff) | (zext(*:4 {a}) << 32);")
            elif w == 4 and kind in "rc":
                body.append(f"  {reg} = ({reg} & 0xffffffff00000000) | zext(*:4 {a});")
            else:
                body.append(f"  {reg} = *:{w} {a};")
        elif op == "s":
            if kind == "h":
                body.append(f"  *:4 {a} = {reg}(4);")
            else:
                body.append(f"  *:{w} {a} = {reg}:4;" if w == 4 and kind in "rc" else f"  *:{w} {a} = {reg};")
        else:
            body.append(f"  {reg} = (zext(*:4 {a}) << 32) | zext(*:4 (eb + {k} * 4));")
        body.append(f"  <s{t}_{r}>")
    m, v = int.from_bytes(e["mask"], "big"), int.from_bytes(e["opcode"], "big")
    if any(n == name for n, _ in range_done):
        return []           # an older, shorter-displacement entry of the same mnemonic
    range_done.add((name, (m, v & m)))
    return [f":{name.upper()} {disp} is {' & '.join(pat)} {{\n" + "\n".join(body) + "\n}\n"]

range_done = set()
_rid = [0]
def uid_range():
    _rid[0] += 1
    return _rid[0]

def build_range(e, items, cons):
    if COMPACT_RANGE:
        return build_range_compact(e, items, cons)
    name, L = e["name"], e["len"]
    kind, w, op = RANGE[name]
    vec = kind == "v"
    f1, f3 = field(L, 8, 4, "u"), field(L, 12, 4, "u")
    x1, x3 = (rxb_bit(L, 8), rxb_bit(L, 12)) if vec else (None, None)
    addrs = [it[1] for it in items if it[0] == "addr"]
    tail = ""
    if vec:     # optional alignment hint M4
        m4 = field(L, 32, 4, "u")
        st = f"optm{L}_32"
        if st not in subtables:
            subtables[st] = f"{st}: is {m4}=0 {{ }}\n{st}: \",\"{m4} is {m4} {{ }}\n"
        tail = "^" + st
    out = []
    pairs_ = ([(a, b) for a in range(32) for b in range(a, min(a + 16, 32))] if vec else
              [(a, b) for a in range(16) for b in range(16)])
    for a, b in pairs_:
        # GPR/AR/CR ranges wrap from 15 to 0; vector ranges need V3 >= V1 (at most 16 registers)
        regs = list(range(a, b + 1)) if vec or b >= a else list(range(a, 16)) + list(range(0, b + 1))
        pat = list(cons) + [f"{f1}={a & 15}", f"{f3}={b & 15}"]
        if vec:
            pat += [f"{x1}={a >> 4}", f"{x3}={b >> 4}"]
        pat += addrs + ([tail[1:]] if tail else [])
        disp = f'"{kind}{a}" "," "{kind}{b}" "," ' + ' "," '.join(addrs) + tail
        body = ["  local ea:8 = " + addrs[0] + ";"]
        if op == "d":
            body.append("  local eb:8 = " + addrs[1] + ";")
        for r in regs:
            reg = f"{kind}{r}"
            if op == "l":
                if w == 4 and kind in "rc":
                    body.append(f"  {reg} = ({reg} & 0xffffffff00000000) | zext(*:4 ea);")
                else:
                    body.append(f"  {reg} = *:{w} ea;")
            elif op == "s":
                body.append(f"  *:{w} ea = {reg}:4;" if w == 4 and kind == "c" else f"  *:{w} ea = {reg};")
            else:
                body.append(f"  {reg} = (zext(*:4 ea) << 32) | zext(*:4 eb); eb = eb + 4;")
            body.append(f"  ea = ea + {w};")
        out.append(f":{name.upper()} {disp} is {' & '.join(pat)} {{\n" + "\n".join(body) + "\n}\n")
    return out

def build(e):
    name, opcode, mask, L, operands, flags = e["name"], e["opcode"], e["mask"], e["len"], e["ops"], e["flags"]
    cons = mask_constraints(L, opcode, mask)
    # group operands; each item: (kind, display, symbol-or-None, raw field, value-expression)
    items = []
    pairs.clear()
    ors.clear()
    VINDEX[0] = None
    i = 0
    lenfld = None
    while i < len(operands):
        oid = operands[i]
        bits, shift, fl = OPS[oid]
        if fl & DISP:
            grp = [(oid, bits, shift, fl)]
            j = i + 1
            while j < len(operands) and not OPS[operands[j]][2] & BASE:
                grp.append((operands[j],) + OPS[operands[j]])
                j += 1
            grp.append((operands[j],) + OPS[operands[j]])
            st, lf = addr_subtable(L, grp)
            lenfld = lenfld or lf
            if len(grp) == 3 and grp[1][3] & VR:       # D(V,B): the semantics need the index vector
                VINDEX[0] = vr_subtable(L, grp[1][2])
            items.append(("addr", st, st, None))
            i = j + 1
            continue
        if fl & VR:
            st = vr_subtable(L, shift)
            items.append(("vr", st, st, [f"{field(L, shift, 4, 'u')}=0", f"{rxb_bit(L, shift)}=0"]))
        elif fl & PCREL:
            st = rel_subtable(L, shift, bits)
            items.append(("rel", st, st, None))
        elif fl & (GPR | FPR | AR | CR):
            kind = "gpr" if fl & GPR else "fpr" if fl & FPR else "ar" if fl & AR else "cr"
            f = field(L, shift, bits, kind)
            items.append((kind, f, f, [f"{field(L, shift, bits, 'u')}=0"]))
            if fl & GPR and fl & PAIR:
                pairs[len(items) - 1] = field(L, shift, bits, "gpro")
            if fl & FPR:                      # extended operands use FPR n+2 (some table rows lack the pair flag)
                pairs[len(items) - 1] = field(L, shift, bits, "fprp2")
            if fl & GPR and name in gen_semantics.NEEDS_OR:
                ors[len(items) - 1] = field(L, shift, bits, "gpror")
        elif fl & LENGTH:
            f = field(L, shift, bits, "u")
            st = f"len{L}_{shift}_{bits}"
            if st not in subtables:
                subtables[st] = f"{st}: len is {f} [ len = {f} + 1; ] {{ export *[const]:8 len; }}\n"
            items.append(("len", st, st, None))
        else:
            fm, fv = fixed_bits(opcode, mask, bits, shift)
            if fm == (1 << bits) - 1:
                i += 1
                continue          # fully fixed by the mask: not an operand of this mnemonic
            kind = "s" if fl & SIGNED else "u"
            f = field(L, shift, bits, kind)
            if fm:
                st = f"imm{L}_{shift}_{bits}_m{fm:x}"
                if st not in subtables:
                    subtables[st] = (f"{st}: val is {f} [ val = {f} & 0x{((1 << bits) - 1) & ~fm:x}; ] "
                                     f"{{ export *[const]:8 val; }}\n")
                zc = [f"{field(L, shift + k, 1, 'u')}=0" for k in range(bits)
                      if not (fm >> (bits - 1 - k)) & 1]
                items.append(("imm", st, st, zc))
            else:
                items.append(("imm", f, f, [f"{field(L, shift, bits, 'u')}=0"]))
        i += 1
    if name in RANGE:
        return build_range(e, items, cons)
    # optional trailing operands
    variants = [(items, [])]
    if flags & (OPTPARM | OPTPARM2) and items and items[-1][0] not in ("addr",):
        last = items[-1]
        if last[3] is not None:
            variants.insert(0, (items[:-1], list(last[3])))
            if flags & OPTPARM2 and len(items) >= 2 and items[-2][3] is not None and items[-2][0] != "addr":
                variants.insert(0, (items[:-2], list(last[3]) + list(items[-2][3])))
    out = []
    mn = name.upper()
    # extra fields the semantics need beyond the table operands (e.g. the access register named
    # by an R field): gen_semantics.EXTRA_FIELDS[name] = [(shift, bits, kind), ...]
    xf = [field(L, sh, bt, kd) for sh, bt, kd in gen_semantics.EXTRA_FIELDS.get(name, [])]
    for its, extra in variants:
        # identical bit pattern already generated (e.g. an older entry of the same mnemonic
        # without the optional operand): the first one wins, as in the disassembler
        m, v = int.from_bytes(mask, "big"), int.from_bytes(opcode, "big")
        for c in extra:
            mm = re.match(r"g\d+_u(\d+)_(\d+)=0", c)
            sh, bt = int(mm.group(1)), int(mm.group(2))
            m |= ((1 << bt) - 1) << (48 - sh - bt)
        if (m, v & m) in emitted:
            continue
        emitted.add((m, v & m))
        disp = ",".join(it[1] for it in its)
        pat = " & ".join(cons + extra + [it[1] for it in its if it[1] not in cons] +
                         [pf for pi, pf in pairs.items() if items[pi] in its] +
                         [of for oi, of in ors.items() if items[oi] in its] +
                         ([VINDEX[0]] if VINDEX[0] else []) + xf)
        out.append(f":{mn} {disp} is {pat} {{\n{semantics(e, its, items, lenfld, xf)}\n}}\n")
    return out

CC_WRITE = re.compile(r"(?<![_A-Za-z0-9])(cc\s*=(?!=)[^;]*;)")

def semantics(e, its, items, lenfld, xf=()):
    name, flags = e["name"], e["flags"]
    syms = [it[2] for it in items]
    kinds = [it[0] for it in items]
    fixed = {}
    for oid in e["ops"]:
        bits, shift, fl = OPS[oid]
        fm, fv = fixed_bits(e["opcode"], e["mask"], bits, shift)
        if fm == (1 << bits) - 1 and not fl & (DISP | BASE | INDEX):
            fixed[shift] = fv
    ctx = dict(name=name, kinds=kinds, fixed=fixed, pairs=dict(pairs), ors=dict(ors), vindex=VINDEX[0], extra=list(xf),
               ops=[it[2] if it in its else "0" for it in items])
    try:
        t = gen_semantics.semantics(ctx)
    except Exception as ex:
        import traceback; traceback.print_exc()
        t = None
    if t is not None:
        # every direct write of cc is followed by cc_sync() (the condition flags, s390x.slaspec)
        t = CC_WRITE.sub(lambda m: m.group(1) + " cc_sync();", t)
        return "  " + t.replace("\n", "\n  ")
    op = "s390_" + ident(name)
    pcodeops.add(op)
    vals, pre = [], ""
    for n, (s, k) in enumerate(zip(syms, kinds)):
        if items[n] not in its:                      # optional operand left out: it is 0
            pre += f"  local i{n}:8 = 0;\n"
            s = f"i{n}"
        elif k == "imm" and not s.startswith("imm"):   # raw field: give the constant a size
            pre += f"  local i{n}:8 = {s};\n"
            s = f"i{n}"
        vals.append(s)
    is_branch = flags & BRANCH
    tgt = [s for s, k in zip(syms, kinds) if k == "rel"]
    if is_branch and tgt:
        others = [s for s, k in zip(syms, kinds) if k != "rel"]
        if flags & SUBROUTINE:
            w = others[0] if others and kinds[0] == "gpr" else None
            pre = f"  {w} = inst_next;\n" if w else ""
            return pre + f"  call {tgt[0]};"
        if flags & CONDITIONAL:
            pcodeops.add(op + "_taken")
            others = [v for v, k in zip(vals, kinds) if k != "rel"]
            return pre + f"  local taken:1 = {op}_taken({', '.join(others)});\n  if (taken != 0) goto {tgt[0]};"
        return f"  goto {tgt[0]};"
    w = bool(kinds) and kinds[0] in ("gpr", "fpr", "vr", "ar", "cr") and writes_first(name) \
        and items[0] in its
    args = ", ".join(vals[1:] if w else vals)
    if w:
        return pre + (f"  {syms[0]} = {op}({args});" if args else f"  {syms[0]} = {op}();")
    return pre + f"  {op}({args});"

def writes_first(name):
    """Heuristic for the fallback: does the instruction write its first (register) operand?
    Stores, compares, tests and branch/trap instructions do not."""
    n = name.lower()
    return not re.match(r"(st|c[^v]|cl|t[^r]|tr[^ae]|b|j|k|ppa|pfd|lpsw|sp[mk]|spt|sck|stck|lctl|sam|sigp|ptlb|ipte|idte|sske|rrb|iske|pf|niai|ntstg|tabort|tend|tbegin|ldgr|vst|vsc|vtm|vtp|wfc|wfk|vec|vcl|vce|vch|vfce|vfch|vfk|wfk)", n) or \
        n.startswith(("cvb", "cdfbr", "cefbr", "cxfbr", "cdgbr", "cegbr", "cxgbr", "cdlfbr", "celfbr",
                      "cxlfbr", "cdlgbr", "celgbr", "cxlgbr", "cfdbr", "cfebr", "cfxbr", "cgdbr",
                      "cgebr", "cgxbr", "clfdbr", "clfebr", "clfxbr", "clgdbr", "clgebr", "clgxbr",
                      "cdfr", "cefr", "cxfr", "cdgr", "cegr", "cxgr", "cfdr", "cfer", "cfxr", "cgdr",
                      "cger", "cgxr", "cdtr", "cxtr", "cdft", "cdgt", "cdlf", "cdlg", "cxft", "cxgt",
                      "cxlf", "cxlg", "cfdt", "cfxt", "cgdt", "cgxt", "clfdt", "clfxt", "clgdt",
                      "clgxt", "cdpt", "cxpt", "cpdt", "cpxt", "cdzt", "cxzt", "czdt", "czxt",
                      "cdsg", "cds", "csst", "csg", "cs", "csy", "cdsy", "csp", "cspg", "cu",
                      "cksm", "cmpsc", "clcl", "cuse", "cpya", "cpsdr", "cvd", "tre", "trt"))

entries = []
seen = set()
emitted = set()
for line in open(opc_file):
    f = line.split()
    name = f[0]
    e = dict(name=name, opcode=bytes.fromhex(f[1]), mask=bytes.fromhex(f[2]), len=int(f[3]) * 8,
             modes=int(f[4], 16), cpu=int(f[5], 16), flags=int(f[6], 16), ops=[int(x) for x in f[7:]])
    key = (f[1], f[2])
    if e["flags"] & PSEUDO or not e["modes"] & 2:
        continue
    if key in seen:
        continue          # alias with identical encoding: the disassembler prints the first
    seen.add(key)
    if (name,) in SKIP or (name, f[1], f[2]) in SKIP:
        continue
    entries.append(e)

body = []
failed = []
for e in entries:
    try:
        body += build(e)
    except (ValueError, KeyError, IndexError) as ex:
        failed.append(f"{e['name']}: {ex}")

with open(out_file, "w") as fh:
    fh.write("# GENERATED by tools/gen_table.py -- do not edit; see the script header.\n")
    fh.write(f"# {len(entries)} opcode-table entries.\n\n")
    for L in (16, 32, 48):
        fl = [(n, v) for n, v in fields.items() if v[0] == L]
        if not fl:
            continue
        fh.write(f"define token g{L}({L})\n")
        for n, (_, lo, hi, s) in fl:
            fh.write(f"    {n} = ({lo},{hi}){' signed' if s else ''}\n")
        fh.write(";\n")
    for f, kind in attaches.items():
        fh.write(f"attach variables [ {f} ] [ {' '.join(REGS[kind])} ];\n")
    for op in sorted(pcodeops):
        fh.write(f"define pcodeop {op};\n")
    fh.write(gen_semantics.PRELUDE)
    fh.write("\n")
    for st in subtables.values():
        fh.write(st)
    fh.write("\n")
    fh.write("".join(body))
print(f"{len(entries)} entries, {len(body)} constructors, {len(subtables)} subtables, "
      f"{len(fields)} fields; failed: {failed[:10]}")
