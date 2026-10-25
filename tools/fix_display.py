#!/usr/bin/env python3
"""Rewrite the display section of every s390x constructor into assembler syntax.

  tools/fix_display.py data/languages

The generators produced displays such as
    :LM_0_1 "LM " "0" "," "1" "," RSa_D2 "(" RSa_B2 ")" is ...
which Ghidra shows as mnemonic "LM_0_1" with operands "LM 0,1,0x10(zero)": the mnemonic is
repeated, unrolled variants carry a _N_N suffix, registers print as bare numbers, 20-bit
displacements show only their low 12 bits, SS lengths show the encoded length-1 and base/index
register 0 prints as "zero". This pass rewrites each header to
    :LM "r0","r1",RSa_db_D2 is ... & RSa_db_D2
with display-only subtables (defined just before their first use) for the address operands:
  D(X,B)  index and base omitted when 0          (RX, RXY: 20-bit signed for DL/DH pairs)
  D(B)    base omitted when 0                    (RS, SI, S, RSY, SIY)
  D(L,B)  length printed as L+1                  (SS)
The p-code bodies are not touched. Idempotent: already rewritten headers are left alone.
"""
import glob, os, re, sys

LANG = sys.argv[1]
subtables = {}          # name -> definition text
FIELDS = set()
for _f in glob.glob(os.path.join(LANG, "s390x*.sinc")) + [os.path.join(LANG, "s390x.slaspec")]:
    for _blk in re.findall(r"define\s+token\s+\w+\s*\(\s*\d+\s*\)(.*?);", open(_f).read(), re.S):
        FIELDS.update(re.findall(r"(\w+)\s*=\s*\(", _blk))

def field_kind(name):
    return re.sub(r"^[A-Za-z0-9]+?_", "", name)

def prefix(name):
    return name.split("_")[0]

def dh_for(dl):
    """RXYa_DL2 -> RXYa_DH2, RXYc_DXL2 -> RXYc_DXH2, SIY_DL1 -> SIY_DH1."""
    return re.sub(r"_D(X?)L(\d)$", r"_D\1H\2", dl)

def disp_expr(d):
    """Display symbol (and action) for a displacement field."""
    if re.search(r"_DX?L\d$", d) and dh_for(d) in FIELDS:   # RXF names its 12-bit D2 "DL2"
        dh = dh_for(d)
        return f"disp{d}", f"[ disp{d} = (({dh} << 12) | {d}) - ((({dh} >> 7) & 1) << 20); ]", [d, dh]
    return d, "", [d]

def sub_dxb(d, x, b):
    name = f"dxb_{d}_{x}_{b}"
    if name not in subtables:
        sym, act, flds = disp_expr(d)
        pat = " & ".join(flds)
        subtables[name] = (
            f"{name}: {sym} is {pat} & {x}=0 & {b}=0 {act} {{ }}\n"
            f"{name}: {sym}({b}) is {pat} & {x}=0 & {b} {act} {{ }}\n"
            f"{name}: {sym}({x},0) is {pat} & {x} & {b}=0 {act} {{ }}\n"
            f"{name}: {sym}({x},{b}) is {pat} & {x} & {b} {act} {{ }}\n")
    return name

def sub_db(d, b):
    name = f"db_{d}_{b}"
    if name not in subtables:
        sym, act, flds = disp_expr(d)
        pat = " & ".join(flds)
        subtables[name] = (
            f"{name}: {sym} is {pat} & {b}=0 {act} {{ }}\n"
            f"{name}: {sym}({b}) is {pat} & {b} {act} {{ }}\n")
    return name

def sub_dlb(d, l, b):
    name = f"dlb_{d}_{l}_{b}"
    if name not in subtables:
        sym, act, flds = disp_expr(d)
        pat = " & ".join(flds)
        a = act[1:-1].strip() if act else ""
        acts = f"[ {a} len{l} = {l} + 1; ]"
        subtables[name] = (
            f"{name}: {sym}(len{l},0) is {pat} & {l} & {b}=0 {acts} {{ }}\n"
            f"{name}: {sym}(len{l},{b}) is {pat} & {l} & {b} {acts} {{ }}\n")
    return name

TOK = re.compile(r'"[^"]*"|[A-Za-z_][A-Za-z0-9_]*|[^\s"]')

def rewrite(name, disp, pattern):
    mn = name.split("_")[0]
    # flatten the display into text with {FIELD} placeholders
    text = ""
    for t in TOK.findall(disp):
        if t.startswith('"'):
            text += t[1:-1]
        elif re.match(r"[A-Za-z_]", t):
            text += "{" + t + "}"
        else:
            text += t
    text = text.strip()
    # drop the repeated mnemonic
    m = re.match(r"([A-Za-z0-9]+)\s*(.*)$", text)
    if m and m.group(1).upper() == mn.upper():
        text = m.group(2)
    text = text.strip()
    # register numbers fixed by the pattern (unrolled LM/MR/... variants)
    fixed = [int(v) for f, v in re.findall(r"\b([A-Za-z0-9]+_R\d)\s*=\s*(\d+)", pattern)]
    ops = [o.strip() for o in re.split(r",(?![^()]*\))", text)] if text else []
    out_ops, extra = [], []
    for o in ops:
        mm = re.fullmatch(r"(?:r)?(\d+)", o)
        if mm and int(mm.group(1)) in fixed:
            out_ops.append(f'"r{int(mm.group(1))}"')
            continue
        mm = re.fullmatch(r"\{(\w+)\}\(\{(\w+)\},\{(\w+)\}\)", o)
        if mm:
            d, a, b = mm.groups()
            if re.search(r"_L\d?$", a) or field_kind(a) in ("L", "L1", "L2"):
                st = sub_dlb(d, a, b)
            else:
                st = sub_dxb(d, a, b)
            out_ops.append(st)
            extra.append(st)
            continue
        mm = re.fullmatch(r"\{(\w+)\}\(\{(\w+)\}\)", o)
        if mm:
            d, b = mm.groups()
            st = sub_db(d, b)
            out_ops.append(st)
            extra.append(st)
            continue
        mm = re.fullmatch(r"\{(\w+)\}", o)
        if mm:
            out_ops.append(mm.group(1))
            continue
        # anything else: keep as literal text with fields
        parts = re.split(r"(\{\w+\})", o)
        piece = []
        for p in parts:
            if not p:
                continue
            if p.startswith("{"):
                piece.append(p[1:-1])
            else:
                piece.append('"' + p + '"')
        out_ops.append(" ".join(piece))
    newdisp = ' "," '.join(out_ops)
    newpat = pattern + "".join(f" & {e}" for e in extra)
    return mn.upper(), newdisp, newpat

HDR = re.compile(r"(?ms)^:(\S+)[ \t]+(.*?)\s+is\s+(.*?)(?=\s*(?:\{|\[|\bunimpl\b))")
defined = set()

def process(path):
    s = open(path).read()
    out, pos = [], 0
    for m in HDR.finditer(s):
        name, disp, pat = m.group(1), m.group(2), m.group(3)
        out.append(s[pos:m.start()])
        pos = m.end()
        if re.search(r"\b(dxb|db|dlb)_", pat):
            out.append(m.group(0))
            continue
        before = set(subtables)
        mn, d, p = rewrite(name, disp, pat)
        for st in re.findall(r"\b(?:dxb|db|dlb)_\w+", p):
            if st not in defined:
                defined.add(st)
                out.append("# display-only address operand (tools/fix_display.py)\n" + subtables[st])
        out.append(f":{mn} {d} is {p}" if d else f":{mn} is {p}")
    out.append(s[pos:])
    s2 = "".join(out)
    s2 = re.sub(r"(?m)^:([A-Za-z0-9]+)_\w+(\s+is\s)", lambda m: ":" + m.group(1).upper() + m.group(2), s2)
    if s2 != s:
        open(path, "w").write(s2)

spec = open(os.path.join(LANG, "s390x.slaspec")).read()
for inc in re.findall(r'@include "(s390x_\w+\.sinc)"', spec):
    process(os.path.join(LANG, inc))
print(f"{len(subtables)} display subtables")
