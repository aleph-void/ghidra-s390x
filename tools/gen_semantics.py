"""P-code for the generated s390x constructors (used by gen_table.py).

semantics(ctx) returns the constructor body for an opcode-table entry, or None to fall back to
the named-pcodeop default. ctx carries:
  name     mnemonic (lower case)
  ops      operand symbols in assembler order: registers export the register, address
           operands export the effective address (8 bytes), immediates are fields (signed
           when the format says so), PC-relative operands export the target location
  kinds    "gpr" "fpr" "vr" "ar" "cr" "addr" "rel" "imm" "len" per operand
  fixed    values of operands the opcode mask fixes (extended mnemonics), keyed by the
           operand's bit position (shift) in the instruction
The condition code is the byte register `cc` holding 0-3, as in the hand-written files. The
helper macros below are branch-free so the decompiler can fold them.
"""
import re

PRELUDE = r"""
# ---- helpers for generated semantics (tools/gen_semantics.py) ----
# The flags cc0..cc3 (cc == N) are set directly from the operands so that branches decompile
# to the comparison; cc is the architected value (see s390x.slaspec).
macro gs_cc_flags(f0, f1, f2, f3) {
  cc0 = f0; cc1 = f1; cc2 = f2; cc3 = f3;
  cc = zext(f1) + zext(f2) * 2 + zext(f3) * 3;
}
# signed result: 0 zero, 1 negative, 2 positive, 3 overflow
macro gs_cc_arith(r, ov) {
  local o:1 = ov != 0;
  gs_cc_flags(!o && (r == 0), !o && (r s< 0), !o && (r s> 0), o);
}
# logical add: 0 zero, 1 nonzero, 2 zero with carry, 3 nonzero with carry
macro gs_cc_addl(r, carry) {
  local c:1 = carry != 0;
  gs_cc_flags(!c && (r == 0), !c && (r != 0), c && (r == 0), c && (r != 0));
}
# logical subtract: 1 nonzero with borrow, 2 zero without borrow, 3 nonzero without borrow
macro gs_cc_subl(r, borrow) {
  local b:1 = borrow != 0;
  gs_cc_flags(b && (r == 0), b && (r != 0), !b && (r == 0), !b && (r != 0));
}
# compare: 0 equal, 1 low, 2 high
macro gs_cc_cmps(a, b) { gs_cc_flags(a == b, a s< b, a s> b, 0:1); }
macro gs_cc_cmpu(a, b) { gs_cc_flags(a == b, a < b, a > b, 0:1); }
# 0 zero, 1 nonzero
macro gs_cc_nz(r) { gs_cc_flags(r == 0, r != 0, 0:1, 0:1); }
# condition mask test: bit (8 >> cc) of mask
macro gs_mask(m, out) { cc_hit(m, out); }
macro gs_set32(reg, v) { reg = (reg & 0xffffffff00000000) | zext(v); }
macro gs_seth32(reg, v) { reg = (reg & 0xffffffff) | (zext(v) << 32); }
define pcodeop s390_trap;
define pcodeop s390_execute;
define pcodeop s390_svc;
define pcodeop s390_vector;
"""

_wn = [0]
def _w32(reg, val):
    _wn[0] += 1
    return f"local w32_{_wn[0]}:4 = {val}; gs_set32({reg}, w32_{_wn[0]});"

ARITH3 = {
    # name: (op, width, signed-cc kind)
    "ark": ("+", 4, "s"), "agrk": ("+", 8, "s"), "srk": ("-", 4, "s"), "sgrk": ("-", 8, "s"),
    "alrk": ("+", 4, "l"), "algrk": ("+", 8, "l"), "slrk": ("-", 4, "l"), "slgrk": ("-", 8, "l"),
    "nrk": ("&", 4, "z"), "ngrk": ("&", 8, "z"), "ork": ("|", 4, "z"), "ogrk": ("|", 8, "z"),
    "xrk": ("^", 4, "z"), "xgrk": ("^", 8, "z"),
    "ahik": ("+", 4, "s"), "aghik": ("+", 8, "s"), "alhsik": ("+", 4, "l"), "alghsik": ("+", 8, "l"),
}

def arith(dst, a, b, op, w, kind):
    """dst = a op b at width w (4 or 8 bytes); a, b are expressions of that width."""
    t = []
    t.append(f"local x:{w} = {a}; local y:{w} = {b}; local r:{w} = x {op} y;")
    if kind == "s":
        if op == "+":
            t.append("local ov:1 = scarry(x, y);")
        else:
            t.append("local ov:1 = sborrow(x, y);")
        t.append("gs_cc_arith(r, ov);")
    elif kind == "l":
        if op == "+":
            t.append("local c:1 = carry(x, y); gs_cc_addl(r, c);")
        else:
            t.append("local b:1 = x < y; gs_cc_subl(r, b);")
    elif kind == "z":
        t.append("gs_cc_nz(r);")
    t.append(_w32(dst, "r") if w == 4 else f"{dst} = r;")
    return "\n".join(t)

IMM = {
    # name: (width, expression on r and imm, cc kind or None, imm is signed)
    "afi": (4, "+", "s"), "agfi": (8, "+", "s"), "alfi": (4, "+", "l"), "algfi": (8, "+", "l"),
    "slfi": (4, "-", "l"), "slgfi": (8, "-", "l"),
}

COND_JUMP = re.compile(r"^(c|cl)(g?)(r|i|fi|f?)(j|b|t)(.*)$")
CC_NAMES = {"": None, "h": 2, "nle": 2, "l": 4, "nhe": 4, "lh": 6, "ne": 6, "e": 8, "nlh": 8,
            "he": 10, "nl": 10, "le": 12, "nh": 12}

def mem(addr, size):
    return f"*:{size} {addr}"

def semantics(ctx):
    n, ops, kinds, fixed = ctx["name"], ctx["ops"], ctx["kinds"], ctx["fixed"]
    o = ops

    if n in ARITH3:
        op, w, k = ARITH3[n]
        if kinds[2] == "imm":
            b = f"{o[2]}" if w == 8 else f"{o[2]}:4"
            return f"local i:8 = {o[2]};\n" + arith(o[0], f"{o[1]}" if w == 8 else f"{o[1]}:4",
                                                      "i" if w == 8 else "i:4", op, w, k)
        return arith(o[0], o[1] if w == 8 else f"{o[1]}:4", o[2] if w == 8 else f"{o[2]}:4", op, w, k)
    if n in IMM:
        w, op, k = IMM[n]
        return f"local i:8 = {o[1]};\n" + arith(o[0], o[0] if w == 8 else f"{o[0]}:4",
                                                  "i" if w == 8 else "i:4", op, w, k)
    # immediate logical on halves
    m = re.fullmatch(r"(n|o|x)i(h|l)f", n)
    if m:
        op = {"n": "&", "o": "|", "x": "^"}[m.group(1)]
        half = m.group(2)
        if half == "l":
            return (f"local i:4 = {o[1]}; local r:4 = {o[0]}:4 {op} i; gs_cc_nz(r); {_w32(o[0], 'r')}")
        return (f"local i:4 = {o[1]}; local h:4 = {o[0]}(4); local r:4 = h {op} i; gs_cc_nz(r); "
                f"gs_seth32({o[0]}, r);")
    if n == "lgfi":
        return f"local i:4 = {o[1]}; {o[0]} = sext(i);"
    if n in ("llihf", "llilf"):
        sh = 32 if n == "llihf" else 0
        return f"local i:8 = {o[1]}; {o[0]} = (i & 0xffffffff) << {sh};"
    if n in ("iihf", "iilf"):
        return (f"local i:4 = {o[1]}; " + ("gs_seth32" if n == "iihf" else "gs_set32") + f"({o[0]}, i);")
    if n in ("clfi", "clgfi", "cfi", "cgfi"):
        w = 8 if "g" in n else 4
        cmp = "gs_cc_cmpu" if n.startswith("cl") else "gs_cc_cmps"
        ext = "zext" if n.startswith("cl") else "sext"
        b = f"{ext}(i:4)" if w == 8 else "i:4"
        return f"local i:8 = {o[1]}; local a:{w} = {o[0]}{':4' if w == 4 else ''}; local b:{w} = {b}; {cmp}(a, b);"
    # zero-extending loads
    lz = {"llc": (1, 4), "llh": (2, 4), "llgc": (1, 8), "llgh": (2, 8), "llgf": (4, 8),
          "llgt": (4, 8)}
    if n in lz and kinds[1] == "addr":
        s, w = lz[n]
        v = f"*:{s} {o[1]}"
        if n == "llgt":
            return f"local v:4 = {v}; {o[0]} = zext(v & 0x7fffffff);"
        return f"local v:{s} = {v}; " + (_w32(o[0], "zext(v)") if w == 4 else f"{o[0]} = zext(v);")
    lzr = {"llcr": (1, 4), "llhr": (2, 4), "llgcr": (1, 8), "llghr": (2, 8), "llgfr": (4, 8)}
    if n in lzr:
        s, w = lzr[n]
        return f"local v:{s} = {o[1]}:{s}; " + (_w32(o[0], "zext(v)") if w == 4 else f"{o[0]} = zext(v);")
    if n == "llgtr":
        return f"local v:4 = {o[1]}:4; {o[0]} = zext(v & 0x7fffffff);"
    sx = {"lb": (1, 4), "lgb": (1, 8), "lhy": (2, 4), "lgh": (2, 8), "lgf": (4, 8), "lt": (4, 4),
          "ltg": (8, 8), "ltgf": (4, 8), "lhh": (2, 0), "ly": (4, 4)}
    if n in sx and kinds[1] == "addr" and n not in ("lhh",):
        s, w = sx[n]
        load = f"local v:{s} = *:{s} {o[1]};"
        ext = f"sext(v)" if s < w else "v"
        res = (_w32(o[0], ext) if w == 4 else f"{o[0]} = {ext};")
        if n.startswith("lt"):
            return f"{load} local r:{w} = {ext}; {(_w32(o[0], 'r') if w == 4 else o[0] + ' = r;')} gs_cc_arith(r, 0:1);"
        return f"{load} {res}"
    sxr = {"lbr": (1, 4), "lgbr": (1, 8), "lhr": (2, 4), "lghr": (2, 8)}
    if n in sxr:
        s, w = sxr[n]
        return f"local v:{s} = {o[1]}:{s}; " + (_w32(o[0], "sext(v)") if w == 4 else f"{o[0]} = sext(v);")
    # PC-relative loads/stores (target exported as memory: take its address)
    rl = {"lrl": (4, "s32"), "lgrl": (8, None), "lgfrl": (4, "sext"), "llgfrl": (4, "zext"),
          "lhrl": (2, "s32"), "lghrl": (2, "sext"), "llhrl": (2, "z32"), "llghrl": (2, "zext")}
    if n in rl:
        s, how = rl[n]
        v = f"local a:8 = &{o[1]}; local v:{s} = *:{s} a;"
        if how is None:
            return f"{v} {o[0]} = v;"
        if how == "s32":
            return f"{v} " + _w32(o[0], "sext(v)" if s < 4 else "v")
        if how == "z32":
            return f"{v} " + _w32(o[0], "zext(v)")
        return f"{v} {o[0]} = {how}(v);"
    sr = {"strl": 4, "stgrl": 8, "sthrl": 2}
    if n in sr:
        s = sr[n]
        return f"local a:8 = &{o[1]}; *:{s} a = {o[0]}:{s};"
    if n in ("cgrl", "cgfrl", "crl", "clgrl", "clgfrl", "clrl", "chrl", "cghrl", "clhrl", "clghrl"):
        s = {"cgrl": 8, "cgfrl": 4, "crl": 4, "clgrl": 8, "clgfrl": 4, "clrl": 4, "chrl": 2,
             "cghrl": 2, "clhrl": 2, "clghrl": 2}[n]
        w = 8 if "g" in n else 4
        u = n.startswith("cl")
        ext = "zext" if u else "sext"
        b = f"{ext}(v)" if s < w else "v"
        return (f"local a:8 = &{o[1]}; local v:{s} = *:{s} a; local x:{w} = {o[0]}{':4' if w == 4 else ''}; "
                f"local y:{w} = {b}; {'gs_cc_cmpu' if u else 'gs_cc_cmps'}(x, y);")
    if n == "larl":
        return f"{o[0]} = &{o[1]};"
    # byte-reversed loads/stores
    if n in ("lrv", "lrvg", "lrvh"):
        s = {"lrv": 4, "lrvg": 8, "lrvh": 2}[n]
        bs = " | ".join(f"(zext(v[{8*k},8]) << {8*(s-1-k)})" for k in range(s))
        load = f"local v:{s} = *:{s} {o[1]}; local r:{s} = {bs};"
        if s == 8:
            return f"{load} {o[0]} = r;"
        if s == 4:
            return f"{load} {_w32(o[0], 'r')}"
        return f"{load} {o[0]} = ({o[0]} & 0xffffffffffff0000) | zext(r);"
    if n in ("lrvr", "lrvgr"):
        s = 4 if n == "lrvr" else 8
        bs = " | ".join(f"(zext(v[{8*k},8]) << {8*(s-1-k)})" for k in range(s))
        st = f"local v:{s} = {o[1]}:{s}; local r:{s} = {bs};"
        return st + (f" {_w32(o[0], 'r')}" if s == 4 else f" {o[0]} = r;")
    if n in ("strv", "strvg", "strvh"):
        s = {"strv": 4, "strvg": 8, "strvh": 2}[n]
        bs = " | ".join(f"(zext(v[{8*k},8]) << {8*(s-1-k)})" for k in range(s))
        return f"local v:{s} = {o[0]}:{s}; local r:{s} = {bs}; *:{s} {o[1]} = r;"
    # long-displacement variants of base RX instructions
    ry = {"ay": ("+", 4, "s"), "sy": ("-", 4, "s"), "aly": ("+", 4, "l"), "sly": ("-", 4, "l"),
          "ny": ("&", 4, "z"), "oy": ("|", 4, "z"), "xy": ("^", 4, "z"), "ahy": ("+", 2, "s"),
          "shy": ("-", 2, "s")}
    if n in ry and kinds[1] == "addr":
        op, s, k = ry[n]
        b = f"sext(*:2 {o[1]})" if s == 2 else f"*:4 {o[1]}"
        return arith(o[0], f"{o[0]}:4", b, op, 4, k)
    if n in ("cy", "chy", "cly"):
        b = f"sext(*:2 {o[1]})" if n == "chy" else f"*:4 {o[1]}"
        f = "gs_cc_cmpu" if n == "cly" else "gs_cc_cmps"
        return f"local x:4 = {o[0]}:4; local y:4 = {b}; {f}(x, y);"
    if n in ("icy",):
        return f"local v:1 = *:1 {o[1]}; {o[0]} = ({o[0]} & 0xffffffffffffff00) | zext(v);"
    if n in ("sty", "sthy", "stcy"):
        s = {"sty": 4, "sthy": 2, "stcy": 1}[n]
        return f"*:{s} {o[1]} = {o[0]}:{s};"
    if n in ("lhy",):
        return f"local v:2 = *:2 {o[1]}; " + _w32(o[0], "sext(v)")
    if n in ("lay",):
        return f"{o[0]} = {o[1]};"
    # 64 <- 32 mixed arithmetic
    mx = {"agfr": ("+", "sext", "s"), "sgfr": ("-", "sext", "s"), "algfr": ("+", "zext", "l"),
          "slgfr": ("-", "zext", "l"), "agf": ("+", "sext", "s"), "sgf": ("-", "sext", "s"),
          "algf": ("+", "zext", "l"), "slgf": ("-", "zext", "l")}
    if n in mx:
        op, ext, k = mx[n]
        src = f"{o[1]}:4" if kinds[1] != "addr" else f"*:4 {o[1]}"
        return f"local v:4 = {src};\n" + arith(o[0], o[0], f"{ext}(v)", op, 8, k)
    if n in ("cgfr", "clgfr", "cgf", "clgf"):
        u = n.startswith("cl")
        src = f"{o[1]}:4" if kinds[1] != "addr" else f"*:4 {o[1]}"
        return (f"local v:4 = {src}; local y:8 = {'zext' if u else 'sext'}(v); local x:8 = {o[0]}; "
                f"{'gs_cc_cmpu' if u else 'gs_cc_cmps'}(x, y);")
    # add/subtract logical with carry/borrow (carry = cc bit 1)
    ac = {"alcr": (4, "+"), "alcgr": (8, "+"), "slbr": (4, "-"), "slbgr": (8, "-"),
          "alc": (4, "+"), "alcg": (8, "+"), "slb": (4, "-"), "slbg": (8, "-")}
    if n in ac:
        w, op = ac[n]
        src = (f"{o[1]}:4" if w == 4 else o[1]) if kinds[1] != "addr" else f"*:{w} {o[1]}"
        x = f"{o[0]}:4" if w == 4 else o[0]
        if op == "+":
            body = (f"local x:{w} = {x}; local y:{w} = {src}; local c:{w} = zext((cc & 2) != 0); "
                    f"local t:{w} = x + y; local r:{w} = t + c; local co:1 = carry(x, y) || carry(t, c); "
                    f"gs_cc_addl(r, co);")
        else:
            body = (f"local x:{w} = {x}; local y:{w} = {src}; local bi:{w} = zext((cc & 2) == 0); "
                    f"local t:{w} = x - y; local r:{w} = t - bi; local bo:1 = (x < y) || (t < bi); "
                    f"gs_cc_subl(r, bo);")
        return body + (" " + _w32(o[0], "r") if w == 4 else f" {o[0]} = r;")
    # add immediate to storage
    si = {"asi": (4, "s"), "agsi": (8, "s"), "alsi": (4, "l"), "algsi": (8, "l")}
    if n in si:
        w, k = si[n]
        t = (f"local i:8 = {o[1]}; local x:{w} = *:{w} {o[0]}; local y:{w} = i:{w}; local r:{w} = x + y; ")
        t += "local ov:1 = scarry(x, y); gs_cc_arith(r, ov);" if k == "s" else "local c:1 = carry(x, y); gs_cc_addl(r, c);"
        return t + f" *:{w} {o[0]} = r;"
    # compare immediate with storage
    cs = {"chsi": (4, 2, "s"), "cghsi": (8, 2, "s"), "chhsi": (2, 2, "s"), "clfhsi": (4, 2, "u"),
          "clghsi": (8, 2, "u"), "clhhsi": (2, 2, "u")}
    if n in cs:
        w, s, k = cs[n]
        ext = "sext" if k == "s" else "zext"
        y = f"{ext}(i:2)" if w > 2 else "i:2"
        return (f"local i:8 = {o[1]}; local x:{w} = *:{w} {o[0]}; local y:{w} = {y}; "
                f"{'gs_cc_cmps' if k == 's' else 'gs_cc_cmpu'}(x, y);")
    # storage-immediate long displacement
    siy = {"cliy": "c", "mviy": "m", "niy": "&", "oiy": "|", "xiy": "^", "tmy": "t"}
    if n in siy:
        k = siy[n]
        if k == "c":
            return f"local i:1 = {o[1]}; local x:1 = *:1 {o[0]}; gs_cc_cmpu(x, i);"
        if k == "m":
            return f"local i:1 = {o[1]}; *:1 {o[0]} = i;"
        if k == "t":
            return (f"local i:1 = {o[1]}; local x:1 = *:1 {o[0]} & i; "
                    f"cc = zext(x != 0) * (1 + zext(x == i) * 2);")
        return f"local i:1 = {o[1]}; local r:1 = *:1 {o[0]} {k} i; *:1 {o[0]} = r; gs_cc_nz(r);"
    # move immediate to storage
    mv = {"mvhhi": 2, "mvhi": 4, "mvghi": 8}
    if n in mv:
        w = mv[n]
        return f"local i:8 = {o[1]}; local v:2 = i:2; *:{w} {o[0]} = sext(v);"
    # interlocked load-and-<op>
    la = {"laa": ("+", 4, "s"), "laag": ("+", 8, "s"), "laal": ("+", 4, "l"), "laalg": ("+", 8, "l"),
          "lan": ("&", 4, "z"), "lang": ("&", 8, "z"), "lao": ("|", 4, "z"), "laog": ("|", 8, "z"),
          "lax": ("^", 4, "z"), "laxg": ("^", 8, "z")}
    if n in la:
        op, w, k = la[n]
        src = f"{o[1]}:4" if w == 4 else o[1]
        x = "old"
        y = f"{o[1]}:4" if w == 4 else o[1]
        t = [f"local old:{w} = *:{w} {o[2]}; local y:{w} = {y}; local r:{w} = old {op} y;"]
        if k == "s":
            t.append("local ov:1 = scarry(old, y); gs_cc_arith(r, ov);")
        elif k == "l":
            t.append("local c:1 = carry(old, y); gs_cc_addl(r, c);")
        else:
            t.append("gs_cc_nz(r);")
        t.append(f"*:{w} {o[2]} = r;")
        t.append(_w32(o[0], "old") if w == 4 else f"{o[0]} = old;")
        return "\n".join(t)
    # compare and swap
    if n in ("cs", "csy", "csg"):
        w = 8 if n == "csg" else 4
        x = f"{o[0]}:4" if w == 4 else o[0]
        nv = f"{o[1]}:4" if w == 4 else o[1]
        upd = _w32(o[0], "old") if w == 4 else f"{o[0]} = old;"
        return (f"local old:{w} = *:{w} {o[2]}; local cmp:{w} = {x};\n"
                f"if (old != cmp) goto <neq>;\n*:{w} {o[2]} = {nv}; cc = 0;\ngoto <done>;\n"
                f"<neq>\ncc = 1; {upd}\n<done>")
    # extract/set access register
    if n == "ear":
        return _w32(o[0], o[1])
    if n == "sar":
        return f"{o[0]} = {o[1]}:4;"
    # rotate then insert selected bits
    if n.startswith(("risbg", "risbhg", "risblg", "rnsbg", "rosbg", "rxsbg")):
        return risbg(ctx)
    if n in ("popcnt",):
        return (f"local v:8 = {o[1]}; local r:8 = 0;\n" +
                "".join(f"local pc{k}:1 = popcount(v[{8*k},8]); r = r | (zext(pc{k}) << {8*k});\n" for k in range(8)) +
                f"{o[0]} = r; gs_cc_nz(v);")
    if n == "lcbb":
        b = o[2]
        return (f"local i:8 = {b}; local bs:8 = 64 << (i & 7); local ea:8 = {o[1]}; "
                f"local left:8 = bs - (ea & (bs - 1)); local cnt:8 = left; "
                f"if (left <= 16) goto <ok>; cnt = 16;\n<ok>\n" + _w32(o[0], "cnt:4") +
                " cc = zext(cnt != 16) * 3;")
    if n in ("pfd", "pfdrl", "niai", "ppa", "bpp", "bprp"):
        return "local nop:1 = 0;"
    if n == "exrl":
        return f"local a:8 = &{o[1]}; s390_execute({o[0]}, a);"
    # load and store on condition / select (mask fixed by mnemonic or as operand)
    m = re.fullmatch(r"(loc|stoc)(g|fh)?(r|hi|ghi|hhi)?(.*)", n)
    if m and (n.startswith("loc") or n.startswith("stoc")):
        return loc(ctx)
    m = re.fullmatch(r"sel(g|fh)?r(.*)", n)
    if m:
        return sel(ctx)
    # compare and branch/jump/trap families
    m = COND_JUMP.match(n)
    if m and n not in ("clm", "clmy", "clmh", "clst", "clc", "cli", "clr", "clg", "clgr", "clgf",
                       "clgfr", "clfi", "clgfi", "cl", "cly", "clih", "clhf", "clhhr", "clhlr"):
        r = cmp_branch(ctx, m)
        if r:
            return r
    # vector loads/stores with exact memory effects
    if n == "vl":
        return f"{o[0]} = *:16 {o[1]};"
    if n == "vst":
        return f"*:16 {o[1]} = {o[0]};"
    return None

def risbg(ctx):
    n, o, kinds = ctx["name"], ctx["ops"], ctx["kinds"]
    # operands: R1, R2, I3, I4[, I5]; z suffix (zero remaining bits) fixed in I4 bit 0x80
    i3, i4 = o[2], o[3]
    i5 = o[4] if len(o) > 4 else "0"
    zero = n.endswith("z") or n.endswith("zt") or n.endswith("z")
    base = n.rstrip("zt") if n.endswith(("gz", "gnz", "z")) else n
    op = {"risbg": "insert", "risbgn": "insert", "risbhg": "insert_h", "risblg": "insert_l",
          "rnsbg": "&", "rosbg": "|", "rxsbg": "^"}
    key = n.replace("z", "") if n.startswith("risb") else n.rstrip("t")
    kind = op.get(key, "insert")
    test = n.startswith(("rnsbg", "rosbg", "rxsbg")) and n.endswith("t")
    zbit = "0" if not zero else "1"
    lines = [f"local s:8 = {i3}; local e:8 = {i4}; local rot:8 = {i5};"]
    if kind == "insert_h":
        lines.append("s = s & 31; e = e & 31;")
    elif kind == "insert_l":
        lines.append("s = (s & 31) + 32; e = (e & 31) + 32;")
    else:
        lines.append("s = s & 63; e = e & 63;")
    lines.append(f"local src:8 = {o[1]}; local rs:8 = rot & 63;")
    lines.append("local rv:8 = (src << rs) | (src >> ((64 - rs) & 63)); rv = zext(rs != 0) * rv + zext(rs == 0) * src;")
    # mask of bit positions s..e (big-endian bit numbering, wrapping)
    lines.append("local ms:8 = 0xffffffffffffffff >> s; local me:8 = 0xffffffffffffffff << (63 - e);")
    lines.append("local wrap:1 = s > e; local m:8 = zext(!wrap) * (ms & me) + zext(wrap) * (ms | me);")
    if kind.startswith("insert"):
        if n.endswith("z") or "nz" in n or n in ("risbgz", "risbgnz", "risbhgz", "risblgz"):
            lines.append(f"local r:8 = rv & m;")
        else:
            lines.append(f"local r:8 = ({o[0]} & ~m) | (rv & m);")
        if kind == "insert_h":
            lines.append(f"{o[0]} = ({o[0]} & 0xffffffff) | (r & 0xffffffff00000000);")
        elif kind == "insert_l":
            lines.append(f"{o[0]} = ({o[0]} & 0xffffffff00000000) | (r & 0xffffffff);")
        else:
            lines.append(f"{o[0]} = r;")
        if n.startswith("risbg") and not n.startswith("risbgn"):
            lines.append("local sr:8 = r; gs_cc_arith(sr, 0:1);")
        return "\n".join(lines)
    lines.append(f"local t:8 = ({o[0]} {kind} rv) & m; local r:8 = ({o[0]} & ~m) | t; gs_cc_nz(t);")
    if not test:
        lines.append(f"{o[0]} = r;")
    return "\n".join(lines)

BC_NAMES = {"o": 1, "h": 2, "p": 2, "nle": 3, "l": 4, "m": 4, "nhe": 5, "lh": 6, "ne": 7,
            "nz": 7, "e": 8, "z": 8, "nlh": 9, "he": 10, "nl": 11, "nm": 11, "le": 12, "nh": 13,
            "np": 13, "no": 14}

def cc_cond(m):
    """Branch condition for a constant mask m (bit 8 >> cc) as a flag expression the decompiler
    simplifies well: one flag, or the negation of the complementary flags; two-flag masks use
    the form that contains cc3 (constant false after a compare)."""
    m = int(m)
    on = [k for k in range(4) if m & (8 >> k)]
    off = [k for k in range(4) if k not in on]
    if not on:
        return "0:1"
    if not off:
        return "1:1"
    if len(on) == 1 or (len(on) == 2 and 3 in on):
        return "(" + " || ".join(f"cc{k}" for k in on) + ")"
    return "!(" + " || ".join(f"cc{k}" for k in off) + ")"

def mask_test(mexpr, out="take"):
    """'local take:1 = ...' for a mask expression (constant: cc_cond, else cc_hit)."""
    if str(mexpr).isdigit():
        return f"local {out}:1 = {cc_cond(mexpr)};"
    return f"local mk:8 = {mexpr}; local {out}:1; gs_mask(mk, {out});"

def mask_from(ctx, base):
    """Condition mask fixed by an extended mnemonic (<base><suffix>), else None (the M operand
    is then an operand)."""
    n = ctx["name"]
    if base and n.startswith(base) and n != base:
        return str(BC_NAMES.get(n[len(base):], "")) or None
    return None

def loc(ctx):
    n, o, kinds = ctx["name"], ctx["ops"], ctx["kinds"]
    base = re.match(r"(locg?fh?r|locg?hi|lochhi|locg?fh|locg?|stocg?fh|stocg?)", n).group(1)
    fixedm = mask_from(ctx, base)
    mexpr = fixedm if fixedm is not None else o[-1]
    g = "g" in base
    fh = "fh" in n
    lines = [mask_test(mexpr), "if (!take) goto <skip>;"]
    if n.startswith("stoc"):
        w = 8 if g else 4
        src = f"{o[0]}(4)" if fh else (o[0] if g else f"{o[0]}:4")
        lines.append(f"*:{w} {o[1]} = {src};")
    else:
        if kinds[1] == "addr":
            w = 8 if g else 4
            v = f"*:{w} {o[1]}"
        elif kinds[1] == "imm":
            w = 8 if g else 4
            v = f"sext({o[1]}:2)" if True else o[1]
            lines.insert(0, f"local iv:8 = {o[1]};")
            v = "sext(iv:2)"
        else:
            w = 8 if g else 4
            v = o[1] if g else (f"{o[1]}(4)" if fh and n.endswith("fhr") else f"{o[1]}:4")
        if fh:
            lines.append(f"local val:4 = {v}; gs_seth32({o[0]}, val);")
        elif w == 4:
            lines.append(f"local val:4 = {v}; gs_set32({o[0]}, val);")
        else:
            lines.append(f"{o[0]} = {v};")
    lines.append("<skip>")
    return "\n".join(lines)

def sel(ctx):
    n, o = ctx["name"], ctx["ops"]
    base = re.match(r"sel(g|fh)?r", n).group(0)
    fixedm = mask_from(ctx, base)
    mexpr = fixedm if fixedm is not None else o[3]
    g = n.startswith("selg")
    fh = n.startswith("selfh")
    a, b = (o[1], o[2]) if g else ((f"{o[1]}(4)", f"{o[2]}(4)") if fh else (f"{o[1]}:4", f"{o[2]}:4"))
    w = 8 if g else 4
    put = (f"{o[0]} = v;" if g else (f"gs_seth32({o[0]}, v);" if fh else f"gs_set32({o[0]}, v);"))
    return (mask_test(mexpr) + f" local x:{w} = {a}; local y:{w} = {b};\n"
            f"local v:{w} = zext(take) * x + zext(!take) * y;\n{put}")

def cmp_branch(ctx, m):
    n, o, kinds = ctx["name"], ctx["ops"], ctx["kinds"]
    log, g, form, act, suf = m.groups()
    if act == "t":
        tsuf = suf
    if suf not in CC_NAMES and not suf.isdigit():
        return None
    w = 8 if g else 4
    u = log == "cl"
    # operands: R1, (R2 | I2), [M3], target (j: rel, b: addr, t: none)
    a = o[0] if w == 8 else f"{o[0]}:4"
    if kinds[1] in ("gpr",):
        b = o[1] if w == 8 else f"{o[1]}:4"
        pre = ""
    elif kinds[1] == "imm":
        pre = f"local iv:8 = {o[1]}; "
        b = "iv" if w == 8 else "iv:4"
        if not u:
            pre = f"local iv:8 = {o[1]}; "
    elif kinds[1] == "addr":   # clt/clgt (compare logical and trap with storage)
        pre = ""
        b = f"*:{w} {o[1]}"
    else:
        return None
    if suf:
        mexpr = str(CC_NAMES[suf])
    else:
        mi = [i for i, k in enumerate(kinds) if k == "imm"][-1]
        mexpr = o[mi]
    lt = "<" if u else "s<"
    gt = ">" if u else "s>"
    cond = (f"{pre}local x:{w} = {a}; local y:{w} = {b}; local mk:8 = {mexpr};\n"
            f"local take:1 = ((mk & 8) != 0 && x == y) || ((mk & 4) != 0 && x {lt} y) || "
            f"((mk & 2) != 0 && x {gt} y);")
    if act == "j":
        tgt = o[[i for i, k in enumerate(kinds) if k == "rel"][0]]
        return cond + f"\nif (take) goto {tgt};"
    if act == "b":
        tgt = o[[i for i, k in enumerate(kinds) if k == "addr"][-1]]
        return cond + f"\nif (!take) goto <nt>;\ngoto [{tgt}];\n<nt>"
    if act == "t":
        return cond + "\nif (!take) goto <nt>;\ns390_trap();\n<nt>"
    return None

# ---------------------------------------------------------------------------------------------
# Core integer instructions, table driven. Operand access helpers: width 4 = bits 32-63 of a
# register, 8 = the whole register, "h" = bits 0-31 (high-word facility).

def rd(sym, kind, w, ext=None, size=None):
    """Read an operand as a value of width w (4/8/'h' -> 4). size: source size for memory
    and immediates; ext: 's'/'z' to widen it."""
    vw = 4 if w in (4, "h") else w
    if kind == "addr":
        s = size or vw
        v = f"*:{s} {sym}"
    elif kind == "imm":
        s = size or vw
        v = f"imm_{s}"
        return v, s
    else:
        if w == "h":
            v, s = f"{sym}(4)", 4
        else:
            s = size or vw
            v = f"{sym}:{s}" if s < 8 else sym
    return v, s

def widen(v, s, w, ext):
    vw = 4 if w in (4, "h") else w
    if s == vw:
        return v
    return f"{'sext' if ext == 's' else 'zext'}({v})"

def put(sym, w, val):
    if w == 8:
        return f"{sym} = {val};"
    if w == "h":
        _wn[0] += 1
        return f"local wh_{_wn[0]}:4 = {val}; gs_seth32({sym}, wh_{_wn[0]});"
    return _w32(sym, val)

def imm_prelude(o, kinds, idx, size):
    return f"local immv:8 = {o[idx]}; local imm_{size}:{size} = immv:{size};" if kinds[idx] == "imm" else ""

# name: (op, dst width, src size, ext, cc, form)   form: 2 = R1 op= op2, 3 = R1 = op2 op op3
ARITH = {}
def _a(names, op, w, s, ext, cc, form=2):
    for n in names.split():
        ARITH[n] = (op, w, s, ext, cc, form)
_a("ar a ay ahi afi", "+", 4, 4, "s", "s");  _a("ah ahy", "+", 4, 2, "s", "s")
_a("agr ag aghi agfi", "+", 8, 8, "s", "s");  _a("agf agfr", "+", 8, 4, "s", "s"); _a("agh", "+", 8, 2, "s", "s")
_a("sr s sy", "-", 4, 4, "s", "s");  _a("sh shy", "-", 4, 2, "s", "s")
_a("sgr sg", "-", 8, 8, "s", "s");  _a("sgf sgfr", "-", 8, 4, "s", "s"); _a("sgh", "-", 8, 2, "s", "s")
_a("alr al aly alfi", "+", 4, 4, "z", "l");  _a("algr alg algfi", "+", 8, 8, "z", "l"); _a("algf algfr", "+", 8, 4, "z", "l")
_a("slr sl sly slfi", "-", 4, 4, "z", "b");  _a("slgr slg slgfi", "-", 8, 8, "z", "b"); _a("slgf slgfr", "-", 8, 4, "z", "b")
_a("nr n ny", "&", 4, 4, "z", "z"); _a("ngr ng", "&", 8, 8, "z", "z")
_a("or o oy", "|", 4, 4, "z", "z"); _a("ogr og", "|", 8, 8, "z", "z")
_a("xr x xy", "^", 4, 4, "z", "z"); _a("xgr xg", "^", 8, 8, "z", "z")
_a("ark ahik", "+", 4, 4, "s", "s", 3); _a("agrk aghik", "+", 8, 8, "s", "s", 3)
_a("srk", "-", 4, 4, "s", "s", 3); _a("sgrk", "-", 8, 8, "s", "s", 3)
_a("alrk alhsik", "+", 4, 4, "s", "l", 3); _a("algrk alghsik", "+", 8, 8, "s", "l", 3)
_a("slrk", "-", 4, 4, "z", "b", 3); _a("slgrk", "-", 8, 8, "z", "b", 3)
_a("nrk", "&", 4, 4, "z", "z", 3); _a("ngrk", "&", 8, 8, "z", "z", 3)
_a("ork", "|", 4, 4, "z", "z", 3); _a("ogrk", "|", 8, 8, "z", "z", 3)
_a("xrk", "^", 4, 4, "z", "z", 3); _a("xgrk", "^", 8, 8, "z", "z", 3)
_a("ncrk", "&~", 4, 4, "z", "z", 3); _a("ncgrk", "&~", 8, 8, "z", "z", 3)
_a("ocrk", "|~", 4, 4, "z", "z", 3); _a("ocgrk", "|~", 8, 8, "z", "z", 3)
_a("nnrk", "~&", 4, 4, "z", "z", 3); _a("nngrk", "~&", 8, 8, "z", "z", 3)
_a("nork", "~|", 4, 4, "z", "z", 3); _a("nogrk", "~|", 8, 8, "z", "z", 3)
_a("nxrk", "~^", 4, 4, "z", "z", 3); _a("nxgrk", "~^", 8, 8, "z", "z", 3)
_a("ms msr msy msfi", "*", 4, 4, "s", None); _a("mh mhy mhi", "*", 4, 2, "s", None)
_a("msg msgr msgfi mghi", "*", 8, 8, "s", None); _a("msgf msgfr", "*", 8, 4, "s", None); _a("mgh", "*", 8, 2, "s", None)
_a("msc msrkc", "*", 4, 4, "s", "m", 2); _a("msgc msgrkc", "*", 8, 8, "s", "m", 2)
# high-word facility: R1 high op R2 high/low (3-operand)
for n, op, cc in (("ahhhr", "+", "s"), ("ahhlr", "+", "s"), ("shhhr", "-", "s"), ("shhlr", "-", "s"),
                  ("alhhhr", "+", "l"), ("alhhlr", "+", "l"), ("slhhhr", "-", "b"), ("slhhlr", "-", "b")):
    ARITH[n] = (op, "h", 4, "z", cc, "hw")
_a("aih", "+", "h", 4, "s", "s"); _a("alsih", "+", "h", 4, "s", "l"); _a("alsihn", "+", "h", 4, "s", None)
for n in ("msrkc", "msgrkc"):
    ARITH[n] = ARITH[n][:5] + (3,)

LOADS = {}
def _l(names, w, s, ext, cc=None):
    for n in names.split():
        LOADS[n] = (w, s, ext, cc)
_l("l ly lr lhi", 4, 4, "s"); _l("lg lgr lghi", 8, 8, "s"); _l("lgf lgfr lgfi", 8, 4, "s")
_l("lh lhy lhr", 4, 2, "s"); _l("lgh lghr", 8, 2, "s"); _l("lb lbr", 4, 1, "s"); _l("lgb lgbr", 8, 1, "s")
_l("llc llcr", 4, 1, "z"); _l("llgc llgcr", 8, 1, "z"); _l("llh llhr", 4, 2, "z"); _l("llgh llghr", 8, 2, "z")
_l("llgf llgfr", 8, 4, "z"); _l("lt ltr", 4, 4, "s", "t"); _l("ltg ltgr", 8, 8, "s", "t"); _l("ltgf ltgfr", 8, 4, "s", "t")
_l("lfh", "h", 4, "s"); _l("lbh", "h", 1, "s"); _l("lhh", "h", 2, "s"); _l("llch", "h", 1, "z"); _l("llhh", "h", 2, "z")
_l("iilf", 4, 4, "z"); _l("iihf", "h", 4, "z")

STORES = {"st": (4, 4), "sty": (4, 4), "stg": (8, 8), "sth": (4, 2), "sthy": (4, 2), "stc": (4, 1),
          "stcy": (4, 1), "stfh": ("h", 4), "sthh": ("h", 2), "stch": ("h", 1)}

COMPARES = {}
def _c(names, w, s, ext, u):
    for n in names.split():
        COMPARES[n] = (w, s, ext, u)
_c("c cr cy cfi", 4, 4, "s", False); _c("ch chy chi", 4, 2, "s", False)
_c("cg cgr cgfi cghi", 8, 8, "s", False); _c("cgf cgfr", 8, 4, "s", False); _c("cgh", 8, 2, "s", False)
_c("cl clr cly clfi", 4, 4, "z", True); _c("clg clgr", 8, 8, "z", True); _c("clgf clgfr clgfi", 8, 4, "z", True)
_c("chf", "h", 4, "s", False); _c("clhf", "h", 4, "z", True); _c("cih", "h", 4, "s", False); _c("clih", "h", 4, "z", True)
_c("chhr", "h", 4, "s", False); _c("clhhr", "h", 4, "z", True); _c("chlr", "hl", 4, "s", False); _c("clhlr", "hl", 4, "z", True)

NEEDS_OR = {"brxh", "brxhg", "brxle", "brxlg", "bxh", "bxhg", "bxle", "bxleg"}

# fields the semantics need beyond the table operands: name -> [(shift, bits, kind)]
EXTRA_FIELDS = {
    "lae": [(8, 4, "ar"), (16, 4, "ar"), (16, 4, "u")],
    "laey": [(8, 4, "ar"), (16, 4, "ar"), (16, 4, "u")],
}

def core(ctx):
    n, o, k = ctx["name"], ctx["ops"], ctx["kinds"]
    if n in NEEDS_OR:
        w = 8 if n.endswith(("g",)) else 4
        cmpreg = ctx["ors"][1]
        sel = (lambda r: r) if w == 8 else (lambda r: f"{r}:4")
        tgt = o[2]
        t = [f"local inc:{w} = {sel(o[1])}; local lim:{w} = {sel(cmpreg)}; local sum:{w} = {sel(o[0])} + inc;",
             put(o[0], w, "sum"),
             f"local take:1 = sum {'s>' if 'h' in n[1:4] else 's<='} lim;"]
        if k[2] == "rel":
            t.append(f"if (take) goto {tgt};")
        else:
            t.append(f"if (!take) goto <nt>;\ngoto [{tgt}];\n<nt>")
        return "\n".join(t)
    if n == "brcth":
        return f"local v:4 = {o[0]}(4) - 1; gs_seth32({o[0]}, v);\nif (v != 0) goto {o[1]};"
    if n in ("bi", "bic") or re.fullmatch(r"bi(o|h|p|nle|l|m|nhe|lh|ne|nz|e|z|nlh|he|nl|nm|le|nh|np|no)", n):
        tgt = o[-1]
        if n == "bi":
            return f"local t:8 = *:8 {tgt}; goto [t];"
        mexpr = o[0] if n == "bic" else str(BC_NAMES[n[2:]])
        return (mask_test(mexpr) + f" local t:8 = *:8 {tgt};\n"
                f"if (!take) goto <nt>;\ngoto [t];\n<nt>")
    if n in ARITH:
        op, w, s, ext, cc, form = ARITH[n]
        vw = 4 if w in (4, "h") else w
        pre = []
        if form == "hw":    # R1(high) = R2(high) op R3(high|low)
            a, _ = rd(o[1], "gpr", "h")
            b = f"{o[2]}(4)" if n.endswith("hhr") else f"{o[2]}:4"
            dst = o[0]
        elif form == 3:
            a, _ = rd(o[1], k[1], w)
            if k[2] == "imm":
                pre.append(f"local immv:8 = {o[2]};")
                b = f"immv:{vw}" if s == vw else f"{'sext' if ext == 's' else 'zext'}(immv:{s})"
                if s != vw:
                    pre[-1] = f"local immv:8 = {o[2]}; local imms:{s} = immv:{s};"
                    b = f"{'sext' if ext == 's' else 'zext'}(imms)"
            else:
                bv, bs = rd(o[2], k[2], w, size=s)
                b = widen(bv, bs, w, ext)
            dst = o[0]
        else:
            a, _ = rd(o[0], "gpr", w)
            dst = o[0]
            if k[1] == "imm":
                pre.append(f"local immv:8 = {o[1]}; local imms:{s} = immv:{s};")
                b = widen("imms", s, w, ext)
            else:
                bv, bs = rd(o[1], k[1], w, size=s)
                b = widen(bv, bs, w, ext)
        if op.startswith("~"):
            body = f"local r:{vw} = ~(x {op[1:]} y);"
        elif op.endswith("~"):
            body = f"local r:{vw} = x {op[0]} ~y;"
        else:
            body = f"local r:{vw} = x {op} y;"
        t = pre + [f"local x:{vw} = {a}; local y:{vw} = {b};", body]
        if cc == "s":
            t.append(f"local ov:1 = {'scarry' if op == '+' else 'sborrow'}(x, y); gs_cc_arith(r, ov);")
        elif cc == "l":
            if op == "+" and ext == "s" and form == 3:     # add logical with signed immediate
                t.append("local c:1 = carry(x, y); gs_cc_addl(r, c);")
            else:
                t.append("local c:1 = carry(x, y); gs_cc_addl(r, c);")
        elif cc == "b":
            t.append("local bo:1 = x < y; gs_cc_subl(r, bo);")
        elif cc == "z":
            t.append("gs_cc_nz(r);")
        elif cc == "m":
            t.append(f"local wide:{2 * vw} = sext(x) * sext(y); local ov:1 = wide != sext(r); "
                     f"gs_cc_arith(r, ov);")
        t.append(put(dst, w, "r"))
        return "\n".join(t)
    if n in LOADS:
        w, s, ext, cc = LOADS[n]
        vw = 4 if w in (4, "h") else w
        t = []
        if k[1] == "imm":
            t.append(f"local immv:8 = {o[1]}; local v:{s} = immv:{s};")
        elif k[1] == "addr":
            t.append(f"local v:{s} = *:{s} {o[1]};")
        else:
            t.append(f"local v:{s} = {o[1]}:{s};" if s < 8 else f"local v:{s} = {o[1]};")
        t.append(f"local r:{vw} = {widen('v', s, w, ext)};")
        if cc == "t":
            t.append("gs_cc_arith(r, 0:1);")
        t.append(put(o[0], w, "r"))
        return "\n".join(t)
    if n in STORES:
        w, s = STORES[n]
        src = f"{o[0]}(4)" if w == "h" else f"{o[0]}:{s}"
        if w == "h" and s < 4:
            return f"local hv:4 = {o[0]}(4); *:{s} {o[1]} = hv:{s};"
        return f"*:{s} {o[1]} = {src};"
    if n in COMPARES:
        w, s, ext, u = COMPARES[n]
        vw = 8 if w == 8 else 4
        a = f"{o[0]}(4)" if w in ("h", "hl") else (f"{o[0]}:4" if w == 4 else o[0])
        if k[1] == "imm":
            pre = f"local immv:8 = {o[1]}; local imms:{s} = immv:{s}; "
            b = widen("imms", s, w if w != "hl" else 4, ext)
        elif k[1] == "addr":
            pre = ""
            b = widen(f"*:{s} {o[1]}", s, w if w != "hl" else 4, ext)
        else:
            pre = ""
            if w == "h":
                b = f"{o[1]}(4)"
            elif w == "hl":
                b = f"{o[1]}:4"
            else:
                b = widen(f"{o[1]}:{s}" if s < 8 else o[1], s, w, ext)
        return f"{pre}local x:{vw} = {a}; local y:{vw} = {b}; {'gs_cc_cmpu' if u else 'gs_cc_cmps'}(x, y);"
    # shifts
    m = re.fullmatch(r"(s)(l|r)(l|a)(g|k)?", n)
    if m:
        if True:
            lr, la, g = m.group(2), m.group(3), m.group(4)
            w = 8 if g == "g" else 4
            if g in ("g", "k"):
                src, amt = o[1], o[2]
            else:
                src, amt = o[0], o[1]
            sv = src if w == 8 else f"{src}:4"
            t = [f"local x:{w} = {sv}; local sh:8 = {amt} & 63;"]
            if lr == "l" and la == "l":
                t.append(f"local r:{w} = x << sh;")
            elif lr == "r" and la == "l":
                t.append(f"local r:{w} = x >> sh;")
            elif lr == "r" and la == "a":
                t.append(f"local r:{w} = x s>> sh; gs_cc_arith(r, 0:1);")
            else:   # sla: numeric shift left, sign kept, overflow if lost bits differ from sign
                t.append(f"local sgn:{w} = x & (1 << {8 * w - 1}); local body:{w} = (x << sh) & ~(1 << {8 * w - 1});")
                t.append(f"local r:{w} = body | sgn;")
                t.append(f"local full:{w} = ((x << sh) s>> sh); local ov:1 = full != x;")
                t.append(f"gs_cc_arith(r, ov);")
            t.append(put(o[0], w, "r"))
            return "\n".join(t)
    if n in ("rll", "rllg"):
        w = 8 if n == "rllg" else 4
        b = 8 * w
        sv = o[1] if w == 8 else f"{o[1]}:4"
        return (f"local x:{w} = {sv}; local sh8:8 = {o[2]} & {b - 1}; local sh:{w} = sh8:{w}; "
                f"local r:{w} = (x << sh) | (x >> (({b} - sh) & {b - 1})); "
                f"r = zext(sh == 0) * x + zext(sh != 0) * r;\n" + put(o[0], w, "r"))
    # 16-bit immediate on register halves (nill nilh nihl nihh, oi.., xi.. none, ii.., lli..)
    m = re.fullmatch(r"(n|o|i|ll|tm)i?(h|l)(h|l)", n) if n.startswith(("ni", "oi", "ii", "lli")) else None
    m = re.fullmatch(r"(ni|oi|ii|lli)(h|l)(h|l)", n)
    if m:
        f, hh, ll = m.groups()
        sh = {"hh": 48, "hl": 32, "lh": 16, "ll": 0}[hh + ll]
        mask = f"(0xffff << {sh})"
        t = [f"local immv:8 = {o[1]}; local iv:8 = (immv & 0xffff) << {sh};"]
        if f == "ni":
            t.append(f"local r:8 = {o[0]} & (iv | ~{mask}); local part:8 = r & {mask}; gs_cc_nz(part); {o[0]} = r;")
        elif f == "oi":
            t.append(f"local r:8 = {o[0]} | iv; local part:8 = r & {mask}; gs_cc_nz(part); {o[0]} = r;")
        elif f == "ii":
            t.append(f"{o[0]} = ({o[0]} & ~{mask}) | iv;")
        else:
            t.append(f"{o[0]} = iv;")
        return "\n".join(t)
    m = re.fullmatch(r"tm(h|l)(h|l)", n)
    if m:
        sh = {"hh": 48, "hl": 32, "lh": 16, "ll": 0}[m.group(1) + m.group(2)]
        return (f"local immv:8 = {o[1]}; local mk:2 = immv:2; local fld:8 = {o[0]} >> {sh}; local fv:2 = fld:2;\n"
                f"local sel:2 = fv & mk; local top:2 = lzcount(mk); local bit:2 = (fv << top) & 0x8000;\n"
                f"local mixed:1 = (sel != 0) && (sel != mk);\n"
                f"gs_cc_flags(sel == 0, mixed && (bit == 0), mixed && (bit != 0), (sel != 0) && (sel == mk));")
    if n in ("tm", "tmy"):
        return (f"local immv:8 = {o[1]}; local mk:1 = immv:1; local v:1 = *:1 {o[0]}; local sel:1 = v & mk;\n"
                f"gs_cc_flags(sel == 0, (sel != 0) && (sel != mk), 0:1, (sel != 0) && (sel == mk));")
    if n in ("mvi", "cli", "ni", "oi", "xi"):
        t = f"local immv:8 = {o[1]}; local i:1 = immv:1; "
        if n == "mvi":
            return t + f"*:1 {o[0]} = i;"
        if n == "cli":
            return t + f"local v:1 = *:1 {o[0]}; gs_cc_cmpu(v, i);"
        op = {"ni": "&", "oi": "|", "xi": "^"}[n]
        return t + f"local r:1 = *:1 {o[0]} {op} i; *:1 {o[0]} = r; gs_cc_nz(r);"
    if n == "ts":
        return f"local v:1 = *:1 {o[0]}; cc = v >> 7; *:1 {o[0]} = 0xff;"
    if n in ("lzrf", "lzrg", "llzrgf"):
        if n == "lzrg":
            return f"local v:8 = *:8 {o[1]}; {o[0]} = v & 0xffffffffffffff00;"
        if n == "lzrf":
            return f"local v:4 = *:4 {o[1]}; local r:4 = v & 0xffffff00;\n" + put(o[0], 4, "r")
        return f"local v:4 = *:4 {o[1]}; {o[0]} = zext(v & 0xffffff00);"
    if n in ("lae", "laey"):
        # access register R1 from the address-space control (PSW bits 16-17): primary 0,
        # access-register mode the contents of AR B2 (0 when B2 is 0), secondary 1, home 2
        ar1, arb, b2 = ctx["extra"]
        return (f"{o[0]} = {o[1]};\nlocal asc:8 = (pswm >> 46) & 3;\n"
                f"local sec:4 = zext(asc == 2); local home:4 = zext(asc == 3); local arm:1 = (asc == 1) && ({b2}:1 != 0);\n"
                f"{ar1} = sec + home * 2 + zext(arm) * {arb};")
    if n == "flogr" and ctx["pairs"].get(0):
        odd = ctx["pairs"][0]
        return (f"local v:8 = {o[1]}; local z:8 = lzcount(v); {o[0]} = z;\n"
                f"local bitv:8 = zext(v != 0) * (0x8000000000000000 >> z); {odd} = v & ~bitv;\n"
                f"cc = zext(v != 0) * 2;")
    if n == "popcnt":
        mexpr = o[2] if len(o) > 2 else "0"
        per = ("local v:8 = {0}; local r:8 = 0;\n".format(o[1]) +
               "".join(f"local pc{k}:1 = popcount(v[{8*k},8]); r = r | (zext(pc{k}) << {8*k});\n" for k in range(8)))
        return (per + f"local mm:8 = {mexpr}; local tot:8 = popcount(v);\n"
                f"{o[0]} = zext((mm & 8) == 0) * r + zext((mm & 8) != 0) * tot; gs_cc_nz(v);")
    if n in ("la", "lay"):
        return f"{o[0]} = {o[1]};"
    if n in ("ic", "icy"):
        return f"local v:1 = *:1 {o[1]}; {o[0]} = ({o[0]} & 0xffffffffffffff00) | zext(v);"
    if n in ("icm", "icmy", "icmh", "stcm", "stcmy", "stcmh"):
        return icm(ctx)
    if n in ("lcr", "lcgr", "lcgfr", "lpr", "lpgr", "lpgfr", "lnr", "lngr", "lngfr"):
        w = 8 if "g" in n else 4
        s = 4 if n.endswith(("fr",)) or w == 4 else 8
        src = f"{o[1]}:{s}" if s < 8 else o[1]
        v = f"sext(t0)" if s < w else "t0"
        t = [f"local t0:{s} = {src}; local x:{w} = {v};"]
        if n.startswith("lc"):
            t.append(f"local r:{w} = -x; local ov:1 = x == (1 << {8 * w - 1}); gs_cc_arith(r, ov);")
        elif n.startswith("lp"):
            t.append(f"local neg:1 = x s< 0; local r:{w} = zext(neg) * (-x) + zext(!neg) * x; "
                     f"local ov:1 = x == (1 << {8 * w - 1}); gs_cc_arith(r, ov);")
        else:
            t.append(f"local pos:1 = x s> 0; local r:{w} = zext(pos) * (-x) + zext(!pos) * x; gs_cc_arith(r, 0:1);")
        t.append(put(o[0], w, "r"))
        return "\n".join(t)
    return None

def icm(ctx):
    n, o = ctx["name"], ctx["ops"]
    store = n.startswith("stcm")
    hi = n.endswith("h")
    base = 32 if not hi else 0          # big-endian bit offset of the 32-bit register half
    t = [f"local immv:8 = {o[1]}; local mk:1 = immv:1; local ea:8 = {o[2]};",
         f"local reg:8 = {o[0]}; local half:4 = reg{'(4)' if hi else ':4'};"]
    # bytes of the half, left to right, selected by mask bits 8 4 2 1; storage is consecutive
    if store:
        for i in range(4):
            bit = 8 >> i
            t.append(f"if ((mk & {bit}) == 0) goto <s{i}>; local b{i}:1 = half({3 - i}); *:1 ea = b{i}; ea = ea + 1;\n<s{i}>")
        return "\n".join(t)
    t.append("local first:1 = 0; local seen:1 = 0; local any:1 = 0;")
    for i in range(4):
        bit = 8 >> i
        sh = 8 * (3 - i)
        t.append(f"if ((mk & {bit}) == 0) goto <i{i}>; local b{i}:1 = *:1 ea; ea = ea + 1;\n"
                 f"half = (half & ~(0xff << {sh})) | (zext(b{i}) << {sh});\n"
                 f"first = first | (zext(seen == 0) * (b{i} >> 7)); seen = 1; any = any | b{i};\n<i{i}>")
    t.append(put(o[0], "h" if hi else 4, "half"))
    t.append("cc = zext(any != 0) * (2 - zext(first != 0));")
    return "\n".join(t)

_semantics_tables = semantics
import gen_vector
import gen_fp
import gen_misc
import gen_hfp
HFP_NAMES = set("""ad adr ae aer au aur aw awr axr cd cdfr cdgr cdr ce cefr cegr cer cfdr cfer cfxr cgdr cger
cgxr cxfr cxgr cxr dd ddr de der dxr fidr fier fixr hdr her lcdr lcer lcxr lde lder ldxr ledr lexr
lndr lner lnxr lpdr lper lpxr lrdr lrer ltdr lter ltxr lxd lxdr lxe lxer mad madr mae maer md mde
mder mdr me mee meer mer msd msdr mse mser mxd mxdr mxr sd sdr se ser sqd sqdr sqe sqer sqxr su sur
sw swr sxr tbdr tbedr thdr thder""".split())
EXTRA_FIELDS.update(gen_misc.EXTRA)

def semantics(ctx):
    r = core(ctx)
    if r is None:
        r = gen_misc.semantics(ctx)
    if r is None and ctx["name"] in HFP_NAMES:
        r = gen_hfp.semantics(ctx)
    if r is None and gen_fp.SCALAR_NAMES.match(ctx["name"]):
        r = gen_fp.scalar(ctx)
    if r is None and ctx["name"][0] in "vw":
        r = gen_fp.vfp(ctx)
    if r is None and (ctx["name"][0] in "vw" or ctx["name"] in ("ldrv", "lerv", "stdrv", "sterv")):
        r = gen_vector.semantics(ctx)
    return r if r is not None else _semantics_tables(ctx)
