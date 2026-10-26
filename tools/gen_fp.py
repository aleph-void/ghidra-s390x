"""P-code for binary floating-point (BFP) instructions, scalar and vector (used by
gen_semantics.py).

Short (32-bit) values live in the leftmost word of an FPR, long (64-bit) in the whole FPR,
extended (128-bit) in the register pair FPR n (high) and FPR n+2 (low). P-code float operations
round to nearest-even, the default BFP rounding mode; the explicit rounding-method operands of
the convert and load-FP-integer instructions are honoured.
"""
import re
from gen_vector import Block, SIZES, assemble, dispatch, uid, parts_or_loop

ZERO = {4: "0:4", 8: "0:8", 16: "zext(0:8)"}

def fconst(blk, v, s):
    """Float constant v (small integer or 0.5) of size s."""
    if v == 0.5:
        one = blk.local(s, f"int2float(1:8)")
        two = blk.local(s, f"int2float(2:8)")
        return blk.local(s, f"{one} f/ {two}")
    return blk.local(s, f"int2float({int(v)}:8)")

FB = {4: 23, 8: 52, 16: 112}

def qbit(blk, s):
    if s < 16:
        return blk.local(s, f"{1 << (FB[s] - 1)}:{s}")
    return blk.local(16, "zext(0x800000000000:8) << 64")

def default_nan(blk, s):
    if s < 16:
        return blk.local(s, {4: "0x7fc00000:4", 8: "0x7ff8000000000000:8"}[s])
    return blk.local(16, "zext(0x7fff800000000000:8) << 64")

def nanfix(blk, r, srcs, s):
    """IEEE NaN rules as z/Architecture implements them: a signaling NaN operand (first in
    operand order) is returned quieted, else the first quiet NaN operand, else the default NaN
    (positive). P-code float operations would produce the host's NaN instead."""
    lt = uid()
    q = qbit(blk, s)
    out = blk.local(s, r)
    blk.add(f"if (!nan({r})) goto <nf{lt}>;")
    blk.add(f"{out} = {default_nan(blk, s)};")
    for src in reversed(srcs):          # first quiet NaN wins over later ones
        blk.add(f"if (!nan({src})) goto <nq{lt}_{src}>; {out} = {src};\n<nq{lt}_{src}>")
    for src in reversed(srcs):          # a signaling NaN wins over quiet NaNs
        blk.add(f"if (!nan({src}) || (({src} & {q}) != 0)) goto <ns{lt}_{src}>; {out} = {src} | {q};\n<ns{lt}_{src}>")
    blk.add(f"<nf{lt}>")
    return out

def nanconv(blk, r, src, s, t):
    """Format conversion of a NaN keeps sign and payload (left-aligned) and sets the quiet bit."""
    lt = uid()
    out = blk.local(t, r)
    sgn = blk.local(t, f"zext(({src} >> {8 * s - 1}) & 1) << {8 * t - 1}" if t > s else f"zext(0:1)")
    if t > s:
        payload = blk.local(t, f"(zext({src}) & {((1 << FB[s]) - 1) if s < 16 else 0}) << {FB[t] - FB[s]}" if s < 16 else "zext(0:8)")
        expo = blk.local(t, f"{((1 << (8 * t - FB[t] - 1)) - 1)}:8" if t < 16 else "zext(0x7fff:8) << 112")
        expo2 = blk.local(t, f"{expo} << {FB[t]}" if t < 16 else expo)
        blk.add(f"if (!nan({src})) goto <nc{lt}>; {out} = {sgn} | {expo2} | {payload} | {qbit(blk, t)};\n<nc{lt}>")
    else:
        sh = FB[s] - FB[t]
        sg = blk.local(s, f"{src} >> {8 * s - 1}")
        pl = blk.local(s, f"({src} >> {sh}) & {(1 << FB[t]) - 1}") if s < 16 else blk.local(s, f"({src} >> {sh}) & zext({(1 << FB[t]) - 1}:8)")
        nar = blk.local(t, f"({sg}:{t} << {8 * t - 1}) | ({((1 << (8 * t - FB[t] - 1)) - 1)}:{t} << {FB[t]}) | {pl}:{t} | {qbit(blk, t)}")
        blk.add(f"if (!nan({src})) goto <nc{lt}>; {out} = {nar};\n<nc{lt}>")
    return out

def cc_value(blk, r, s):
    z = ZERO[s] if s < 16 else blk.local(16, "zext(0:8)")
    n = blk.local(1, f"nan({r})")
    blk.add(f"cc = zext({n}) * 3 + zext(!{n}) * (zext({r} f< {z}) + 2 * zext({r} f> {z}));")

def cc_compare(blk, a, b):
    u = blk.local(1, f"nan({a}) || nan({b})")
    blk.add(f"cc = zext({u}) * 3 + zext(!{u}) * (zext({a} f< {b}) + 2 * zext({a} f> {b}));")

# ---- register access -------------------------------------------------------------------------
def rd(blk, sym, s, pair=None):
    if s == 4:
        return blk.local(4, f"{sym}(4)")
    if s == 8:
        return blk.local(8, sym)
    return blk.local(16, f"(zext({sym}) << 64) | zext({pair})")

def wr(blk, sym, s, val, pair=None):
    if s == 4:
        blk.add(f"{sym} = ({sym} & 0xffffffff) | (zext({val}) << 32);")
    elif s == 8:
        blk.add(f"{sym} = {val};")
    else:
        blk.add(f"{sym} = {val}(8); {pair} = {val}:8;")

def mem(blk, addr, s):
    return blk.local(s, f"*:{s} {addr}")

def fma(blk, a, b, c, s, neg_prod=False, sub=False):
    """a*b+c (or -, negated) with one rounding, computed in binary128 (exact for the product of
    two binary32/64 values)."""
    if s == 16:
        p = blk.local(16, f"{a} f* {b}")
        r = blk.local(16, f"{p} {'f-' if sub else 'f+'} {c}")
        return blk.local(16, f"f- {r}") if neg_prod else r
    A = blk.local(16, f"float2float({a})")
    B = blk.local(16, f"float2float({b})")
    C = blk.local(16, f"float2float({c})")
    p = blk.local(16, f"{A} f* {B}")
    r = blk.local(16, f"{p} {'f-' if sub else 'f+'} {C}")
    if neg_prod:
        r = blk.local(16, f"f- {r}")
    return blk.local(s, f"float2float({r})")

def round_int(blk, x, s, mode):
    """Round float x to an integral float value by rounding method mode (a run-time 8-byte
    value): 1 nearest/ties away, 5 toward 0, 6 toward +inf, 7 toward -inf, else nearest even."""
    z = ZERO[s] if s < 16 else "zext(0:8)"
    fl = blk.local(s, f"floor({x})")
    ce = blk.local(s, f"ceil({x})")
    neg = blk.local(1, f"{x} f< {z}")
    half, one, two = fconst(blk, 0.5, s), fconst(blk, 1, s), fconst(blk, 2, s)
    diff = blk.local(s, f"{x} f- {fl}")
    q = blk.local(s, f"floor({fl} f/ {two})")
    odd = blk.local(1, f"({q} f* {two}) f!= {fl}")
    up_even = blk.local(1, f"({diff} f> {half}) || (({diff} f== {half}) && {odd})")
    up_away = blk.local(1, f"({diff} f> {half}) || (({diff} f== {half}) && !{neg})")
    flp1 = blk.local(s, f"{fl} f+ {one}")
    out = blk.local(s, fl)
    t = uid()
    blk.add(f"if (!{up_even}) goto <rne{t}>; {out} = {flp1};\n<rne{t}>")
    blk.add(f"if ({mode} != 1) goto <m1{t}>; {out} = {fl}; if (!{up_away}) goto <m1{t}>; {out} = {flp1};\n<m1{t}>")
    blk.add(f"if ({mode} != 5) goto <m5{t}>; {out} = {fl}; if (!{neg}) goto <m5{t}>; {out} = {ce};\n<m5{t}>")
    blk.add(f"if ({mode} != 6) goto <m6{t}>; {out} = {ce};\n<m6{t}>")
    blk.add(f"if ({mode} != 7) goto <m7{t}>; {out} = {fl};\n<m7{t}>")
    keep = blk.local(1, f"nan({x}) || ({x} f== {fl})")
    blk.add(f"if (!{keep}) goto <rk{t}>; {out} = {x};\n<rk{t}>")
    return out

def to_int(blk, x, s, w, unsigned, mode):
    """Float -> integer of w bytes with rounding method mode; saturates (cc 3) on NaN and
    overflow, otherwise cc by the sign of the source."""
    lt = uid()
    r = round_int(blk, x, s, mode)
    lo, hi = (0, (1 << (8 * w)) - 1) if unsigned else (-(1 << (8 * w - 1)), (1 << (8 * w - 1)) - 1)
    t = blk.local(w, f"trunc({r})")
    # range checks done in binary128 so the limits are exact
    R = blk.local(16, f"float2float({r})") if s < 16 else r
    LO = blk.local(16, f"int2float({lo}:8)") if not unsigned else blk.local(16, "int2float(0:8)")
    HI = blk.local(16, f"int2float({hi}:8)") if hi < (1 << 63) else blk.local(16, f"int2float(0x7fffffffffffffff:8) f+ int2float(0x7fffffffffffffff:8) f+ int2float(1:8)")
    n = blk.local(1, f"nan({x})")
    big = blk.local(1, f"{R} f> {HI}")
    small = blk.local(1, f"{R} f< {LO}")
    res = blk.local(w, t)
    if unsigned:
        # values >= 2^63 do not fit trunc()'s signed result: subtract 2^63 first
        if w == 8:
            two63 = blk.local(16, "int2float(0x4000000000000000:8) f+ int2float(0x4000000000000000:8)")
            hiv = blk.local(1, f"{R} f>= {two63}")
            t2 = blk.local(8, f"trunc({R} f- {two63})")
            blk.add(f"if (!{hiv}) goto <uh{lt}>; {res} = {t2} + 0x8000000000000000;\n<uh{lt}>")
        else:
            t8 = blk.local(8, f"trunc({R})")
            blk.add(f"{res} = {t8}:4;")
    sat = blk.local(1, f"{n} || {big} || {small}")
    satv = hex(hi) if not unsigned else hex(hi)
    blk.add(f"if (!{big}) goto <sb{lt}>; {res} = {hex(hi)};\n<sb{lt}>")
    blk.add(f"if (!({small} || {n})) goto <ss{lt}>; {res} = {hex(lo & ((1 << 8 * w) - 1))};\n<ss{lt}>")
    z = ZERO[s] if s < 16 else "zext(0:8)"
    blk.add(f"cc = zext({sat}) * 3 + zext(!{sat}) * (zext({x} f< {z}) + 2 * zext({x} f> {z}));")
    return res

def from_int(blk, v, w, s, unsigned):
    if not unsigned or w == 4:
        src = blk.local(8, f"zext({v})") if unsigned and w == 4 else blk.local(w, v)
        return blk.local(s, f"int2float({src})")
    lt = uid()
    # unsigned 64-bit: halve (keeping the sticky bit) when the top bit is set, then double
    top = blk.local(1, f"{v} s< 0")
    h = blk.local(8, f"({v} >> 1) | ({v} & 1)")
    a = blk.local(s, f"int2float({h})")
    b = blk.local(s, f"{a} f+ {a}")
    c = blk.local(s, f"int2float({v})")
    out = blk.local(s, c)
    blk.add(f"if (!{top}) goto <u{lt}>; {out} = {b};\n<u{lt}>")
    return out

def test_class(blk, x, s, mask):
    """TEST DATA CLASS: cc 1 when the class bit of x is set in the 12-bit mask."""
    lt = uid()
    eb, fb = {4: (8, 23), 8: (11, 52), 16: (15, 112)}[s]
    raw = blk.local(s, x)
    sign = blk.local(1, f"({raw} >> {8 * s - 1}) != 0")
    expo = blk.local(s, f"({raw} >> {fb}) & {(1 << eb) - 1}")
    frac = blk.local(s, f"{raw} & ((1 << {fb}) - 1)" if fb < 64 else f"{raw} & ~(zext(0xffffffffffffffff:8) << {fb})" if False else f"({raw} << {8 * s - fb}) >> {8 * s - fb}")
    quiet = blk.local(1, f"(({raw} >> {fb - 1}) & 1) != 0")
    emax = (1 << eb) - 1
    cls = blk.local(2, "0")
    for cond, bit in ((f"{expo} == 0 && {frac} == 0", 11), (f"{expo} == 0 && {frac} != 0", 7),
                      (f"{expo} != 0 && {expo} != {emax}", 9), (f"{expo} == {emax} && {frac} == 0", 5),
                      (f"{expo} == {emax} && {frac} != 0 && {quiet}", 3),
                      (f"{expo} == {emax} && {frac} != 0 && !{quiet}", 1)):
        c = blk.local(1, cond)
        blk.add(f"if (!{c}) goto <tc{lt}_{bit}>; {cls} = (1 << ({bit} - zext({sign})));\n<tc{lt}_{bit}>")
    blk.add(f"cc = zext(({cls} & {mask}) != 0);")

# ---- scalar BFP ------------------------------------------------------------------------------
SUF = {"e": 4, "d": 8, "x": 16}

def scalar(ctx):
    n, o, k, pairs = ctx["name"], ctx["ops"], ctx["kinds"], ctx["pairs"]
    def P(i):
        return pairs.get(i)
    blk = Block()
    m = re.fullmatch(r"(a|s|m|d)(e|d|x)b(r?)", n) or re.fullmatch(r"(me)(e)b(r?)", n)
    if n in ("meebr", "meeb"):
        m = re.fullmatch(r"(m)e(e)b(r?)", n)
    if m and n not in ("mdeb", "mdebr", "mxdb", "mxdbr"):
        op = {"a": "f+", "s": "f-", "m": "f*", "d": "f/"}[m.group(1)]
        s = SUF[m.group(2)]
        a = rd(blk, o[0], s, P(0))
        b = mem(blk, o[1], s) if k[1] == "addr" else rd(blk, o[1], s, P(1))
        r = nanfix(blk, blk.local(s, f"{a} {op} {b}"), [a, b], s)
        wr(blk, o[0], s, r, P(0))
        if op in ("f+", "f-"):
            cc_value(blk, r, s)
        return blk.text()
    if n in ("mdeb", "mdebr", "mxdb", "mxdbr"):
        s, t = (4, 8) if n.startswith("mde") else (8, 16)
        a = rd(blk, o[0], s)
        b = mem(blk, o[1], s) if k[1] == "addr" else rd(blk, o[1], s)
        A, B = nanconv(blk, blk.local(t, f"float2float({a})"), a, s, t), nanconv(blk, blk.local(t, f"float2float({b})"), b, s, t)
        r = nanfix(blk, blk.local(t, f"{A} f* {B}"), [A, B], t)
        wr(blk, o[0], t, r, P(0))
        return blk.text()
    m = re.fullmatch(r"m(a|s)(e|d)b(r?)", n)
    if m:
        s = SUF[m.group(2)]
        # MADBR R1,R3,R2: R1 = R3*R2 + R1
        a = rd(blk, o[1], s)
        b = mem(blk, o[2], s) if k[2] == "addr" else rd(blk, o[2], s)
        c = rd(blk, o[0], s)
        r = nanfix(blk, fma(blk, a, b, c, s, sub=m.group(1) == "s"), [a, b, c], s)
        wr(blk, o[0], s, r)
        return blk.text()
    m = re.fullmatch(r"sq(e|d|x)b(r?)", n)
    if m:
        s = SUF[m.group(1)]
        b = mem(blk, o[1], s) if k[1] == "addr" else rd(blk, o[1], s, P(1))
        r = nanfix(blk, blk.local(s, f"sqrt({b})"), [b], s)
        wr(blk, o[0], s, r, P(0))
        return blk.text()
    m = re.fullmatch(r"(c|k)(e|d|x)b(r?)", n)
    if m:
        s = SUF[m.group(2)]
        a = rd(blk, o[0], s, P(0))
        b = mem(blk, o[1], s) if k[1] == "addr" else rd(blk, o[1], s, P(1))
        cc_compare(blk, a, b)
        return blk.text()
    m = re.fullmatch(r"l(p|n|c|t)(e|d|x)br", n)
    if m:
        s = SUF[m.group(2)]
        b = rd(blk, o[1], s, P(1))
        sign = {4: "0x80000000:4", 8: "0x8000000000000000:8"}.get(s)
        if s == 16:
            sg = blk.local(16, "zext(0x8000000000000000:8) << 64")
        else:
            sg = blk.local(s, sign)
        op = m.group(1)
        if op == "p":
            r = blk.local(s, f"{b} & ~{sg}")
        elif op == "n":
            r = blk.local(s, f"{b} | {sg}")
        elif op == "c":
            r = blk.local(s, f"{b} ^ {sg}")
        else:
            r = b
        wr(blk, o[0], s, r, P(0))
        cc_value(blk, r, s)
        return blk.text()
    m = re.fullmatch(r"l(d|x)(e|d)b(r?)", n)          # lengthen
    if m:
        t, s = SUF[m.group(1)], SUF[m.group(2)]
        b = mem(blk, o[1], s) if k[1] == "addr" else rd(blk, o[1], s)
        r = nanconv(blk, blk.local(t, f"float2float({b})"), b, s, t)
        wr(blk, o[0], t, r, P(0))
        return blk.text()
    m = re.fullmatch(r"l(e|d)(d|x)br(a?)", n)          # round to shorter
    if m:
        t, s = SUF[m.group(1)], SUF[m.group(2)]
        b = rd(blk, o[2] if m.group(3) else o[1], s, P(2) if m.group(3) else P(1))
        r = nanconv(blk, blk.local(t, f"float2float({b})"), b, s, t)
        wr(blk, o[0], t, r, P(0))
        return blk.text()
    m = re.fullmatch(r"c(e|d|x)(l?)(f|g)br(a?)", n)    # integer -> BFP
    if m:
        s = SUF[m.group(1)]
        w = 4 if m.group(3) == "f" else 8
        src = o[2] if (m.group(4) or m.group(2)) else o[1]
        v = blk.local(w, f"{src}:4" if w == 4 else src)
        r = from_int(blk, v, w, s, bool(m.group(2)))
        wr(blk, o[0], s, r, P(0))
        return blk.text()
    m = re.fullmatch(r"c(l?)(f|g)(e|d|x)br(a?)", n)    # BFP -> integer
    if m:
        s = SUF[m.group(3)]
        w = 4 if m.group(2) == "f" else 8
        blk.add(f"local md{blk.tag}:8 = {o[1]};")
        x = rd(blk, o[2], s, P(2))
        r = to_int(blk, x, s, w, bool(m.group(1)), f"md{blk.tag}")
        if w == 4:
            blk.add(f"{o[0]} = ({o[0]} & 0xffffffff00000000) | zext({r});")
        else:
            blk.add(f"{o[0]} = {r};")
        return blk.text()
    m = re.fullmatch(r"fi(e|d|x)br(a?)", n)
    if m:
        s = SUF[m.group(1)]
        blk.add(f"local md{blk.tag}:8 = {o[1]};")
        x = rd(blk, o[2], s, P(2))
        r = round_int(blk, x, s, f"md{blk.tag}")
        wr(blk, o[0], s, r, P(0))
        return blk.text()
    m = re.fullmatch(r"tc(e|d|x)b", n)
    if m:
        s = SUF[m.group(1)]
        x = rd(blk, o[0], s, P(0))
        blk.add(f"local tm{blk.tag}:8 = {o[1]};")
        test_class(blk, x, s, f"tm{blk.tag}:2")
        return blk.text()
    if n in ("lzer", "lzdr", "lzxr"):
        s = {"lzer": 4, "lzdr": 8, "lzxr": 16}[n]
        z = blk.local(s, ZERO[s])
        wr(blk, o[0], s, z, P(0))
        return blk.text()
    if n in ("ler", "ldr", "lxr"):
        s = {"ler": 4, "ldr": 8, "lxr": 16}[n]
        wr(blk, o[0], s, rd(blk, o[1], s, P(1)), P(0))
        return blk.text()
    if n in ("lcdfr", "lndfr", "lpdfr"):
        op = {"lcdfr": "^", "lndfr": "|", "lpdfr": "&~"}[n]
        sg = "0x8000000000000000"
        return f"{o[0]} = {o[1]} {op[0]} {'~' if len(op) > 1 else ''}{sg};"
    if n == "cpsdr":
        return f"{o[0]} = ({o[1]} & 0x8000000000000000) | ({o[2]} & 0x7fffffffffffffff);"
    if n == "ldgr":
        return f"{o[0]} = {o[1]};"
    if n == "lgdr":
        return f"{o[0]} = {o[1]};"
    if n == "lder":        # HFP lengthen: append zeros
        return f"{o[0]} = {o[1]} & 0xffffffff00000000;"
    if n == "lxr":
        return None
    if n in ("le", "ley"):
        return f"local v:4 = *:4 {o[1]}; {o[0]} = ({o[0]} & 0xffffffff) | (zext(v) << 32);"
    if n in ("ld", "ldy"):
        return f"{o[0]} = *:8 {o[1]};"
    if n in ("ste", "stey"):
        return f"*:4 {o[1]} = {o[0]}(4);"
    if n in ("std", "stdy"):
        return f"*:8 {o[1]} = {o[0]};"
    return None

SCALAR_NAMES = re.compile(
    r"^((a|s|m|d)(e|d|x)br?|meebr?|mdebr?|mxdbr?|m(a|s)(e|d)br?|sq(e|d|x)br?|(c|k)(e|d|x)br?|l(p|n|c|t)(e|d|x)br"
    r"|l(d|x)(e|d)br?|l(e|d)(d|x)bra?|c(e|d|x)l?(f|g)bra?|cl?(f|g)(e|d|x)bra?|fi(e|d|x)bra?|tc(e|d|x)b"
    r"|lz(e|d|x)r|l(e|d|x)r|l(c|n|p)dfr|cpsdr|ldgr|lgdr|lder|le|ley|ld|ldy|ste|stey|std|stdy)$")

# ---- vector BFP ------------------------------------------------------------------------------
FPSZ = {"sb": 4, "db": 8, "xb": 16}

def vfp(ctx):
    n, o, k = ctx["name"], ctx["ops"], ctx["kinds"]
    r = vfp_base(ctx)
    if r is not None:
        return r
    m = re.fullmatch(r"(v|w)f(a|s|m|d)(sb|db|xb)", n)
    if m:
        return vbin(o, FPSZ[m.group(3)], m.group(1) == "w", {"a": "f+", "s": "f-", "m": "f*", "d": "f/"}[m.group(2)])
    m = re.fullmatch(r"(v|w)fsq(sb|db|xb)", n)
    if m:
        return vun(o, FPSZ[m.group(2)], m.group(1) == "w", lambda blk, a, s: nanfix(blk, blk.local(s, f"sqrt({a})"), [a], s))
    m = re.fullmatch(r"(v|w)f(n?)m(a|s)(sb|db|xb)", n)
    if m:
        return vfma(o, FPSZ[m.group(4)], m.group(1) == "w", bool(m.group(2)), m.group(3) == "s")
    m = re.fullmatch(r"(v|w)fl(c|n|p)(sb|db|xb)", n)
    if m:
        op = m.group(2)
        KEEP_REST[0] = True
        try:
            return vun(o, FPSZ[m.group(3)], m.group(1) == "w", lambda blk, a, s: signop(blk, a, s, op))
        finally:
            KEEP_REST[0] = False
    m = re.fullmatch(r"(v|w)f(c|k)(e|h|he)(sb|db|xb)(s?)", n)
    if m:
        cmp = {"e": "f==", "h": "f>", "he": "f>="}[m.group(3)]
        return vcmp(o, FPSZ[m.group(4)], m.group(1) == "w", cmp, bool(m.group(5)))
    m = re.fullmatch(r"wf(c|k)(sb|db|xb)", n)
    if m:
        s = FPSZ[m.group(2)]
        blk = Block()
        a, b = elemf(blk, o[0], 0, s), elemf(blk, o[1], 0, s)
        cc_compare(blk, a, b)
        return blk.text()
    m = re.fullmatch(r"(v|w)ftci(sb|db|xb)", n)
    if m:
        s = FPSZ[m.group(2)]
        blk = Block()
        blk.add(f"local tm{blk.tag}:8 = {o[2]};")
        cnt = 1 if m.group(1) == "w" else 16 // s
        hits = blk.local(1, "0")
        parts = []
        for i in range(16 // s):
            if i < cnt:
                x = elemf(blk, o[1], i, s)
                test_class(blk, x, s, f"tm{blk.tag}:2")
                blk.add(f"{hits} = {hits} + cc;")
                if s < 16:
                    parts.append(blk.local(s, f"-zext(cc)"))
                else:
                    h = blk.local(8, "-zext(cc)")
                    parts.append(blk.local(16, f"zext({h}) | (zext({h}) << 64)"))
            else:
                parts.append(blk.elem(o[0], i, s))
        blk.add(f"{o[0]} = {assemble(blk, parts, s)};")
        blk.add(f"cc = zext({hits} != {cnt} && {hits} != 0) + zext({hits} == 0) * 3;")
        return blk.text()
    m = re.fullmatch(r"(v|w)(ldeb|lde|flls?|fll)", n) or re.fullmatch(r"wfll(s|d)", n) or re.fullmatch(r"vfll(s|d)?", n)
    if n in ("vldeb", "wldeb", "vflls", "wflls", "wflld"):
        s, t = (4, 8) if n in ("vldeb", "wldeb", "vflls", "wflls") else (8, 16)
        single = n.startswith("w")
        return vconv_len(o, s, t, single)
    if n in ("vledb", "wledb", "vflrd", "wflrd", "wflrx"):
        s, t = (8, 4) if n in ("vledb", "wledb", "vflrd", "wflrd") else (16, 8)
        return vconv_round(o, s, t, n.startswith("w"))
    m = re.fullmatch(r"(v|w)fi(sb|db|xb)", n)
    if m:
        s = FPSZ[m.group(2)]
        return vun(o, s, m.group(1) == "w", lambda blk, a, s: round_int(blk, a, s, f"md{blk.tag}"), mode=o[3])
    m = re.fullmatch(r"(v|w)c(d|e)(l?)(g|f)b", n)          # int -> float
    if m:
        s = 8 if m.group(2) == "d" else 4
        return vconv_from_int(o, s, m.group(1) == "w", bool(m.group(3)))
    m = re.fullmatch(r"(v|w)c(l?)(g|f)(d|e)b", n)          # float -> int
    if m:
        s = 8 if m.group(4) == "d" else 4
        return vconv_to_int(o, s, m.group(1) == "w", bool(m.group(2)))
    return None

def elemf(blk, v, i, s):
    return blk.elem(v, i, s)

KEEP_REST = [False]

def vparts(blk, o, s, single, fn):
    """Single-element (W) forms: element 0 only. The other elements are architecturally
    unpredictable; like the hardware model in QEMU they are zeroed, except for the sign
    operations (VFPSO family), which work on doubleword 0 of V2 (short format: element 1 is
    copied from V2) and leave doubleword 1 of V1 unchanged."""
    if not single:
        return parts_or_loop(blk, s, fn)
    parts = []
    for i in range(16 // s):
        if i > 0 and KEEP_REST[0] and s == 4 and i == 1:
            parts.append(blk.elem(o[1], i, s))      # QEMU: doubleword 0 comes from V2
        elif i > 0:
            parts.append(blk.elem(o[0], i, s) if KEEP_REST[0] else blk.local(s, ZERO[s]))
        else:
            parts.append(fn(i))
    return parts

def vbin(o, s, single, op):
    blk = Block()
    def one(i):
        a, b = elemf(blk, o[1], i, s), elemf(blk, o[2], i, s)
        return nanfix(blk, blk.local(s, f"{a} {op} {b}"), [a, b], s)
    parts = vparts(blk, o, s, single, one)
    blk.add(f"{o[0]} = {assemble(blk, parts, s)};")
    return blk.text()

def vun(o, s, single, fn, mode=None):
    blk = Block()
    if mode is not None:
        blk.add(f"local md{blk.tag}:8 = {mode};")
    parts = vparts(blk, o, s, single, lambda i: fn(blk, elemf(blk, o[1], i, s), s))
    blk.add(f"{o[0]} = {assemble(blk, parts, s)};")
    return blk.text()

def vfma(o, s, single, neg, sub):
    blk = Block()
    def one(i):
        a, b, c = elemf(blk, o[1], i, s), elemf(blk, o[2], i, s), elemf(blk, o[3], i, s)
        return nanfix(blk, fma(blk, a, b, c, s, neg_prod=neg, sub=sub), [a, b, c], s)
    parts = vparts(blk, o, s, single, one)
    blk.add(f"{o[0]} = {assemble(blk, parts, s)};")
    return blk.text()

def signop(blk, a, s, op):
    sg = blk.local(s, f"1 << {8 * s - 1}" if s < 16 else "zext(1:8) << 127")
    return blk.local(s, {"c": f"{a} ^ {sg}", "n": f"{a} | {sg}", "p": f"{a} & ~{sg}"}[op])

def vcmp(o, s, single, cmp, cs):
    blk = Block()
    cnt = 1 if single else 16 // s
    hits = blk.local(1, "0")
    def one(i):
        a, b = elemf(blk, o[1], i, s), elemf(blk, o[2], i, s)
        c = blk.local(1, f"{a} {cmp} {b}")
        blk.add(f"{hits} = {hits} + {c};")
        if s < 16:
            return blk.local(s, f"-zext({c})")
        h = blk.local(8, f"-zext({c})")
        return blk.local(16, f"zext({h}) | (zext({h}) << 64)")
    parts = vparts(blk, o, s, single, one)
    blk.add(f"{o[0]} = {assemble(blk, parts, s)};")
    if cs:
        blk.add(f"cc = zext({hits} == 0) * 3 + zext({hits} != 0 && {hits} != {cnt});")
    return blk.text()

def vconv_len(o, s, t, single):
    blk = Block()
    cnt = 1 if single else 16 // t
    parts = []
    for i in range(16 // t):
        if i < cnt:
            a = elemf(blk, o[1], 2 * i if t == 2 * s else i, s)
            parts.append(nanconv(blk, blk.local(t, f"float2float({a})"), a, s, t))
        else:
            parts.append(blk.local(t, ZERO[t]))
    blk.add(f"{o[0]} = {assemble(blk, parts, t)};")
    return blk.text()

def vconv_round(o, s, t, single):
    blk = Block()
    cnt = 1 if single else 16 // s
    parts = []
    for i in range(16 // t):
        src_i = i // 2 if t * 2 == s else i
        if i % 2 == 0 and src_i < cnt:
            a = elemf(blk, o[1], src_i, s)
            parts.append(nanconv(blk, blk.local(t, f"float2float({a})"), a, s, t))
        else:
            parts.append(blk.local(t, ZERO[t]))
    blk.add(f"{o[0]} = {assemble(blk, parts, t)};")
    return blk.text()

def vconv_from_int(o, s, single, unsigned):
    blk = Block()
    parts = vparts(blk, o, s, single, lambda i: from_int(blk, elemf(blk, o[1], i, s), s, s, unsigned))
    blk.add(f"{o[0]} = {assemble(blk, parts, s)};")
    return blk.text()

def vconv_to_int(o, s, single, unsigned):
    blk = Block()
    blk.add(f"local md{blk.tag}:8 = {o[3]};")
    keep = blk.local(1, "cc")
    parts = vparts(blk, o, s, single, lambda i: to_int(blk, elemf(blk, o[1], i, s), s, s, unsigned, f"md{blk.tag}"))
    blk.add(f"cc = {keep};")
    blk.add(f"{o[0]} = {assemble(blk, parts, s)};")
    return blk.text()

# ---- VECTOR FP MAXIMUM/MINIMUM ----------------------------------------------------------------
def snan(blk, x, s):
    return blk.local(1, f"nan({x}) && (({x} & {qbit(blk, s)}) == 0)")

def pick(blk, cur, cond, val, s):
    blk.add(f"{cur} = zext({cond}) * {val} + zext(!{cond}) * {cur};")

def minmax_elem(blk, a, b, s, is_min, method):
    """One element of VFMIN/VFMAX for a constant method (M6): 0 IEEE minNum/maxNum, 1 Java,
    2 C-style, 3 C++, 4 fmin/fmax; +8 compares magnitudes."""
    typ, ab = method & 7, bool(method & 8)
    sg = blk.local(s, f"1 << {8 * s - 1}" if s < 16 else "zext(1:8) << 127")
    na, nb = blk.local(1, f"nan({a})"), blk.local(1, f"nan({b})")
    sa, sb = snan(blk, a, s), snan(blk, b, s)
    q = qbit(blk, s)
    if typ == 0:
        ma, mb = (blk.local(s, f"{a} & ~{sg}"), blk.local(s, f"{b} & ~{sg}")) if ab else (a, b)
        lt, gt = blk.local(1, f"{ma} f< {mb}"), blk.local(1, f"{mb} f< {ma}")
        r = blk.local(s, f"{a} | {b}" if is_min else f"{a} & {b}")
        pick(blk, r, gt, b if is_min else a, s)
        pick(blk, r, lt, a if is_min else b, s)
        pn = nanfix(blk, blk.local(s, f"{a} f+ {b}"), [a, b], s)
        num = blk.local(1, f"!{sa} && !{sb} && !({na} && {nb})")
        nn = blk.local(s, b)
        pick(blk, nn, nb, a, s)
        lbl = f"mm{blk.tag}_{uid()}"
        blk.add(f"if (!({na} || {nb})) goto <{lbl}>;")
        pick(blk, pn, num, nn, s)
        blk.add(f"{r} = {pn};")
        blk.add(f"<{lbl}>")
        return r
    if ab:
        a, b = blk.local(s, f"{a} & ~{sg}"), blk.local(s, f"{b} & ~{sg}")
    c = blk.local(1, f"{a} f< {b}" if is_min else f"{a} f> {b}")
    r = blk.local(s, b)
    pick(blk, r, c, a, s)
    zz = blk.local(1, f"(({a} & ~{sg}) == 0) && (({b} & ~{sg}) == 0)")
    nega = blk.local(1, f"({a} & {sg}) != 0")
    if typ in (1, 4):
        zr = blk.local(s, b)
        if is_min:
            pick(blk, zr, nega, a, s)
        else:
            blk.add(f"{zr} = {a};")
            pick(blk, zr, nega, b, s)
    else:
        zr = blk.local(s, b if typ == 2 else a)
    pick(blk, r, zz, zr, s)
    if typ == 1:
        nr = blk.local(s, b)
        pick(blk, nr, na, a, s)
        pick(blk, nr, sb, blk.local(s, f"{b} | {q}"), s)
        pick(blk, nr, sa, blk.local(s, f"{a} | {q}"), s)
    elif typ == 4:
        nr = blk.local(s, b)
        pick(blk, nr, nb, a, s)
    else:
        nr = b if typ == 2 else a
    anyn = blk.local(1, f"{na} || {nb}")
    pick(blk, r, anyn, nr, s)
    return r

def vminmax(o, s, single, is_min, method):
    """method: run-time M6 value; one block per legal method."""
    def body(mt):
        blk = Block()
        parts = vparts(blk, o, s, single, lambda i: minmax_elem(blk, elemf(blk, o[1], i, s), elemf(blk, o[2], i, s), s, is_min, mt))
        blk.add(f"{o[0]} = {assemble(blk, parts, s)};")
        return blk.text()
    return dispatch({m: m for m in (0, 1, 2, 3, 4, 8, 9, 10, 11, 12)}, body, method)

def vpso(o, s, single, op):
    KEEP_REST[0] = True
    try:
        return dispatch({0: "c", 1: "n", 2: "p"}, lambda p: vun(o, s, single, lambda blk, a, s_: signop(blk, a, s_, p)), op)
    finally:
        KEEP_REST[0] = False

def vtci(o, s, single):
    blk = Block()
    blk.add(f"local tm{blk.tag}:8 = {o[2]};")
    cnt = 1 if single else 16 // s
    hits = blk.local(1, "0")
    parts = []
    for i in range(16 // s):
        if i < cnt:
            x = elemf(blk, o[1], i, s)
            test_class(blk, x, s, f"tm{blk.tag}:2")
            blk.add(f"{hits} = {hits} + cc;")
            if s < 16:
                parts.append(blk.local(s, f"-zext(cc)"))
            else:
                h = blk.local(8, "-zext(cc)")
                parts.append(blk.local(16, f"zext({h}) | (zext({h}) << 64)"))
        else:
            parts.append(blk.local(s, ZERO[s]))
    blk.add(f"{o[0]} = {assemble(blk, parts, s)};")
    blk.add(f"cc = zext({hits} != {cnt} && {hits} != 0) + zext({hits} == 0) * 3;")
    return blk.text()

def fmt_single(fmt, flags, fn, extra=None):
    """Run-time element format (2 short, 3 long, 4 extended) and single-element flag (bit 8 of
    flags); extra: optional (expr, values) appended to the selector."""
    combos = {}
    for f, s in ((2, 4), (3, 8), (4, 16)):
        for se in (0, 1):
            if extra:
                for v in extra[1]:
                    combos[(f * 2 + se) * 16 + v] = (s, bool(se) or s == 16, v)
            else:
                combos[f * 2 + se] = (s, bool(se) or s == 16)
    key = f"(({fmt}) * 2 + ((({flags}) >> 3) & 1))"
    if extra:
        key = f"({key} * 16 + ({extra[0]}))"
    return dispatch(combos, lambda t: fn(*t), key)

def vfp_base(ctx):
    n, o = ctx["name"], ctx["ops"]
    op = {"vfa": "f+", "vfs": "f-", "vfm": "f*", "vfd": "f/"}
    if n in op:                                       # V1,V2,V3,M4,M5
        return fmt_single(o[3], o[4], lambda s, se: vbin(o, s, se, op[n]))
    if n == "vfsq":                                   # V1,V2,M3,M4
        return fmt_single(o[2], o[3], lambda s, se: vun(o, s, se, lambda blk, a, s_: nanfix(blk, blk.local(s_, f"sqrt({a})"), [a], s_)))
    m = re.fullmatch(r"vf(n?)m(a|s)", n)              # V1,V2,V3,V4,M5,M6
    if m:
        return fmt_single(o[5], o[4], lambda s, se: vfma(o, s, se, bool(m.group(1)), m.group(2) == "s"))
    if n in ("vfce", "vfch", "vfche"):                # V1,V2,V3,M4,M5,M6 (M6 bit 3: CS)
        cmp = {"vfce": "f==", "vfch": "f>", "vfche": "f>="}[n]
        return fmt_single(o[3], o[4], lambda s, se, cs: vcmp(o, s, se, cmp, bool(cs)), (f"({o[5]}) & 1", (0, 1)))
    if n in ("wfc", "wfk"):                           # V1,V2,M3,M4
        return dispatch({2: 4, 3: 8, 4: 16}, lambda s: _wfc(o, s), o[2])
    if n == "vftci":                                  # V1,V2,I3,M4,M5
        return fmt_single(o[3], o[4], lambda s, se: vtci(o, s, se))
    if n == "vfpso":                                  # V1,V2,M3,M4,M5
        return fmt_single(o[2], o[3], lambda s, se: vpso(o, s, se, o[4]))
    if n == "vfi":                                    # V1,V2,M3,M4,M5
        o2 = [o[0], o[1], o[3], o[4]]
        return fmt_single(o[2], o[3], lambda s, se: vun(o2, s, se, lambda blk, a, s_: round_int(blk, a, s_, f"md{blk.tag}"), mode=o[4]))
    if n in ("vfmax", "vfmin"):                       # V1,V2,V3,M4,M5,M6
        return fmt_single(o[3], o[4], lambda s, se: vminmax(o, s, se, n == "vfmin", o[5]))
    if n in ("vflr", "vfll"):                         # V1,V2,M3,M4[,M5]
        if n == "vfll":
            return fmt_single(o[2], o[3], lambda s, se: vconv_len(o, s, 2 * s, se) if s < 16 else "")
        return fmt_single(o[2], o[3], lambda s, se: vconv_round(o, s, s // 2, se) if s > 4 else "")
    if n in ("vcdg", "vcdlg", "vcfps", "vcfpl"):      # V1,V2,M3,M4,M5
        return fmt_single(o[2], o[3], lambda s, se: vconv_from_int(o, s, se, n in ("vcdlg", "vcfpl")) if s < 16 else "")
    if n in ("vcgd", "vclgd", "vcsfp", "vclfp"):
        o2 = [o[0], o[1], o[3], o[4]]
        return fmt_single(o[2], o[3], lambda s, se: vconv_to_int(o2, s, se, n in ("vclgd", "vclfp")) if s < 16 else "")
    m = re.fullmatch(r"(v|w)f(max|min)(sb|db|xb)", n)  # V1,V2,V3,M6
    if m:
        return vminmax(o, FPSZ[m.group(3)], m.group(1) == "w", m.group(2) == "min", o[3])
    m = re.fullmatch(r"(v|w)fpso(sb|db|xb)", n)        # V1,V2,M5
    if m:
        return vpso(o, FPSZ[m.group(2)], m.group(1) == "w", o[2])
    return None

def _wfc(o, s):
    blk = Block()
    a, b = elemf(blk, o[0], 0, s), elemf(blk, o[1], 0, s)
    cc_compare(blk, a, b)
    return blk.text()
