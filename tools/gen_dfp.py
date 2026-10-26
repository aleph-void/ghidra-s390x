"""P-code for the decimal-floating-point (DFP) instructions (used by gen_semantics.py).

Values are IEEE 754 decimal32/64/128 with densely packed decimal (DPD) coefficients. Operands
are decoded into sign, class (finite, infinity, quiet or signaling NaN), exponent q and the
coefficient as a binary integer; results are computed exactly in 32- or 64-byte integers and
rounded once by the decimal rounding mode (the FPC DRM, or M3/M4 when its bit 8 is set),
with subnormal results, overflow to infinity or the largest finite number, and the clamp
(fold-down) of large exponents, as the General Decimal Arithmetic specification (the decNumber
library behind the Hercules emulator's DFP) defines them. NaN operands propagate (a signaling
NaN first, quieted); invalid operations give the default quiet NaN. The special-value
encodings and condition codes of the s390x instructions follow Hercules dfp.c. Exceptions
(FPC traps and flags) are not modelled. Round to prepare for shorter precision rounds up a
truncated result whose last digit is 0 or 5 (Hercules rounds toward zero there).
"""
import re
from gen_vector import Block, uid

FMT = {   # P, exponent-continuation bits, coefficient-continuation bits, bias, width
    "s": (7, 6, 20, 101, 32),
    "d": (16, 8, 50, 398, 64),
    "x": (34, 12, 110, 6176, 128),
}

def big(v, size):
    parts = [(v >> (64 * k)) & ((1 << 64) - 1) for k in range(size // 8)]
    terms = [f"(zext({p:#x}:8) << {64 * k})" if k else f"zext({p:#x}:8)" for k, p in enumerate(parts) if p]
    return "(" + " | ".join(terms) + ")" if terms else "zext(0:8)"

def lbl(blk, n):
    return f"{n}{blk.tag}_{uid()}"

class D:
    """A decoded operand: s sign (1), cl class (1: 0 finite, 1 inf, 2 qNaN, 3 sNaN), q exponent
    (8, signed), c coefficient (16; of an infinity or NaN: the value of the coefficient
    continuation, the NaN payload), cont the raw coefficient-continuation bits (16)."""
    def __init__(self, blk, fmt):
        self.fmt = fmt
        self.s = blk.local(1, "0")
        self.cl = blk.local(1, "0")
        self.q = blk.local(8, "0")
        self.c = blk.local(16, "zext(0:8)")
        self.cont = blk.local(16, "zext(0:8)")

# ---- DPD ----------------------------------------------------------------------------------
def declets_to_bin(blk, cont, nd):
    """Binary value of the nd declets in cont (16 bytes)."""
    v = blk.local(16, "zext(0:8)")
    k = blk.local(8, f"{nd}")
    l = lbl(blk, "dd")
    dl = blk.local(2, "0")
    a, b, c = blk.local(2, "0"), blk.local(2, "0"), blk.local(2, "0")
    sh = blk.local(16, "zext(0:8)")
    blk.add(f"<{l}>\n"
            f"{k} = {k} - 1; {sh} = {cont} >> ({k} * 10); {dl} = {sh}:2 & 0x3ff;\n"
            f"local p{l}:2 = ({dl} >> 9) & 1; local q{l}:2 = ({dl} >> 8) & 1; local r{l}:2 = ({dl} >> 7) & 1;\n"
            f"local s{l}:2 = ({dl} >> 6) & 1; local t{l}:2 = ({dl} >> 5) & 1; local u{l}:2 = ({dl} >> 4) & 1;\n"
            f"local v{l}:2 = ({dl} >> 3) & 1; local w{l}:2 = ({dl} >> 2) & 1; local x{l}:2 = ({dl} >> 1) & 1; local y{l}:2 = {dl} & 1;\n"
            f"local pqr{l}:2 = p{l} * 4 + q{l} * 2 + r{l}; local stu{l}:2 = s{l} * 4 + t{l} * 2 + u{l};\n"
            f"local pqy{l}:2 = p{l} * 4 + q{l} * 2 + y{l}; local sty{l}:2 = s{l} * 4 + t{l} * 2 + y{l};\n"
            f"local pqu{l}:2 = p{l} * 4 + q{l} * 2 + u{l};\n"
            f"{a} = pqr{l}; {b} = stu{l}; {c} = w{l} * 4 + x{l} * 2 + y{l};\n"
            f"if (v{l} == 0) goto <{l}e>;\n"
            f"if ((w{l} != 0) || (x{l} != 0)) goto <{l}1>; {c} = 8 + y{l}; goto <{l}e>;\n"
            f"<{l}1> if ((w{l} != 0) || (x{l} == 0)) goto <{l}2>; {b} = 8 + u{l}; {c} = sty{l}; goto <{l}e>;\n"
            f"<{l}2> if ((w{l} == 0) || (x{l} != 0)) goto <{l}3>; {a} = 8 + r{l}; {c} = pqy{l}; goto <{l}e>;\n"
            f"<{l}3> if ((s{l} != 0) || (t{l} != 0)) goto <{l}4>; {a} = 8 + r{l}; {b} = 8 + u{l}; {c} = pqy{l}; goto <{l}e>;\n"
            f"<{l}4> if ((s{l} != 0) || (t{l} == 0)) goto <{l}5>; {a} = 8 + r{l}; {b} = pqu{l}; {c} = 8 + y{l}; goto <{l}e>;\n"
            f"<{l}5> if ((s{l} == 0) || (t{l} != 0)) goto <{l}6>; {b} = 8 + u{l}; {c} = 8 + y{l}; goto <{l}e>;\n"
            f"<{l}6> {a} = 8 + r{l}; {b} = 8 + u{l}; {c} = 8 + y{l};\n"
            f"<{l}e>\n"
            f"{v} = {v} * 1000 + zext({a} * 100 + {b} * 10 + {c});\n"
            f"if ({k} != 0) goto <{l}>;")
    return v

def bin_to_declets(blk, val, nd):
    """DPD continuation (16 bytes) of val < 1000^nd."""
    out = blk.local(16, "zext(0:8)")
    v = blk.local(16, val)
    k = blk.local(8, "0")
    l = lbl(blk, "de")
    g = blk.local(16, "zext(0:8)")
    a, b, c = blk.local(2, "0"), blk.local(2, "0"), blk.local(2, "0")
    d = blk.local(2, "0")
    blk.add(f"<{l}>\n"
            f"{g} = {v} % 1000; {v} = {v} / 1000; {c} = {g}:2 % 10; {b} = ({g}:2 / 10) % 10; {a} = {g}:2 / 100;\n"
            f"local la{l}:1 = {a} > 7; local lb{l}:1 = {b} > 7; local lc{l}:1 = {c} > 7;\n"
            f"{d} = ({a} << 7) | ({b} << 4) | {c};\n"
            f"if (!la{l} && !lb{l} && lc{l}) goto <{l}1>; if (!la{l} && lb{l} && !lc{l}) goto <{l}2>;\n"
            f"if (la{l} && !lb{l} && !lc{l}) goto <{l}3>; if (la{l} && lb{l} && !lc{l}) goto <{l}4>;\n"
            f"if (la{l} && !lb{l} && lc{l}) goto <{l}5>; if (!la{l} && lb{l} && lc{l}) goto <{l}6>;\n"
            f"if (la{l} && lb{l} && lc{l}) goto <{l}7>; goto <{l}e>;\n"
            f"<{l}1> {d} = ({a} << 7) | ({b} << 4) | 8 | ({c} & 1); goto <{l}e>;\n"
            f"<{l}2> {d} = ({a} << 7) | ((({c} >> 1) & 3) << 5) | (({b} & 1) << 4) | 0xa | ({c} & 1); goto <{l}e>;\n"
            f"<{l}3> {d} = ((({c} >> 1) & 3) << 8) | (({a} & 1) << 7) | ({b} << 4) | 0xc | ({c} & 1); goto <{l}e>;\n"
            f"<{l}4> {d} = ((({c} >> 1) & 3) << 8) | (({a} & 1) << 7) | (({b} & 1) << 4) | 0xe | ({c} & 1); goto <{l}e>;\n"
            f"<{l}5> {d} = ((({b} >> 1) & 3) << 8) | (({a} & 1) << 7) | 0x20 | (({b} & 1) << 4) | 0xe | ({c} & 1); goto <{l}e>;\n"
            f"<{l}6> {d} = ({a} << 7) | 0x40 | (({b} & 1) << 4) | 0xe | ({c} & 1); goto <{l}e>;\n"
            f"<{l}7> {d} = (({a} & 1) << 7) | 0x60 | (({b} & 1) << 4) | 0xe | ({c} & 1);\n"
            f"<{l}e>\n"
            f"{out} = {out} | (zext({d}) << ({k} * 10)); {k} = {k} + 1;\n"
            f"if ({k} < {nd}) goto <{l}>;")
    return out

# ---- register formats -------------------------------------------------------------------------
def width(fmt):
    return FMT[fmt][4] // 8

def read_bits(blk, fmt, op, kind, pair):
    n = width(fmt)
    if kind == "addr":
        return blk.local(n, f"*:{n} {op}")
    if fmt == "s":
        return blk.local(4, f"{op}(4)")
    if fmt == "d":
        return blk.local(8, op)
    return blk.local(16, f"(zext({op}) << 64) | zext({pair})")

def write_bits(blk, fmt, op, pair, bits):
    if fmt == "s":
        blk.add(f"{op} = ({op} & 0xffffffff) | (zext({bits}) << 32);")
    elif fmt == "d":
        blk.add(f"{op} = {bits};")
    else:
        blk.add(f"{op} = {bits}(8); {pair} = {bits}:8;")

def decode(blk, fmt, bits):
    P, ec, cc, bias, n = FMT[fmt]
    nd = cc // 10
    d = D(blk, fmt)
    w = blk.local(16, f"zext({bits})")
    G = blk.local(1, "0")
    t = blk.local(16, f"{w} >> {n - 6}")
    sg = blk.local(16, f"{w} >> {n - 1}")
    blk.add(f"{G} = {t}:1 & 0x1f; {d.s} = {sg}:1; {d.cont} = {w} & {big((1 << cc) - 1, 16)};")
    l = lbl(blk, "dc")
    lead = blk.local(16, "zext(0:8)")
    em = blk.local(8, "0")
    ecv = blk.local(16, f"({w} >> {cc}) & {(1 << ec) - 1}")
    sn = blk.local(16, f"({w} >> {n - 7}) & 1")
    cv = declets_to_bin(blk, d.cont, nd)
    blk.add(f"if ({G} != 0x1e) goto <{l}n>; {d.cl} = 1; {d.c} = {cv}; goto <{l}e>;\n"
            f"<{l}n> if ({G} != 0x1f) goto <{l}f>; {d.cl} = 2 + {sn}:1; {d.c} = {cv}; goto <{l}e>;\n"
            f"<{l}f> if (({G} >> 3) != 3) goto <{l}a>; {em} = zext(({G} >> 1) & 3); {lead} = zext(8 + ({G} & 1)); goto <{l}b>;\n"
            f"<{l}a> {em} = zext({G} >> 3); {lead} = zext({G} & 7);\n"
            f"<{l}b>")
    blk.add(f"{d.q} = (({em} << {ec}) | {ecv}:8) - {bias};\n"
            f"{d.c} = {lead} * {big(10 ** (3 * nd), 16)} + {cv};\n<{l}e>")
    return d

def encode_finite(blk, fmt, s, q, c):
    """bits for a finite value (c < 10^P, etiny <= q <= emax_q)."""
    P, ec, cc, bias, n = FMT[fmt]
    nd = cc // 10
    lead = blk.local(16, f"{c} / {big(10 ** (3 * nd), 16)}")
    rest = blk.local(16, f"{c} % {big(10 ** (3 * nd), 16)}")
    cont = bin_to_declets(blk, rest, nd)
    e = blk.local(16, f"zext({q} + {bias})")
    emsb = blk.local(16, f"{e} >> {ec}")
    G = blk.local(16, f"zext({lead} < 8) * (({emsb} << 3) | {lead}) + zext({lead} >= 8) * (0x18 | ({emsb} << 1) | ({lead} - 8))")
    r = blk.local(16, f"(zext({s}) << {n - 1}) | ({G} << {n - 6}) | (({e} & {(1 << ec) - 1}) << {cc}) | {cont}")
    return blk.local(width(fmt), f"{r}:{width(fmt)}")

def encode_special(blk, fmt, s, kind, payload):
    """kind: 1 infinity, 2 qNaN, 3 sNaN (8-bit local or constant); payload: binary < 10^(P-1)."""
    P, ec, cc, bias, n = FMT[fmt]
    cont = bin_to_declets(blk, payload, cc // 10)
    k = blk.local(1, kind)
    G = blk.local(16, f"zext(0x1e:1 + zext({k} >= 2))")
    r = blk.local(16, f"(zext({s}) << {n - 1}) | ({G} << {n - 6}) | (zext({k} == 3) << {n - 7}) | "
                      f"(zext({k} >= 2) * {cont})")
    return blk.local(width(fmt), f"{r}:{width(fmt)}")

# ---- arithmetic helpers -----------------------------------------------------------------------
def pow10(blk, n_expr, size):
    """size-byte 10^n (n an 8-byte expression, 0 <= n)."""
    v = blk.local(size, "zext(1:1)")
    k = blk.local(8, n_expr)
    l = lbl(blk, "pw")
    blk.add(f"<{l}> if ({k} s<= 0) goto <{l}e>; {v} = {v} * 10; {k} = {k} - 1; goto <{l}>;\n<{l}e>")
    return v

def ndigits(blk, v, size):
    n = blk.local(8, "0")
    p = blk.local(size, "zext(1:1)")
    l = lbl(blk, "nd")
    blk.add(f"<{l}> if ({p} > {v}) goto <{l}e>; {p} = {p} * 10; {n} = {n} + 1; if ({n} < {2 * size + 4}) goto <{l}>;\n<{l}e>")
    return n

def drm(blk, mask):
    """effective DFP rounding method (as the FPC DRM encodes it) of the modifier field mask:
    0 and 2 the FPC DRM; 1 ties away from 0; 3 prepare for shorter precision; 4-7 ties to
    even, toward 0, toward +inf, toward -inf; 8-15 the DRM encoding mask - 8"""
    m = blk.local(8, mask)
    return blk.local(8, f"zext(({m} & 8) != 0) * ({m} & 7) + zext(({m} == 0) || ({m} == 2)) * zext((fpc >> 4) & 7) + "
                        f"zext({m} == 1) * 4 + zext({m} == 3) * 7 + zext(({m} >= 4) && ({m} <= 7)) * ({m} - 4)")

class R:
    """A result: kind 0 finite / 1 inf / 2 NaN (cc 3), sign, bits."""

def round_finite(blk, fmt, s, q, V, size, sticky, mode):
    """bits of the value V * 10^q (V: size-byte magnitude, sticky: a nonzero tail below V),
    rounded to the format by mode; returns (bits, iszero, isinf)."""
    P, ec, cc, bias, n = FMT[fmt]
    emaxq = (3 << ec) - 1 - bias
    etiny = -bias
    l = lbl(blk, "rd")
    sticky = blk.local(1, f"{sticky}")
    nd = ndigits(blk, V, size)
    t = blk.local(8, f"{q} + zext({nd} s> {P}) * ({nd} - {P})")
    blk.add(f"if ({t} s>= {etiny}) goto <{l}t>; {t} = {etiny};\n<{l}t>")
    dr = blk.local(8, f"{t} - {q}")
    qv = blk.local(size, V)
    gt, eq, inx = blk.local(1, "0"), blk.local(1, "0"), blk.local(1, f"{sticky}")
    blk.add(f"if ({dr} s<= 0) goto <{l}nd>;\n"
            f"if ({dr} s> {2 * size + 4}) goto <{l}far>;")
    pw = pow10(blk, dr, size)
    rem = blk.local(size, f"{V} % {pw}")
    half = blk.local(size, f"({pw} / 10) * 5")
    blk.add(f"{qv} = {V} / {pw};\n"
            f"{gt} = ({rem} > {half}) || (({rem} == {half}) && {sticky}); {eq} = ({rem} == {half}) && !{sticky};\n"
            f"{inx} = ({rem} != 0) || {sticky}; goto <{l}nd>;\n"
            f"<{l}far> {qv} = 0; {inx} = ({V} != 0) || {sticky};\n"
            f"<{l}nd>")
    up = blk.local(1, f"(({mode} == 0) && ({gt} || ({eq} && (({qv} & 1) != 0)))) || "
                      f"(({mode} == 2) && {inx} && ({s} == 0)) || (({mode} == 3) && {inx} && ({s} != 0)) || "
                      f"(({mode} == 4) && ({gt} || {eq})) || (({mode} == 5) && {gt}) || (({mode} == 6) && {inx}) || "
                      f"(({mode} == 7) && {inx} && ((({qv} % 5) == 0)))")
    blk.add(f"{qv} = {qv} + zext({up});\n"
            f"if ({qv} != {big(10 ** P, size)}) goto <{l}c>; {qv} = {big(10 ** (P - 1), size)}; {t} = {t} + 1;\n<{l}c>")
    bits = blk.local(width(fmt), "0")
    zero = blk.local(1, f"{qv} == 0")
    isinf = blk.local(1, "0")
    # zero: clamp the exponent; overflow: fold down or infinity / largest finite
    blk.add(f"if (!{zero}) goto <{l}nz>; if ({t} s<= {emaxq}) goto <{l}ok>; {t} = {emaxq}; goto <{l}ok>;\n"
            f"<{l}nz> if ({t} s<= {emaxq}) goto <{l}ok>;")
    nq = ndigits(blk, qv, size)
    blk.add(f"if (({nq} + ({t} - {emaxq})) s> {P}) goto <{l}ov>;")
    pf = pow10(blk, f"{t} - {emaxq}", size)
    blk.add(f"{qv} = {qv} * {pf}; {t} = {emaxq}; goto <{l}ok>;\n<{l}ov>")
    toinf = blk.local(1, f"({mode} == 0) || ({mode} == 4) || ({mode} == 5) || ({mode} == 6) || "
                         f"(({mode} == 2) && ({s} == 0)) || (({mode} == 3) && ({s} != 0))")
    inf = encode_special(blk, fmt, s, "1:1", "zext(0:8)")
    blk.add(f"if (!{toinf}) goto <{l}mx>; {bits} = {inf}; {isinf} = 1; goto <{l}e>;\n"
            f"<{l}mx> {qv} = {big(10 ** P - 1, size)}; {t} = {emaxq};\n<{l}ok>")
    c16 = blk.local(16, f"{qv}:16" if size > 16 else qv)
    fb = encode_finite(blk, fmt, s, t, c16)
    blk.add(f"{bits} = {fb};\n<{l}e>")
    return bits, zero, isinf

def set_cc(blk, s, zero, nan):
    blk.add(f"gs_cc_flags(!{nan} && {zero}, !{nan} && !{zero} && ({s} != 0), !{nan} && !{zero} && ({s} == 0), {nan});")

def nan_result(blk, fmt, a, b=None):
    """(bits, isnan) for NaN propagation: first sNaN quieted, else first qNaN (a before b)."""
    l = lbl(blk, "nn")
    isn = blk.local(1, f"{a.cl} >= 2" + (f" || ({b.cl} >= 2)" if b else ""))
    s, pl = blk.local(1, a.s), blk.local(16, a.c)
    if b:
        blk.add(f"if ({a.cl} == 3) goto <{l}a>; if ({b.cl} == 3) goto <{l}b>; if ({a.cl} == 2) goto <{l}a>;\n"
                f"<{l}b> {s} = {b.s}; {pl} = {b.c};\n<{l}a>")
    bits = encode_special(blk, fmt, s, "2:1", pl)
    return bits, isn

def default_nan(blk, fmt):
    return encode_special(blk, fmt, "0:1", "2:1", "zext(0:8)")

# ---- operations -------------------------------------------------------------------------------
def addsub(blk, fmt, a, b, sub, mode, store):
    """a + b (b negated for sub)."""
    P = FMT[fmt][0]
    l = lbl(blk, "as")
    S = 32
    bs = blk.local(1, f"{b.s} ^ {1 if sub else 0}")
    nb, isn = nan_result(blk, fmt, a, b)
    blk.add(f"if (!{isn}) goto <{l}nn>;")
    store(nb)
    set_cc(blk, "0:1", "0:1", "1:1")
    blk.add(f"goto <{l}x>;\n<{l}nn>")
    inf = blk.local(1, f"({a.cl} == 1) || ({b.cl} == 1)")
    blk.add(f"if (!{inf}) goto <{l}fin>;")
    bad = blk.local(1, f"({a.cl} == 1) && ({b.cl} == 1) && ({a.s} != {bs})")
    dn = default_nan(blk, fmt)
    blk.add(f"if (!{bad}) goto <{l}inf>;")
    store(dn)
    set_cc(blk, "0:1", "0:1", "1:1")
    blk.add(f"goto <{l}x>;\n<{l}inf>")
    isg = blk.local(1, f"zext({a.cl} == 1) * {a.s} + zext({a.cl} != 1) * {bs}")
    ib = encode_special(blk, fmt, isg, "1:1", "zext(0:8)")
    store(ib)
    set_cc(blk, isg, "0:1", "0:1")
    blk.add(f"goto <{l}x>;\n<{l}fin>")
    # finite: align (operands far below the other's msd only contribute a sticky digit)
    za, zb = blk.local(1, f"{a.c} == 0"), blk.local(1, f"{b.c} == 0")
    qa, qb = blk.local(8, a.q), blk.local(8, b.q)
    ca, cb = blk.local(S, f"zext({a.c})"), blk.local(S, f"zext({b.c})")
    qmin = blk.local(8, f"zext({qa} s< {qb}) * {qa} + zext({qa} s>= {qb}) * {qb}")
    sg = blk.local(1, a.s)
    V = blk.local(S, "zext(0:8)")
    qr = blk.local(8, qmin)
    blk.add(f"if (!({za} && {zb})) goto <{l}nz>;\n"
            f"{sg} = zext({a.s} == {bs}) * {a.s} + zext({a.s} != {bs}) * zext({mode} == 3); goto <{l}rd>;\n"
            f"<{l}nz> if ({zb}) goto <{l}ob>; if ({za}) goto <{l}oa>; goto <{l}both>;")
    # one operand zero: the other, scaled toward the smaller exponent as far as P digits allow
    for (cx, qx, sx, tag) in ((ca, qa, a.s, "ob"), (cb, qb, bs, "oa")):
        blk.add(f"<{l}{tag}> {sg} = {sx};")
        ndx = ndigits(blk, cx, S)
        room = blk.local(8, f"{P} - {ndx}")
        dq = blk.local(8, f"{qx} - {qmin}")
        blk.add(f"if ({dq} s<= {room}) goto <{l}r{tag}>; {dq} = {room};\n<{l}r{tag}>")
        pw = pow10(blk, dq, S)
        blk.add(f"{V} = {cx} * {pw}; {qr} = {qx} - {dq}; goto <{l}rd>;")
    blk.add(f"<{l}both>")
    na, nbd = ndigits(blk, ca, S), ndigits(blk, cb, S)
    ma, mb = blk.local(8, f"{qa} + {na}"), blk.local(8, f"{qb} + {nbd}")
    cut = blk.local(8, f"zext({ma} s> {mb}) * {ma} + zext({ma} s<= {mb}) * {mb} - {P + 3}")
    for cx, qx, tag in ((ca, qa, "a"), (cb, qb, "b")):
        blk.add(f"if ({qx} s>= {cut}) goto <{l}k{tag}>;")
        k = blk.local(8, f"{cut} - {qx}")
        blk.add(f"if ({k} s> {2 * S}) goto <{l}f{tag}>;")
        pw = pow10(blk, k, S)
        st = blk.local(1, f"({cx} % {pw}) != 0")
        blk.add(f"{cx} = {cx} / {pw}; {qx} = {cut}; if (!{st}) goto <{l}k{tag}>; {cx} = {cx} * 10 + 1; {qx} = {cut} - 1; goto <{l}k{tag}>;\n"
                f"<{l}f{tag}> {cx} = 1; {qx} = {cut} - 1;\n<{l}k{tag}>")
    blk.add(f"{qr} = zext({qa} s< {qb}) * {qa} + zext({qa} s>= {qb}) * {qb};")
    pa, pb = pow10(blk, f"{qa} - {qr}", S), pow10(blk, f"{qb} - {qr}", S)
    xa, xb = blk.local(S, f"{ca} * {pa}"), blk.local(S, f"{cb} * {pb}")
    blk.add(f"if ({a.s} != {bs}) goto <{l}df>; {V} = {xa} + {xb}; {sg} = {a.s}; goto <{l}rd>;\n"
            f"<{l}df> if ({xa} < {xb}) goto <{l}lt>; {V} = {xa} - {xb}; {sg} = {a.s};\n"
            f"if ({V} != 0) goto <{l}rd>; {sg} = zext({mode} == 3); goto <{l}rd>;\n"
            f"<{l}lt> {V} = {xb} - {xa}; {sg} = {bs};\n"
            f"<{l}rd>")
    bits, zero, isinf = round_finite(blk, fmt, sg, qr, V, S, "0:1", mode)
    store(bits)
    set_cc(blk, sg, zero, "0:1")
    blk.add(f"<{l}x>")

def multiply(blk, fmt, a, b, mode, store):
    l = lbl(blk, "mu")
    S = 32
    nb, isn = nan_result(blk, fmt, a, b)
    sg = blk.local(1, f"{a.s} ^ {b.s}")
    blk.add(f"if (!{isn}) goto <{l}nn>;")
    store(nb)
    set_cc(blk, "0:1", "0:1", "1:1")
    blk.add(f"goto <{l}x>;\n<{l}nn>")
    blk.add(f"if (({a.cl} != 1) && ({b.cl} != 1)) goto <{l}fin>;")
    bad = blk.local(1, f"(({a.cl} == 1) && ({b.cl} == 0) && ({b.c} == 0)) || (({b.cl} == 1) && ({a.cl} == 0) && ({a.c} == 0))")
    dn = default_nan(blk, fmt)
    blk.add(f"if (!{bad}) goto <{l}inf>;")
    store(dn)
    set_cc(blk, "0:1", "0:1", "1:1")
    blk.add(f"goto <{l}x>;\n<{l}inf>")
    store(encode_special(blk, fmt, sg, "1:1", "zext(0:8)"))
    set_cc(blk, sg, "0:1", "0:1")
    blk.add(f"goto <{l}x>;\n<{l}fin>")
    V = blk.local(S, f"zext({a.c}) * zext({b.c})")
    q = blk.local(8, f"{a.q} + {b.q}")
    bits, zero, isinf = round_finite(blk, fmt, sg, q, V, S, "0:1", mode)
    store(bits)
    set_cc(blk, sg, zero, "0:1")
    blk.add(f"<{l}x>")

def divide(blk, fmt, a, b, mode, store):
    P = FMT[fmt][0]
    l = lbl(blk, "dv")
    S = 64
    nb, isn = nan_result(blk, fmt, a, b)
    sg = blk.local(1, f"{a.s} ^ {b.s}")
    dn = default_nan(blk, fmt)
    blk.add(f"if (!{isn}) goto <{l}nn>;")
    store(nb)
    set_cc(blk, "0:1", "0:1", "1:1")
    blk.add(f"goto <{l}x>;\n<{l}nn>")
    blk.add(f"if (({a.cl} != 1) && ({b.cl} != 1)) goto <{l}fin>;\n"
            f"if (({a.cl} == 1) && ({b.cl} == 1)) goto <{l}inv>;\n"
            f"if ({a.cl} == 1) goto <{l}inf>;")
    # finite / infinity: zero with the smallest exponent
    zb = encode_finite(blk, fmt, sg, f"{-FMT[fmt][3]}:8", "zext(0:8)")
    store(zb)
    set_cc(blk, sg, "1:1", "0:1")
    blk.add(f"goto <{l}x>;\n<{l}inf>")
    store(encode_special(blk, fmt, sg, "1:1", "zext(0:8)"))
    set_cc(blk, sg, "0:1", "0:1")
    blk.add(f"goto <{l}x>;\n<{l}inv>")
    store(dn)
    set_cc(blk, "0:1", "0:1", "1:1")
    blk.add(f"goto <{l}x>;\n<{l}fin>\n"
            f"if ({b.c} != 0) goto <{l}nz>; if ({a.c} == 0) goto <{l}inv>; goto <{l}inf>;\n<{l}nz>")
    ideal = blk.local(8, f"{a.q} - {b.q}")
    V = blk.local(S, f"zext({a.c})")
    q = blk.local(8, ideal)
    rem = blk.local(S, "zext(0:8)")
    blk.add(f"if ({a.c} == 0) goto <{l}rd>;")
    n1, n2 = ndigits(blk, blk.local(S, f"zext({a.c})"), S), ndigits(blk, blk.local(S, f"zext({b.c})"), S)
    k = blk.local(8, f"{P + 1} + {n2} - {n1}")
    blk.add(f"if ({k} s>= 0) goto <{l}k>; {k} = 0;\n<{l}k>")
    pw = pow10(blk, k, S)
    num = blk.local(S, f"zext({a.c}) * {pw}")
    blk.add(f"{V} = {num} / zext({b.c}); {rem} = {num} % zext({b.c}); {q} = {ideal} - {k};\n"
            f"if ({rem} != 0) goto <{l}rd>;\n"
            f"<{l}tz> if (({q} s>= {ideal}) || (({V} % 10) != 0)) goto <{l}rd>; {V} = {V} / 10; {q} = {q} + 1; goto <{l}tz>;\n"
            f"<{l}rd>")
    bits, zero, isinf = round_finite(blk, fmt, sg, q, V, S, f"{rem} != 0", mode)
    store(bits)
    set_cc(blk, sg, zero, "0:1")
    blk.add(f"<{l}x>")

def encode_special_cont(blk, fmt, s, kind, payload):
    """Like encode_special, but infinity keeps the coefficient continuation too (the s390x
    instructions that 'set the CF field' of a re-encoded coefficient)."""
    P, ec, cc, bias, n = FMT[fmt]
    cont = bin_to_declets(blk, payload, cc // 10)
    k = blk.local(1, kind)
    G = blk.local(16, f"zext(0x1e:1 + zext({k} >= 2))")
    r = blk.local(16, f"(zext({s}) << {n - 1}) | ({G} << {n - 6}) | (zext({k} == 3) << {n - 7}) | {cont}")
    return blk.local(width(fmt), f"{r}:{width(fmt)}")

def mag_compare(blk, a, b, S=32):
    """(lt, gt) of |a| vs |b| for finite nonzero operands."""
    na, nb = ndigits(blk, blk.local(S, f"zext({a.c})"), S), ndigits(blk, blk.local(S, f"zext({b.c})"), S)
    ma, mb = blk.local(8, f"{a.q} + {na}"), blk.local(8, f"{b.q} + {nb}")
    qm = blk.local(8, f"zext({a.q} s< {b.q}) * {a.q} + zext({a.q} s>= {b.q}) * {b.q}")
    lt, gt = blk.local(1, f"{ma} s< {mb}"), blk.local(1, f"{ma} s> {mb}")
    l = lbl(blk, "mc")
    blk.add(f"if ({ma} != {mb}) goto <{l}>;")
    pa, pb = pow10(blk, f"{a.q} - {qm}", S), pow10(blk, f"{b.q} - {qm}", S)
    xa, xb = blk.local(S, f"zext({a.c}) * {pa}"), blk.local(S, f"zext({b.c}) * {pb}")
    blk.add(f"{lt} = {xa} < {xb}; {gt} = {xa} > {xb};\n<{l}>")
    return lt, gt

def compare(blk, a, b):
    """cc 0 equal, 1 low, 2 high, 3 unordered."""
    l = lbl(blk, "cp")
    c0, c1, c2, c3 = (blk.local(1, "0") for _ in range(4))
    blk.add(f"if (({a.cl} < 2) && ({b.cl} < 2)) goto <{l}o>; {c3} = 1; goto <{l}e>;\n<{l}o>")
    def rank(x):
        return blk.local(1, f"zext({x.cl} == 1) * (2 - zext({x.s}) * 4) + "
                            f"zext({x.cl} == 0) * zext({x.c} != 0) * (1 - zext({x.s}) * 2)")
    ra, rb = rank(a), rank(b)
    blk.add(f"if (({ra} != {rb}) || ({a.cl} == 1) || ({ra} == 0)) goto <{l}r>;")
    lt, gt = mag_compare(blk, a, b)
    blk.add(f"{c1} = ({a.s} == 0) && {lt} || ({a.s} != 0) && {gt}; {c2} = ({a.s} == 0) && {gt} || ({a.s} != 0) && {lt};\n"
            f"{c0} = !{c1} && !{c2}; goto <{l}e>;\n"
            f"<{l}r> {c1} = {ra} s< {rb}; {c2} = {ra} s> {rb}; {c0} = {ra} == {rb};\n<{l}e>")
    blk.add(f"gs_cc_flags({c0}, {c1}, {c2}, {c3});")

def to_integral(blk, a, mode, S=32):
    """(V magnitude, inexact) of the finite a rounded to an integer by mode."""
    l = lbl(blk, "ti")
    V = blk.local(S, f"zext({a.c})")
    blk.add(f"if ({a.q} s>= 0) goto <{l}up>;")
    k = blk.local(8, f"0 - {a.q}")
    q, gt, eq, inx = blk.local(S, "zext(0:8)"), blk.local(1, "0"), blk.local(1, "0"), blk.local(1, "0")
    blk.add(f"if ({k} s> {2 * S}) goto <{l}far>;")
    pw = pow10(blk, k, S)
    rem = blk.local(S, f"{V} % {pw}")
    half = blk.local(S, f"({pw} / 10) * 5")
    blk.add(f"{q} = {V} / {pw}; {gt} = {rem} > {half}; {eq} = {rem} == {half}; {inx} = {rem} != 0; goto <{l}rd>;\n"
            f"<{l}far> {inx} = {V} != 0;\n<{l}rd>")
    up = blk.local(1, f"(({mode} == 0) && ({gt} || ({eq} && (({q} & 1) != 0)))) || "
                      f"(({mode} == 2) && {inx} && ({a.s} == 0)) || (({mode} == 3) && {inx} && ({a.s} != 0)) || "
                      f"(({mode} == 4) && ({gt} || {eq})) || (({mode} == 5) && {gt}) || (({mode} == 6) && {inx}) || "
                      f"(({mode} == 7) && {inx} && ((({q} % 5) == 0)))")
    blk.add(f"{V} = {q} + zext({up}); goto <{l}e>;\n<{l}up>\n"
            f"if ({a.q} s> {S + 8}) goto <{l}big>;")
    pw2 = pow10(blk, a.q, S)
    blk.add(f"{V} = {V} * {pw2}; goto <{l}e>;\n"
            f"<{l}big> {V} = zext({a.c} != 0) * {big((1 << (8 * S - 2)), S)};\n<{l}e>")
    return V, inx

def canon(blk, fmt, a, quiet):
    """bits of operand a re-encoded (canonical declets; an infinity loses its coefficient
    continuation, a signaling NaN is quieted when quiet)."""
    l = lbl(blk, "cn")
    bits = blk.local(width(fmt), "0")
    kind = blk.local(1, f"{a.cl} - zext(({a.cl} == 3) && {quiet})")
    blk.add(f"if ({a.cl} != 0) goto <{l}s>;")
    fb = encode_finite(blk, fmt, a.s, a.q, a.c)
    blk.add(f"{bits} = {fb}; goto <{l}e>;\n<{l}s>")
    pl = blk.local(16, f"{a.c} * zext({a.cl} >= 2)")
    sb = encode_special(blk, fmt, a.s, kind, pl)
    blk.add(f"{bits} = {sb};\n<{l}e>")
    return bits

def cc_value(blk, a):
    """cc 0 zero, 1 negative, 2 positive, 3 NaN"""
    blk.add(f"gs_cc_flags(({a.cl} == 0) && ({a.c} == 0), ({a.cl} < 2) && ({a.s} != 0) && (({a.c} != 0) || ({a.cl} == 1)), "
            f"({a.cl} < 2) && ({a.s} == 0) && (({a.c} != 0) || ({a.cl} == 1)), {a.cl} >= 2);")

def to_fixed(blk, a, mode, bits, signed):
    """(result, invalid) of CONVERT TO FIXED / LOGICAL: a rounded to an integer by mode,
    NaN and out-of-range values giving the extreme value (0 for a NaN to logical)."""
    l = lbl(blk, "fx")
    S = 32
    r = blk.local(8, "0")
    inv = blk.local(1, "1")
    mx = (1 << (bits - 1)) - 1 if signed else (1 << bits) - 1
    mn = (1 << (bits - 1)) if signed else 0
    blk.add(f"{r} = {mn:#x}; if ({a.cl} >= 2) goto <{l}e>;\n"
            f"if ({a.cl} == 0) goto <{l}f>; {r} = zext({a.s} == 0) * {mx:#x} + zext({a.s} != 0) * {mn:#x}; goto <{l}e>;\n<{l}f>")
    V, inx = to_integral(blk, a, mode, S)
    lim = blk.local(S, f"zext({mx:#x}:8) + zext({a.s} != 0) * zext({1 if signed else 0}:8)")
    if signed:
        blk.add(f"if ({V} <= {lim}) goto <{l}ok>; {r} = zext({a.s} == 0) * {mx:#x} + zext({a.s} != 0) * {mn:#x}; goto <{l}e>;\n"
                f"<{l}ok> {inv} = 0; {r} = {V}:8; if ({a.s} == 0) goto <{l}e>; {r} = -{r};\n<{l}e>")
    else:
        blk.add(f"if (({a.s} != 0) && ({V} != 0)) goto <{l}e>; if ({V} <= {lim}) goto <{l}ok>; {r} = {mx:#x}; goto <{l}e>;\n"
                f"<{l}ok> {inv} = 0; {r} = {V}:8;\n<{l}e>")
    return r, inv

def lim_payload(blk, fmt, c):
    P = FMT[fmt][0]
    return blk.local(16, f"{c} % {big(10 ** (P - 1), 16)}")

def bcd_to_bin(blk, hi, lo, ndig, signed):
    """(V, negative) of the BCD digits in the 16-byte value (hi:lo)"""
    l = lbl(blk, "bc")
    w = blk.local(16, f"(zext({hi}) << 64) | zext({lo})" if hi else f"zext({lo})")
    V = blk.local(16, "zext(0:8)")
    k = blk.local(8, f"{ndig}")
    sh = 4 if signed else 0
    blk.add(f"<{l}> {k} = {k} - 1; {V} = {V} * 10 + (({w} >> ({k} * 4 + {sh})) & 0xf); if ({k} != 0) goto <{l}>;")
    neg = blk.local(1, f"(({w}:1 & 0xf) == 0xb) || (({w}:1 & 0xf) == 0xd)" if signed else "0")
    return V, neg

def bin_to_bcd(blk, V, ndig):
    """16-byte BCD of the rightmost ndig digits of V"""
    l = lbl(blk, "bd")
    out = blk.local(16, "zext(0:8)")
    v = blk.local(16, V)
    k = blk.local(8, "0")
    blk.add(f"<{l}> {out} = {out} | (({v} % 10) << ({k} * 4)); {v} = {v} / 10; {k} = {k} + 1; if ({k} < {ndig}) goto <{l}>;")
    return out

def put_gr(blk, o, val, size):
    if size == 4:
        blk.add(f"{o} = ({o} & 0xffffffff00000000) | zext({val}:4);")
    else:
        blk.add(f"{o} = {val};")

def semantics(ctx):
    n, o, k = ctx["name"], ctx["ops"], ctx["kinds"]
    p = ctx.get("pairs", {})
    x = ctx.get("extra", [])
    blk = Block()
    def rd(i, fmt):
        return decode(blk, fmt, read_bits(blk, fmt, o[i], k[i], p.get(i)))
    def st(i, fmt):
        return lambda bits: write_bits(blk, fmt, o[i], p.get(i), bits)
    def done():
        return blk.text()
    m = re.fullmatch(r"(a|s|m|d)([dx])tr(a?)", n)
    if m:
        op, f, ra = m.group(1), m.group(2), m.group(3)
        mode = drm(blk, o[3] if ra else "0")
        a, b = rd(1, f), rd(2, f)
        {"a": lambda: addsub(blk, f, a, b, False, mode, st(0, f)),
         "s": lambda: addsub(blk, f, a, b, True, mode, st(0, f)),
         "m": lambda: multiply(blk, f, a, b, mode, st(0, f)),
         "d": lambda: divide(blk, f, a, b, mode, st(0, f))}[op]()
        return done()
    m = re.fullmatch(r"(c|k)([dx])tr", n)
    if m:
        f = m.group(2)
        compare(blk, rd(0, f), rd(1, f))
        return done()
    m = re.fullmatch(r"ce([dx])tr", n)
    if m:
        f = m.group(1)
        a, b = rd(0, f), rd(1, f)
        an, bn = blk.local(1, f"{a.cl} >= 2"), blk.local(1, f"{b.cl} >= 2")
        ai, bi = blk.local(1, f"{a.cl} == 1"), blk.local(1, f"{b.cl} == 1")
        c3 = blk.local(1, f"({an} != {bn}) || (!{an} && ({ai} != {bi}))")
        c0 = blk.local(1, f"!{c3} && ({an} || {ai} || ({a.q} == {b.q}))")
        c1 = blk.local(1, f"!{c3} && !{c0} && ({a.q} s< {b.q})")
        blk.add(f"gs_cc_flags({c0}, {c1}, !{c3} && !{c0} && !{c1}, {c3});")
        return done()
    m = re.fullmatch(r"lt([dx])tr", n)
    if m:
        f = m.group(1)
        a = rd(1, f)
        st(0, f)(canon(blk, f, a, "1:1"))
        cc_value(blk, a)
        return done()
    m = re.fullmatch(r"c([dx])(g|f|lg|lf)tr(a?)", n)
    if m:
        f, src = m.group(1), m.group(2)
        mode = drm(blk, o[1] if len(o) > 2 else "0")
        r = o[2] if len(o) > 2 else o[1]
        if src in ("g", "f"):
            v = blk.local(8, f"sext({r}:4)" if src == "f" else r)
            sg = blk.local(1, f"{v} s< 0")
            V = blk.local(32, f"zext({v} * (1 - 2 * zext({sg})))")
        else:
            sg = blk.local(1, "0")
            V = blk.local(32, f"zext({r}:4)" if src == "lf" else f"zext({r})")
        bits, z, i = round_finite(blk, f, sg, "0:8", V, 32, "0:1", mode)
        st(0, f)(bits)
        return done()
    m = re.fullmatch(r"c(g|f|lg|lf)([dx])tr(a?)", n)
    if m:
        dst, f = m.group(1), m.group(2)
        mode = drm(blk, o[1])
        a = rd(2, f)
        r, inv = to_fixed(blk, a, mode, 64 if "g" in dst else 32, dst[0] != "l")
        put_gr(blk, o[0], r, 8 if "g" in dst else 4)
        blk.add(f"gs_cc_flags(!{inv} && ({a.cl} == 0) && ({a.c} == 0), !{inv} && ({a.s} != 0) && ({a.c} != 0), "
                f"!{inv} && ({a.s} == 0) && ({a.c} != 0), {inv});")
        return done()
    m = re.fullmatch(r"c([dx])([su])tr", n)
    if m:
        f, sgn = m.group(1), m.group(2) == "s"
        if f == "d":
            V, neg = bcd_to_bin(blk, None, o[1], 15 if sgn else 16, sgn)
        else:
            V, neg = bcd_to_bin(blk, o[1], x[0], 31 if sgn else 32, sgn)
        st(0, f)(encode_finite(blk, f, neg, "0:8", V))
        return done()
    m = re.fullmatch(r"c([su])([dx])tr", n)
    if m:
        sgn, f = m.group(1) == "s", m.group(2)
        a = rd(1, f)
        nd = (15 if f == "d" else 31) + (0 if sgn else 1)
        out = bin_to_bcd(blk, a.c, nd)
        if sgn:
            m4 = blk.local(8, o[2])
            blk.add(f"{out} = ({out} << 4) | zext(0xc:1 + zext({a.s} != 0) + zext(({a.s} == 0) && (({m4} & 1) != 0)) * 3);")
        if f == "d":
            blk.add(f"{o[0]} = {out}:8;")
        else:
            hi = o[0]
            lo = p.get(0) if sgn else x[0]
            blk.add(f"{hi} = {out}(8); {lo} = {out}:8;")
        return done()
    m = re.fullmatch(r"c([dx])([zp])t", n)
    if m:
        f, z = m.group(1), m.group(2) == "z"
        ad, m3 = o[1], blk.local(8, o[2])
        L = blk.local(8, f"{x[0]} + 1")
        l = lbl(blk, "zp")
        V = blk.local(16, "zext(0:8)")
        i = blk.local(8, "0")
        by = blk.local(1, "0")
        neg = blk.local(1, "0")
        last = blk.local(1, f"*:1 ({ad} + {L} - 1)")
        if z:
            blk.add(f"<{l}> {by} = *:1 ({ad} + {i}); {V} = {V} * 10 + zext({by} & 0xf); {i} = {i} + 1; if ({i} < {L}) goto <{l}>;\n"
                    f"{neg} = (({m3} & 8) != 0) && (((({last} >> 4) == 0xb)) || (({last} >> 4) == 0xd));")
        else:
            blk.add(f"<{l}> {by} = *:1 ({ad} + {i}); {V} = {V} * 10 + zext({by} >> 4); {i} = {i} + 1;\n"
                    f"if (({i} == {L}) && (({m3} & 8) != 0)) goto <{l}e>; {V} = {V} * 10 + zext({by} & 0xf); if ({i} < {L}) goto <{l}>;\n<{l}e>\n"
                    f"{neg} = (({m3} & 9) == 8) && ((({last} & 0xf) == 0xb) || (({last} & 0xf) == 0xd));")
        st(0, f)(encode_finite(blk, f, neg, "0:8", V))
        return done()
    m = re.fullmatch(r"c([zp])([dx])t", n)
    if m:
        z, f = m.group(1) == "z", m.group(2)
        a = rd(0, f)
        ad, m3 = o[1], blk.local(8, o[2])
        L = blk.local(8, f"{x[0]} + 1")
        l = lbl(blk, "tz")
        v = blk.local(16, a.c)
        i = blk.local(8, L)
        sp = blk.local(1, f"{a.cl} != 0")
        neg = blk.local(1, f"({a.s} != 0) && !((({m3} & 1) != 0) && !{sp} && ({a.c} == 0))")
        sgn = blk.local(1, f"zext({neg}) * 0xd + zext(!{neg}) * (0xc + zext(({m3} & 2) != 0) * 3)")
        if z:
            zone = blk.local(1, f"0xf0 - zext(({m3} & 4) != 0) * 0xc0")
            dg = blk.local(16, "zext(0:8)")
            blk.add(f"<{l}> {i} = {i} - 1; {dg} = {v} % 10; *:1 ({ad} + {i}) = {zone} | {dg}:1; {v} = {v} / 10; if ({i} != 0) goto <{l}>;\n"
                    f"if (({m3} & 8) == 0) goto <{l}e>; local zb{l}:1 = *:1 ({ad} + {L} - 1); *:1 ({ad} + {L} - 1) = (zb{l} & 0xf) | ({sgn} << 4);\n<{l}e>")
        else:
            d, e = blk.local(16, "zext(0:8)"), blk.local(16, "zext(0:8)")
            blk.add(f"if (({m3} & 8) == 0) goto <{l}u>; {i} = {i} - 1; {d} = {v} % 10; *:1 ({ad} + {i}) = ({d}:1 << 4) | {sgn}; {v} = {v} / 10;\n"
                    f"if ({i} == 0) goto <{l}e>;\n<{l}u>\n"
                    f"<{l}> {i} = {i} - 1; {d} = {v} % 10; {v} = {v} / 10; {e} = {v} % 10; *:1 ({ad} + {i}) = ({e}:1 << 4) | {d}:1; {v} = {v} / 10;\n"
                    f"if ({i} != 0) goto <{l}>;\n<{l}e>")
        blk.add(f"gs_cc_flags(!{sp} && ({v} == 0) && ({a.c} == 0), !{sp} && ({v} == 0) && ({a.c} != 0) && ({a.s} != 0), "
                f"!{sp} && ({v} == 0) && ({a.c} != 0) && ({a.s} == 0), {sp} || ({v} != 0));")
        return done()
    m = re.fullmatch(r"e([es])([dx])tr", n)
    if m:
        what, f = m.group(1), m.group(2)
        a = rd(1, f)
        r = blk.local(8, f"-1 - zext({a.cl} >= 2) - zext({a.cl} == 3)")
        l = lbl(blk, "ex")
        blk.add(f"if ({a.cl} != 0) goto <{l}>;")
        if what == "e":
            blk.add(f"{r} = {a.q} + {FMT[f][3]};")
        else:
            nd = ndigits(blk, a.c, 16)
            blk.add(f"{r} = {nd};")
        blk.add(f"<{l}> {o[0]} = {r};")
        return done()
    m = re.fullmatch(r"ie([dx])tr", n)
    if m:
        f = m.group(1)
        P, ec, cc, bias, nb = FMT[f]
        ehigh = (3 << ec) - 1
        a = rd(1, f)
        e = blk.local(8, o[2])
        l = lbl(blk, "ie")
        bits = blk.local(width(f), "0")
        kind = blk.local(1, f"zext(({e} == -1)) + zext(({e} != -1) && ({e} != -3)) * 2 + zext({e} == -3) * 3")
        blk.add(f"if (({e} s>= 0) && ({e} s<= {ehigh})) goto <{l}f>;")
        sb = encode_special_cont(blk, f, a.s, kind, lim_payload(blk, f, a.c))
        blk.add(f"{bits} = {sb}; goto <{l}e>;\n<{l}f>")
        fb = encode_finite(blk, f, a.s, f"{e} - {bias}", a.c)
        blk.add(f"{bits} = {fb};\n<{l}e>")
        st(0, f)(bits)
        return done()
    m = re.fullmatch(r"fi([dx])tr", n)
    if m:
        f = m.group(1)
        mode = drm(blk, o[1])
        a = rd(2, f)
        l = lbl(blk, "fi")
        bits = canon(blk, f, a, "1:1")
        blk.add(f"if (({a.cl} != 0) || ({a.q} s>= 0)) goto <{l}e>;")
        V, inx = to_integral(blk, a, mode, 32)
        fb = encode_finite(blk, f, a.s, "0:8", blk.local(16, f"{V}:16"))
        blk.add(f"{bits} = {fb};\n<{l}e>")
        st(0, f)(bits)
        return done()
    lr = {"ldetr": ("s", "d"), "lxdtr": ("d", "x"), "ledtr": ("d", "s"), "ldxtr": ("x", "d")}
    if n in lr:
        fs, fd = lr[n]
        shorten = n in ("ledtr", "ldxtr")
        mode = drm(blk, o[1]) if shorten else None
        a = rd(2 if shorten else 1, fs)
        m4 = blk.local(8, o[-1])
        keep = blk.local(1, f"({m4} & 8) != 0")
        l = lbl(blk, "lr")
        bits = blk.local(width(fd), "0")
        blk.add(f"if ({a.cl} == 0) goto <{l}f>;")
        kind = blk.local(1, f"{a.cl} - zext(({a.cl} == 3) && !{keep})")
        pl = lim_payload(blk, fd, a.c) if shorten else a.c
        pl = blk.local(16, f"{pl} * zext(({a.cl} >= 2) || {keep})")
        sb = encode_special_cont(blk, fd, a.s, kind, pl)
        blk.add(f"{bits} = {sb}; goto <{l}e>;\n<{l}f>")
        if shorten:
            V = blk.local(32, f"zext({a.c})")
            fb, z, i = round_finite(blk, fd, a.s, a.q, V, 32, "0:1", mode)
        else:
            fb = encode_finite(blk, fd, a.s, a.q, a.c)
        blk.add(f"{bits} = {fb};\n<{l}e>")
        st(0, fd)(bits)
        return done()
    m = re.fullmatch(r"qa([dx])tr", n)
    if m:
        f = m.group(1)
        P = FMT[f][0]
        mode = drm(blk, o[3])
        a, b = rd(2, f), rd(1, f)           # the value (R2) and the exponent source (R3)
        l = lbl(blk, "qa")
        bits = blk.local(width(f), "0")
        nb, isn = nan_result(blk, f, a, b)
        dn = default_nan(blk, f)
        blk.add(f"{bits} = {nb}; if ({isn}) goto <{l}e>; {bits} = {dn};\n"
                f"if (({a.cl} == 1) != ({b.cl} == 1)) goto <{l}e>; if ({a.cl} == 0) goto <{l}f>;")
        ib = encode_special(blk, f, a.s, "1:1", "zext(0:8)")
        blk.add(f"{bits} = {ib}; goto <{l}e>;\n<{l}f>")
        V = blk.local(32, f"zext({a.c})")
        blk.add(f"if ({a.q} s< {b.q}) goto <{l}dn>; if ({a.q} - {b.q} s<= {P}) goto <{l}up>; {V} = {V} * {big(10 ** P, 32)}; goto <{l}ck>;\n<{l}up>")
        pw = pow10(blk, f"{a.q} - {b.q}", 32)
        blk.add(f"{V} = {V} * {pw}; goto <{l}ck>;\n<{l}dn>")
        t = D(blk, f)
        blk.add(f"{t.s} = {a.s}; {t.q} = {a.q} - {b.q}; {t.c} = {a.c};")
        Vr, inx = to_integral(blk, t, mode, 32)
        blk.add(f"{V} = {Vr};\n<{l}ck>\n"
                f"if ({V} >= {big(10 ** P, 32)}) goto <{l}e>;")
        fb = encode_finite(blk, f, a.s, b.q, blk.local(16, f"{V}:16"))
        blk.add(f"{bits} = {fb};\n<{l}e>")
        st(0, f)(bits)
        return done()
    m = re.fullmatch(r"rr([dx])tr", n)
    if m:
        f = m.group(1)
        mode = drm(blk, o[3])
        a = rd(1, f)
        sig = blk.local(8, f"zext({o[2]}:1 & 0x3f)")
        l = lbl(blk, "rr")
        bits = canon(blk, f, a, "1:1")
        nd = ndigits(blk, blk.local(32, f"zext({a.c})"), 32)
        blk.add(f"if (({a.cl} != 0) || ({a.c} == 0) || ({sig} == 0) || ({nd} s<= {sig})) goto <{l}e>;")
        t = D(blk, f)
        blk.add(f"{t.s} = {a.s}; {t.q} = {sig} - {nd}; {t.c} = {a.c};")
        Vr, inx = to_integral(blk, t, mode, 32)
        q = blk.local(8, f"{a.q} + {nd} - {sig}")
        pc = pow10(blk, sig, 32)
        blk.add(f"if ({Vr} != {pc}) goto <{l}r>; {Vr} = {Vr} / 10; {q} = {q} + 1;\n<{l}r>")
        rb, z, i = round_finite(blk, f, a.s, q, Vr, 32, "0:1", mode)
        dn = default_nan(blk, f)
        blk.add(f"{bits} = {rb}; if ({q} s<= {(3 << FMT[f][1]) - 1 - FMT[f][3]}) goto <{l}e>; {bits} = {dn};\n<{l}e>")
        st(0, f)(bits)
        return done()
    m = re.fullmatch(r"s([lr])([dx])t", n)
    if m:
        left, f = m.group(1) == "l", m.group(2)
        P = FMT[f][0]
        a = rd(1, f)
        sh = blk.local(8, f"{o[2]} & 0x3f")
        l = lbl(blk, "sh")
        V = blk.local(32, f"zext({a.c})")
        if left:
            blk.add(f"if ({sh} s<= {P}) goto <{l}m>; {sh} = {P + 1};\n<{l}m>")
            pw = pow10(blk, sh, 32)
            blk.add(f"{V} = {V} * {pw};")
        else:
            blk.add(f"if ({sh} s> 40) goto <{l}z>;")
            pw = pow10(blk, sh, 32)
            blk.add(f"{V} = {V} / {pw}; goto <{l}d>;\n<{l}z> {V} = 0;\n<{l}d>")
        bits = blk.local(width(f), "0")
        blk.add(f"if ({a.cl} == 0) goto <{l}f>;")
        sb = encode_special_cont(blk, f, a.s, a.cl, blk.local(16, blk.local(32, f"{V} % {big(10 ** (P - 1), 32)}") + ":16"))
        blk.add(f"{bits} = {sb}; goto <{l}e>;\n<{l}f>")
        fb = encode_finite(blk, f, a.s, a.q, blk.local(16, blk.local(32, f"{V} % {big(10 ** P, 32)}") + ":16"))
        blk.add(f"{bits} = {fb};\n<{l}e>")
        st(0, f)(bits)
        return done()
    m = re.fullmatch(r"td([cg])([edx])t", n)
    if m:
        grp, f = m.group(1) == "g", {"e": "s"}.get(m.group(2), m.group(2))
        P, ec, cc, bias, nb = FMT[f]
        emaxq, etiny = (3 << ec) - 1 - bias, -bias
        emin = 1 - (emaxq + P - 1)
        a = rd(0, f)
        bitn = blk.local(8, "0")
        if not grp:
            nd = ndigits(blk, a.c, 16)
            blk.add(f"{bitn} = zext({a.cl} == 0) * (zext({a.c} == 0) * 52 + zext({a.c} != 0) * (54 + zext(({a.q} + {nd} - 1) s>= {emin}) * 2)) + "
                    f"zext({a.cl} != 0) * (56 + zext({a.cl}) * 2);")
        else:
            lead = blk.local(16, f"{a.c} / {big(10 ** (P - 1), 16)}")
            ext = blk.local(1, f"({a.q} == {etiny}) || ({a.q} == {emaxq})")
            blk.add(f"{bitn} = zext({a.cl} != 0) * 62 + zext({a.cl} == 0) * (zext({a.c} == 0) * (52 + zext({ext}) * 2) + "
                    f"zext({a.c} != 0) * (zext({ext}) * 56 + zext(!{ext}) * (58 + zext({lead} != 0) * 2)));")
        blk.add(f"{bitn} = {bitn} + zext({a.s}); local hit{blk.tag}:1 = (({o[1]} >> (63 - {bitn})) & 1) != 0;\n"
                f"gs_cc_flags(!hit{blk.tag}, hit{blk.tag}, 0:1, 0:1);")
        return done()
    return None
