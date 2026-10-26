"""P-code for the vector packed-decimal instructions (used by gen_semantics.py).

A vector register holds a signed packed-decimal number of 31 digits and a sign code in its
rightmost 4 bits. The arithmetic converts the digits to a binary magnitude, computes exactly
(32-byte integers), and stores the rightmost RDC result digits with the preferred sign (C, D, or
F when P1 forces a positive sign); a result whose digits do not fit is a decimal overflow
(cc 3 when CS is one). Sign codes A, C, E, F are plus, B and D minus. Semantics follow the
Principles of Operation as implemented by the Hercules emulator (zvector2.c), with Hercules
index slips in leading-zero counting, byte-padding testing and 128-bit overflow detection
corrected. Data exceptions (invalid digits or signs) and decimal/fixed-point overflow
interruptions are not modelled.
"""
from gen_vector import Block, uid

def lbl(blk, n):
    return f"{n}{blk.tag}_{uid()}"

# ---- packed-decimal vectors ----------------------------------------------------------------
def nib(v, n):
    """expression: nibble n (0 leftmost digit ... 30 rightmost digit, 31 sign) of 16-byte v"""
    return f"(({v} >> (4 * (31 - {n}))) & 0xf)"

def sign_of(blk, v):
    return blk.local(1, f"{v}:1 & 0xf")

def minus(s):
    return f"(({s} == 0xb) || ({s} == 0xd))"

def plus(s):
    return f"(({s} == 0xa) || ({s} == 0xc) || ({s} >= 0xe))"

def to_bin(blk, v, size=32):
    """binary magnitude of the 31 digits of v"""
    m = blk.local(size, "zext(0:8)")
    k = blk.local(8, "0")
    t = blk.local(16, v)
    l = lbl(blk, "pb")
    blk.add(f"<{l}> {m} = {m} * 10 + zext(({t} >> (124 - {k} * 4)) & 0xf); {k} = {k} + 1; if ({k} < 31) goto <{l}>;")
    return m

def signed_in(blk, v, force):
    """(magnitude, negative) of packed v; force: P bit expression (sign treated as plus)"""
    m = to_bin(blk, v)
    s = sign_of(blk, v)
    neg = blk.local(1, f"{minus(s)} && !({force})")
    return m, neg

def to_digits(blk, m, rdc, size=32):
    """(16-byte packed digits without sign, overflow) of the rightmost rdc digits of m"""
    out = blk.local(16, "zext(0:8)")
    r = blk.local(size, m)
    k = blk.local(8, "0")
    d = blk.local(size, "zext(0:8)")
    l = lbl(blk, "pd")
    blk.add(f"if ({k} >= {rdc}) goto <{l}e>;\n"
            f"<{l}> {d} = {r} % 10; {r} = {r} / 10; {k} = {k} + 1; {out} = {out} | (zext({d}:1) << ({k} * 4));\n"
            f"if (({k} < {rdc}) && ({r} != 0)) goto <{l}>;\n<{l}e>")
    ov = blk.local(1, f"{r} != 0")
    blk.add(f"{ov} = {r} != 0;")
    return out, ov

def store_result(blk, dst, m, neg, p1, rdc, cs, size=32):
    """v1 = rightmost rdc digits of the signed value (m, neg); the minus-zero result gets a plus
    sign; cc (when cs): 0 zero result, 1 minus, 2 plus, 3 overflow."""
    out, ov = to_digits(blk, m, rdc, size)
    z = blk.local(1, f"{out} == 0")
    sg = blk.local(1, f"zext({p1}) * 0xf + zext(!{p1}) * (0xc + zext({neg} && !{z}))")
    blk.add(f"{dst} = {out} | zext({sg});")
    l = lbl(blk, "cs")
    blk.add(f"if (!{cs}) goto <{l}>; gs_cc_flags(!{ov} && ({m} == 0), !{ov} && ({m} != 0) && ({sg} == 0xd), "
            f"!{ov} && ({m} != 0) && ({sg} != 0xd), {ov});\n<{l}>")

def fields5(blk, m5):
    m = blk.local(1, f"{m5}:1")
    return (blk.local(1, f"({m} & 8) != 0"), blk.local(1, f"({m} & 4) != 0"),
            blk.local(1, f"({m} & 2) != 0"), blk.local(1, f"({m} & 1) != 0"))

def pow10(blk, n, size=32):
    v = blk.local(size, "zext(1:1)")
    k = blk.local(8, n)
    l = lbl(blk, "pw")
    blk.add(f"<{l}> if ({k} s<= 0) goto <{l}e>; {v} = {v} * 10; {k} = {k} - 1; goto <{l}>;\n<{l}e>")
    return v

def shift_round(blk, m, sh, drd):
    """m (32-byte magnitude) shifted by sh digits (signed 8-byte; left when positive), the
    last digit shifted out rounding half up when drd; returns the 32-byte result"""
    r = blk.local(32, m)
    l = lbl(blk, "sr")
    s2 = blk.local(8, sh)
    blk.add(f"if ({s2} s< 0) goto <{l}r>; if ({s2} s<= 32) goto <{l}m>; {s2} = 32;\n<{l}m>")
    pw = pow10(blk, s2)
    blk.add(f"{r} = {m} * {pw}; goto <{l}e>;\n"
            f"<{l}r>")
    k = blk.local(8, f"-{sh}")
    blk.add(f"if ({k} s> 40) goto <{l}z>;")
    pw2 = pow10(blk, k)
    blk.add(f"{r} = {m} / {pw2};\n"
            f"if (!{drd}) goto <{l}e>; {r} = ({m} / ({pw2} / 10) + 5) / 10; goto <{l}e>;\n"
            f"<{l}z> {r} = 0;\n<{l}e>")
    return r

def imm(blk, op, size):
    t = blk.local(8, op)
    return blk.local(size, f"{t}:{size}")


def hexdigits(blk, v, size):
    n = blk.local(8, "0")
    t = blk.local(size, v)
    l = lbl(blk, "hx")
    blk.add(f"<{l}> if ({t} == 0) goto <{l}e>; {t} = {t} >> 4; {n} = {n} + 1; goto <{l}>;\n<{l}e>")
    return n

def hfp_norm(blk, N, n, D, size):
    """fraction of D hex digits of N (n significant hex digits), left aligned"""
    f = blk.local(size, "zext(0:8)")
    l = lbl(blk, "hn")
    blk.add(f"if ({n} s> {D}) goto <{l}r>; {f} = {N} << (4 * ({D} - {n})); goto <{l}e>;\n<{l}r> {f} = {N} >> (4 * ({n} - {D}));\n<{l}e>")
    return f

def scale_to_hfp(blk, n, o):
    """VSCHP / VSCSHP: the packed decimal V2 times 10 ** (V3 byte 7 & 7) as HFP"""
    a, neg = signed_in(blk, o[1], "0:1")
    t3 = blk.local(16, f"{o[2]} >> 64")
    sc = blk.local(8, f"zext({t3}:1 & 7)")
    N = blk.local(16, f"{a}:16 * {pow10(blk, sc, 16)}")
    s = blk.local(16, f"zext({neg})")
    l = lbl(blk, "sh")
    r = blk.local(16, "zext(0:8)")
    blk.add(f"if ({N} == 0) goto <{l}e>;")
    nd = hexdigits(blk, N, 16)
    if n.startswith("vsch") and n != "vscshp":
        if n == "vschp":
            m4, m5 = imm(blk, o[3], 1), o[4]
        else:
            m4, m5 = blk.local(1, {"vschsp": "2", "vschdp": "3", "vschxp": "4"}[n]), o[3]
        rm = blk.local(1, f"({imm(blk, m5, 1)} & 1) != 0")
        D = blk.local(8, f"zext({m4} == 2) * 6 + zext({m4} == 3) * 14 + zext({m4} == 4) * 28")
        blk.add(f"if (!{rm} || ({nd} s<= {D})) goto <{l}nr>; {N} = {N} + (zext(8:1) << (4 * ({nd} - {D} - 1)));\n<{l}nr>")
        nd2 = hexdigits(blk, N, 16)
        f = hfp_norm(blk, N, nd2, D, 16)
        ch = blk.local(16, f"zext({nd2}:1 + 64)")
        blk.add(f"if ({m4} != 2) goto <{l}l>; {r} = ((({s} << 31) | ({ch} << 24) | {f}) << 96); goto <{l}e>;\n"
                f"<{l}l> if ({m4} != 3) goto <{l}x>; {r} = ((({s} << 63) | ({ch} << 56) | {f}) << 64); goto <{l}e>;\n"
                f"<{l}x> {r} = ((({s} << 63) | ({ch} << 56) | ({f} >> 56)) << 64) | ({s} << 63) | ((({ch} - 14) & 0x7f) << 56) | ({f} & 0xffffffffffffff);\n"
                f"<{l}e> {o[0]} = {r};")
        return
    f = hfp_norm(blk, N, nd, 6, 16)
    ch = blk.local(16, f"zext({nd}:1 + 64)")
    blk.add(f"{r} = (({s} << 31) | ({ch} << 24) | {f}) << 96; if ({nd} s<= 6) goto <{l}e>;")
    R = blk.local(16, f"{N} & ((zext(1:1) << (4 * ({nd} - 6))) - 1)")
    blk.add(f"if ({R} == 0) goto <{l}e>;")
    n2 = hexdigits(blk, R, 16)
    f2 = hfp_norm(blk, R, n2, 14, 16)
    blk.add(f"{r} = {r} | ({s} << 63) | (zext({n2}:1 + 64) << 56) | {f2};\n<{l}e> {o[0]} = {r};")

def hfp_to_scaled(blk, o):
    """VCSPH: extended HFP V2 times 10 ** (V3 byte 7 & 31), rounded to an integer"""
    x = blk.local(16, o[1])
    t3 = blk.local(16, f"{o[2]} >> 64")
    sc = blk.local(8, f"zext({t3}:1 & 0x1f)")
    rm = blk.local(1, f"({imm(blk, o[3], 1)} & 1) != 0")
    hi = blk.local(8, f"{x}(8)")
    F = blk.local(64, "zext(0:8)")
    blk.add(f"{F} = (zext(({hi} & 0xffffffffffffff) >> 8) << 64) | (zext({hi} & 0xff) << 56) | zext({x}:8 & 0xffffffffffffff);")
    k = blk.local(8, f"zext(({hi} >> 56) & 0x7f) - 92")
    N = blk.local(64, f"{F} * {pow10(blk, sc, 64)}")
    q = blk.local(64, N)
    l = lbl(blk, "cs")
    blk.add(f"if ({k} s< 0) goto <{l}r>; {q} = {N} << (4 * {k}); goto <{l}d>;\n"
            f"<{l}r> if ({k} s< -100) goto <{l}z>;")
    sh = blk.local(8, f"-4 * {k}")
    blk.add(f"{q} = {N} >> {sh}; if (!{rm}) goto <{l}d>;\n"
            f"if ((({N} >> ({sh} - 1)) & 1) == 0) goto <{l}d>; {q} = {q} + 1; goto <{l}d>;\n"
            f"<{l}z> {q} = 0;\n<{l}d>")
    out, ov = to_digits(blk, q, "31:8", 64)
    blk.add(f"{o[0]} = {out} | zext(0xc:1 + zext({hi} s< 0));\n"
            f"if ({x} != 0) goto <{l}x>; {o[0]} = zext(0xc:1);\n<{l}x>")

# ---- instructions -----------------------------------------------------------------------------
ARITH = {"vap", "vsp", "vmp", "vmsp", "vdp", "vrp", "vsdp"}
NAMES = ARITH | set("""vsrp vsrpr vcp vcvd vcvdg vcvdq vcvb vcvbg vcvbq vlip vpkz vupkz vupkzh vupkzl vpkzr
vclzdp vpsop vtp vtz vschp vschsp vschdp vschxp vscshp vcsph""".split())

def semantics(ctx):
    n, o = ctx["name"], ctx["ops"]
    blk = Block()
    if n in ARITH:
        i4 = imm(blk, o[3], 1)
        p2, p3, p1, cs = fields5(blk, o[4])
        a, an = signed_in(blk, o[1], p2)
        b, bn = signed_in(blk, o[2], p3)
        rdc = blk.local(8, f"zext({i4} & 0x1f)")
        r = blk.local(32, "zext(0:8)")
        neg = blk.local(1, "0")
        if n in ("vap", "vsp"):
            bs = f"({bn} != {1 if n == 'vsp' else 0})"
            l = lbl(blk, "ad")
            blk.add(f"if ({an} != {bs}) goto <{l}d>; {r} = {a} + {b}; {neg} = {an}; goto <{l}e>;\n"
                    f"<{l}d> if ({a} < {b}) goto <{l}l>; {r} = {a} - {b}; {neg} = {an}; goto <{l}e>;\n"
                    f"<{l}l> {r} = {b} - {a}; {neg} = {bs};\n<{l}e>")
        elif n in ("vmp", "vmsp"):
            blk.add(f"{r} = {a} * {b}; {neg} = {an} != {bn};")
            if n == "vmsp":
                sh = blk.local(8, f"-zext({i4} & 0x1f)")
                blk.add(f"{r} = {shift_round(blk, r, sh, '0:1')}; {rdc} = 31;")
        elif n in ("vdp", "vrp", "vsdp"):
            num = a
            if n == "vsdp":
                num = blk.local(32, f"{a} * {pow10(blk, f'zext({i4} & 0x1f)')}")
                blk.add(f"{rdc} = 31;")
            l = lbl(blk, "dv")
            blk.add(f"if ({b} == 0) goto <{l}>;")
            if n == "vrp":
                blk.add(f"{r} = {num} % {b}; {neg} = {an};")
            else:
                blk.add(f"{r} = {num} / {b}; {neg} = {an} != {bn};")
            blk.add(f"<{l}>")
        store_result(blk, o[0], r, neg, p1, rdc, cs)
        return blk.text()
    if n in ("vsrp", "vsrpr"):
        if n == "vsrp":
            i3, i4 = imm(blk, o[2], 1), imm(blk, o[3], 1)
            m5 = o[4]
            rdc = blk.local(8, f"zext({i3} & 0x1f)")
            drd = blk.local(1, f"({i4} & 0x80) != 0")
            sh = blk.local(8, f"zext({i4} & 0x7f) - zext(({i4} & 0x7f) > 0x4f) * 0x80")
        else:
            i4 = imm(blk, o[3], 1)
            m5 = o[4]
            rdc = blk.local(8, f"zext({i4} & 0x1f)")
            drd = blk.local(1, f"({i4} & 0x40) != 0")
            t3 = blk.local(16, f"{o[2]} >> 64")
            sh = blk.local(8, f"sext({t3}:1)")
            l = lbl(blk, "cl")
            blk.add(f"if ({sh} s>= -32) goto <{l}a>; {sh} = -32;\n<{l}a> if ({sh} s<= 31) goto <{l}b>; {sh} = 31;\n<{l}b>")
        p2, _, p1, cs = fields5(blk, m5)
        a, an = signed_in(blk, o[1], p2)
        r = shift_round(blk, a, sh, drd)
        store_result(blk, o[0], r, an, p1, rdc, cs)
        return blk.text()
    if n == "vcp":
        m3 = imm(blk, o[2], 1)
        a, an = signed_in(blk, o[0], f"({m3} & 8) != 0")
        b, bn = signed_in(blk, o[1], f"({m3} & 4) != 0")
        sa = blk.local(1, f"{an} && ({a} != 0)")
        sb = blk.local(1, f"{bn} && ({b} != 0)")
        eq = blk.local(1, f"({a} == {b}) && ({sa} == {sb})")
        lt = blk.local(1, f"!{eq} && (({sa} && !{sb}) || ({sa} && {sb} && ({a} > {b})) || (!{sa} && !{sb} && ({a} < {b})))")
        blk.add(f"gs_cc_flags({eq}, {lt}, !{eq} && !{lt}, 0:1);")
        return blk.text()
    if n in ("vcvd", "vcvdg", "vcvdq"):
        i3 = imm(blk, o[2], 1)
        m4 = imm(blk, o[3], 1)
        lb, p1, cs = (blk.local(1, f"({m4} & {b}) != 0") for b in (8, 2, 1))
        rdc = blk.local(8, f"zext({i3} & 0x1f)")
        src = {"vcvd": f"sext({o[1]}:4)", "vcvdg": f"sext({o[1]})", "vcvdq": f"sext({o[1]})"}[n]
        usrc = {"vcvd": f"zext({o[1]}:4)", "vcvdg": f"zext({o[1]})", "vcvdq": f"zext({o[1]})"}[n]
        s = blk.local(32, src)
        neg = blk.local(1, f"!{lb} && ({s} s< 0)")
        m = blk.local(32, f"zext({lb}) * {usrc} + zext(!{lb}) * (zext({neg}) * -{s} + zext(!{neg}) * {s})")
        out, ov = to_digits(blk, m, rdc)
        sg = blk.local(1, f"zext({p1}) * 0xf + zext(!{p1}) * (0xc + zext({neg}))")
        blk.add(f"{o[0]} = {out} | zext({sg});")
        l = lbl(blk, "cs")
        blk.add(f"if (!{cs}) goto <{l}>; gs_cc_flags(!{ov}, 0:1, 0:1, {ov});\n<{l}>")
        return blk.text()
    if n in ("vcvb", "vcvbg", "vcvbq"):
        m3 = imm(blk, o[2], 1)
        p2, lb, cs = (blk.local(1, f"({m3} & {b}) != 0") for b in (8, 2, 1))
        a, an = signed_in(blk, o[1], f"{p2} || {lb}")
        v = blk.local(32, f"zext({an}) * -{a} + zext(!{an}) * {a}")
        if n == "vcvbq":
            blk.add(f"{o[0]} = {v}:16;")
            return blk.text()
        bits = 32 if n == "vcvb" else 64
        m4 = imm(blk, o[3], 1)
        orc = blk.local(1, f"({m4} & 4) != 0")
        lim = blk.local(32, f"zext({(1 << (bits - 1)) - 1}:8) + zext({an}) + zext({lb}) * zext({1 << (bits - 1)}:8)")
        ov = blk.local(1, f"{a} > {lim}")
        r = blk.local(8, f"zext(!({orc} && {ov})) * {v}:8")
        if bits == 32:
            blk.add(f"{o[0]} = ({o[0]} & 0xffffffff00000000) | ({r} & 0xffffffff);")
        else:
            blk.add(f"{o[0]} = {r};")
        l = lbl(blk, "cs")
        blk.add(f"if (!{cs}) goto <{l}>; gs_cc_flags(!{ov}, 0:1, 0:1, {ov});\n<{l}>")
        return blk.text()
    if n == "vlip":
        i3 = imm(blk, o[2], 1)
        sh = blk.local(1, f"(({i3} & 7) + 1) * 4")
        i2 = blk.local(8, o[1])
        blk.add(f"{o[0]} = (zext({i2}:2) << {sh}) | zext(0xc:1 + zext(({i3} & 8) != 0));")
        return blk.text()
    if n in ("vpkz", "vupkz"):
        v, ad = o[0], o[1]
        lf = blk.local(8, o[2])
        L = blk.local(8, f"{lf} & 0x1f")
        k = blk.local(8, "0")
        l = lbl(blk, "pz")
        if n == "vpkz":
            r = blk.local(16, "zext(0:8)")
            last = blk.local(1, f"*:1 ({ad} + {L})")
            blk.add(f"<{l}> {r} = {r} | (zext(*:1 ({ad} + {L} - {k}) & 0xf) << (4 + 4 * {k})); {k} = {k} + 1; if ({k} <= {L}) goto <{l}>;\n"
                    f"{v} = {r} | zext({last} >> 4);")
        else:
            t = blk.local(16, v)
            u = blk.local(16, "zext(0:8)")
            blk.add(f"*:1 ({ad} + {L}) = ({t}:1 << 4) | ({t}:1 >> 4); {k} = 1;\n"
                    f"<{l}> if ({k} > {L}) goto <{l}e>; {u} = {t} >> (4 + 4 * {k}); *:1 ({ad} + {L} - {k}) = 0xf0 | ({u}:1 & 0xf); {k} = {k} + 1; goto <{l}>;\n<{l}e>")
        return blk.text()
    if n in ("vupkzh", "vupkzl"):
        t = blk.local(16, o[1])
        r = blk.local(16, "zext(0:8)")
        k = blk.local(8, "0")
        base = -1 if n == "vupkzh" else 15
        l = lbl(blk, "uz")
        u = blk.local(16, "zext(0:8)")
        blk.add(f"<{l}> {u} = {t} >> (4 * (31 - ({k} + {base}))); {r} = {r} | (zext(0xf0:1 | ({u}:1 & 0xf)) << (8 * (15 - {k}))); "
                f"{k} = {k} + 1; if ({k} < 16) goto <{l}>;")
        if n == "vupkzl":
            m3 = imm(blk, o[2], 1)
            zs = blk.local(1, f"zext(({m3} & 2) != 0) * 0xf + zext(({m3} & 2) == 0) * ({t}:1 & 0xf)")
            blk.add(f"{r} = ({r} & ~zext(0xf0:1)) | zext({zs} << 4);")
        blk.add(f"{o[0]} = {r};")
        return blk.text()
    if n == "vpkzr":
        i4 = imm(blk, o[3], 1)
        _, _, p1, cs = fields5(blk, o[4])
        rdc = blk.local(8, f"zext({i4} & 0x1f)")
        z2, z3 = blk.local(16, o[1]), blk.local(16, o[2])
        r = blk.local(16, "zext(0:8)")
        k = blk.local(8, "0")
        bad, nz, hi = blk.local(1, "0"), blk.local(1, "0"), blk.local(1, "0")
        zb = blk.local(1, "0")
        l = lbl(blk, "pr")
        # zoned byte k (0 rightmost ... 31 leftmost) of v2:v3
        ua, ub = blk.local(16, "zext(0:8)"), blk.local(16, "zext(0:8)")
        blk.add(f"<{l}> {ua} = {z3} >> (8 * {k}); {ub} = {z2} >> (8 * ({k} - 16)); {zb} = zext({k} < 16) * {ua}:1 + zext({k} >= 16) * {ub}:1;\n"
                f"{bad} = {bad} || (({zb} & 0xf) > 9); {nz} = {nz} || (({zb} & 0xf) != 0);\n"
                f"if ({k} >= {rdc}) goto <{l}h>; {r} = {r} | (zext({zb} & 0xf) << (4 + 4 * {k})); goto <{l}n>;\n"
                f"<{l}h> {hi} = {hi} || (({zb} & 0xf) != 0);\n"
                f"<{l}n> {k} = {k} + 1; if ({k} < 32) goto <{l}>;")
        zs = blk.local(1, f"{z3}:1 >> 4")
        ps = blk.local(1, f"zext({p1}) * 0xf + zext(!{p1}) * {zs}")
        blk.add(f"{o[0]} = {r} | zext({ps});")
        c3 = blk.local(1, f"{hi} || {bad} || ({zs} <= 9)")
        l2 = lbl(blk, "cs")
        blk.add(f"if (!{cs}) goto <{l2}>; gs_cc_flags(!{c3} && !{nz}, !{c3} && {nz} && !{plus(ps)}, !{c3} && {nz} && {plus(ps)}, {c3});\n<{l2}>")
        return blk.text()
    if n == "vclzdp":
        t = blk.local(16, o[1])
        m3 = imm(blk, o[2], 1)
        nzf, cs = blk.local(1, f"({m3} & 2) != 0"), blk.local(1, f"({m3} & 1) != 0")
        c = blk.local(8, "0")
        bad = blk.local(1, "0")
        k = blk.local(8, "0")
        l = lbl(blk, "lz")
        blk.add(f"<{l}> if (({k} == 31) || ({nib(t, k)} != 0)) goto <{l}e>; {c} = {c} + 1; {k} = {k} + 1; goto <{l}>;\n<{l}e>\n"
                f"{k} = 0;\n<{l}v> {bad} = {bad} || ({nib(t, k)} > 9); {k} = {k} + 1; if ({k} < 31) goto <{l}v>;")
        s = sign_of(blk, t)
        valid = blk.local(1, f"!{bad} && ({s} > 9)")
        neg, zero = blk.local(1, minus(s)), blk.local(1, f"({t} >> 4) == 0")
        c0 = blk.local(1, f"{valid} && {zero} && !({nzf} && {neg})")
        c1 = blk.local(1, f"!{c0} && (({valid} && {neg}) || ({nzf} && {neg} && {zero}))")
        c2 = blk.local(1, f"!{c0} && !{c1} && {valid} && !{zero} && !{neg}")
        blk.add(f"{o[0]} = zext({c}:1) << 64;")
        l2 = lbl(blk, "cs")
        blk.add(f"if (!{cs}) goto <{l2}>; gs_cc_flags({c0}, {c1}, {c2}, !{c0} && !{c1} && !{c2});\n<{l2}>")
        return blk.text()
    if n == "vpsop":
        i3, i4 = imm(blk, o[2], 1), imm(blk, o[3], 1)
        _, _, _, cs = fields5(blk, o[4])
        rdc = blk.local(8, f"zext({i3} & 0x1f)")
        nzf, ps, pc = (blk.local(1, f"({i4} & {b}) != 0") for b in (0x40, 0x10, 2))
        so = blk.local(1, f"({i4} >> 2) & 3")
        t = blk.local(16, o[1])
        msk = blk.local(16, f"(zext(1:1) << (4 * {rdc} + 4)) - 16")
        d = blk.local(16, f"{t} & {msk}")
        lzc = blk.local(8, "0")
        l = lbl(blk, "ps")
        blk.add(f"<{l}l> if (({lzc} == 31) || ({nib(t, lzc)} != 0)) goto <{l}le>; {lzc} = {lzc} + 1; goto <{l}l>;\n<{l}le>")
        ov = blk.local(1, f"{lzc} < (31 - {rdc})")
        s = sign_of(blk, t)
        pl, mi = blk.local(1, plus(s)), blk.local(1, minus(s))
        z = blk.local(1, f"{d} == 0")
        P, C, D = blk.local(1, f"0xc + zext({pc}) * 3"), "0xc", "0xd"
        ns = blk.local(1, s)
        cc = blk.local(1, "0")
        # so 0 maintain, 1 complement, 2 force positive, 3 force negative
        blk.add(f"if ({so} != 0) goto <{l}1>;\n"
                f"if (!{ps}) goto <{l}0n>; {cc} = zext(!{z}) * (2 - zext({mi})); goto <{l}e>;\n"
                f"<{l}0n> if ({z}) goto <{l}0z>; {cc} = 2 - zext({mi}); if ({pl}) goto <{l}sp>; if ({mi}) goto <{l}sd>; goto <{l}e>;\n"
                f"<{l}0z> {cc} = 0; if ({pl}) goto <{l}sp>; if (!{mi}) goto <{l}e>; if ({nzf}) goto <{l}sd>; goto <{l}sp>;\n"
                f"<{l}1> if ({so} != 1) goto <{l}2>; if (!{pl} && !{mi}) goto <{l}e>;\n"
                f"if ({z}) goto <{l}1z>; {cc} = 1 + zext({mi}); if ({pl}) goto <{l}sd>; goto <{l}sp>;\n"
                f"<{l}1z> {cc} = 0; if ({pl} && {nzf}) goto <{l}sd>; goto <{l}sp>;\n"
                f"<{l}2> if ({so} != 2) goto <{l}3>; {cc} = zext(!{z}) * 2; goto <{l}sp>;\n"
                f"<{l}3> {cc} = zext(!{z}); if (!{z} || {nzf}) goto <{l}sd>; goto <{l}sp>;\n"
                f"<{l}sp> {ns} = {P}; goto <{l}e>;\n"
                f"<{l}sd> {ns} = {D};\n<{l}e>")
        blk.add(f"{o[0]} = {d} | zext({ns});")
        blk.add(f"{cc} = zext(!{z}) * {cc}; if (!{ov}) goto <{l}c>; {cc} = 3;\n<{l}c>")
        l2 = lbl(blk, "cs")
        blk.add(f"if (!{cs}) goto <{l2}>; gs_cc_flags({cc} == 0, {cc} == 1, {cc} == 2, {cc} == 3);\n<{l2}>")
        return blk.text()
    if n == "vtp":
        t = blk.local(16, o[0])
        i2 = imm(blk, o[1], 2)
        et, bpt = blk.local(1, f"({i2} & 0x8000) != 0"), blk.local(1, f"({i2} & 0x4000) != 0")
        st2 = blk.local(2, f"({i2} >> 5) & 7")
        stc = blk.local(1, f"{st2}:1 * {et}")
        dc = blk.local(8, f"zext({i2} & 0x1f)")
        first = blk.local(8, f"zext({et}) * (31 - {dc})")
        bad, allz = blk.local(1, "0"), blk.local(1, "1")
        k = blk.local(8, first)
        l = lbl(blk, "tp")
        blk.add(f"<{l}> if ({k} >= 31) goto <{l}e>; {bad} = {bad} || ({nib(t, k)} > 9); {allz} = {allz} && ({nib(t, k)} == 0); "
                f"{k} = {k} + 1; goto <{l}>;\n<{l}e>\n"
                f"if (!({et} && {bpt} && (({dc} & 1) == 0) && ({dc} != 0))) goto <{l}p>; {bad} = {bad} || ({nib(t, f'(30 - {dc})')} != 0);\n<{l}p>\n"
                f"{allz} = {allz} && ({dc} != 0);")
        s = sign_of(blk, t)
        valid = blk.local(1, f"(({stc} == 0) && ({s} >= 0xa)) || (({stc} == 1) && ((!{allz} && ({s} >= 0xa)) || ({allz} && {plus(s)}))) || "
                             f"(({stc} == 2) && (({s} == 0xc) || ({s} == 0xd))) || "
                             f"(({stc} == 3) && (({s} == 0xc) || (!{allz} && ({s} == 0xd)))) || "
                             f"((({stc} == 4) || ({stc} == 5)) && ({s} == 0xf)) || "
                             f"(({stc} == 6) && (({s} == 0xc) || ({s} == 0xd) || ({s} == 0xf))) || "
                             f"(({stc} == 7) && (({s} == 0xc) || ({s} == 0xf) || (!{allz} && ({s} == 0xd))))")
        blk.add(f"gs_cc_flags(!{bad} && {valid}, !{bad} && !{valid}, {bad} && {valid}, {bad} && !{valid});")
        return blk.text()
    if n.startswith("vsch") or n == "vscshp":
        scale_to_hfp(blk, n, o)
        return blk.text()
    if n == "vcsph":
        hfp_to_scaled(blk, o)
        return blk.text()
    if n == "vtz":
        hi, lo = blk.local(16, o[0]), blk.local(16, o[1])
        i3 = imm(blk, o[2], 2)
        ssc, ls = blk.local(1, f"({i3} & 0x4000) != 0"), blk.local(1, f"({i3} & 0x2000) != 0")
        dsc = blk.local(8, f"zext(({i3} >> 8) & 0x1f)")
        st8 = blk.local(2, f"{i3} >> 5")
        stc = blk.local(1, f"{st8}:1 & 7")
        dc = blk.local(8, f"zext({i3} & 0x1f)")
        ua, ub = blk.local(16, "zext(0:8)"), blk.local(16, "zext(0:8)")
        def zb(k, dst):      # dst = byte 31 - k of the 32-byte source (k = 0: rightmost)
            return (f"{ua} = {lo} >> (8 * {k}); {ub} = {hi} >> (8 * ({k} - 16)); {dst} = zext({k} < 16) * {ua}:1 + zext({k} >= 16) * {ub}:1")
        sb = blk.local(1, "0")
        bad, z = blk.local(1, "0"), blk.local(1, "1")
        k = blk.local(8, "0")
        lim = blk.local(8, "0")
        b = blk.local(1, "0")
        l = lbl(blk, "tz")
        # sign byte position: rightmost, or left of the dc digits (leading sign)
        blk.add(f"{k} = zext({ls}) * {dc}; {zb(k, sb)};\n"
                f"if ({ssc}) goto <{l}ss>; {z} = ({sb} & 0xf) == 0; {bad} = ({sb} & 0xf) > 9;\n<{l}ss>\n"
                # digit bytes: ETS/SETS/STS from 1, ELS 0..dc-2, SLS 0..dc-1
                f"{k} = zext(!{ls}); {lim} = {dc} - zext({ls} && !{ssc});\n"
                f"<{l}> if ({k} >= {lim}) goto <{l}e>; {zb(k, b)};\n"
                f"if (!{ssc} && !{ls} && ({k} >= {dsc}) && ({b} == 0x40)) goto <{l}sp>;\n"
                f"{bad} = {bad} || ({b} < 0xf0) || ({b} > 0xf9); {z} = {z} && ({b} == 0xf0); goto <{l}n>;\n"
                f"<{l}sp> {z} = 0;\n"
                f"<{l}n> {k} = {k} + 1; goto <{l}>;\n<{l}e>")
        s = blk.local(1, f"{sb} >> 4")
        sd = blk.local(1, f"(({stc} == 0) && ({s} >= 0xa)) || (({stc} == 1) && ((!{z} && ({s} >= 0xa)) || ({z} && {plus(s)}))) || "
                          f"(({stc} == 2) && (({s} == 0xc) || ({s} == 0xd))) || "
                          f"(({stc} == 3) && (({s} == 0xc) || (!{z} && ({s} == 0xd)))) || "
                          f"((({stc} == 4) || ({stc} == 5)) && ({s} == 0xf)) || "
                          f"(({stc} == 6) && (({s} == 0xc) || ({s} == 0xd) || ({s} == 0xf))) || "
                          f"(({stc} == 7) && (({s} == 0xc) || ({s} == 0xf) || (!{z} && ({s} == 0xd))))")
        ss = blk.local(1, f"(({stc} != 2) && ({stc} != 3)) || ({sb} == 0x4e) || (({sb} == 0x60) && !(({stc} == 3) && {z}))")
        valid = blk.local(1, f"(!{ssc} && {sd}) || ({ssc} && {ss})")
        blk.add(f"gs_cc_flags(!{bad} && {valid}, !{bad} && !{valid}, {bad} && {valid}, {bad} && !{valid});")
        return blk.text()
    return None
