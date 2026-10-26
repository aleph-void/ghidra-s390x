"""P-code for the hexadecimal-floating-point (HFP) instructions (used by gen_semantics.py).

Upstream modelled HFP with IEEE float operators on the HFP bit patterns, which gives wrong
values for every operand. Here every operation works on the sign, the 7-bit characteristic and
the fraction as an integer, following the Principles of Operation (chapter 18) as implemented
by the Hercules emulator (float.c), which serves as the reference: one guard digit in addition
and comparison, prenormalized multiplication and division, truncated results, LOAD ROUNDED
adding one at the first discarded bit, square root rounded at a guard digit, exponent overflow
wrapping the characteristic, and exponent underflow / significance results that depend on the
PSW program-mask bits (EU: PSW bit 22, SG: bit 23). The program interruptions themselves are
not raised.
"""
import re
from gen_vector import Block, uid

D = {"e": 6, "d": 14, "x": 28}          # fraction digits per format
F56 = 0x00FFFFFFFFFFFFFF

def c16(v):
    hi, lo = v >> 64, v & ((1 << 64) - 1)
    return f"((zext({hi:#x}:8) << 64) | zext({lo:#x}:8))" if hi else f"zext({lo:#x}:8)"

def c32(v):
    parts = [(v >> (64 * k)) & ((1 << 64) - 1) for k in range(4)]
    return "(" + " | ".join(f"(zext({p:#x}:8) << {64 * k})" for k, p in enumerate(parts) if p) + ")" if v else "zext(0:16)"

class H:
    """An HFP value being computed: sign s (1), characteristic e (8, signed), fraction f (16)."""
    def __init__(self, blk, fmt):
        self.blk, self.fmt, self.W = blk, fmt, 4 * D[fmt]
        self.s = blk.local(1, "0")
        self.e = blk.local(8, "0")
        self.f = blk.local(16, "zext(0:8)")

def lbl(blk, name):
    return f"{name}{blk.tag}_{uid()}"

# ---- operand access ---------------------------------------------------------------------------
def read_bits(blk, fmt, op, kind, pair):
    """The operand's raw bits: short 4 bytes, long 8, extended 16 (high doubleword first)."""
    if kind == "addr":
        n = {"e": 4, "d": 8, "x": 16}[fmt]
        return blk.local(n, f"*:{n} {op}")
    if fmt == "e":
        return blk.local(4, f"{op}(4)")
    if fmt == "d":
        return blk.local(8, op)
    return blk.local(16, f"(zext({op}) << 64) | zext({pair})")

def unpack(blk, fmt, bits):
    h = H(blk, fmt)
    if fmt == "e":
        t = blk.local(4, f"{bits} >> 31")
        blk.add(f"{h.s} = {t}:1; {h.e} = zext(({bits} >> 24) & 0x7f); {h.f} = zext({bits} & 0xffffff);")
    elif fmt == "d":
        t = blk.local(8, f"{bits} >> 63")
        blk.add(f"{h.s} = {t}:1; {h.e} = ({bits} >> 56) & 0x7f; {h.f} = zext({bits} & {F56:#x});")
    else:
        hi = blk.local(8, f"{bits}(8)")
        lo = blk.local(8, f"{bits}:8")
        t = blk.local(8, f"{hi} >> 63")
        blk.add(f"{h.s} = {t}:1; {h.e} = ({hi} >> 56) & 0x7f; "
                f"{h.f} = (zext({hi} & {F56:#x}) << 56) | zext({lo} & {F56:#x});")
    return h

def pack(blk, h):
    """Bits of h (characteristic taken mod 128 by the caller's overflow/underflow handling)."""
    if h.fmt == "e":
        return blk.local(4, f"(zext({h.s}) << 31) | ({h.e}:4 << 24) | {h.f}:4")
    if h.fmt == "d":
        return blk.local(8, f"(zext({h.s}) << 63) | ({h.e} << 56) | {h.f}:8")
    fh = blk.local(16, f"{h.f} >> 56")
    hi = blk.local(8, f"(zext({h.s}) << 63) | ({h.e} << 56) | {fh}:8")
    lo = blk.local(8, f"(zext({h.s}) << 63) | ({h.f}:8 & {F56:#x})")
    blk.add(f"if (({hi} == 0) && ({lo} == 0)) goto <{(l := lbl(blk, 'pz'))}>; {lo} = {lo} | ((({h.e} - 14) & 0x7f) << 56);\n<{l}>")
    return blk.local(16, f"(zext({hi}) << 64) | zext({lo})")

def write_bits(blk, fmt, op, pair, bits):
    if fmt == "e":
        blk.add(f"{op} = ({op} & 0xffffffff) | (zext({bits}) << 32);")
    elif fmt == "d":
        blk.add(f"{op} = {bits};")
    else:
        blk.add(f"{op} = {bits}(8); {pair} = {bits}:8;")

def store(blk, h, op, pair):
    write_bits(blk, h.fmt, op, pair, pack(blk, h))

def cc_frac(blk, h):
    blk.add(f"gs_cc_flags({h.f} == 0, ({h.f} != 0) && ({h.s} != 0), ({h.f} != 0) && ({h.s} == 0), 0:1);")

# ---- common steps -----------------------------------------------------------------------------
def normalize(blk, h):
    """Shift out leading zero digits (true zero for a zero fraction)."""
    l = lbl(blk, "nz")
    blk.add(f"if ({h.f} != 0) goto <{l}>; {h.s} = 0; {h.e} = 0; goto <{l}e>;\n<{l}>")
    lz = blk.local(8, f"lzcount({h.f})")
    n = blk.local(8, f"({lz} - {128 - h.W}) >> 2")
    blk.add(f"{h.f} = {h.f} << ({n} * 4); {h.e} = {h.e} - {n};\n<{l}e>")

def underflow(blk, h):
    eu = blk.local(1, "(pswm & (1 << 41)) != 0")
    l = lbl(blk, "uf")
    blk.add(f"if ({h.e} s>= 0) goto <{l}>; if (!{eu}) goto <{l}z>; {h.e} = {h.e} & 0x7f; goto <{l}>;\n"
            f"<{l}z> {h.s} = 0; {h.e} = 0; {h.f} = zext(0:8);\n<{l}>")

def overflow(blk, h):
    blk.add(f"{h.e} = zext({h.e} s> 127) * ({h.e} & 0x7f) + zext({h.e} s<= 127) * {h.e};")

def over_under(blk, h):
    overflow(blk, h)
    underflow(blk, h)

def significance(blk, h, sigex):
    """Zero fraction from an addition: plus sign; characteristic kept only with SG on."""
    blk.add(f"{h.s} = 0;")
    if sigex:
        sg = blk.local(1, "(pswm & (1 << 40)) != 0")
        blk.add(f"{h.e} = zext({sg}) * {h.e};")
    else:
        blk.add(f"{h.e} = 0;")

# ---- add / subtract / compare ---------------------------------------------------------------
def add(blk, a, b, normal=True, sigex=True):
    """a = a + b (Hercules add_sf/add_lf/add_ef)."""
    W, Dg = a.W, D[a.fmt]
    done = lbl(blk, "ad")
    sig, tail = done + "s", done + "t"
    blk.add(f"if (({b.f} != 0) || ({b.e} != 0)) goto <{done}b>;\n"
            f"if ({a.f} == 0) goto <{sig}>; goto <{tail}>;\n<{done}b>")
    blk.add(f"if (({a.f} != 0) || ({a.e} != 0)) goto <{done}c>;\n"
            f"{a.s} = {b.s}; {a.e} = {b.e}; {a.f} = {b.f};\n"
            f"if ({a.f} == 0) goto <{sig}>; goto <{tail}>;\n<{done}c>")
    sh = blk.local(8, "0")
    blk.add(f"if ({a.e} != {b.e}) goto <{done}ne>; {a.f} = {a.f} << 4; {b.f} = {b.f} << 4; goto <{done}sum>;\n<{done}ne>")
    blk.add(f"if ({a.e} s> {b.e}) goto <{done}gt>;\n"
            f"{sh} = {b.e} - {a.e} - 1; {a.e} = {b.e};\n"
            f"if ({sh} == 0) goto <{done}g1>;\n"
            f"{a.f} = zext({sh} < {Dg}) * ({a.f} >> ({sh} * 4));\n"
            f"if ({a.f} != 0) goto <{done}g1>;\n"
            f"{a.s} = {b.s}; {a.f} = {b.f}; if ({a.f} == 0) goto <{sig}>; goto <{tail}>;\n"
            f"<{done}g1> {b.f} = {b.f} << 4; goto <{done}sum>;\n"
            f"<{done}gt>\n"
            f"{sh} = {a.e} - {b.e} - 1;\n"
            f"if ({sh} == 0) goto <{done}g2>;\n"
            f"{b.f} = zext({sh} < {Dg}) * ({b.f} >> ({sh} * 4));\n"
            f"if ({b.f} != 0) goto <{done}g2>;\n"
            f"if ({a.f} == 0) goto <{sig}>; goto <{tail}>;\n"
            f"<{done}g2> {a.f} = {a.f} << 4;\n"
            f"<{done}sum>")
    blk.add(f"if ({a.s} != {b.s}) goto <{done}df>; {a.f} = {a.f} + {b.f}; goto <{done}ck>;\n"
            f"<{done}df>\n"
            f"if ({a.f} == {b.f}) goto <{done}z>;\n"
            f"if ({a.f} > {b.f}) goto <{done}sb>; {a.f} = {b.f} - {a.f}; {a.s} = {b.s}; goto <{done}ck>;\n"
            f"<{done}sb> {a.f} = {a.f} - {b.f}; goto <{done}ck>;\n"
            f"<{done}z> {a.f} = zext(0:8); goto <{sig}>;\n"
            f"<{done}ck>")
    ov = blk.local(16, f"{a.f} >> {W + 4}")
    blk.add(f"if ({ov} == 0) goto <{done}no>; {a.f} = {a.f} >> 8; {a.e} = {a.e} + 1;")
    overflow(blk, a)
    blk.add(f"goto <{done}>;\n<{done}no>")
    if normal:
        top = blk.local(16, f"{a.f} >> {W}")
        blk.add(f"if ({a.f} == 0) goto <{sig}>;\n"
                f"if ({top} == 0) goto <{done}n>; {a.f} = {a.f} >> 4; goto <{done}>;\n"
                f"<{done}n> {a.e} = {a.e} - 1;")
        normalize(blk, a)
        underflow(blk, a)
        blk.add(f"goto <{done}>;")
    else:
        blk.add(f"{a.f} = {a.f} >> 4; if ({a.f} == 0) goto <{sig}>; goto <{done}>;")
    blk.add(f"<{sig}>")
    significance(blk, a, sigex)
    blk.add(f"goto <{done}>;\n<{tail}>")
    if normal:
        normalize(blk, a)
        underflow(blk, a)
    blk.add(f"<{done}>")

def compare(blk, a, b):
    """cc from a - b with the guard digit (Hercules cmp_sf/cmp_lf/cmp_ef)."""
    W, Dg = a.W, D[a.fmt]
    done = lbl(blk, "cm")
    c0, c1, c2 = (blk.local(1, "0") for _ in range(3))
    def ccfrom(f, neg):
        return (f"{c0} = {f} == 0; {c1} = ({f} != 0) && {neg}; {c2} = ({f} != 0) && !{neg}; goto <{done}>;")
    blk.add(f"if (({b.f} != 0) || ({b.e} != 0)) goto <{done}b>; {ccfrom(a.f, f'({a.s} != 0)')}\n<{done}b>")
    blk.add(f"if (({a.f} != 0) || ({a.e} != 0)) goto <{done}c>; {ccfrom(b.f, f'({b.s} == 0)')}\n<{done}c>")
    sh = blk.local(8, "0")
    blk.add(f"if ({a.e} != {b.e}) goto <{done}ne>; {a.f} = {a.f} << 4; {b.f} = {b.f} << 4; goto <{done}sum>;\n<{done}ne>")
    blk.add(f"if ({a.e} s> {b.e}) goto <{done}gt>;\n"
            f"{sh} = {b.e} - {a.e} - 1;\n"
            f"if ({sh} == 0) goto <{done}g1>;\n"
            f"{a.f} = zext({sh} < {Dg}) * ({a.f} >> ({sh} * 4));\n"
            f"if ({a.f} != 0) goto <{done}g1>; {ccfrom(b.f, f'({b.s} == 0)')}\n"
            f"<{done}g1> {b.f} = {b.f} << 4; goto <{done}sum>;\n"
            f"<{done}gt>\n"
            f"{sh} = {a.e} - {b.e} - 1;\n"
            f"if ({sh} == 0) goto <{done}g2>;\n"
            f"{b.f} = zext({sh} < {Dg}) * ({b.f} >> ({sh} * 4));\n"
            f"if ({b.f} != 0) goto <{done}g2>; {ccfrom(a.f, f'({a.s} != 0)')}\n"
            f"<{done}g2> {a.f} = {a.f} << 4;\n"
            f"<{done}sum>")
    sg = blk.local(1, f"{a.s}")
    blk.add(f"if ({a.s} == {b.s}) goto <{done}eq>; {a.f} = {a.f} + {b.f}; goto <{done}r>;\n"
            f"<{done}eq> if ({a.f} < {b.f}) goto <{done}lt>; {a.f} = {a.f} - {b.f}; goto <{done}r>;\n"
            f"<{done}lt> {a.f} = {b.f} - {a.f}; {sg} = {b.s} == 0;\n"
            f"<{done}r> {ccfrom(a.f, f'({sg} != 0)')}\n<{done}>")
    blk.add(f"gs_cc_flags({c0}, {c1}, {c2}, 0:1);")

# ---- multiply / divide / halve / square root -------------------------------------------------
def multiply(blk, a, b, rfmt, ovunf=True):
    """Prenormalized product, truncated to the result format (Hercules mul_*)."""
    r = H(blk, rfmt)
    W1, R = a.W, 4 * D[rfmt]
    done = lbl(blk, "mu")
    blk.add(f"if (({a.f} == 0) || ({b.f} == 0)) goto <{done}>;")
    normalize(blk, a)
    normalize(blk, b)
    P = blk.local(32, f"zext({a.f}) * zext({b.f})")
    top = blk.local(32, f"{P} >> {2 * W1 - 4}")
    def sh(n):
        return f"({P} << {-n})" if n < 0 else f"({P} >> {n})"
    t1 = blk.local(32, sh(2 * W1 - R))
    t2 = blk.local(32, sh(2 * W1 - R - 4))
    blk.add(f"if ({top} == 0) goto <{done}lo>; {r.f} = {t1}:16; {r.e} = {a.e} + {b.e} - 64; goto <{done}sg>;\n"
            f"<{done}lo> {r.f} = {t2}:16; {r.e} = {a.e} + {b.e} - 65;\n"
            f"<{done}sg> {r.s} = {a.s} != {b.s};")
    if ovunf:
        over_under(blk, r)
    blk.add(f"<{done}>")
    return r

def divide(blk, a, b, store_fn):
    """Quotient truncated (Hercules div_*); a zero divisor leaves the first operand alone."""
    W = a.W
    done = lbl(blk, "dv")
    r = H(blk, a.fmt)
    blk.add(f"if ({b.f} == 0) goto <{done}x>; if ({a.f} == 0) goto <{done}s>;")
    normalize(blk, a)
    normalize(blk, b)
    wk = blk.local(32, "zext(0:8)")
    blk.add(f"if ({a.f} >= {b.f}) goto <{done}ge>; {wk} = zext({a.f}) << {W}; {r.e} = {a.e} - {b.e} + 64; goto <{done}d>;\n"
            f"<{done}ge> {wk} = zext({a.f}) << {W - 4}; {r.e} = {a.e} - {b.e} + 65;\n"
            f"<{done}d> {wk} = {wk} / zext({b.f}); {r.f} = {wk}:16; {r.s} = {a.s} != {b.s};")
    over_under(blk, r)
    blk.add(f"<{done}s>")
    store_fn(r)
    blk.add(f"<{done}x>")

def halve(blk, a):
    W = a.W
    done = lbl(blk, "hv")
    blk.add(f"if (({a.f} & {c16(0xE << (W - 4))}) == 0) goto <{done}n>; {a.f} = {a.f} >> 1; goto <{done}>;\n"
            f"<{done}n> {a.f} = {a.f} << 3; {a.e} = {a.e} - 1;")
    normalize(blk, a)
    underflow(blk, a)
    blk.add(f"<{done}>")

def isqrt(blk, x, size):
    """Integer square root (floor) of the size-byte value x, by bit-by-bit restoring."""
    r = blk.local(size, "0" if size <= 8 else f"zext(0:8)")
    rem = blk.local(size, x)
    bit = blk.local(size, f"zext(1:1) << {8 * size - 2}")
    l = lbl(blk, "sq")
    blk.add(f"<{l}a> if ({bit} <= {rem}) goto <{l}b>; {bit} = {bit} >> 2; goto <{l}a>;\n"
            f"<{l}b> if ({bit} == 0) goto <{l}e>;\n"
            f"if ({rem} < {r} + {bit}) goto <{l}c>; {rem} = {rem} - ({r} + {bit}); {r} = ({r} >> 1) + {bit}; goto <{l}d>;\n"
            f"<{l}c> {r} = {r} >> 1;\n"
            f"<{l}d> {bit} = {bit} >> 2; goto <{l}b>;\n<{l}e>")
    return r

def sqrt(blk, a):
    """Square root rounded at a guard digit; negative operands give no result change here
    except a cleared result (the square-root exception is not raised)."""
    W = a.W
    done = lbl(blk, "rt")
    r = H(blk, a.fmt)
    blk.add(f"if ({a.f} == 0) goto <{done}>; if ({a.s} != 0) goto <{done}>;")
    normalize(blk, a)
    x = blk.local(32, "zext(0:8)")
    odd = blk.local(1, f"({a.e} & 1) != 0")
    # fraction F = f / 16^D; sqrt(F) to D+1 digits = isqrt(F * 16^(2D+2)) = isqrt(f * 16^(D+2))
    # (odd characteristic: one more digit of the fraction is consumed first)
    blk.add(f"{x} = zext({a.f}) << {W + 8}; if (!{odd}) goto <{done}ev>; {x} = {x} >> 4; {r.e} = ({a.e} + 65) s>> 1; goto <{done}q>;\n"
            f"<{done}ev> {r.e} = ({a.e} + 64) s>> 1;\n<{done}q>")
    q = isqrt(blk, x, 32)
    qr = blk.local(32, f"({q} + 8) >> 4")
    blk.add(f"{r.f} = {qr}:16;")
    blk.add(f"<{done}>")
    return r

# ---- conversions ------------------------------------------------------------------------------
def from_fixed(blk, fmt, val, w):
    """Signed integer (w bytes) -> HFP, truncated to the fraction width and normalized."""
    h = H(blk, fmt)
    W = h.W
    done = lbl(blk, "cf")
    v = blk.local(16, f"sext({val})")
    blk.add(f"if ({v} == 0) goto <{done}>; {h.s} = {v} s< 0; {h.f} = zext({h.s}) * (-{v}) + zext(!{h.s}) * {v}; {h.e} = {64 + D[fmt]};\n"
            f"<{done}l> if (({h.f} >> {W}) == 0) goto <{done}n>; {h.f} = {h.f} >> 4; {h.e} = {h.e} + 1; goto <{done}l>;\n"
            f"<{done}n>")
    normalize(blk, h)
    blk.add(f"<{done}>")
    return h

def to_fixed(blk, h, w, m3, dst):
    """HFP -> signed w-byte integer with rounding method M3 (1 nearest ties away, 4 nearest
    even, 6 toward +inf, 7 toward -inf, else toward 0); saturates with cc 3."""
    W = h.W
    done = lbl(blk, "ct")
    m = blk.local(8, m3)
    mag = blk.local(16, "zext(0:8)")
    blk.add(f"if ({h.f} == 0) goto <{done}z>;")
    normalize(blk, h)
    lim = (1 << (8 * w - 1))
    blk.add(f"if ({h.e} s> {64 + 2 * w}) goto <{done}sat>;")
    # value = f * 16^(e - 64 - D); shift right by s digits (s >= 0 here unless e > 64 + D)
    s = blk.local(8, f"{64 + D[h.fmt]} - {h.e}")
    q = blk.local(16, "zext(0:8)")
    rem = blk.local(16, "zext(0:8)")
    half = blk.local(16, "zext(0:8)")
    blk.add(f"if ({s} s>= 0) goto <{done}r>; {mag} = {h.f} << (0 - {s} * 4); goto <{done}ck>;\n"
            f"<{done}r> if ({s} s> {D[h.fmt]}) goto <{done}small>;\n"
            f"{q} = {h.f} >> ({s} * 4); {rem} = {h.f} - ({q} << ({s} * 4)); {half} = (zext(1:1) << ({s} * 4)) >> 1; goto <{done}rnd>;\n"
            f"<{done}small> {q} = zext(0:8); {rem} = {h.f}; {half} = {c16(1 << (W + 3))};\n"
            f"<{done}rnd>\n"
            f"local up{done}:1 = (({m} == 1) && ({rem} >= {half}) && ({half} != 0)) || "
            f"(({m} == 4) && (({rem} > {half}) || (({rem} == {half}) && ({half} != 0) && (({q} & 1) != 0)))) || "
            f"(({m} == 6) && ({h.s} == 0) && ({rem} != 0)) || (({m} == 7) && ({h.s} != 0) && ({rem} != 0));\n"
            f"{mag} = {q} + zext(up{done});\n"
            f"<{done}ck>\n"
            f"if (({h.s} == 0) && ({mag} > {c16(lim - 1)})) goto <{done}sat>;\n"
            f"if (({h.s} != 0) && ({mag} > {c16(lim)})) goto <{done}sat>;\n"
            f"local iv{done}:16 = zext({h.s} == 0) * {mag} - zext({h.s} != 0) * {mag};")
    blk.add(dst(f"iv{done}:{w}"))
    blk.add(f"gs_cc_flags(0:1, {h.s} != 0, {h.s} == 0, 0:1); goto <{done}>;\n"
            f"<{done}sat>")
    sat = blk.local(16, f"zext({h.s} == 0) * {c16(lim - 1)} + zext({h.s} != 0) * {c16(lim)}")
    blk.add(dst(f"{sat}:{w}"))
    blk.add(f"gs_cc_flags(0:1, 0:1, 0:1, 1:1); goto <{done}>;\n<{done}z>")
    blk.add(dst(f"0:{w}"))
    blk.add(f"gs_cc_flags(1:1, 0:1, 0:1, 0:1);\n<{done}>")

def fp_int(blk, h):
    """LOAD FP INTEGER: fraction digits right of the radix point truncated, then normalized."""
    done = lbl(blk, "fi")
    top = 64 + D[h.fmt]
    blk.add(f"if ({h.e} s> 64) goto <{done}p>; {h.s} = 0; {h.e} = 0; {h.f} = zext(0:8); goto <{done}>;\n"
            f"<{done}p> if ({h.e} s>= {top}) goto <{done}n>; {h.f} = {h.f} >> (({top} - {h.e}) * 4); {h.e} = {top};\n"
            f"<{done}n>")
    normalize(blk, h)
    blk.add(f"<{done}>")

def round_to(blk, h, rfmt):
    """LOAD ROUNDED: add one at the first discarded bit, truncate; a carry adds a digit."""
    r = H(blk, rfmt)
    k = h.W - 4 * D[rfmt]
    blk.add(f"{r.f} = ({h.f} + {c16(1 << (k - 1))}) >> {k}; {r.s} = {h.s}; {r.e} = {h.e};")
    l = lbl(blk, "rd")
    blk.add(f"if (({r.f} >> {r.W}) == 0) goto <{l}>; {r.f} = {r.f} >> 4; {r.e} = {r.e} + 1;")
    overflow(blk, r)
    blk.add(f"<{l}>")
    return r

# ---- instruction table -----------------------------------------------------------------------
def opfmt(n):
    return n

def semantics(ctx):
    n, o, k = ctx["name"], ctx["ops"], ctx["kinds"]
    p = ctx.get("pairs", {})
    blk = Block()
    def rd(i, fmt):
        return unpack(blk, fmt, read_bits(blk, fmt, o[i], k[i], p.get(i)))
    def st(h, i):
        store(blk, h, o[i], p.get(i))
    m = re.fullmatch(r"(a|s)([edx])r?", n) or re.fullmatch(r"(a|s)([uw])r?", n)
    if m and n not in ("ar", "sr", "a", "s", "axr" if False else "-"):
        op, f = m.groups()
        normal = f in "edx"
        fmt = {"u": "e", "w": "d"}.get(f, f)
        a, b = rd(0, fmt), rd(1, fmt)
        if op == "s":
            blk.add(f"{b.s} = {b.s} ^ 1;")
        add(blk, a, b, normal=normal)
        st(a, 0)
        cc_frac(blk, a)
        return blk.text()
    m = re.fullmatch(r"c([edx])r?", n)
    if m:
        fmt = m.group(1)
        a, b = rd(0, fmt), rd(1, fmt)
        compare(blk, a, b)
        return blk.text()
    mul = {"meer": ("e", "e", "e"), "mee": ("e", "e", "e"), "mer": ("e", "d", "d"), "me": ("e", "d", "d"),
           "mder": ("e", "d", "d"), "mde": ("e", "d", "d"), "mdr": ("d", "d", "d"), "md": ("d", "d", "d"),
           "mxdr": ("d", "x", "x"), "mxd": ("d", "x", "x"), "mxr": ("x", "x", "x")}
    if n in mul:
        fin, fres, fdst = mul[n]
        a, b = rd(0, fin), rd(1, fin)
        r = multiply(blk, a, b, fres)
        st(r, 0)
        return blk.text()
    m = re.fullmatch(r"d([edx])r?", n)
    if m:
        fmt = m.group(1)
        a, b = rd(0, fmt), rd(1, fmt)
        divide(blk, a, b, lambda r: st(r, 0))
        return blk.text()
    if n in ("her", "hdr"):
        fmt = n[1]
        a = rd(1, fmt)
        halve(blk, a)
        st(a, 0)
        return blk.text()
    m = re.fullmatch(r"sq([edx])r?", n)
    if m:
        fmt = m.group(1)
        a = rd(1, fmt)
        r = sqrt(blk, a)
        st(r, 0)
        return blk.text()
    rnd = {"ledr": ("d", "e"), "lrer": ("d", "e"), "ldxr": ("x", "d"), "lrdr": ("x", "d"), "lexr": ("x", "e")}
    if n in rnd:
        f1, f2 = rnd[n]
        a = rd(1, f1)
        r = round_to(blk, a, f2)
        st(r, 0)
        return blk.text()
    m = re.fullmatch(r"fi([edx])r", n)
    if m:
        fmt = m.group(1)
        a = rd(1, fmt)
        fp_int(blk, a)
        st(a, 0)
        return blk.text()
    m = re.fullmatch(r"c([edx])([fg])r", n)
    if m:
        fmt, iw = m.group(1), 4 if m.group(2) == "f" else 8
        v = blk.local(iw, o[1] if iw == 8 else f"{o[1]}:4")
        h = from_fixed(blk, fmt, v, iw)
        st(h, 0)
        return blk.text()
    m = re.fullmatch(r"c([fg])([edx])r", n)
    if m:
        iw, fmt = 4 if m.group(1) == "f" else 8, m.group(2)
        a = rd(2, fmt)
        def dst(v):
            if iw == 8:
                return f"{o[0]} = {v};"
            c = f"cw{blk.tag}_{uid()}"
            return f"local {c}:4 = {v}; {o[0]} = ({o[0]} & 0xffffffff00000000) | zext({c});"
        to_fixed(blk, a, iw, o[1], dst)
        return blk.text()
    # sign operations and load and test
    m = re.fullmatch(r"l(t|c|n|p)([edx])r", n)
    if m:
        op, fmt = m.groups()
        a = rd(1, fmt)
        if fmt == "x":
            l = lbl(blk, "lx")
            blk.add(f"if ({a.f} != 0) goto <{l}>;")
            sgn = {"t": a.s, "c": f"{a.s} ^ 1", "n": "1:1", "p": "0:1"}[op]
            z = blk.local(8, f"zext({sgn}) << 63")
            blk.add(f"{o[0]} = {z}; {p[0]} = {z}; gs_cc_flags(1:1, 0:1, 0:1, 0:1); goto <{l}e>;\n<{l}>")
        newsign = {"t": a.s, "c": f"{a.s} ^ 1", "n": "1:1", "p": "0:1"}[op]
        blk.add(f"{a.s} = {newsign};")
        st(a, 0)
        cc_frac(blk, a)
        if fmt == "x":
            blk.add(f"<{l}e>")
        return blk.text()
    # lengthen
    ln = {"lder": ("e", "d"), "lde": ("e", "d"), "lxdr": ("d", "x"), "lxd": ("d", "x"), "lxer": ("e", "x"), "lxe": ("e", "x")}
    if n in ln:
        f1, f2 = ln[n]
        bits = read_bits(blk, f1, o[1], k[1], p.get(1))
        if f2 == "d":
            blk.add(f"{o[0]} = zext({bits}) << 32;")
            return blk.text()
        hi = blk.local(8, f"zext({bits}) << 32" if f1 == "e" else bits)
        fr = blk.local(8, f"{hi} & {F56:#x}")
        sgn = blk.local(8, f"{hi} & 0x8000000000000000")
        lo = blk.local(8, f"{sgn} | (({hi} - 0x0e00000000000000) & 0x7f00000000000000)")
        blk.add(f"if ({fr} != 0) goto <{(l := lbl(blk, 'lx'))}>; {hi} = {sgn}; {lo} = {sgn};\n<{l}>")
        blk.add(f"{o[0]} = {hi}; {p[0]} = {lo};")
        return blk.text()
    # multiply and add / subtract (normalized, product not range-checked, no significance)
    m = re.fullmatch(r"m(a|s)([ed])r?", n)
    if m:
        op, fmt = m.groups()
        a = rd(0, fmt)
        x3 = rd(1, fmt)
        x2 = rd(2, fmt)
        prod = multiply(blk, x2, x3, fmt, ovunf=False)
        if op == "s":
            blk.add(f"{a.s} = {a.s} ^ 1;")
        add(blk, a, prod, normal=True, sigex=False)
        st(a, 0)
        return blk.text()
    return None
