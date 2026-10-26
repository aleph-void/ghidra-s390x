"""Reference model of the decimal-floating-point (DFP) instructions for test/model_diff.py.

The arithmetic is Python's decimal module (the General Decimal Arithmetic specification, the
same as the decNumber library behind the Hercules emulator's DFP); the register formats are
IEEE 754 decimal32/64/128 with densely packed decimal (DPD) coefficients. The special-value
encodings of the s390x instructions (infinity/NaN coefficient handling, cc) follow Hercules
dfp.c. FPC traps are off (as the test harness runs)."""
import decimal
from decimal import Decimal

FMT = {   # P, exponent-continuation bits, coefficient-continuation bits, bias, width
    "s": (7, 6, 20, 101, 32),
    "d": (16, 8, 50, 398, 64),
    "x": (34, 12, 110, 6176, 128),
}

def ctx(fmt, rounding=decimal.ROUND_HALF_EVEN, prec=None):
    P, ec, cc, bias, n = FMT[fmt]
    emax = (3 << ec) - 1 - bias + P - 1          # largest adjusted exponent
    return decimal.Context(prec=prec or P, Emax=emax, Emin=1 - emax, clamp=1, rounding=rounding,
                           traps=[])

DRM = [decimal.ROUND_HALF_EVEN, decimal.ROUND_DOWN, decimal.ROUND_CEILING, decimal.ROUND_FLOOR,
       decimal.ROUND_HALF_UP, decimal.ROUND_HALF_DOWN, decimal.ROUND_UP, decimal.ROUND_05UP]

def rmode(mask, fpc):
    """the effective rounding method of a DFP rounding-modifier field (PoO, e.g. ADD)"""
    if mask & 8:
        return DRM[mask & 7]
    if mask in (0, 2):
        return DRM[(fpc >> 4) & 7]
    return DRM[{1: 4, 3: 7, 4: 0, 5: 1, 6: 2, 7: 3}[mask]]

# ---- densely packed decimal -----------------------------------------------------------------
def dpd_decode(d):
    p, q, r, s, t, u, v, w, x, y = [(d >> (9 - k)) & 1 for k in range(10)]
    if not v:
        return [p * 4 + q * 2 + r, s * 4 + t * 2 + u, w * 4 + x * 2 + y]
    if (w, x) == (0, 0):
        return [p * 4 + q * 2 + r, s * 4 + t * 2 + u, 8 + y]
    if (w, x) == (0, 1):
        return [p * 4 + q * 2 + r, 8 + u, s * 4 + t * 2 + y]
    if (w, x) == (1, 0):
        return [8 + r, s * 4 + t * 2 + u, p * 4 + q * 2 + y]
    if (s, t) == (0, 0):
        return [8 + r, 8 + u, p * 4 + q * 2 + y]
    if (s, t) == (0, 1):
        return [8 + r, p * 4 + q * 2 + u, 8 + y]
    if (s, t) == (1, 0):
        return [p * 4 + q * 2 + r, 8 + u, 8 + y]
    return [8 + r, 8 + u, 8 + y]

def dpd_encode(a, b, c):
    la, lb, lc = a > 7, b > 7, c > 7
    if not (la or lb or lc):
        return (a << 7) | (b << 4) | c
    if (la, lb, lc) == (0, 0, 1):
        return (a << 7) | (b << 4) | 8 | (c & 1)
    if (la, lb, lc) == (0, 1, 0):
        return (a << 7) | (((c >> 1) & 3) << 5) | ((b & 1) << 4) | 0b1010 | (c & 1)
    if (la, lb, lc) == (1, 0, 0):
        return (((c >> 1) & 3) << 8) | ((a & 1) << 7) | (b << 4) | 0b1100 | (c & 1)
    if (la, lb, lc) == (1, 1, 0):
        return (((c >> 1) & 3) << 8) | ((a & 1) << 7) | ((b & 1) << 4) | 0b1110 | (c & 1)
    if (la, lb, lc) == (1, 0, 1):
        return (((b >> 1) & 3) << 8) | ((a & 1) << 7) | (1 << 5) | ((b & 1) << 4) | 0b1110 | (c & 1)
    if (la, lb, lc) == (0, 1, 1):
        return (a << 7) | (2 << 5) | ((b & 1) << 4) | 0b1110 | (c & 1)
    return ((a & 1) << 7) | (3 << 5) | ((b & 1) << 4) | 0b1110 | (c & 1)

def cont_decode(bits, nd):
    v = 0
    for k in range(nd - 1, -1, -1):
        a, b, c = dpd_decode((bits >> (10 * k)) & 0x3ff)
        v = v * 1000 + a * 100 + b * 10 + c
    return v

def cont_encode(v, nd):
    bits = 0
    for k in range(nd):
        g = v % 1000
        v //= 1000
        bits |= dpd_encode(g // 100, g // 10 % 10, g % 10) << (10 * k)
    return bits

# ---- register format <-> Decimal -------------------------------------------------------------
def decode(fmt, bits):
    """-> Decimal"""
    P, ec, cc, bias, n = FMT[fmt]
    s = bits >> (n - 1)
    G = (bits >> (n - 6)) & 0x1f
    cont = bits & ((1 << cc) - 1)
    nd = cc // 10
    if G == 0b11110:
        return Decimal("-Infinity" if s else "Infinity")
    if G == 0b11111:
        snan = (bits >> (n - 7)) & 1
        payload = cont_decode(cont, nd)
        return Decimal(("-" if s else "") + ("sNaN" if snan else "NaN") + (str(payload) if payload else ""))
    if G >> 3 == 0b11:
        emsb, lead = (G >> 1) & 3, 8 + (G & 1)
    else:
        emsb, lead = G >> 3, G & 7
    e = (emsb << ec) | ((bits >> cc) & ((1 << ec) - 1))
    coef = lead * 10 ** (3 * nd) + cont_decode(cont, nd)
    return Decimal((s, tuple(int(c) for c in str(coef)), e - bias))

def encode(fmt, d):
    """Decimal (already rounded to the format) -> bits"""
    P, ec, cc, bias, n = FMT[fmt]
    nd = cc // 10
    t = d.as_tuple()
    s = t.sign
    if d.is_infinite():
        return (s << (n - 1)) | (0b11110 << (n - 6))
    if d.is_nan():
        payload = int("".join(map(str, t.digits)) or "0") % 10 ** (P - 1)
        return (s << (n - 1)) | (0b11111 << (n - 6)) | (int(d.is_snan()) << (n - 7)) | cont_encode(payload, nd)
    coef = int("".join(map(str, t.digits)))
    e = t.exponent + bias
    lead, rest = coef // 10 ** (3 * nd), coef % 10 ** (3 * nd)
    emsb = e >> ec
    G = (emsb << 3) | lead if lead < 8 else 0b11000 | (emsb << 1) | (lead - 8)
    return (s << (n - 1)) | (G << (n - 6)) | ((e & ((1 << ec) - 1)) << cc) | cont_encode(rest, nd)

def cc_of(d):
    return 3 if d.is_nan() else (0 if d.is_zero() else (1 if d.is_signed() else 2))

def fin(fmt, d, c):
    """Round/fold a result into the format (decimal64FromNumber)."""
    return c.plus(d) if not d.is_nan() else d

# ---- instructions -----------------------------------------------------------------------------
def arith(op, fmt, x, y, mask, fpc):
    c = ctx(fmt, rmode(mask, fpc))
    r = {"a": c.add, "s": c.subtract, "m": c.multiply, "d": c.divide}[op](x, y)
    return r, cc_of(r)

def compare(x, y):
    if x.is_nan() or y.is_nan():
        return 3
    return 0 if x == y else (1 if x < y else 2)

def compare_exp(x, y):
    if x.is_nan() and y.is_nan():
        return 0
    if x.is_nan() or y.is_nan():
        return 3
    if x.is_infinite() and y.is_infinite():
        return 0
    if x.is_infinite() or y.is_infinite():
        return 3
    a, b = x.as_tuple().exponent, y.as_tuple().exponent
    return 0 if a == b else (1 if a < b else 2)
