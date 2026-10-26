"""Reference model of the HFP instructions for test/model_diff.py, written from the Hercules
emulator's float.c (the semantics of z/Architecture hexadecimal floating point), with the PSW
exponent-underflow and significance masks off (as the test harness runs). One function per
Hercules routine, on Python integers; formats: 'e' short (6 digits), 'd' long (14), 'x'
extended (28)."""

DIG = {"e": 6, "d": 14, "x": 28}
M56 = (1 << 56) - 1

class F:
    def __init__(self, s, e, f, fmt):
        self.s, self.e, self.f, self.fmt = s, e, f, fmt
        self.W = 4 * DIG[fmt]

def get(fmt, bits):
    if fmt == "e":
        return F(bits >> 31, (bits >> 24) & 0x7f, bits & 0xffffff, fmt)
    if fmt == "d":
        return F(bits >> 63, (bits >> 56) & 0x7f, bits & M56, fmt)
    hi, lo = bits >> 64, bits & ((1 << 64) - 1)
    return F(hi >> 63, (hi >> 56) & 0x7f, ((hi & M56) << 56) | (lo & M56), fmt)

def put(x):
    if x.fmt == "e":
        return (x.s << 31) | (x.e << 24) | x.f
    if x.fmt == "d":
        return (x.s << 63) | (x.e << 56) | x.f
    hi = (x.s << 63) | (x.e << 56) | (x.f >> 56)
    lo = (x.s << 63) | (x.f & M56)
    if hi or lo:
        lo |= ((x.e - 14) & 0x7f) << 56
    return (hi << 64) | lo

def normal(x):
    if x.f:
        while not (x.f >> (x.W - 4)):
            x.f <<= 4
            x.e -= 1
    else:
        x.s, x.e = 0, 0

def underflow(x):
    if x.e < 0:
        x.s, x.e, x.f = 0, 0, 0

def overflow(x):
    if x.e > 127:
        x.e &= 0x7f

def over_under(x):
    if x.e > 127:
        x.e &= 0x7f
    elif x.e < 0:
        x.s, x.e, x.f = 0, 0, 0

def significance(x):
    x.s, x.e = 0, 0

def add(a, b, norm=True):
    W, Dg = a.W, DIG[a.fmt]
    def tail():
        if norm:
            normal(a)
            underflow(a)
    if b.f or b.e:
        if a.f or a.e:
            if a.e == b.e:
                a.f <<= 4
                b.f <<= 4
            elif a.e < b.e:
                sh = b.e - a.e - 1
                a.e = b.e
                if sh:
                    a.f = 0 if sh >= Dg else a.f >> (4 * sh)
                    if a.f == 0:
                        a.s, a.f = b.s, b.f
                        if a.f == 0:
                            significance(a)
                        else:
                            tail()
                        return
                b.f <<= 4
            else:
                sh = a.e - b.e - 1
                if sh:
                    b.f = 0 if sh >= Dg else b.f >> (4 * sh)
                    if b.f == 0:
                        if a.f == 0:
                            significance(a)
                        else:
                            tail()
                        return
                a.f <<= 4
            if a.s == b.s:
                a.f += b.f
            elif a.f == b.f:
                a.f = 0
                significance(a)
                return
            elif a.f > b.f:
                a.f -= b.f
            else:
                a.f, a.s = b.f - a.f, b.s
            if a.f >> (W + 4):
                a.f >>= 8
                a.e += 1
                overflow(a)
            elif norm:
                if a.f:
                    if a.f >> W:
                        a.f >>= 4
                    else:
                        a.e -= 1
                        normal(a)
                        underflow(a)
                else:
                    significance(a)
            else:
                a.f >>= 4
                if a.f == 0:
                    significance(a)
            return
        a.e, a.s, a.f = b.e, b.s, b.f
        if a.f == 0:
            significance(a)
            return
    elif a.f == 0:
        significance(a)
        return
    tail()

def compare(a, b):
    Dg = DIG[a.fmt]
    def cc_of(x, neg):
        return 0 if x == 0 else (1 if neg else 2)
    if not (b.f or b.e):
        return cc_of(a.f, a.s)
    if not (a.f or a.e):
        return cc_of(b.f, not b.s)
    if a.e == b.e:
        a.f <<= 4
        b.f <<= 4
    elif a.e < b.e:
        sh = b.e - a.e - 1
        if sh:
            a.f = 0 if sh >= Dg else a.f >> (4 * sh)
            if a.f == 0:
                return cc_of(b.f, not b.s)
        b.f <<= 4
    else:
        sh = a.e - b.e - 1
        if sh:
            b.f = 0 if sh >= Dg else b.f >> (4 * sh)
            if b.f == 0:
                return cc_of(a.f, a.s)
        a.f <<= 4
    sg = a.s
    if a.s != b.s:
        a.f += b.f
    elif a.f >= b.f:
        a.f -= b.f
    else:
        a.f, sg = b.f - a.f, not b.s
    return cc_of(a.f, sg)

def mul(a, b, rfmt, ovunf=True):
    r = F(0, 0, 0, rfmt)
    if a.f and b.f:
        normal(a)
        normal(b)
        P = a.f * b.f
        W1, R = a.W, r.W
        if P >> (2 * W1 - 4):
            sh, r.e = 2 * W1 - R, a.e + b.e - 64
        else:
            sh, r.e = 2 * W1 - R - 4, a.e + b.e - 65
        r.f = (P >> sh if sh >= 0 else P << -sh) & ((1 << R) - 1)
        r.s = int(a.s != b.s)
        if ovunf:
            over_under(r)
    return r

def div(a, b):
    """None for a zero divisor (the first operand is left alone)."""
    if b.f == 0:
        return None
    r = F(0, 0, 0, a.fmt)
    if a.f:
        normal(a)
        normal(b)
        if a.f < b.f:
            wk, r.e = a.f << a.W, a.e - b.e + 64
        else:
            wk, r.e = a.f << (a.W - 4), a.e - b.e + 65
        r.f = wk // b.f
        r.s = int(a.s != b.s)
        over_under(r)
    return r

def halve(a):
    if a.f & (0xE << (a.W - 4)):
        a.f >>= 1
    else:
        a.f <<= 3
        a.e -= 1
        normal(a)
        underflow(a)
    return a

def isqrt(n):
    x = 0
    if n:
        x = 1 << ((n.bit_length() + 1) // 2)
        while True:
            y = (x + n // x) // 2
            if y >= x:
                break
            x = y
    return x

def sqrt(a):
    r = F(0, 0, 0, a.fmt)
    if a.f and not a.s:
        normal(a)
        x = a.f << (a.W + 8)
        if a.e & 1:
            x >>= 4
            r.e = (a.e + 65) >> 1
        else:
            r.e = (a.e + 64) >> 1
        r.f = ((isqrt(x) + 8) >> 4) & ((1 << r.W) - 1)
    return r

def round_to(a, rfmt):
    r = F(a.s, a.e, 0, rfmt)
    k = a.W - r.W
    r.f = (a.f + (1 << (k - 1))) >> k
    if r.f >> r.W:
        r.f >>= 4
        r.e += 1
        overflow(r)
    return r

def fp_int(a):
    top = 64 + DIG[a.fmt]
    if a.e > 64:
        if a.e < top:
            a.f >>= (top - a.e) * 4
            a.e = top
        normal(a)
    else:
        a.s, a.e, a.f = 0, 0, 0
    return a

def from_fixed(v, fmt):
    r = F(int(v < 0), 64 + DIG[fmt], abs(v), fmt)
    if v == 0:
        return F(0, 0, 0, fmt)
    while r.f >> r.W:
        r.f >>= 4
        r.e += 1
    normal(r)
    return r

def to_fixed(a, w, m3):
    """(value, cc)"""
    lim = 1 << (8 * w - 1)
    if a.f == 0:
        return 0, 0
    normal(a)
    if a.e > 64 + 2 * w:
        return (lim - 1 if not a.s else -lim), 3
    s = 64 + DIG[a.fmt] - a.e
    if s < 0:
        mag = a.f << (-4 * s)
    else:
        if s > DIG[a.fmt]:
            q, rem, half = 0, a.f, 1 << (a.W + 3)
        else:
            q, rem, half = a.f >> (4 * s), a.f & ((1 << (4 * s)) - 1), (1 << (4 * s)) >> 1
        up = ((m3 == 1 and half and rem >= half) or
              (m3 == 4 and (rem > half or (half and rem == half and q & 1))) or
              (m3 == 6 and not a.s and rem) or (m3 == 7 and a.s and rem))
        mag = q + bool(up)
    if (not a.s and mag > lim - 1) or (a.s and mag > lim):
        return (lim - 1 if not a.s else -lim), 3
    return (-mag if a.s else mag), (1 if a.s else 2)

# ---- BFP <-> HFP ------------------------------------------------------------------------------
from fractions import Fraction

def bfp_to_hfp(bits, short):
    """(HFP long bits, cc) following Hercules cnvt_bfp_to_hfp."""
    if short:
        sg, eb, m = bits >> 31, (bits >> 23) & 0xff, bits & 0x7fffff
        emax, bias, m = 0xff, 127, m << 29
    else:
        sg, eb, m = bits >> 63, (bits >> 52) & 0x7ff, bits & ((1 << 52) - 1)
        emax, bias = 0x7ff, 1023
    mx = (sg << 63) | ((1 << 63) - 1)
    if eb == emax:
        return ((1 << 63) - 1 if m else mx), 3
    if eb == 0:
        return sg << 63, (0 if m == 0 else (1 if sg else 2))
    fr = (m | (1 << 52)) << 3
    ex = eb - bias + 1
    while ex & 3:
        ex += 1
        fr >>= 1
    ex >>= 2
    if ex < -64:
        return sg << 63, 1 if sg else 2
    if ex > 63:
        return mx, 3
    return (sg << 63) | ((ex + 64) << 56) | fr, 1 if sg else 2

def hfp_to_bfp(x, short, m3, fpc=0):
    """(BFP bits, cc), the HFP long value rounded to BFP by M3 (0: FPC mode)."""
    P, emin, emax, eb, n = (24, -126, 127, 8, 32) if short else (53, -1022, 1023, 11, 64)
    if m3 == 0:
        m3 = {0: 4, 1: 5, 2: 6, 3: 7}[fpc & 3]
    if x.f == 0:
        return x.s << (n - 1), 0
    v = Fraction(x.f) * Fraction(16) ** (x.e - 64 - 14)
    E = v.numerator.bit_length() - v.denominator.bit_length()
    while Fraction(2) ** E > v:
        E -= 1
    while Fraction(2) ** (E + 1) <= v:
        E += 1
    Eq = max(E, emin)
    scaled = v / Fraction(2) ** (Eq - (P - 1))          # integer part = kept bits
    q = scaled.numerator // scaled.denominator
    rem = scaled - q
    half = Fraction(1, 2)
    up = ((m3 == 1 and rem >= half) or (m3 == 4 and (rem > half or (rem == half and q & 1))) or
          (m3 == 6 and not x.s and rem) or (m3 == 7 and x.s and rem))
    q += bool(up)
    if q >> P:
        q >>= 1
        Eq += 1
    cc = 1 if x.s else 2
    if Eq > emax:
        toinf = m3 in (1, 4) or (m3 == 6 and not x.s) or (m3 == 7 and x.s)
        bexp, q, cc = ((1 << eb) - 1, 0, 3) if toinf else ((1 << eb) - 2, (1 << P) - 1, 3)
    else:
        bexp = Eq + (1 << (eb - 1)) - 1 if q >> (P - 1) else 0
    return (x.s << (n - 1)) | (bexp << (P - 1)) | (q & ((1 << (P - 1)) - 1)), cc

# ---- MULTIPLY (AND ADD) UNNORMALIZED, long to extended ------------------------------------------
def may(addend, a, b):
    """(sign, characteristic, 128-bit fraction) as Hercules mul_lf_to_ef_unnorm/add_ef_unnorm."""
    R = a.f * b.f
    ep = a.e + b.e - 64
    sp = int(a.s != b.s)
    if addend is None:
        return sp, ep, R
    A, ea, rd, ld = addend.f << 56, addend.e, 0, 0
    if ea < ep:
        while ea != ep and A:
            rd |= A & 0xf
            A >>= 4
            ea += 1
    elif ea > ep:
        while ea != ep and A:
            ld |= A >> 124
            A = (A << 4) & ((1 << 128) - 1)
            ea -= 1
    sg = sp
    if addend.s == sp:
        R += A
        ld |= R >> 112
        R &= (1 << 112) - 1
    elif R >= A:
        if rd:
            R -= 1
            ld = 1
        R = (R - A) & ((1 << 128) - 1)
    else:
        R, sg = A - R, addend.s
    if R == 0 and not ld and not rd:
        sg = 0
    return sg, ep, R

def unnorm_hi(sg, e, R):
    ms, ls = R >> 64, R & ((1 << 64) - 1)
    return ((sg << 63) | ((e << 56) & ((1 << 64) - 1)) | ((ms << 8) & ((1 << 64) - 1)) | (ls >> 56))

def unnorm_lo(sg, e, R):
    ls = R & ((1 << 64) - 1)
    return (sg << 63) | ((((e << 56) - (14 << 56)) & (0x7f << 56))) | (ls & M56)
