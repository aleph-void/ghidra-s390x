"""Reference model of PERFORM FLOATING-POINT OPERATION (convert floating-point radix) for
test/model_diff.py, written from the Principles of Operation (SA22-7832-14, 9-35 to 9-45) with
exact rational arithmetic, independently of the p-code: binary and hexadecimal results are
rounded from a Fraction, decimal results by Python's decimal module (dfp_model.py).

Not modelled (as in the p-code): FPC trap masks, the alternate-exception-action control and the
DXC. The condition code is 1 when an exception is recognized in nontrap form: invalid,
overflow, underflow (tiny and inexact), inexact (unless GR0 bit 56), or a quantum exception
(DFP result, GR0 bit 58); GR1 bits 32-63 become zero. fpc is 0 in the tests.
"""
import decimal
from decimal import Decimal
from fractions import Fraction
import dfp_model as DM

BFP = {0: (8, 23, 127, 32), 1: (11, 52, 1023, 64), 2: (15, 112, 16383, 128)}   # eb, fb, bias, width
HFPD = {0: 6, 1: 14, 2: 28}
DFPF = {0: "s", 1: "d", 2: "x"}
OFC = {0: ("h", 0), 1: ("h", 1), 2: ("h", 2), 5: ("b", 0), 6: ("b", 1), 7: ("b", 2),
       8: ("d", 0), 9: ("d", 1), 10: ("d", 2)}

def fpr_bits(kind_z, f_hi, f_lo):
    k, z = kind_z
    if z == 0:
        return f_hi >> 32
    if z == 1:
        return f_hi
    return (f_hi << 64) | f_lo

def decode_src(k, z, bits):
    """-> (sign, cls, payload, value): cls 'fin' (value a nonnegative Fraction, maybe 0),
    'inf', 'qnan', 'snan'"""
    if k == "h":
        D = HFPD[z]
        w = {0: 32, 1: 64, 2: 128}[z]
        if z == 2:
            hi, lo = bits >> 64, bits & ((1 << 64) - 1)
            s = hi >> 63
            ch = (hi >> 56) & 0x7f
            frac = ((hi & ((1 << 56) - 1)) << 56) | (lo & ((1 << 56) - 1))
        else:
            s = bits >> (w - 1)
            ch = (bits >> (w - 8)) & 0x7f
            frac = bits & ((1 << (w - 8)) - 1)
        return s, "fin", 0, Fraction(frac) * Fraction(16) ** (ch - 64 - D)
    if k == "b":
        eb, fb, bias, w = BFP[z]
        s = bits >> (w - 1)
        ex = (bits >> fb) & ((1 << eb) - 1)
        fr = bits & ((1 << fb) - 1)
        if ex == (1 << eb) - 1:
            if fr == 0:
                return s, "inf", 0, None
            pay = fr & ((1 << (fb - 1)) - 1)
            return s, ("qnan" if fr >> (fb - 1) else "snan"), pay, None
        if ex == 0:
            return s, "fin", 0, Fraction(fr) * Fraction(2) ** (1 - bias - fb)
        return s, "fin", 0, Fraction(fr | (1 << fb)) * Fraction(2) ** (ex - bias - fb)
    d = DM.decode(DFPF[z], bits)
    s = int(d.is_signed())
    if d.is_infinite():
        return s, "inf", 0, None
    if d.is_nan():
        t = d.as_tuple()
        pay = int("".join(map(str, t.digits)) or "0")
        return s, ("snan" if d.is_snan() else "qnan"), pay, None
    return s, "fin", 0, Fraction(d.copy_abs())

def rnd(x, sign, mode):
    """x >= 0 (Fraction) rounded to an integer: (integer, inexact); mode as DM.DRM"""
    q = x.numerator // x.denominator
    r = x - q
    if r == 0:
        return q, False
    half = Fraction(1, 2)
    up = {0: r > half or (r == half and q & 1), 1: False, 2: not sign, 3: bool(sign),
          4: r >= half, 5: r > half, 6: True, 7: False}[mode]
    return q + int(up), True

def pack_bfp(z, s, x, mode):
    """-> (bits, inexact, overflow, tiny)"""
    eb, fb, bias, w = BFP[z]
    P = fb + 1
    emin, emax = 1 - bias, bias
    if x == 0:
        return s << (w - 1), False, False, False
    e = x.numerator.bit_length() - x.denominator.bit_length()
    if Fraction(2) ** e > x:
        e -= 1
    tiny = e < emin
    U = max(e, emin) - (P - 1)
    q, inx = rnd(x / Fraction(2) ** U, s, mode)
    if mode == 7 and inx:
        q |= 1
    if q == 1 << P:
        q = 1 << (P - 1)
        U += 1
    ep = U + P - 1
    if ep > emax:
        toinf = mode in (0, 4, 5, 6) or (mode == 2 and not s) or (mode == 3 and s)
        ex = (1 << eb) - 1
        if toinf:
            return (s << (w - 1)) | (ex << fb), True, True, False
        return (s << (w - 1)) | ((ex - 1) << fb) | ((1 << fb) - 1), True, True, False
    if q < 1 << (P - 1):
        return (s << (w - 1)) | q, inx, False, tiny
    return (s << (w - 1)) | ((ep + bias) << fb) | (q - (1 << (P - 1))), inx, False, tiny

def pack_hfp(z, s, x, mode):
    """-> ((hi, lo), inexact, overflow, underflow); no value on overflow or underflow"""
    D = HFPD[z]
    ch = 0
    while Fraction(16) ** ch <= x:
        ch += 1
    while Fraction(16) ** (ch - 1) > x:
        ch -= 1
    q, inx = rnd(x * Fraction(16) ** (D - ch), s, mode)
    if mode == 7 and inx:
        q |= 1
    if q == 16 ** D:
        q = 16 ** (D - 1)
        ch += 1
    c = ch + 64
    if c > 127:
        return None, inx, True, False
    if c < 0:
        return None, True, False, True
    return hfp_bits(z, s, c, q), inx, False, False

def hfp_bits(z, s, c, frac):
    """-> (hi, lo) FPR contents (lo only for extended)"""
    if z == 0:
        return ((s << 31) | (c << 24) | frac, 0)
    if z == 1:
        return ((s << 63) | (c << 56) | frac, 0)
    hi = (s << 63) | (c << 56) | (frac >> 56)
    lo = (s << 63) | ((((c - 14) & 0x7f) << 56) if frac else 0) | (frac & ((1 << 56) - 1))
    return hi, lo

def convert(r0, f0, f2, f4, f6):
    """-> (f0, f2, cc or None (unchanged), rc_set) for GR0 r0 and the FPRs"""
    tb = (r0 >> 31) & 1
    otc = (r0 >> 24) & 0x7f
    c1, c2 = (r0 >> 16) & 0xff, (r0 >> 8) & 0xff
    inxs, b58, b59, rm = (r0 >> 7) & 1, (r0 >> 5) & 1, (r0 >> 4) & 1, r0 & 0xf
    valid = (otc == 1 and c1 in OFC and c2 in OFC and OFC[c1][0] != OFC[c2][0]
             and not (OFC[c1][0] == "b" and (b58 or b59)) and (rm in (0, 1) or rm >= 8))
    if not valid:
        return (f0, f2, 3, True) if tb else (f0, f2, None, False)
    if tb:
        return f0, f2, 0, True
    k1, z1 = OFC[c1]
    k2, z2 = OFC[c2]
    mode = 0 if rm == 0 else (0 if rm == 1 else rm - 8)       # fpc = 0: both modes round to nearest even
    s, cls, pay, x = decode_src(k2, z2, fpr_bits((k2, z2), f4, f6))
    inv = ovf = unf = inx = qtm = False
    out = None            # (hi, lo)

    def put_bfp(bits):
        eb, fb, bias, w = BFP[z1]
        if z1 == 0:
            return (f0 & 0xffffffff) | (bits << 32), f2
        if z1 == 1:
            return bits, f2
        return bits >> 64, bits & ((1 << 64) - 1)

    def put_hfp(hi, lo):
        if z1 == 0:
            return (f0 & 0xffffffff) | (hi << 32), f2
        return hi, (lo if z1 == 2 else f2)

    def put_dfp(bits):
        if z1 == 0:
            return (f0 & 0xffffffff) | (bits << 32), f2
        if z1 == 1:
            return bits, f2
        return bits >> 64, bits & ((1 << 64) - 1)

    if cls != "fin":
        if k1 == "h":
            inv = True
            D = HFPD[z1]
            hi, lo = hfp_bits(z1, s if cls == "inf" else 0, 127, (1 << (4 * D)) - 1)
            r = put_hfp(hi, lo)
        elif k1 == "b":
            eb, fb, bias, w = BFP[z1]
            if cls == "inf":
                bits = (s << (w - 1)) | (((1 << eb) - 1) << fb)
            else:
                if cls == "snan":
                    inv = True
                p = pay if pay < 1 << (fb - 1) else 0
                bits = (s << (w - 1)) | (((1 << eb) - 1) << fb) | (1 << (fb - 1)) | p
            r = put_bfp(bits)
        else:
            f = DFPF[z1]
            P = DM.FMT[f][0]
            if cls == "inf":
                d = Decimal("-Infinity" if s else "Infinity")
            else:
                if cls == "snan":
                    inv = True
                p = pay if pay < 10 ** (P - 1) else 0
                d = Decimal(("-" if s else "") + "NaN" + (str(p) if p else ""))
            r = put_dfp(DM.encode(f, d))
        anyx = inv
        return r[0], r[1], int(anyx), True
    if x == 0:
        if k1 == "h":
            r = put_hfp(*hfp_bits(z1, s, 0, 0))
        elif k1 == "b":
            r = put_bfp(s << (BFP[z1][3] - 1))
        else:
            f = DFPF[z1]
            P, ec, ccb, bias, n = DM.FMT[f]
            q = 0 if b59 else (3 << ec) - 1 - bias
            d = Decimal((s, (0,), q))
            r = put_dfp(DM.encode(f, d))
            qtm = q > 0
        quant = k1 == "d" and b58 and qtm
        return r[0], r[1], int(quant), True
    if k1 == "d":
        f = DFPF[z1]
        P, ec, ccb, bias, n = DM.FMT[f]
        emaxq = (3 << ec) - 1 - bias
        etiny = -bias
        big = decimal.Context(prec=60000, Emax=999999, Emin=-999999, traps=[])
        num, den = x.numerator, x.denominator
        # x is a dyadic rational (binary or hexadecimal source): exact decimal expansion
        k = den.bit_length() - 1
        ex = big.multiply(Decimal(num), big.power(Decimal(5), k)).scaleb(-k, context=big)
        c = DM.ctx(f, DM.DRM[mode])
        c.clear_flags()
        if s:
            ex = ex.copy_negate()
        r = c.plus(ex)
        inx = bool(c.flags[decimal.Inexact])
        ovf = bool(c.flags[decimal.Overflow])
        nmin = Fraction(10) ** (etiny + P - 1)
        unf = x < nmin and inx
        if not inx and not ovf and not r.is_infinite():
            # exact: the cohort member of the preferred-quantum control
            t = r.as_tuple()
            coef = int("".join(map(str, t.digits)))
            q = t.exponent
            while coef % 10 == 0 and coef and q < emaxq:
                coef //= 10
                q += 1
            if b59 and q > 0:
                nd = len(str(coef))
                dq = min(q, P - nd)
                coef *= 10 ** dq
                q -= dq
            r = Decimal((s, tuple(int(ch) for ch in str(coef)), q))
            qtm = q > 0
        else:
            qtm = True
        res = put_dfp(DM.encode(f, r))
    elif k1 == "b":
        bits, inx, ovf, tiny = pack_bfp(z1, s, x, mode)
        unf = tiny and inx
        res = put_bfp(bits)
    else:
        (hi, lo), inx, ovf, unf = (lambda t: ((t[0] or (0, 0)), t[1], t[2], t[3]))(pack_hfp(z1, s, x, mode))
        if ovf:
            ovf_ctl = b58
            hi, lo = hfp_bits(z1, s, 127, (1 << (4 * HFPD[z1])) - 1)
            inv = not ovf_ctl
            ovf = bool(ovf_ctl)
            inx = True
        elif unf:
            hi, lo = hfp_bits(z1, s, 0, 0)
            unf = bool(b59)
            inx = True
        res = put_hfp(hi, lo)
    quant = k1 == "d" and b58 and qtm
    anyx = inv or ovf or unf or (inx and not inxs) or quant
    return res[0], res[1], int(anyx), True
