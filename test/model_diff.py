#!/usr/bin/env python3
"""Ghidra p-code vs reference models, for instructions qemu-s390x does not implement: the
packed-decimal arithmetic AP, SP, ZAP, CP, MP, DP, SRP (z/Architecture Principles of
Operation, chapter 8) and the hexadecimal floating point (hfp_model.py, after the Hercules
emulator). Same test image as qemu_diff.py; the expected results come from the Python models
instead of from qemu. Decimal floating point (dfp_model.py, Python's decimal module) too.

  model_diff.py gen <outdir> [tests-per-mnemonic] [seed]      packed decimal: qd.elf, qd.txt
  model_diff.py hfp <outdir> <s390-opc.txt> <s390-operands.txt> [tests-per-mnemonic] [seed]
  model_diff.py dfp <outdir> <s390-opc.txt> <s390-operands.txt> [tests-per-mnemonic] [seed]
                (ONLY=<regex> limits the mnemonics of hfp/dfp)
  model_diff.py cmp <outdir> <ghidra.bin> [examples]           compares with the models
"""
import os, random, re, struct, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import qemu_diff as Q

KINDS = ["ap", "sp", "zap", "cp", "mp", "dp", "srp"]

def unpack(b):
    """packed decimal bytes -> (value, negative)"""
    digits = "".join(f"{x:02x}" for x in b)[:-1]
    neg = (b[-1] & 0xf) in (0xb, 0xd)
    v = int(digits)
    return (-v if neg else v), neg

def pack(mag, neg, n):
    digits = f"{mag % 10 ** (2 * n - 1):0{2 * n - 1}d}"
    nib = [int(c) for c in digits] + [0xd if neg else 0xc]
    return bytes(nib[2 * i] << 4 | nib[2 * i + 1] for i in range(n))

def model(op, win, cc):
    """Apply the SS instruction op (bytes, operands based on the window) to win; returns cc."""
    code = op[0]
    if code == 0xf0:                                  # SRP D1(L1,B1),D2(B2),I3
        n1, rnd = (op[1] >> 4) + 1, op[1] & 0xf
        d1 = (op[2] & 0xf) << 8 | op[3]
        d2 = (op[4] & 0xf) << 8 | op[5]
        sh = d2 & 63
        sh = sh - 64 if sh & 32 else sh
        v, neg = unpack(win[d1:d1 + n1])
        mag = abs(v)
        if sh >= 0:
            r = mag * 10 ** sh
        else:
            k = -sh
            r = (mag // 10 ** (k - 1) + rnd) // 10
        cap = 10 ** (2 * n1 - 1)
        ovf = r >= cap and sh > 0
        r %= cap
        rneg = neg and (r != 0 or ovf)
        win[d1:d1 + n1] = pack(r, rneg, n1)
        return 3 if ovf else (0 if r == 0 else (1 if rneg else 2))
    n1, n2 = (op[1] >> 4) + 1, (op[1] & 0xf) + 1
    d1 = (op[2] & 0xf) << 8 | op[3]
    d2 = (op[4] & 0xf) << 8 | op[5]
    v1, neg1 = unpack(win[d1:d1 + n1])
    v2, neg2 = unpack(win[d2:d2 + n2])
    if code == 0xf9:                                  # CP
        return 0 if v1 == v2 else (1 if v1 < v2 else 2)
    if code == 0xfc:                                  # MP: sign by the rules of algebra
        win[d1:d1 + n1] = pack(abs(v1) * abs(v2), neg1 != neg2, n1)
        return cc
    if code == 0xfd:                                  # DP: quotient, then remainder (dividend sign)
        q, r = abs(v1) // abs(v2), abs(v1) % abs(v2)
        win[d1:d1 + n1] = pack(q, neg1 != neg2, n1 - n2) + pack(r, neg1, n2)
        return cc
    v = {0xfa: v1 + v2, 0xfb: v1 - v2, 0xf8: v2}[code]
    cap = 10 ** (2 * n1 - 1)
    ovf = abs(v) >= cap
    mag = abs(v) % cap
    rneg = v < 0 and (mag != 0 or ovf)
    win[d1:d1 + n1] = pack(mag, rneg, n1)
    return 3 if ovf else (0 if mag == 0 else (1 if rneg else 2))

# ---- hexadecimal floating point ---------------------------------------------------------------
import hfp_model as HM

def hfp_pattern(rng):
    """8 bytes: an HFP long value, mostly normalized, with zero/extreme characteristics."""
    s = rng.getrandbits(1)
    e = rng.choice([rng.randrange(56, 72)] * 6 + [0, 1, 2, 126, 127, rng.randrange(128)])
    f = rng.getrandbits(56)
    r = rng.random()
    if r < 0.6:
        f |= rng.randrange(1, 16) << 52
    elif r < 0.7:
        f = 0
    elif r < 0.8:
        f &= (1 << rng.randrange(4, 56)) - 1
    return (s << 63) | (e << 56) | f

def hfp_tests(opc, operands, per, seed, kind="hfp"):
    from qemu_diff import candidates, encode, ld
    import gen_names
    names = {"hfp": gen_names.HFP_NAMES, "dfp": gen_names.DFP_NAMES, "vpd": gen_names.VPD_NAMES,
             "pfpo": {"pfpo"}}[kind]
    pattern = {"hfp": hfp_pattern, "dfp": dfp_pattern, "vpd": hfp_pattern, "pfpo": hfp_pattern}[kind]
    ents = []
    OPS = {}
    for line in open(operands):
        i, b, sh, f = line.split()
        OPS[int(i)] = (int(b), int(sh), int(f, 16))
    seen = set()
    for line in open(opc):
        f = line.split()
        if f[0] not in names or (f[1], f[2]) in seen or not re.fullmatch(os.environ.get("ONLY", ".*"), f[0]) or int(f[6], 16) & 0x100:
            continue
        seen.add((f[1], f[2]))
        ids = [int(x) for x in f[7:]]
        ents.append((f[0], bytes.fromhex(f[1]), bytes.fromhex(f[2]), int(f[3]), [(i,) + OPS[i] for i in ids]))
    tests, data, meta = [], bytearray(), []
    for e in ents:
        rng = random.Random(f"{seed}/{e[0]}/{e[1].hex()}")
        for _ in range(per):
            w = encode(rng, *e)
            win = bytearray()
            for k in range(32):
                win += pattern(rng).to_bytes(8, "big")
            gprs = [rng.getrandbits(64) if rng.random() < 0.7 else rng.getrandbits(32) for k in range(4)]
            vecs = bytes(128)
            if kind == "dfp":
                w = dfp_fix(e[0], bytearray(w), win, gprs, rng)
            if kind == "vpd":
                w, vecs = vpd_fix(e[0], bytearray(w), win, gprs, rng)
            pre = b"".join(ld(k, 8 * k, 12) for k in range(8))
            if kind == "pfpo":
                from qemu_diff import lg
                pfpo_fix(rng, win)
                pre += lg(0, 64, 12)
            tests.append(pre + w)
            meta.append((e[0], w.hex(), e))
            for k in range(4):
                data += struct.pack(">Q", gprs[k])
            data += struct.pack(">Q", rng.randrange(4) << 28) + bytes(8)
            data += bytes(64) + vecs                # FPRs: loaded by the test itself
            data += bytes(win)
    return tests, data, meta

def fields(w, e):
    """operand values of instruction bytes w for opcode-table entry e"""
    v = int.from_bytes(w, "big")
    L = 8 * len(w)
    out = []
    for oid, bits, shift, fl in e[4]:
        out.append((v >> (L - shift - bits)) & ((1 << bits) - 1))
    return out, [fl for (_, _, _, fl) in e[4]]

def hfp_model(name, w, e, fpr, gpr, win, cc):
    """Apply instruction to fpr (list of 16 x 64-bit), gpr (dict 1-4), win; returns cc."""
    vals, fls = fields(w, e)
    regs, mems = [], []
    i = 0
    while i < len(vals):
        fl = fls[i]
        if fl & Q.DISP:                     # D(X,B) or D(B): window offset = D (B = r12, X = 0)
            mems.append(vals[i])
            i += 2 if (i + 2 < len(vals) and fls[i + 1] & Q.INDEX) else 1
            i += 1 if i < len(vals) and fls[i] & Q.BASE_F else 0
            regs.append(("m", mems[-1]))
            continue
        regs.append(("r", vals[i], fl))
        i += 1
    def get(op, fmt):
        if op[0] == "m":
            n = {"e": 4, "d": 8, "x": 16}[fmt]
            return HM.get(fmt, int.from_bytes(win[op[1]:op[1] + n], "big"))
        r = op[1]
        if fmt == "e":
            return HM.get("e", fpr[r] >> 32)
        if fmt == "d":
            return HM.get("d", fpr[r])
        return HM.get("x", (fpr[r] << 64) | fpr[(r + 2) % 16])
    def put(op, x):
        r = op[1]
        b = HM.put(x)
        if x.fmt == "e":
            fpr[r] = (fpr[r] & 0xffffffff) | (b << 32)
        elif x.fmt == "d":
            fpr[r] = b
        else:
            fpr[r], fpr[(r + 2) % 16] = b >> 64, b & ((1 << 64) - 1)
    def ccf(x):
        return 0 if x.f == 0 else (1 if x.s else 2)
    import re
    n = name
    m = re.fullmatch(r"(a|s)([edxuw])r?", n)
    if m:
        op, f = m.groups()
        fmt = {"u": "e", "w": "d"}.get(f, f)
        a, b = get(regs[0], fmt), get(regs[1], fmt)
        if op == "s":
            b.s ^= 1
        HM.add(a, b, norm=f in "edx")
        put(regs[0], a)
        return ccf(a)
    m = re.fullmatch(r"c([edx])r?", n)
    if m:
        return HM.compare(get(regs[0], m.group(1)), get(regs[1], m.group(1)))
    mul = {"meer": ("e", "e"), "mee": ("e", "e"), "mer": ("e", "d"), "me": ("e", "d"), "mder": ("e", "d"),
           "mde": ("e", "d"), "mdr": ("d", "d"), "md": ("d", "d"), "mxdr": ("d", "x"), "mxd": ("d", "x"),
           "mxr": ("x", "x")}
    if n in mul:
        put(regs[0], HM.mul(get(regs[0], mul[n][0]), get(regs[1], mul[n][0]), mul[n][1]))
        return cc
    m = re.fullmatch(r"d([edx])r?", n)
    if m:
        r = HM.div(get(regs[0], m.group(1)), get(regs[1], m.group(1)))
        if r is not None:
            put(regs[0], r)
        return cc
    if n in ("her", "hdr"):
        put(regs[0], HM.halve(get(regs[1], n[1])))
        return cc
    m = re.fullmatch(r"sq([edx])r?", n)
    if m:
        put(regs[0], HM.sqrt(get(regs[1], m.group(1))))
        return cc
    rnd = {"ledr": ("d", "e"), "lrer": ("d", "e"), "ldxr": ("x", "d"), "lrdr": ("x", "d"), "lexr": ("x", "e")}
    if n in rnd:
        put(regs[0], HM.round_to(get(regs[1], rnd[n][0]), rnd[n][1]))
        return cc
    m = re.fullmatch(r"fi([edx])r", n)
    if m:
        put(regs[0], HM.fp_int(get(regs[1], m.group(1))))
        return cc
    m = re.fullmatch(r"c([edx])([fg])r", n)
    if m:
        v = gpr[regs[1][1]]
        if m.group(2) == "f":
            v &= 0xffffffff
            v = v - (1 << 32) if v >> 31 else v
        else:
            v = v - (1 << 64) if v >> 63 else v
        put(regs[0], HM.from_fixed(v, m.group(1)))
        return cc
    m = re.fullmatch(r"c([fg])([edx])r", n)
    if m:
        w = 4 if m.group(1) == "f" else 8
        v, c = HM.to_fixed(get(regs[2], m.group(2)), w, regs[1][1])
        r = regs[0][1]
        if w == 4:
            gpr[r] = (gpr[r] & ~0xffffffff) | (v & 0xffffffff)
        else:
            gpr[r] = v & ((1 << 64) - 1)
        return c
    m = re.fullmatch(r"l(t|c|n|p)([edx])r", n)
    if m:
        op, fmt = m.groups()
        a = get(regs[1], fmt)
        if fmt == "x" and a.f == 0:
            sg = {"t": a.s, "c": a.s ^ 1, "n": 1, "p": 0}[op]
            fpr[regs[0][1]] = fpr[(regs[0][1] + 2) % 16] = sg << 63
            return 0
        a.s = {"t": a.s, "c": a.s ^ 1, "n": 1, "p": 0}[op]
        put(regs[0], a)
        return ccf(a)
    ln = {"lder": ("e", "d"), "lde": ("e", "d"), "lxdr": ("d", "x"), "lxd": ("d", "x"), "lxer": ("e", "x"), "lxe": ("e", "x")}
    if n in ln:
        f1, f2 = ln[n]
        x = get(regs[1], f1)
        bits = HM.put(x)
        hi = bits << 32 if f1 == "e" else bits
        r = regs[0][1]
        if f2 == "d":
            fpr[r] = hi
            return cc
        sgn = hi & (1 << 63)
        if hi & HM.M56:
            fpr[r], fpr[(r + 2) % 16] = hi, sgn | ((hi - (14 << 56)) & (0x7f << 56))
        else:
            fpr[r] = fpr[(r + 2) % 16] = sgn
        return cc
    if n in ("may", "mayr", "mayh", "mayhr", "mayl", "maylr", "my", "myr", "myh", "myhr", "myl", "mylr"):
        add_ = n.startswith("ma")
        part = n.rstrip("r")[-1] if n.rstrip("r")[-1] in "hl" else ""
        sg, e, R = HM.may(get(regs[0], "d") if add_ else None, get(regs[1], "d"), get(regs[2], "d"))
        r = regs[0][1]
        if part == "h":
            fpr[r] = HM.unnorm_hi(sg, e, R)
        elif part == "l":
            fpr[r] = HM.unnorm_lo(sg, e, R)
        else:
            t = (r & 13) if add_ else r
            fpr[t], fpr[(t + 2) % 16] = HM.unnorm_hi(sg, e, R), HM.unnorm_lo(sg, e, R)
        return cc
    if n in ("thdr", "thder"):
        r = regs[1][1]
        bits = fpr[r] if n == "thdr" else fpr[r] >> 32
        fpr[regs[0][1]], c = HM.bfp_to_hfp(bits, n == "thder")
        return c
    if n in ("tbdr", "tbedr"):
        b, c = HM.hfp_to_bfp(get(regs[2], "d"), n == "tbedr", regs[1][1])
        r = regs[0][1]
        fpr[r] = b if n == "tbdr" else (fpr[r] & 0xffffffff) | (b << 32)
        return c
    m = re.fullmatch(r"m(a|s)([ed])r?", n)
    if m:
        op, fmt = m.groups()
        a = get(regs[0], fmt)
        prod = HM.mul(get(regs[2], fmt), get(regs[1], fmt), fmt, ovunf=False)
        if op == "s":
            a.s ^= 1
        HM.add(a, prod, norm=True)
        put(regs[0], a)
        return cc
    raise KeyError(n)

# ---- decimal floating point --------------------------------------------------------------------
import dfp_model as DM
WBASE = [0]                                  # address of the storage window (r12)
VR = [0] * 24                                # v16-v23 of the test being modelled
from decimal import Decimal

def dfp_pattern(rng):
    """8 bytes: two short DFP values or one long one (or half of an extended one): mostly
    finite values of a few digits near exponent 0, with zeros, extremes and special values."""
    r = rng.random()
    if r < 0.15:
        return rng.getrandbits(64)
    if r < 0.25:
        return (dfp_value(rng, "s") << 32) | dfp_value(rng, "s")
    return dfp_value(rng, "d")

def dfp_value(rng, fmt):
    P, ec, cc, bias, n = DM.FMT[fmt]
    emaxq = (3 << ec) - 1 - bias
    s = rng.getrandbits(1)
    r = rng.random()
    if r < 0.04:
        return DM.encode(fmt, Decimal("-Infinity" if s else "Infinity"))
    if r < 0.08:
        pl = rng.choice([0, rng.randrange(10 ** (P - 1))])
        return DM.encode(fmt, Decimal(("-" if s else "") + rng.choice(["NaN", "sNaN"]) + str(pl)))
    nd = rng.choice([0, 1, 1, 2, 3, rng.randrange(1, P + 1), P, P])
    coef = rng.randrange(10 ** (nd - 1), 10 ** nd) if nd else 0
    if rng.random() < 0.2 and nd > 1:
        coef -= coef % 10 ** rng.randrange(1, nd)
    q = rng.choice([rng.randrange(-8, 6)] * 5 + [-bias, -bias + rng.randrange(P + 2), emaxq,
                                                   emaxq - rng.randrange(P + 2), rng.randrange(-bias, emaxq + 1)])
    return DM.encode(fmt, Decimal((s, tuple(int(c) for c in str(coef)), q)))

def dfp_fix(n, w, win, gprs, rng):
    """Make the random test of DFP instruction n meaningful: valid BCD, zoned and packed
    operands, operand lengths within the instruction's limits, exponents and second-operand
    addresses with all low-order bits varied."""
    def setd(d):
        w[2] = (w[2] & 0xf0) | (d >> 8)
        w[3] = d & 0xff
    def digits(nd, maxd):
        v = rng.randrange(10 ** rng.randrange(0, maxd + 1))
        return [int(c) for c in f"{v:0{nd}d}"[-nd:]] if nd else []
    if re.fullmatch(r"td[cg][edx]t|s[lr][dx]t", n):
        setd(rng.getrandbits(12))
    m = re.fullmatch(r"c([dx])([zp])t|c([zp])([dx])t", n)
    if m:
        f = m.group(1) or m.group(4)
        z = (m.group(2) or m.group(3)) == "z"
        P = DM.FMT[f][0]
        lim = (P if z else P // 2 + 1) - 1
        L = rng.randrange(lim + 1) + 1
        w[1] = L - 1
        d = rng.randrange(0, 256 - L + 1)
        setd(d)
        m3 = w[4] & 0xf
        if m.group(1):                                  # from zoned / packed: a valid operand
            signed = bool(m3 & 8)
            if z:
                ds = digits(L, P)
                b = [(rng.randrange(16) << 4) | x for x in ds]
                if signed:
                    b[-1] = (rng.randrange(10, 16) << 4) | ds[-1]
            else:
                nd = 2 * L - (1 if signed else 0)
                ds = digits(nd, P)
                if signed:
                    ds.append(rng.randrange(10, 16))
                b = [(ds[2 * k] << 4) | ds[2 * k + 1] for k in range(L)]
            win[d:d + L] = bytes(b)
    pair_fields = {"cxlftr": (24,), "cfxtr": (28,), "cxstr": (24,), "kxtr": (24, 28)}
    for sh in pair_fields.get(n, ()):                   # extended operands the table lists as single FPRs
        r = rng.choice([0, 1, 4, 5])
        w[sh // 8] = (w[sh // 8] & (0x0f if sh % 8 == 0 else 0xf0)) | (r << (4 if sh % 8 == 0 else 0))
    if n in ("cxstr", "cxutr"):                         # even-odd pairs r2, r3
        w[3] = (w[3] & 0xf0) | 2
    if n in ("cuxtr", "csxtr"):
        w[3] = (w[3] & 0x0f) | 0x20
    if re.fullmatch(r"c[dx][su]tr", n):                  # valid BCD in R2 (and R2 + 1)
        r2 = w[3] & 0xf
        sg = n[2] == "s"
        nd = (16 if n[1] == "d" else 32) - (1 if sg else 0)
        ds = digits(nd, DM.FMT[n[1]][0])
        if sg:
            ds.append(rng.randrange(10, 16))
        v = int("".join(f"{x:x}" for x in ds), 16)
        if n[1] == "d":
            gprs[r2 - 1] = v
        else:
            gprs[r2 - 1], gprs[r2] = v >> 64, v & ((1 << 64) - 1)
    if re.fullmatch(r"ie[dx]tr", n):                    # biased exponent in R2
        r2 = w[3] & 0xf
        P, ec, cc, bias, nb = DM.FMT[n[2]]
        gprs[r2 - 1] = rng.choice([rng.randrange(-5, 3), rng.randrange((3 << ec) - 2, (3 << ec) + 2),
                                   rng.randrange(3 << ec), rng.randrange(bias - 10, bias + 10)]) & ((1 << 64) - 1)
    return bytes(w)

def dfp_model(name, w, e, fpr, gpr, win, cc):
    """Apply DFP instruction name to fpr / gpr / win; returns cc."""
    import re
    vals, fls = fields(w, e)
    n = name
    def reg(i):
        return vals[i]
    def get(r, fmt):
        if fmt == "s":
            return DM.decode("s", fpr[r] >> 32)
        if fmt == "d":
            return DM.decode("d", fpr[r])
        return DM.decode("x", (fpr[r] << 64) | fpr[(r + 2) % 16])
    def put(r, fmt, d):
        b = DM.encode(fmt, d)
        putb(r, fmt, b)
    def putb(r, fmt, b):
        if fmt == "s":
            fpr[r] = (fpr[r] & 0xffffffff) | (b << 32)
        elif fmt == "d":
            fpr[r] = b
        else:
            fpr[r], fpr[(r + 2) % 16] = b >> 64, b & ((1 << 64) - 1)
    fpc = 0
    m = re.fullmatch(r"(a|s|m|d)([dx])tr(a?)", n)
    if m:
        op, f, ra = m.groups()
        r, c = DM.arith(op, f, get(reg(1), f), get(reg(2), f), reg(3) if ra else 0, fpc)
        put(reg(0), f, r)
        return c
    m = re.fullmatch(r"(c|k)([dx])tr", n)
    if m:
        return DM.compare(get(reg(0), m.group(2)), get(reg(1), m.group(2)))
    m = re.fullmatch(r"ce([dx])tr", n)
    if m:
        return DM.compare_exp(get(reg(0), m.group(1)), get(reg(1), m.group(1)))
    def ccv(d):
        return DM.cc_of(d)
    def coef(d):
        return int("".join(map(str, d.as_tuple().digits)) or "0")
    def quiet(d):
        return Decimal(str(d).replace("sNaN", "NaN")) if d.is_snan() else d
    def payload(d, fmt):
        t = d.as_tuple()
        return int("".join(map(str, t.digits)) or "0") % 10 ** (DM.FMT[fmt][0] - 1)
    def contval(fmt, bits):
        """value of the coefficient continuation"""
        P, ec, ccb, bias, nb = DM.FMT[fmt]
        return DM.cont_decode(bits & ((1 << ccb) - 1), ccb // 10)
    def rawbits(r, fmt):
        if fmt == "s":
            return fpr[r] >> 32
        if fmt == "d":
            return fpr[r]
        return (fpr[r] << 64) | fpr[(r + 2) % 16]
    def special(fmt, sign, kind, pl):
        """bits of infinity (kind 1) / qNaN (2) / sNaN (3) with coefficient continuation pl"""
        P, ec, ccb, bias, nb = DM.FMT[fmt]
        G = 0x1e if kind == 1 else 0x1f
        return (sign << (nb - 1)) | (G << (nb - 6)) | (int(kind == 3) << (nb - 7)) | DM.cont_encode(pl, ccb // 10)
    def kind(d):
        return 1 if d.is_infinite() else (3 if d.is_snan() else 2)
    def tointegral(d, mode):
        return d.to_integral_value(rounding=mode)
    def rd_m(i):
        return DM.rmode(vals[i], fpc)
    m = re.fullmatch(r"lt([dx])tr", n)
    if m:
        f = m.group(1)
        d = quiet(get(reg(1), f))
        put(reg(0), f, d if not d.is_infinite() else Decimal(str(d)))
        return ccv(d)
    m = re.fullmatch(r"c([dx])(g|f|lg|lf)tr(a?)", n)
    if m:
        f, src = m.group(1), m.group(2)
        mode = rd_m(1) if len(vals) > 2 else DM.rmode(0, fpc)
        g = gpr[vals[2] if len(vals) > 2 else vals[1]]
        v = {"g": g - ((g >> 63) << 64), "f": (g & 0xffffffff) - (((g >> 31) & 1) << 32),
             "lg": g, "lf": g & 0xffffffff}[src]
        put(reg(0), f, DM.ctx(f, mode).plus(Decimal(v)))
        return cc
    m = re.fullmatch(r"c(g|f|lg|lf)([dx])tr(a?)", n)
    if m:
        dst, f = m.group(1), m.group(2)
        d = get(vals[2], f)
        bits = 64 if "g" in dst else 32
        signed = dst[0] != "l"
        mx = (1 << (bits - 1)) - 1 if signed else (1 << bits) - 1
        mn = -(1 << (bits - 1)) if signed else 0
        inv = True
        if d.is_nan():
            r = mn
        elif d.is_infinite():
            r = mn if d.is_signed() else mx
        else:
            v = int(tointegral(d, rd_m(1)))
            if v > mx:
                r = mx
            elif v < mn:
                r = mn
            else:
                r, inv = v, False
        r &= (1 << bits) - 1
        g = vals[0]
        gpr[g] = r if bits == 64 else (gpr[g] & ~0xffffffff) | r
        return 3 if inv else (0 if d.is_zero() else (1 if d.is_signed() else 2))
    m = re.fullmatch(r"c([dx])([su])tr", n)
    if m:
        f, sg = m.group(1), m.group(2) == "s"
        r2 = vals[1]
        v = gpr[r2] if f == "d" else (gpr[r2] << 64) | gpr[r2 + 1]
        h = f"{v:0{16 if f == 'd' else 32}x}"
        neg = sg and h[-1] in "bd"
        dig = h[:-1] if sg else h
        put(reg(0), f, Decimal((int(neg), tuple(int(c) for c in dig.lstrip("0") or "0"), 0)))
        return cc
    m = re.fullmatch(r"c([su])([dx])tr", n)
    if m:
        sg, f = m.group(1) == "s", m.group(2)
        d = get(vals[1], f)
        bits = rawbits(vals[1], f)
        c = contval(f, bits) if d.is_nan() or d.is_infinite() else coef(d)
        nd = (16 if f == "d" else 32) - (1 if sg else 0)
        v = int(f"{c % 10 ** nd:0{nd}d}", 16)
        if sg:
            neg = d.is_signed()
            v = (v << 4) | (0xd if neg else (0xf if vals[2] & 1 else 0xc))
        if f == "d":
            gpr[vals[0]] = v
        else:
            gpr[vals[0]], gpr[vals[0] + 1] = v >> 64, v & ((1 << 64) - 1)
        return cc
    m = re.fullmatch(r"c([dx])([zp])t", n)
    if m:
        f, z = m.group(1), m.group(2) == "z"
        d2, L, m3 = vals[1], vals[2] + 1, vals[-1]
        b = win[d2:d2 + L]
        signed = bool(m3 & 8)
        if z:
            ds = [x & 0xf for x in b]
            neg = signed and (b[-1] >> 4) in (0xb, 0xd)
        else:
            ds = [y for x in b for y in (x >> 4, x & 0xf)]
            if signed:
                sn = ds.pop()
            neg = signed and not (m3 & 1) and sn in (0xb, 0xd)
        v = int("".join(map(str, ds)))
        put(reg(0), f, Decimal((int(neg), tuple(int(c) for c in str(v)), 0)))
        return cc
    m = re.fullmatch(r"c([zp])([dx])t", n)
    if m:
        z, f = m.group(1) == "z", m.group(2)
        d = get(reg(0), f)
        d2, L, m3 = vals[1], vals[2] + 1, vals[-1]
        sp = d.is_nan() or d.is_infinite()
        c = contval(f, rawbits(reg(0), f)) if sp else coef(d)
        neg = d.is_signed() and not ((m3 & 1) and not sp and c == 0)
        sgn = 0xd if neg else (0xf if m3 & 2 else 0xc)
        nd = L if z else 2 * L - (1 if m3 & 8 else 0)
        lost = c >= 10 ** nd
        ds = [int(x) for x in f"{c % 10 ** nd:0{nd}d}"]
        if z:
            zone = 0x30 if m3 & 4 else 0xf0
            out = [zone | x for x in ds]
            if m3 & 8:
                out[-1] = (sgn << 4) | (out[-1] & 0xf)
        else:
            if m3 & 8:
                ds.append(sgn)
            out = [(ds[2 * k] << 4) | ds[2 * k + 1] for k in range(L)]
        win[d2:d2 + L] = bytes(out)
        if fpr[:8] != [int.from_bytes(win[8 * k:8 * k + 8], "big") for k in range(8)]:
            pass                                    # stores into the FPR area do not reload FPRs
        return 3 if sp or lost else (0 if c == 0 else (1 if d.is_signed() else 2))
    m = re.fullmatch(r"e([es])([dx])tr", n)
    if m:
        what, f = m.group(1), m.group(2)
        d = get(vals[1], f)
        if d.is_infinite():
            r = -1
        elif d.is_nan():
            r = -3 if d.is_snan() else -2
        elif what == "e":
            r = d.as_tuple().exponent + DM.FMT[f][3]
        else:
            r = 0 if d.is_zero() else len(d.as_tuple().digits)
        gpr[vals[0]] = r & ((1 << 64) - 1)
        return cc
    m = re.fullmatch(r"ie([dx])tr", n)
    if m:
        f = m.group(1)
        P, ec, ccb, bias, nb = DM.FMT[f]
        d = get(vals[1], f)
        e2 = gpr[vals[2]]
        e2 -= (e2 >> 63) << 64
        sign = int(d.is_signed())
        sp = d.is_nan() or d.is_infinite()
        c = contval(f, rawbits(vals[1], f)) if sp else coef(d)
        if 0 <= e2 <= (3 << ec) - 1:
            put(vals[0], f, Decimal((sign, tuple(int(x) for x in str(c)), e2 - bias)))
        else:
            putb(vals[0], f, special(f, sign, 1 if e2 == -1 else (3 if e2 == -3 else 2), c % 10 ** (P - 1)))
        return cc
    m = re.fullmatch(r"fi([dx])tr", n)
    if m:
        f = m.group(1)
        d = quiet(get(vals[2], f))
        if not (d.is_nan() or d.is_infinite()):
            d = tointegral(d, rd_m(1))
        put(vals[0], f, d)
        return cc
    lr = {"ldetr": ("s", "d"), "lxdtr": ("d", "x"), "ledtr": ("d", "s"), "ldxtr": ("x", "d")}
    if n in lr:
        fs, fd = lr[n]
        shorten = n in ("ledtr", "ldxtr")
        r2 = vals[2] if shorten else vals[1]
        d = get(r2, fs)
        keep = bool(vals[-1] & 8)
        if d.is_nan() or (d.is_infinite() and keep):
            pl = contval(fs, rawbits(r2, fs)) % 10 ** (DM.FMT[fd][0] - 1)
            k = kind(d)
            if k == 3 and not keep:
                k = 2
            putb(vals[0], fd, special(fd, int(d.is_signed()), k, pl))
        elif d.is_infinite():
            put(vals[0], fd, d)
        else:
            put(vals[0], fd, DM.ctx(fd, rd_m(1)).plus(d).copy_sign(d) if shorten else d)
        return cc
    m = re.fullmatch(r"qa([dx])tr", n)
    if m:
        f = m.group(1)
        a, b = get(vals[2], f), get(vals[1], f)
        c = DM.ctx(f, rd_m(3))
        put(vals[0], f, c.quantize(a, b))
        return cc
    m = re.fullmatch(r"rr([dx])tr", n)
    if m:
        f = m.group(1)
        d = quiet(get(vals[1], f))
        sig = gpr[vals[2]] & 0x3f
        if d.is_nan() or d.is_infinite() or d.is_zero() or sig == 0 or len(d.as_tuple().digits) <= sig:
            put(vals[0], f, d)
        else:
            import decimal
            wide = decimal.Context(prec=200, Emax=99999, Emin=-99999, traps=[])
            e = d.as_tuple().exponent + len(d.as_tuple().digits) - sig
            r = d.quantize(Decimal((0, (1,), e)), rounding=rd_m(3), context=wide)
            if len(r.as_tuple().digits) > sig:
                r = r.quantize(Decimal((0, (1,), e + 1)), context=wide)
            P, ec, ccb, bias, nb = DM.FMT[f]
            if r.as_tuple().exponent > (3 << ec) - 1 - bias:     # beyond the largest quantum
                r = Decimal("NaN")
            put(vals[0], f, r if r.is_nan() else DM.ctx(f).plus(r).copy_sign(r))
        return cc
    m = re.fullmatch(r"s([lr])([dx])t", n)
    if m:
        left, f = m.group(1) == "l", m.group(2)
        P = DM.FMT[f][0]
        d = get(vals[1], f)
        addr = (WBASE[0] + vals[2]) & 0xfff
        sh = addr & 0x3f
        sp = d.is_nan() or d.is_infinite()
        c = contval(f, rawbits(vals[1], f)) if sp else coef(d)
        c = c * 10 ** sh if left else c // 10 ** sh
        if sp:
            putb(vals[0], f, special(f, int(d.is_signed()), kind(d), c % 10 ** (P - 1)))
        else:
            put(vals[0], f, Decimal((int(d.is_signed()), tuple(int(x) for x in str(c % 10 ** P)), d.as_tuple().exponent)))
        return cc
    m = re.fullmatch(r"td([cg])([edx])t", n)
    if m:
        grp, f = m.group(1) == "g", {"e": "s"}.get(m.group(2), m.group(2))
        P, ec, ccb, bias, nb = DM.FMT[f]
        d = get(vals[0], f)
        addr = (WBASE[0] + vals[1]) & 0xfff
        if not grp:
            if d.is_zero():
                bitn = 52
            elif d.is_infinite():
                bitn = 58
            elif d.is_nan():
                bitn = 62 if d.is_snan() else 60
            else:
                bitn = 54 if d.is_subnormal(DM.ctx(f)) else 56
        else:
            q = d.as_tuple().exponent
            ext = not (d.is_nan() or d.is_infinite()) and q in (-bias, (3 << ec) - 1 - bias)
            if d.is_nan() or d.is_infinite():
                bitn = 62
            elif d.is_zero():
                bitn = 54 if ext else 52
            elif ext:
                bitn = 56
            else:
                bitn = 60 if len(d.as_tuple().digits) == P else 58
        bitn += int(d.is_signed())
        return (addr >> (63 - bitn)) & 1
    raise KeyError(n)

# ---- vector packed decimal ----------------------------------------------------------------------
def setf(w, bits, shift, val):
    for k in range(bits):
        pos = shift + k
        byte, bit = pos // 8, 7 - pos % 8
        b = (val >> (bits - 1 - k)) & 1
        w[byte] = (w[byte] & ~(1 << bit)) | (b << bit)

def packed_vec(rng, valid=0.92):
    """16-byte signed packed decimal: digits of random length, sign C/D mostly"""
    nd = rng.choice([0, 1, 2, 3, 5, rng.randrange(32), 31, rng.randrange(20)])
    v = rng.randrange(10 ** nd) if nd else 0
    sign = rng.choice([0xc, 0xd, 0xc, 0xd, 0xa, 0xb, 0xe, 0xf])
    x = (int(f"{v:031d}", 16) << 4) | sign
    if rng.random() > valid:                      # an invalid digit or sign
        if rng.random() < 0.5:
            x = (x & ~0xf) | rng.randrange(10)
        else:
            k = rng.randrange(1, 32)
            x = (x & ~(0xf << (4 * k))) | (rng.randrange(10, 16) << (4 * k))
    return x

def zoned_vec(rng):
    """32 zoned bytes (as an int): F0-F9 digits, a sign zone in the rightmost byte"""
    nd = rng.choice([1, 5, 16, 31, 32, rng.randrange(1, 33)])
    ds = [0] * (32 - nd) + [rng.randrange(10) for _ in range(nd)]
    b = [0xf0 | d for d in ds]
    b[-1] = (rng.choice([0xc, 0xd, 0xf, 0xa, 0xb, 0xe]) << 4) | ds[-1]
    if rng.random() < 0.08:
        b[rng.randrange(32)] = rng.getrandbits(8)
    return int.from_bytes(bytes(b), "big")

def vpd_fix(n, w, win, gprs, rng):
    vec = [packed_vec(rng) for _ in range(8)]
    rdc = rng.randrange(1, 32) if rng.random() < 0.7 else 31
    if n in ("vap", "vsp", "vmp", "vmsp", "vdp", "vrp", "vsdp", "vpkzr"):
        setf(w, 8, 28, (rng.getrandbits(1) << 7) | (rng.randrange(0, 32) if n in ("vmsp", "vsdp") else rdc))
    if n in ("vsrp", "vpsop", "vcvd", "vcvdg", "vcvdq"):
        setf(w, 8, 28, (rng.getrandbits(1) << 7) | rdc)
    if n == "vsrpr":
        setf(w, 8, 28, (rng.getrandbits(2) << 6) | rdc)
    if n in ("vdp", "vrp", "vsdp"):                   # no division by zero
        v3 = (w[2] >> 4) & 7
        if vec[v3] >> 4 == 0:
            vec[v3] |= 0x10
    if n == "vsrpr":
        v3 = (w[2] >> 4) & 7
        b = rng.randrange(-40, 40) & 0xff
        vec[v3] = (vec[v3] & ~(0xff << 64)) | (b << 64)
    if n == "vlip":
        setf(w, 16, 16, int("".join(str(rng.randrange(10)) for _ in range(4)), 16))
    if n in ("vpkz", "vupkz"):
        L = rng.randrange(31)
        setf(w, 8, 8, L)
        d = rng.randrange(0, 256 - 32)
        setf(w, 12, 20, d)
        if n == "vpkz":
            z = zoned_vec(rng).to_bytes(32, "big")[-(L + 1):]
            win[d:d + L + 1] = z
    if n == "vpkzr":
        vec = [zoned_vec(rng) for _ in range(8)]
        vec = [(vec[k] >> 128) if k % 2 == 0 else vec[k] & ((1 << 128) - 1) for k in range(8)]
        if rng.random() < 0.5:                       # v2:v3 one zoned number
            z = zoned_vec(rng)
            v2, v3 = w[1] & 7, (w[2] >> 4) & 7
            vec[v2], vec[v3] = z >> 128, z & ((1 << 128) - 1)
    if n == "vtz":
        dc = rng.randrange(1, 32)
        dsc = rng.choice([dc, rng.randrange(1, dc + 1)])
        setf(w, 16, 20, (rng.getrandbits(2) << 13) | (dsc << 8) | (rng.randrange(8) << 5) | dc)
        z = zoned_vec(rng)
        v1, v2 = w[1] & 7, (w[2] >> 4) & 7
        vec[v1], vec[v2] = z >> 128, z & ((1 << 128) - 1)
    if n == "vcvb" or n == "vcvbg":
        setf(w, 4, 28, rng.getrandbits(4))
    if n.startswith("vsch") or n in ("vscshp", "vcsph"):
        v3 = (w[2] >> 4) & 7
        vec[v3] = (vec[v3] & ~(0xff << 64)) | (rng.getrandbits(8) << 64)
    if n == "vschp":
        setf(w, 4, 32, rng.choice([2, 3, 4]))
    if n == "vcsph":
        v2 = w[1] & 7
        hi, lo = hfp_pattern(rng), hfp_pattern(rng)
        vec[v2] = 0 if rng.random() < 0.05 else (hi << 64) | lo
    return bytes(w), b"".join(v.to_bytes(16, "big") for v in vec)

def vpd_model(name, w, e, fpr, gpr, win, cc):
    """Apply vector packed-decimal instruction name; returns cc."""
    n = name
    vals, fls = fields(w, e)
    def V(i):
        return 16 + (vals[i] & 7)
    def nibs(x):
        return [(x >> (4 * (31 - k))) & 0xf for k in range(32)]
    def val(x, force=False):
        m = 0
        for d in nibs(x)[:31]:
            m = m * 10 + d
        neg = (x & 0xf) in (0xb, 0xd) and not force
        return m, neg
    def isplus(s):
        return s in (0xa, 0xc) or s >= 0xe
    def put(dst, r, neg, p1, rdc, cs):
        m = abs(r)
        digits = m % 10 ** rdc
        ov = m >= 10 ** rdc
        sg = 0xf if p1 else (0xd if neg and digits else 0xc)
        VR[dst] = (int(f"{digits:031d}", 16) << 4) | sg
        if cs:
            return 3 if ov else (0 if m == 0 else (1 if sg == 0xd else 2))
        return cc
    def shift(m, sh, drd):
        if sh >= 0:
            return m * 10 ** sh
        k = -sh
        if drd:
            return (m // 10 ** (k - 1) + 5) // 10
        return m // 10 ** k
    if n in ("vap", "vsp", "vmp", "vmsp", "vdp", "vrp", "vsdp"):
        i4, m5 = vals[3], vals[4]
        p2, p3, p1, cs = bool(m5 & 8), bool(m5 & 4), bool(m5 & 2), bool(m5 & 1)
        a, an = val(VR[V(1)], p2)
        b, bn = val(VR[V(2)], p3)
        A, B = -a if an else a, -b if bn else b
        rdc = i4 & 0x1f
        if n == "vap":
            r = A + B
        elif n == "vsp":
            r = A - B
        elif n == "vmp":
            r = A * B
        elif n == "vmsp":
            r, rdc = shift(abs(A * B), -(i4 & 0x1f), False) * (-1 if an != bn else 1), 31
        else:
            num = a * 10 ** (i4 & 0x1f) if n == "vsdp" else a
            if n == "vsdp":
                rdc = 31
            q, rm = (num // b, num % b) if b else (0, 0)
            r = rm * (-1 if an else 1) if n == "vrp" else q * (-1 if an != bn else 1)
        neg = r < 0
        if n == "vap" or n == "vsp":                 # the sign of a zero sum (unused: no digits)
            pass
        return put(V(0), r, neg, p1, rdc, cs)
    if n in ("vsrp", "vsrpr"):
        if n == "vsrp":
            i3, i4, m5 = vals[2], vals[3], vals[4]
            rdc, drd = i3 & 0x1f, bool(i4 & 0x80)
            sh = i4 & 0x7f
            sh = sh - 0x80 if sh > 0x4f else sh
        else:
            i4, m5 = vals[3], vals[4]
            rdc, drd = i4 & 0x1f, bool(i4 & 0x40)
            sh = (VR[V(2)] >> 64) & 0xff
            sh = max(-32, min(31, sh - 256 if sh & 0x80 else sh))
        p2, p1, cs = bool(m5 & 8), bool(m5 & 2), bool(m5 & 1)
        a, an = val(VR[V(1)], p2)
        r = shift(a, sh, drd)
        return put(V(0), r, an, p1, rdc, cs)
    if n == "vcp":
        m3 = vals[2]
        a, an = val(VR[V(0)], bool(m3 & 8))
        b, bn = val(VR[V(1)], bool(m3 & 4))
        A, B = -a if an else a, -b if bn else b
        return 0 if A == B else (1 if A < B else 2)
    if n in ("vcvd", "vcvdg", "vcvdq"):
        i3, m4 = vals[2], vals[3]
        lb, p1, cs = bool(m4 & 8), bool(m4 & 2), bool(m4 & 1)
        rdc = i3 & 0x1f
        if n == "vcvdq":
            x, bits = VR[V(1)], 128
        else:
            bits = 32 if n == "vcvd" else 64
            x = gpr[vals[1]] & ((1 << bits) - 1)
        if not lb and x >> (bits - 1):
            x -= 1 << bits
        neg = x < 0
        m = abs(x)
        digits = m % 10 ** rdc
        VR[V(0)] = (int(f"{digits:031d}", 16) << 4) | (0xf if p1 else (0xd if neg else 0xc))
        return (3 if m >= 10 ** rdc else 0) if cs else cc
    if n in ("vcvb", "vcvbg", "vcvbq"):
        m3 = vals[2]
        p2, lb, cs = bool(m3 & 8), bool(m3 & 2), bool(m3 & 1)
        a, an = val(VR[V(1)], p2 or lb)
        v = -a if an else a
        if n == "vcvbq":
            VR[V(0)] = v & ((1 << 128) - 1)
            return cc
        bits = 32 if n == "vcvb" else 64
        orc = bool(vals[3] & 4) if len(vals) > 3 else False
        ov = a > ((1 << bits) - 1 if lb else (1 << (bits - 1)) - (0 if an else 1))
        r = 0 if orc and ov else v & ((1 << bits) - 1)
        g = vals[0]
        gpr[g] = r if bits == 64 else (gpr[g] & ~0xffffffff) | r
        return (3 if ov else 0) if cs else cc
    if n == "vlip":
        i2, i3 = vals[1], vals[2]
        VR[V(0)] = (i2 << (4 * ((i3 & 7) + 1))) | (0xd if i3 & 8 else 0xc)
        return cc
    if n in ("vpkz", "vupkz"):
        v, d, L = V(0), vals[1], vals[3] & 0x1f
        if n == "vpkz":
            z = win[d:d + L + 1]
            ds = [b & 0xf for b in z]
            x = 0
            for dd in ds:
                x = (x << 4) | dd
            VR[v] = ((x << 4) | (z[-1] >> 4)) & ((1 << 128) - 1)
        else:
            x = VR[v]
            out = bytearray(L + 1)
            out[L] = ((x & 0xf) << 4) | ((x >> 4) & 0xf)
            for k in range(1, L + 1):
                out[L - k] = 0xf0 | ((x >> (4 + 4 * k)) & 0xf)
            win[d:d + L + 1] = out
        return cc
    if n in ("vupkzh", "vupkzl"):
        nb = nibs(VR[V(1)])
        if n == "vupkzh":
            out = [0xf0] + [0xf0 | nb[k] for k in range(15)]
        else:
            out = [0xf0 | nb[15 + k] for k in range(16)]
            zs = 0xf if vals[2] & 2 else nb[31]
            out[15] = (zs << 4) | nb[30]
        VR[V(0)] = int.from_bytes(bytes(out), "big")
        return cc
    if n == "vpkzr":
        i4, m5 = vals[3], vals[4]
        rdc, p1, cs = i4 & 0x1f, bool(m5 & 2), bool(m5 & 1)
        z = ((VR[V(1)] << 128) | VR[V(2)]).to_bytes(32, "big")
        ds = [b & 0xf for b in z]
        zs = z[31] >> 4
        ps = 0xf if p1 else zs
        x = 0
        for dd in ds[32 - rdc:]:
            x = (x << 4) | dd
        VR[V(0)] = ((x << 4) | ps) & ((1 << 128) - 1)
        bad = any(d > 9 for d in ds) or zs <= 9
        hi = any(ds[:32 - rdc])
        if cs:
            if hi or bad:
                return 3
            return 0 if not any(ds) else (2 if isplus(ps) else 1)
        return cc
    if n == "vclzdp":
        x = VR[V(1)]
        nb = nibs(x)
        c = next((k for k in range(31) if nb[k]), 31)
        m3 = vals[2]
        nz, cs = bool(m3 & 2), bool(m3 & 1)
        VR[V(0)] = c << 64
        valid = all(d <= 9 for d in nb[:31]) and nb[31] > 9
        neg, zero = nb[31] in (0xb, 0xd), not any(nb[:31])
        if not cs:
            return cc
        if valid and zero and not (nz and neg):
            return 0
        if (valid and neg) or (nz and neg and zero):
            return 1
        if valid and not zero and not neg:
            return 2
        return 3
    if n == "vpsop":
        i3, i4, m5 = vals[2], vals[3], vals[4]
        rdc = i3 & 0x1f
        nz, ps, pc = bool(i4 & 0x40), bool(i4 & 0x10), bool(i4 & 2)
        so = (i4 >> 2) & 3
        cs = bool(m5 & 1)
        x = VR[V(1)]
        nb = nibs(x)
        s = nb[31]
        mask = ((1 << (4 * rdc)) - 1) << 4
        d = x & mask
        lz = next((k for k in range(31) if nb[k]), 31)
        ov = lz < 31 - rdc
        z = d == 0
        pl, mi = isplus(s), s in (0xb, 0xd)
        P = 0xf if pc else 0xc
        ns, c = s, 0
        if so == 0:
            if ps:
                c = 0 if z else (1 if mi else 2)
            elif not z:
                c = 1 if mi else 2
                ns = P if pl else (0xd if mi else s)
            else:
                ns = P if pl else ((0xd if nz else P) if mi else s)
        elif so == 1:
            if pl or mi:
                if not z:
                    c, ns = (1, 0xd) if pl else (2, P)
                else:
                    ns = 0xd if (pl and nz) else P
        elif so == 2:
            c, ns = (0 if z else 2), P
        else:
            c = 0 if z else 1
            ns = 0xd if (not z or nz) else P
        VR[V(0)] = d | ns
        if z:
            c = 0
        if ov:
            c = 3
        return c if cs else cc
    def sign_ok(s, stc, allz):
        return {0: s >= 0xa, 1: (s >= 0xa) if not allz else isplus(s), 2: s in (0xc, 0xd),
                3: s == 0xc or (not allz and s == 0xd), 4: s == 0xf, 5: s == 0xf,
                6: s in (0xc, 0xd, 0xf), 7: s in (0xc, 0xf) or (not allz and s == 0xd)}[stc]
    if n == "vtp":
        x = VR[V(0)]
        i2 = vals[1] if len(vals) > 1 else 0
        et, bpt = bool(i2 & 0x8000), bool(i2 & 0x4000)
        stc, dc = ((i2 >> 5) & 7) if et else 0, i2 & 0x1f
        nb = nibs(x)
        rng_ = range(31 - dc if et else 0, 31)
        bad = any(nb[k] > 9 for k in rng_)
        if et and bpt and dc and dc % 2 == 0 and nb[30 - dc]:
            bad = True
        allz = all(nb[k] == 0 for k in rng_) and dc != 0
        ok = sign_ok(nb[31], stc, allz)
        return (0 if ok else 1) if not bad else (2 if ok else 3)
    if n.startswith("vsch") or n == "vscshp":
        a, neg = val(VR[V(1)])
        N = a * 10 ** ((VR[V(2)] >> 64) & 7)
        sg = int(neg)
        def norm(N, D, rnd):
            nd = (N.bit_length() + 3) // 4
            if rnd and nd > D:
                N += 8 << (4 * (nd - D - 1))
                nd = (N.bit_length() + 3) // 4
            f = N << (4 * (D - nd)) if nd <= D else N >> (4 * (nd - D))
            return f, 64 + nd
        if N == 0:
            VR[V(0)] = 0
            return cc
        if n != "vscshp":
            m4, rm = (vals[3], bool(vals[4] & 1)) if n == "vschp" else ({"vschsp": 2, "vschdp": 3, "vschxp": 4}[n], bool(vals[3] & 1))
            D = {2: 6, 3: 14, 4: 28}[m4]
            f, ch = norm(N, D, rm)
            if m4 == 2:
                VR[V(0)] = ((sg << 31) | (ch << 24) | f) << 96
            elif m4 == 3:
                VR[V(0)] = ((sg << 63) | (ch << 56) | f) << 64
            else:
                VR[V(0)] = (((sg << 63) | (ch << 56) | (f >> 56)) << 64) | (sg << 63) | (((ch - 14) & 0x7f) << 56) | (f & ((1 << 56) - 1))
            return cc
        f, ch = norm(N, 6, False)
        r = ((sg << 31) | (ch << 24) | f) << 96
        nd = ch - 64
        if nd > 6:
            R = N & ((1 << (4 * (nd - 6))) - 1)
            if R:
                f2, ch2 = norm(R, 14, False)
                r |= (sg << 63) | (ch2 << 56) | f2
        VR[V(0)] = r
        return cc
    if n == "vcsph":
        x = VR[V(1)]
        if x == 0:
            VR[V(0)] = 0xc
            return cc
        hi, lo = x >> 64, x & ((1 << 64) - 1)
        F = (((hi & ((1 << 56) - 1)) >> 8) << 64) | ((hi & 0xff) << 56) | (lo & ((1 << 56) - 1))
        k = ((hi >> 56) & 0x7f) - 92
        N = F * 10 ** ((VR[V(2)] >> 64) & 0x1f)
        if k >= 0:
            q = N << (4 * k)
        else:
            q = N >> (-4 * k)
            if vals[3] & 1 and (N >> (-4 * k - 1)) & 1:
                q += 1
        VR[V(0)] = (int(f"{q % 10 ** 31:031d}", 16) << 4) | (0xd if hi >> 63 else 0xc)
        return cc
    if n == "vtz":
        z = ((VR[V(0)] << 128) | VR[V(1)]).to_bytes(32, "big")
        i3 = vals[2]
        ssc, ls = bool(i3 & 0x4000), bool(i3 & 0x2000)
        dsc, stc, dc = (i3 >> 8) & 0x1f, (i3 >> 5) & 7, i3 & 0x1f
        B = lambda k: z[31 - k]
        sb = B(dc if ls else 0)
        if ssc:
            zero, bad = True, False
        else:
            zero, bad = (sb & 0xf) == 0, (sb & 0xf) > 9
        lo, hi = (0 if ls else 1), dc - (1 if ls and not ssc else 0)
        for k in range(lo, hi):
            b = B(k)
            if not ssc and not ls and k >= dsc and b == 0x40:
                zero = False
                continue
            if b < 0xf0 or b > 0xf9:
                bad = True
            zero = zero and b == 0xf0
        if ssc:
            ok = stc not in (2, 3) or sb == 0x4e or (sb == 0x60 and not (stc == 3 and zero))
        else:
            ok = sign_ok(sb >> 4, stc, zero)
        return (0 if ok else 1) if not bad else (2 if ok else 3)
    raise KeyError(n)

# ---- PERFORM FLOATING-POINT OPERATION ---------------------------------------------------------
import pfpo_model as PM

def pfpo_bfp(rng, z):
    eb, fb, bias, w = PM.BFP[z]
    s = rng.getrandbits(1)
    r = rng.random()
    frac = rng.choice([rng.getrandbits(fb), rng.getrandbits(fb), 0, 1 << (fb - 1), (1 << fb) - 1,
                       rng.getrandbits(fb) & ((1 << rng.randrange(1, fb + 1)) - 1) << rng.randrange(fb)]) & ((1 << fb) - 1)
    if r < 0.06:
        ex = (1 << eb) - 1
        if rng.random() < 0.5:
            frac = 0 if rng.random() < 0.4 else rng.getrandbits(rng.randrange(1, fb + 1)) | 1
    elif r < 0.12:
        ex = 0
    elif r < 0.55:
        ex = bias + rng.randrange(-12, 13)
    elif r < 0.8:
        ex = rng.randrange(1, (1 << eb) - 1)
    else:
        ex = rng.choice([1, 2, (1 << eb) - 2, (1 << eb) - 3, bias - fb, bias + 1, bias + 20 + rng.randrange(4)])
    return (s << (w - 1)) | (ex << fb) | frac

def pfpo_hfp(rng, z):
    D = PM.HFPD[z]
    s = rng.getrandbits(1)
    ch = rng.choice([64 + rng.randrange(-10, 11)] * 3 + [rng.randrange(128), 0, 127, 1, 126])
    r = rng.random()
    frac = rng.getrandbits(4 * D)
    if r < 0.1:
        frac = 0
    elif r < 0.3:
        frac = (rng.getrandbits(4 * D) & ((1 << rng.randrange(1, 4 * D + 1)) - 1)) << rng.randrange(4 * D)
        frac &= (1 << 4 * D) - 1
    elif r < 0.5:
        frac |= 1 << (4 * D - 4 + rng.randrange(4))
    if z == 2:
        hi = (s << 63) | (ch << 56) | (frac >> 56)
        lo = (s << 63) | (((ch - 14) & 0x7f) << 56) | (frac & ((1 << 56) - 1))
        return (hi << 64) | lo
    w = 32 if z == 0 else 64
    return (s << (w - 1)) | (ch << (w - 8)) | frac

def pfpo_fix(rng, win):
    """window: FPR 0-7 (f4/f6 the source), GR0 at 64"""
    case = os.environ.get("PFPO_CASE")
    if case:                      # "r0hex,f4hex,f6hex[;...]": fixed tests in turn (debugging)
        cases = case.split(";")
        pfpo_fix.n = getattr(pfpo_fix, "n", -1) + 1
        r0, f4, f6 = (int(x, 16) for x in cases[pfpo_fix.n % len(cases)].split(","))
        win[32:40], win[48:56], win[64:72] = (v.to_bytes(8, "big") for v in (f4, f6, r0))
        return
    ofc = [0, 1, 2, 5, 6, 7, 8, 9, 10]
    c1, c2 = rng.choice(ofc), rng.choice(ofc)
    for _ in range(8):
        if PM.OFC[c1][0] != PM.OFC[c2][0]:
            break
        c2 = rng.choice(ofc)
    if rng.random() < 0.03:
        c2 = rng.choice([3, 4, 11, 0x80])
    k2, z2 = PM.OFC.get(c2, ("h", 0))
    bits = {"h": pfpo_hfp, "b": pfpo_bfp, "d": lambda r, z: dfp_value(r, PM.DFPF[z])}[k2](rng, z2)
    if k2 == "d" and c1 in (0, 1, 2, 5, 6, 7) and rng.random() < 0.25:
        # an integer exactly halfway between two values of the target format (ties)
        Pt = {0: 24, 1: 56, 2: 112, 5: 24, 6: 53, 7: 113}[c1]
        n = ((rng.getrandbits(Pt) | (1 << (Pt - 1))) << 1) | 1
        nd = len(str(n))
        zf = 0 if nd <= 7 else (1 if nd <= 16 else (2 if nd <= 34 else None))
        if zf is not None:
            c2, z2 = 8 + zf, zf
            d = Decimal((rng.getrandbits(1), tuple(int(ch) for ch in str(n)), 0))
            bits = DM.encode(PM.DFPF[z2], d)
    w = {0: 32, 1: 64, 2: 128}[z2]
    if z2 == 2:
        hi, lo = bits >> 64, bits & ((1 << 64) - 1)
    else:
        hi, lo = (bits << 32 if z2 == 0 else bits), 0
        lo = rng.getrandbits(64)
    win[32:40] = hi.to_bytes(8, "big")
    win[48:56] = lo.to_bytes(8, "big")
    for a in (0, 16):                       # the old first operand: random
        win[a:a + 8] = rng.getrandbits(64).to_bytes(8, "big")
    rm = rng.choice([0, 1, 8, 9, 10, 11, 12, 13, 14, 15] * 3 + [2, 5, 7])
    b58, b59 = rng.getrandbits(1), rng.getrandbits(1)
    if PM.OFC.get(c1, ("h",))[0] == "b" and rng.random() < 0.95:
        b58 = b59 = 0
    r0 = (rng.getrandbits(32) << 32) | ((1 if rng.random() > 0.02 else rng.choice([0, 2, 0x7f])) << 24) \
        | (c1 << 16) | (c2 << 8) | (rng.getrandbits(1) << 7) | (rng.getrandbits(1) << 6) | (b58 << 5) | (b59 << 4) | rm
    if rng.random() < 0.08:
        r0 |= 1 << 31
    else:
        r0 &= ~(1 << 31)
    win[64:72] = r0.to_bytes(8, "big")

def pfpo_model(name, w, e, fpr, gpr, win, cc):
    r0 = int.from_bytes(win[64:72], "big")
    f0, f2, ncc, rc = PM.convert(r0, fpr[0], fpr[2], fpr[4], fpr[6])
    fpr[0], fpr[2] = f0, f2
    if rc:
        gpr[1] &= ~0xffffffff & ((1 << 64) - 1)
    return cc if ncc is None else ncc

def main():
    mode, out = sys.argv[1], sys.argv[2]
    if mode in ("hfp", "dfp", "vpd", "pfpo"):
        per = int(sys.argv[5]) if len(sys.argv) > 5 else 100
        seed = sys.argv[6] if len(sys.argv) > 6 else "1"
        tests, data, meta = hfp_tests(sys.argv[3], sys.argv[4], per, seed, mode)
        img, stop, outp, scratch = Q.build(tests, data, len(tests))
        open(f"{out}/qd.elf", "wb").write(img)
        with open(f"{out}/qd.txt", "w") as fh:
            fh.write(f"# stop 0x{stop:x} out 0x{outp:x} len {len(tests) * Q.REC + Q.SCRATCH} entry 0x{Q.BASE + 0x1000:x} "
                     f"in 0x{outp - len(tests) * Q.REC:x} {mode} {sys.argv[3]} {sys.argv[4]}\n")
            for i, (n, w, e) in enumerate(meta):
                fh.write(f"{i} {n} {w}\n")
        print(f"{len(tests)} tests over {len(set(m[0] for m in meta))} mnemonics")
        return
    if mode == "gen":
        per = int(sys.argv[3]) if len(sys.argv) > 3 else 200
        seed = sys.argv[4] if len(sys.argv) > 4 else "1"
        ents = [e for e in Q.special_entries() if e[0] in KINDS]
        tests, data, names = Q.make_per_entry(ents, per, seed)
        img, stop, outp, scratch = Q.build(tests, data, len(tests))
        open(f"{out}/qd.elf", "wb").write(img)
        with open(f"{out}/qd.txt", "w") as fh:
            fh.write(f"# stop 0x{stop:x} out 0x{outp:x} len {len(tests) * Q.REC + Q.SCRATCH} entry 0x{Q.BASE + 0x1000:x} "
                     f"in 0x{outp - len(tests) * Q.REC:x}\n")
            for i, (n, w) in enumerate(names):
                fh.write(f"{i} {n} {w}\n")
        print(f"{len(tests)} tests over {len(ents)} mnemonics")
        return
    g = open(sys.argv[3], "rb").read()
    nex = int(sys.argv[4]) if len(sys.argv) > 4 else 3
    lines = open(f"{out}/qd.txt").read().splitlines()
    hdr = lines[0].split()
    inp = int(hdr[10], 16)
    WBASE[0] = inp + 2 * (len(lines) - 1) * Q.REC          # build(): scratch after inputs, outputs
    ents = {}
    fmodel = hfp_model
    if len(hdr) > 11 and hdr[11] in ("hfp", "dfp", "vpd", "pfpo"):
        fmodel = {"hfp": hfp_model, "dfp": dfp_model, "vpd": vpd_model, "pfpo": pfpo_model}[hdr[11]]
        import qemu_diff
        OPS = {}
        for line in open(hdr[13]):
            i, b, sh, f = line.split()
            OPS[int(i)] = (int(b), int(sh), int(f, 16))
        for line in open(hdr[12]):
            f = line.split()
            ents.setdefault(f[0], []).append((f[0], bytes.fromhex(f[1]), bytes.fromhex(f[2]), int(f[3]),
                                              [(int(x),) + OPS[int(x)] for x in f[7:]]))
    img = open(f"{out}/qd.elf", "rb").read()
    from collections import Counter, defaultdict
    per, bad, ok = Counter(), defaultdict(list), 0
    for l in lines[1:]:
        i, n, w = l.split()
        i = int(i)
        rec = img[inp - Q.BASE + i * Q.REC:inp - Q.BASE + (i + 1) * Q.REC]
        win = bytearray(rec[240:496])
        cc_in = (struct.unpack_from(">Q", rec, 32)[0] >> 28) & 3
        gw = g[i * Q.REC + 240:(i + 1) * Q.REC]
        gcc = (struct.unpack_from(">Q", g, i * Q.REC + 32)[0] >> 28) & 3
        per[n] += 1
        if ents:
            wb = bytes.fromhex(w)
            e = next(x for x in ents[n] if all((wb[k] & x[2][k]) == x[1][k] for k in range(len(wb))))
            fpr = [int.from_bytes(win[8 * k:8 * k + 8], "big") for k in range(8)] + [0] * 8
            gpr = {k + 1: struct.unpack_from(">Q", rec, 8 * k)[0] for k in range(4)}
            VR[:] = [0] * 16 + [int.from_bytes(rec[Q.VOFF + 16 * k:Q.VOFF + 16 * k + 16], "big") for k in range(8)]
            cc = fmodel(n, wb, e, fpr, gpr, win, cc_in)
            gf = list(struct.unpack_from(">8Q", g, i * Q.REC + Q.FOFF))
            gg = {k + 1: struct.unpack_from(">Q", g, i * Q.REC + 8 * k)[0] for k in range(4)}
            gv = [int.from_bytes(g[i * Q.REC + Q.VOFF + 16 * k:i * Q.REC + Q.VOFF + 16 * k + 16], "big") for k in range(8)]
            if fpr[:8] == gf and gpr == gg and cc == gcc and VR[16:] == gv and bytes(win) == gw:
                ok += 1
            else:
                d = [f"f{k}: model {fpr[k]:016x} ghidra {gf[k]:016x}" for k in range(8) if fpr[k] != gf[k]]
                d += [f"r{k}: model {gpr[k]:x} ghidra {gg[k]:x}" for k in gpr if gpr[k] != gg[k]]
                d += [f"v{16 + k}: model {VR[16 + k]:032x} ghidra {gv[k]:032x}" for k in range(8) if VR[16 + k] != gv[k]]
                if cc != gcc:
                    d.append(f"cc model {cc} ghidra {gcc}")
                if bytes(win) != gw:
                    dd = [k for k in range(256) if win[k] != gw[k]]
                    d.append(f"window differs at {dd[:6]} model {bytes(win[dd[0]:dd[0] + 8]).hex()} ghidra {gw[dd[0]:dd[0] + 8].hex()}")
                if n == "pfpo":
                    d.append(f"r0={win[64:72].hex()} f4={win[32:40].hex()} f6={win[48:56].hex()}")
                bad[n].append(f"{w}: " + "; ".join(d))
            continue
        code = bytes.fromhex(w)[8:]                 # after LA r1 / LA r2
        cc = model(code, win, cc_in)
        if bytes(win) == gw and cc == gcc:
            ok += 1
        else:
            diff = [k for k in range(256) if win[k] != gw[k]]
            bad[n].append(f"{w}: cc model {cc} ghidra {gcc}; window differs at {diff[:6]}"
                          f" model {bytes(win[diff[0]:diff[0] + 8]).hex() if diff else ''}"
                          f" ghidra {gw[diff[0]:diff[0] + 8].hex() if diff else ''}")
    total = sum(per.values())
    print(f"model vs ghidra: {ok}/{total} tests agree ({100 * ok / max(1, total):.2f}%), "
          f"{len(per)} mnemonics, {len(bad)} with differences")
    for n, v in sorted(bad.items(), key=lambda kv: -len(kv[1])):
        print(f"  [{len(v):4d}/{per[n]}] {n}")
        for d in v[:nex]:
            print(f"         {d}")

if __name__ == "__main__":
    main()
