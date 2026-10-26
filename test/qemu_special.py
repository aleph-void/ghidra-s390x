"""Hand-built qemu_diff tests for instructions random operands cannot exercise: register pairs
with addresses and lengths, valid packed-decimal and Unicode data, divides that must not trap,
register ranges, long moves and compares.

Each generator gets a random.Random and returns (code, regs, window):
  code    bytes run as the test: setup instructions, the instruction under test, then LGR
          copies of results kept in unrecorded registers (r0, r5) into r1-r4. Setup and copies
          do not change the condition code.
  regs    initial r1-r4 (None: random)
  window  the 256-byte storage window at r12 (None: random)
r10-r13 belong to the harness and r6 is its branch marker; tests use r0-r5 and r7-r9.
"""
import struct

W = 12          # window base register

def be(n, v):
    return v.to_bytes(n, "big")

# ---- instruction formats ----------------------------------------------------------------------
def RR(op, r1, r2):
    return bytes([op, r1 << 4 | r2])
def RRE(op, r1, r2):
    return be(2, op) + bytes([0, r1 << 4 | r2])
def RRF(op, r1, r2, r3=0, m4=0):          # RRF-a/c: R3/M3 in bits 16-19, M4 in 20-23
    return be(2, op) + bytes([r3 << 4 | m4, r1 << 4 | r2])
def RX(op, r1, d, x=0, b=W):
    return bytes([op, r1 << 4 | x, b << 4 | d >> 8, d & 0xff])
def RXY(op, op2, r1, d, x=0, b=W):
    d &= 0xfffff
    return bytes([op, r1 << 4 | x, b << 4 | (d >> 8 & 0xf), d & 0xff, d >> 12, op2])
def RS(op, r1, r3, d, b=W):
    return bytes([op, r1 << 4 | r3, b << 4 | d >> 8, d & 0xff])
def RSY(op, op2, r1, r3, d, b=W):
    d &= 0xfffff
    return bytes([op, r1 << 4 | r3, b << 4 | (d >> 8 & 0xf), d & 0xff, d >> 12, op2])
def SS(op, l, d1, d2, b1=W, b2=W):         # SS-a: one 8-bit length (length - 1)
    return bytes([op, l, b1 << 4 | d1 >> 8, d1 & 0xff, b2 << 4 | d2 >> 8, d2 & 0xff])
def SS2(op, l1, l2, d1, d2, b1=W, b2=W):   # SS-b: two 4-bit lengths
    return SS(op, l1 << 4 | l2, d1, d2, b1, b2)
def SSE(op, d1, d2, b1=W, b2=W):
    return be(2, op) + bytes([b1 << 4 | d1 >> 8, d1 & 0xff, b2 << 4 | d2 >> 8, d2 & 0xff])
def SSF(op2, r3, d1, d2, b1=W, b2=W):      # C8x
    return bytes([0xc8, r3 << 4 | op2, b1 << 4 | d1 >> 8, d1 & 0xff, b2 << 4 | d2 >> 8, d2 & 0xff])

LA = lambda r, d, b=W: RX(0x41, r, d, 0, b)
def LOOP(ins):
    """BRC 1 back to an interruptible instruction: repeat while it ends with cc 3 (a
    CPU-determined amount processed), as real code does."""
    return bytes([0xa7, 0x14]) + struct.pack(">h", -(len(ins) // 2))
LGR = lambda r1, r2: RRE(0xb904, r1, r2)
LGHI = lambda r, i: bytes([0xa7, r << 4 | 9]) + struct.pack(">h", i)
LGFI = lambda r, i: bytes([0xc0, r << 4 | 1]) + struct.pack(">i", i)
LLILF = lambda r, i: bytes([0xc0, r << 4 | 0xf]) + struct.pack(">I", i)
L32 = lambda r, d: RX(0x58, r, d)
LG = lambda r, d: RXY(0xe3, 0x04, r, d)

def rnd_window(rng):
    return bytearray(rng.getrandbits(8) for _ in range(256))

def rnd64(rng):
    return rng.getrandbits(64) if rng.random() < 0.7 else rng.choice(
        [0, 1, 0xffffffffffffffff, 0x8000000000000000, 0x7fffffff, 0x80000000, 0xffffffff])

# ---- compare and swap, quadword ----------------------------------------------------------------
def g_cds(kind):
    def f(rng):
        win = rnd_window(rng)
        w = 8 if kind == "cdsg" else 4
        d = rng.randrange(0, 256 - 2 * w, 2 * w)
        regs = [rnd64(rng) for _ in range(4)]
        pre = LGR(5, 1)                                  # R3+1 = r5, from random r1
        if rng.random() < 0.5:                           # make the comparison equal
            pre += (LG(2, d) + LG(3, d + 8)) if w == 8 else (L32(2, d) + L32(3, d + 4))
        op = {"cds": RS(0xbb, 2, 4, d), "cdsy": RSY(0xeb, 0x31, 2, 4, d), "cdsg": RSY(0xeb, 0x3e, 2, 4, d)}[kind]
        return pre + op, regs, win
    return f

def g_lpq(rng):
    d = rng.randrange(0, 240, 16)
    return RXY(0xe3, 0x8f, 2, d), None, rnd_window(rng)

def g_stpq(rng):
    d = rng.randrange(0, 240, 16)
    return RXY(0xe3, 0x8e, 2, d), None, rnd_window(rng)

def g_lpd(kind):
    def f(rng):
        w = 4 if kind == "lpd" else 8
        d1, d2 = rng.randrange(0, 256 - w, w), rng.randrange(0, 256 - w, w)
        return SSF(4 if kind == "lpd" else 5, 2, d1, d2), None, rnd_window(rng)
    return f

def g_csst(rng):
    # qemu 10.2: sc 0 aborts (extract32 with length 0) and function code 0 puts the old value
    # into R3 bits 0-31 instead of 32-63; both are covered by hand-computed tests (emu_tests.py)
    fc, sc = rng.randrange(1, 3), rng.randrange(1, 5)
    win = rnd_window(rng)
    a1 = rng.randrange(0, 64, 16)               # first operand
    pl = 64 + 16 * rng.randrange(2)             # parameter list (16-byte aligned)
    a2 = 160 + 16 * rng.randrange(5)            # store location
    regs = [rnd64(rng) for _ in range(4)]
    # R3 = r2 (r2:r3 for fc 2); r0 = fc | sc << 8; r1 = parameter-list address
    pre = LLILF(0, fc | sc << 8) + LA(1, pl)
    if rng.random() < 0.6:                      # equal comparison
        n = 4 << fc
        pre += {4: L32(2, a1), 8: LG(2, a1), 16: LG(2, a1) + LG(3, a1 + 8)}[n]
    return pre + SSF(2, 2, a1, a2), regs, win

# ---- decimal conversions ----------------------------------------------------------------------
def packed(v, n, rng, neg=None):
    """n-byte packed decimal of |v| with a random valid sign (B/D minus, A/C/E/F plus)."""
    neg = v < 0 if neg is None else neg
    digits = f"{abs(v):0{2 * n - 1}d}"
    assert len(digits) == 2 * n - 1
    sign = rng.choice([0xb, 0xd]) if neg else rng.choice([0xa, 0xc, 0xe, 0xf])
    nib = [int(c) for c in digits] + [sign]
    return bytes(nib[2 * i] << 4 | nib[2 * i + 1] for i in range(n))

def g_cvb(kind):
    def f(rng):
        n = 16 if kind == "cvbg" else 8
        lim = (1 << 63) - 1 if kind == "cvbg" else (1 << 31) - 1
        v = rng.choice([0, 1, -1, lim, -lim]) if rng.random() < 0.2 else rng.randint(-lim, lim)
        if rng.random() < 0.5:
            v = rng.randint(-99999, 99999)
        win = rnd_window(rng)
        d = rng.randrange(0, 256 - n, 8)
        win[d:d + n] = packed(v, n, rng)
        op = {"cvb": RX(0x4f, 2, d), "cvby": RXY(0xe3, 0x06, 2, d), "cvbg": RXY(0xe3, 0x0e, 2, d)}[kind]
        return op, None, win
    return f

def g_cvd(kind):
    def f(rng):
        n = 16 if kind == "cvdg" else 8
        d = rng.randrange(0, 256 - n, 8)
        op = {"cvd": RX(0x4e, 2, d), "cvdy": RXY(0xe3, 0x26, 2, d), "cvdg": RXY(0xe3, 0x2e, 2, d)}[kind]
        return op, None, rnd_window(rng)
    return f

# ---- compare under mask, multiply, divide -----------------------------------------------------
def g_clm(kind):
    def f(rng):
        regs = [rnd64(rng) for _ in range(4)]
        m = rng.randrange(16)
        d = rng.randrange(0, 250)
        win = rnd_window(rng)
        half = (regs[0] >> 32) if kind == "clmh" else regs[0]
        sel = [(half >> (24 - 8 * i)) & 0xff for i in range(4) if m & (8 >> i)]
        if rng.random() < 0.6:                       # equal prefix, maybe one differing byte
            win[d:d + len(sel)] = bytes(sel)
            if sel and rng.random() < 0.5:
                win[d + rng.randrange(len(sel))] = rng.getrandbits(8)
        op = {"clm": RS(0xbd, 1, m, d), "clmy": RSY(0xeb, 0x21, 1, m, d), "clmh": RSY(0xeb, 0x20, 1, m, d)}[kind]
        return op, regs, win
    return f

def g_mul(kind):
    def f(rng):
        regs = [rnd64(rng) for _ in range(4)]
        d = rng.randrange(0, 248, 8)
        op = {"m": RX(0x5c, 2, d), "mr": RR(0x1c, 2, 4), "mfy": RXY(0xe3, 0x5c, 2, d),
              "ml": RXY(0xe3, 0x96, 2, d), "mlr": RRE(0xb996, 2, 4), "mlg": RXY(0xe3, 0x86, 2, d),
              "mlgr": RRE(0xb986, 2, 4), "mg": RXY(0xe3, 0x84, 2, d), "mgrk": RRF(0xb9ec, 2, 1, 4)}[kind]
        return op, regs, rnd_window(rng)
    return f

def g_div(kind):
    """Dividend/divisor chosen so the quotient fits (no fixed-point-divide exception)."""
    def f(rng):
        win = rnd_window(rng)
        d = rng.randrange(0, 248, 8)
        regs = [rnd64(rng) for _ in range(4)]
        signed = kind in ("d", "dr", "dsg", "dsgr", "dsgf", "dsgfr")
        wide = kind in ("dlg", "dlgr")
        qbits = 63 if wide or kind.startswith("dsg") else 31
        dbits = 64 if kind in ("dlg", "dlgr", "dsg", "dsgr") else 32
        while True:
            dv = rng.getrandbits(dbits) or 1
            if signed:
                dv = dv - (1 << dbits) if dv >> (dbits - 1) else dv
                if dv == 0:
                    continue
            q = rng.getrandbits(rng.randint(1, qbits - 1))
            if signed and rng.random() < 0.5:
                q = -q
            r = rng.randrange(abs(dv))
            if signed and rng.random() < 0.5 and q != 0:
                r = -r
            n = q * dv + r
            if signed and n != 0 and (n < 0) != (r < 0) and r != 0:
                continue
            if not wide and abs(n) >= (1 << 63 if signed else 1 << 64):
                continue
            break
        mask = (1 << dbits) - 1
        if kind in ("d", "dr", "dl", "dlr"):          # 64-bit dividend in r2:r3 (low words)
            nn = n & ((1 << 64) - 1)
            regs[1] = (regs[1] & ~0xffffffff) | (nn >> 32)
            regs[2] = (regs[2] & ~0xffffffff) | (nn & 0xffffffff)
        elif wide:                                    # 128-bit dividend in r2:r3
            regs[1], regs[2] = n >> 64, n & ((1 << 64) - 1)
        else:                                         # DSG*: 64-bit dividend in r3
            regs[2] = n & ((1 << 64) - 1)
        dvu = dv & mask
        if kind.endswith("r"):
            regs[3] = (regs[3] & ~mask) | dvu if dbits == 32 else dvu
        else:
            win[d:d + dbits // 8] = be(dbits // 8, dvu)
        op = {"d": RX(0x5d, 2, d), "dr": RR(0x1d, 2, 4), "dl": RXY(0xe3, 0x97, 2, d),
              "dlr": RRE(0xb997, 2, 4), "dlg": RXY(0xe3, 0x87, 2, d), "dlgr": RRE(0xb987, 2, 4),
              "dsg": RXY(0xe3, 0x0d, 2, d), "dsgr": RRE(0xb90d, 2, 4), "dsgf": RXY(0xe3, 0x1d, 2, d),
              "dsgfr": RRE(0xb91d, 2, 4)}[kind]
        return op, regs, win
    return f

# ---- register ranges (r1-r4 only: the harness owns r10-r13) -----------------------------------
def g_range(kind):
    def f(rng):
        a = rng.randint(1, 4)
        b = rng.randint(a, 4)
        d = rng.randrange(0, 200, 8)
        op = {"lm": RS(0x98, a, b, d), "stm": RS(0x90, a, b, d), "lmg": RSY(0xeb, 0x04, a, b, d),
              "stmg": RSY(0xeb, 0x24, a, b, d), "lmh": RSY(0xeb, 0x96, a, b, d),
              "stmh": RSY(0xeb, 0x26, a, b, d), "lmy": RSY(0xeb, 0x98, a, b, d),
              "stmy": RSY(0xeb, 0x90, a, b, d)}[kind]
        return op, None, rnd_window(rng)
    return f

# ---- long moves and compares, string search, checksum -----------------------------------------
def g_long(kind):
    def f(rng):
        win = rnd_window(rng)
        regs = [rnd64(rng) for _ in range(4)]
        dl, sl = rng.randrange(0, 100), rng.randrange(0, 100)
        if rng.random() < 0.3:
            sl = dl
        if kind in ("mvclu", "clclu"):
            dl, sl = dl & ~1, sl & ~1
        pad = rng.getrandbits(16)
        if kind.startswith("cl") and rng.random() < 0.7:     # mostly-equal operands
            win[128:128 + min(dl, sl)] = win[0:min(dl, sl)]
            if rng.random() < 0.5 and min(dl, sl):
                win[128 + rng.randrange(min(dl, sl))] ^= 1 << rng.randrange(8)
        if kind in ("mvcl", "clcl"):                   # 24-bit lengths, pad in R2+1 bits 32-39
            pre = LA(2, 0) + LLILF(3, dl) + LA(4, 128) + LLILF(5, sl | (pad & 0xff) << 24)
            op = RR(0x0e if kind == "mvcl" else 0x0f, 2, 4)
        else:
            pre = LA(2, 0) + LGHI(3, dl) + LA(4, 128) + LGHI(5, sl)
            p = pad & (0xff if kind in ("mvcle", "clcle") else 0xffff)
            op = {"mvcle": RS(0xa8, 2, 4, p, 0), "clcle": RS(0xa9, 2, 4, p, 0),
                  "mvclu": RSY(0xeb, 0x8e, 2, 4, p, 0), "clclu": RSY(0xeb, 0x8f, 2, 4, p, 0)}[kind]
        return pre + op + LOOP(op) + LGR(1, 5), regs, win
    return f

def g_mvcrl(rng):
    l = rng.randrange(0, 100)
    d1, d2 = rng.randrange(0, 150), rng.randrange(0, 150)
    return LGHI(0, l) + SSE(0xe50a, d1, d2), None, rnd_window(rng)

def g_cksm(rng):
    l = rng.randrange(0, 120)
    regs = [rnd64(rng) for _ in range(4)]
    op = RRE(0xb241, 1, 2)
    return LA(2, rng.randrange(0, 100)) + LGHI(3, l) + op + LOOP(op), regs, rnd_window(rng)

def g_srst(kind):
    def f(rng):
        win = rnd_window(rng)
        st = rng.randrange(0, 100)
        if kind == "srstu":
            st &= ~1
        n = rng.randrange(0, 120)
        c = rng.getrandbits(16 if kind == "srstu" else 8)
        if rng.random() < 0.6:
            pos = st + rng.randrange(0, n + 1)
            if kind == "srstu":
                pos &= ~1
            win[pos:pos + (2 if kind == "srstu" else 1)] = be(2 if kind == "srstu" else 1, c)
        pre = LLILF(0, c) + LA(2, st) + LA(1, st + n)
        op = RRE(0xb9be if kind == "srstu" else 0xb25e, 1, 2)
        return pre + op + LOOP(op), None, win
    return f

def g_strop(kind):
    """MVST/CLST: terminator in GR0 bits 56-63."""
    def f(rng):
        win = rnd_window(rng)
        c = rng.getrandbits(8)
        a, b = rng.randrange(0, 100), 128 + rng.randrange(0, 100)
        if kind == "clst" and rng.random() < 0.7:
            k = rng.randrange(1, 28)
            win[b:b + k] = win[a:a + k]
        win[a + rng.randrange(0, 25)] = c
        if kind == "clst":
            win[b + rng.randrange(0, 25)] = c
        op = RRE(0xb255 if kind == "mvst" else 0xb25d, 4 if kind == "mvst" else 2, 2 if kind == "mvst" else 4)
        pre = LLILF(0, c) + LA(2, a) + LA(4, b)
        return pre + op + LOOP(op), None, win
    return f

# ---- Unicode conversions ----------------------------------------------------------------------
def utf_text(rng, enc, n):
    """n code points (some invalid when bad) encoded as UTF-8/16/32 bytes."""
    out = bytearray()
    for _ in range(n):
        cp = rng.choice([rng.randrange(0x80), rng.randrange(0x80, 0x800), rng.randrange(0x800, 0xd800),
                         rng.randrange(0xe000, 0x10000), rng.randrange(0x10000, 0x110000)])
        if enc == 8:
            out += chr(cp).encode("utf-8")
        elif enc == 16:
            out += chr(cp).encode("utf-16-be")
        else:
            out += cp.to_bytes(4, "big")
    if rng.random() < 0.2:                              # a damaged byte
        out[rng.randrange(len(out))] = rng.getrandbits(8)
    return bytes(out)

def g_cu(kind):
    frm, to = {"1": 8, "2": 16, "4": 32}[kind[2]], {"1": 8, "2": 16, "4": 32}[kind[3]]
    op = {"cu12": 0xb2a7, "cu14": 0xb9b0, "cu21": 0xb2a6, "cu24": 0xb9b1, "cu41": 0xb9b2, "cu42": 0xb9b3}[kind]
    def f(rng):
        win = rnd_window(rng)
        txt = utf_text(rng, frm, rng.randrange(1, 12))[:120]
        win[0:len(txt)] = txt
        sl = rng.randrange(0, len(txt) + 1) if rng.random() < 0.3 else len(txt)
        dl = rng.randrange(0, 128)
        m3 = rng.randrange(2) if kind in ("cu12", "cu14", "cu21", "cu24") else 0
        pre = LA(2, 128) + LGHI(3, dl) + LA(4, 0) + LGHI(5, sl)
        ins = RRF(op, 2, 4, m3)
        return pre + ins + LOOP(ins) + LGR(1, 5), None, win
    return f

# ---- packed decimal (SS formats) ---------------------------------------------------------------
def rnd_packed(rng, n, maxdig=None):
    dig = 2 * n - 1 if maxdig is None else min(maxdig, 2 * n - 1)
    v = rng.randrange(10 ** rng.randint(0, dig))
    return packed(v if rng.random() < 0.5 else -v, n, rng)

def g_dec(kind):
    def f(rng):
        win = rnd_window(rng)
        l1, l2 = rng.randint(1, 16), rng.randint(1, 16)
        d1, d2 = rng.randrange(0, 100), 128 + rng.randrange(0, 100)
        if kind in ("ap", "sp", "zap", "cp"):
            win[d1:d1 + l1] = rnd_packed(rng, l1)
            win[d2:d2 + l2] = rnd_packed(rng, l2)
            op = SS2({"ap": 0xfa, "sp": 0xfb, "zap": 0xf8, "cp": 0xf9}[kind], l1 - 1, l2 - 1, d1, d2)
        elif kind == "mp":                 # l1 > l2, l2 <= 8, first operand has l2 leading zero bytes
            l2 = rng.randint(1, 8)
            l1 = rng.randint(l2 + 1, 16)
            win[d1:d1 + l1] = bytes(l2) + rnd_packed(rng, l1 - l2)
            win[d2:d2 + l2] = rnd_packed(rng, l2)
            op = SS2(0xfc, l1 - 1, l2 - 1, d1, d2)
        elif kind == "dp":                 # quotient fits: dividend has l2 leading zero bytes
            l2 = rng.randint(1, 8)
            l1 = rng.randint(l2 + 1, 16)
            dv = rnd_packed(rng, l2)
            while all(b == 0 for b in dv[:-1]) and dv[-1] >> 4 == 0:
                dv = rnd_packed(rng, l2)
            win[d1:d1 + l1] = bytes(l2) + rnd_packed(rng, l1 - l2)
            win[d2:d2 + l2] = dv
            op = SS2(0xfd, l1 - 1, l2 - 1, d1, d2)
        elif kind == "srp":                # shift amount: 6-bit signed address, rounding digit I3
            win[d1:d1 + l1] = rnd_packed(rng, l1)
            sh = rng.randint(-31, 31) & 63
            op = SS(0xf0, (l1 - 1) << 4 | rng.randrange(10), d1, sh, W, 0)
        elif kind == "tp":
            win[d1:d1 + l1] = rnd_packed(rng, l1) if rng.random() < 0.7 else bytes(rng.getrandbits(8) for _ in range(l1))
            op = bytes([0xeb, (l1 - 1) << 4, W << 4 | d1 >> 8, d1 & 0xff, 0, 0xc0])
        elif kind in ("pack", "unpk", "mvo"):
            if kind == "unpk":             # qemu 10.2 ignores the leftmost source byte: never need it
                l2 = rng.randint(2, 16)
                l1 = rng.randint(1, min(16, 2 * (l2 - 2) + 1))
            if kind == "mvo":
                win[d1:d1 + l1] = rnd_packed(rng, l1)
            op = SS2({"pack": 0xf2, "unpk": 0xf3, "mvo": 0xf1}[kind], l1 - 1, l2 - 1, d1, d2)
        elif kind in ("pka", "pku"):       # 16-byte packed result; source length L2
            # qemu 10.2 ignores the leftmost character: only full-length operands (where the
            # architecture drops it too) compare equal; shorter ones are in emu_tests.py
            l = 32 if kind == "pka" else 64
            d2 = 128 + rng.randrange(0, 128 - l)
            op = SS(0xe9 if kind == "pka" else 0xe1, l - 1, d1, d2)
        elif kind in ("unpka", "unpku"):   # 16-byte packed source, result length L1
            win[d2:d2 + 16] = rnd_packed(rng, 16)
            l = rng.randint(1, 32 if kind == "unpka" else 64)
            if kind == "unpku":
                l = max(2, l & ~1)
            d1 = rng.randrange(0, 128 - l)
            op = SS(0xea if kind == "unpka" else 0xe2, l - 1, d1, d2)
        elif kind in ("mvn", "mvz", "mvcin", "tr", "trt", "trtr", "ed", "edmk", "nc", "oc", "xc", "clc", "mvc"):
            l = rng.randrange(0, 20 if kind in ("ed", "edmk") else 64)
            if kind in ("ed", "edmk"):
                win[d2:d2 + 16] = rnd_packed(rng, 16)
                pat = bytearray([rng.choice([0x40, 0x5c])])
                for _ in range(l):
                    pat.append(rng.choice([0x20, 0x20, 0x21, 0x22, 0x4b, 0x6b, 0xc3]))
                win[d1:d1 + l + 1] = pat[:l + 1]
            if kind == "mvcin":
                d2 = max(d2, 128 + l)
            if kind in ("tr", "trt", "trtr"):
                d2 = 0                     # 256-byte table = the window itself
            op = SS({"mvn": 0xd1, "mvz": 0xd3, "mvcin": 0xe8, "tr": 0xdc, "trt": 0xdd, "trtr": 0xd0,
                     "ed": 0xde, "edmk": 0xdf, "nc": 0xd4, "oc": 0xd6, "xc": 0xd7, "clc": 0xd5,
                     "mvc": 0xd2}[kind], l, d1, d2)
        else:
            raise KeyError(kind)
        return LA(1, 0) + LA(2, 0) + op, None, win
    return f

# ---- fused multiply-add edge cases ------------------------------------------------------------
FMT = {4: (8, 23), 8: (11, 52), 16: (15, 112)}

def fbits(rng, n, exp=None, sign=None, mant=None):
    eb, mb = FMT[n]
    e = rng.randrange(1, (1 << eb) - 1) if exp is None else exp
    m = rng.getrandbits(mb) if mant is None else mant
    sg = rng.getrandbits(1) if sign is None else sign
    return (sg << (8 * n - 1)) | (e << mb) | m

def g_fma(op, n):
    """Operands chosen for cancellation, results near the subnormal and overflow limits, and
    product/addend exponent gaps around the precision (where double rounding would show)."""
    def f(rng):
        eb, mb = FMT[n]
        bias = (1 << (eb - 1)) - 1
        kind = rng.randrange(6)
        a = fbits(rng, n); b = fbits(rng, n); c = fbits(rng, n)
        ea, ebb = rng.randrange(1, (1 << eb) - 1), rng.randrange(1, (1 << eb) - 1)
        if kind == 0:     # c = -(a * 1.0...) : near-total cancellation
            b = fbits(rng, n, bias, 0, rng.choice([0, 1, 2, rng.getrandbits(4)]))
            c = a ^ (1 << (8 * n - 1)) ^ rng.choice([0, 0, 1, 2])
        elif kind == 1:   # tiny product, tiny addend: subnormal results
            a = fbits(rng, n, rng.randrange(1, bias // 2)); b = fbits(rng, n, rng.randrange(1, bias // 2 + 2))
            c = fbits(rng, n, rng.choice([0, 1, 2]))
        elif kind == 2:   # huge product: overflow and near-overflow
            a = fbits(rng, n, rng.randrange(bias + bias // 2, (1 << eb) - 1)); b = fbits(rng, n, rng.randrange(bias, bias + bias // 2 + 2))
        elif kind == 3:   # addend just below the product's last bit (rounding decided by c)
            ea2 = rng.randrange(bias - 20, bias + 20)
            a = fbits(rng, n, ea2); b = fbits(rng, n, bias)
            c = fbits(rng, n, ea2 - mb - rng.randrange(0, 4), None, rng.choice([0, rng.getrandbits(mb)]))
        elif kind == 4:   # addend far below: only its sign/stickiness matters
            a = fbits(rng, n, bias); b = fbits(rng, n, bias, None, rng.choice([0, 1 << (mb - 1)]))
            c = fbits(rng, n, rng.randrange(1, max(2, bias - 2 * mb)))
        win = rnd_window(rng)
        for k, v in enumerate((a, b, c)):
            win[16 * k:16 * k + 16] = v.to_bytes(n, "big") + bytes(16 - n)
        vl = lambda v, d: bytes([0xe7, (v & 15) << 4, 0xc0, d, 0x08, 0x06])
        return vl(16, 0) + vl(17, 16) + vl(18, 32) + op, None, win
    return f

def g_trxx(kind):
    """TROO/TROT/TRTO/TRTT: table at the window start (GR1), test character in GR0."""
    op = {"trtt": 0xb990, "trto": 0xb991, "trot": 0xb992, "troo": 0xb993}[kind]
    ss = 1 if kind[2] == "o" else 2
    ds = 1 if kind[3] == "o" else 2
    def f(rng):
        win = rnd_window(rng)
        if kind == "trot":         # qemu 10.2 compares only GR0 bits 56-63 for TROT: keep the
            for k in range(0, 128, 2):    # 2-byte function characters below 256
                win[k] = 0
        n = rng.randrange(1, 30)
        lim = 128 // ds
        for k in range(n):
            win[128 + ss * k:128 + ss * (k + 1)] = rng.randrange(lim).to_bytes(ss, "big")
        tst = int.from_bytes(win[0:ds], "big") if rng.random() < 0.5 else rng.getrandbits(8 * ds)
        if rng.random() < 0.5:
            c = rng.randrange(n)
            sv = int.from_bytes(win[128 + ss * c:128 + ss * (c + 1)], "big")
            tst = int.from_bytes(win[sv * ds:sv * ds + ds], "big")
        m3 = rng.randrange(2)
        pre = LA(1, 0) + LLILF(0, tst) + LA(2, 192) + LGHI(3, n * ss) + LA(4, 128)
        ins = RRF(op, 2, 4, m3)
        return pre + ins + LOOP(ins) + LGR(1, 0), None, win
    return f

SPECIAL = {}
for _k in ("troo", "trot", "trto", "trtt"):
    SPECIAL[_k] = g_trxx(_k)
for _m, _op in (("wfmaxb", "e73014082f8f"), ("wfmsxb", "e73014082f8e"), ("wfnmaxb", "e73014082f9f"),
                ("wfmadb", "e73013082f8f"), ("wfmsdb", "e73013082f8e"), ("wfmasb", "e73012082f8f")):
    SPECIAL[f"{_m}-edge"] = g_fma(bytes.fromhex(_op), {"x": 16, "d": 8, "s": 4}[_m[-2]])
for k in ("cds", "cdsy", "cdsg"):
    SPECIAL[k] = g_cds(k)
SPECIAL.update(lpq=g_lpq, stpq=g_stpq, lpd=g_lpd("lpd"), lpdg=g_lpd("lpdg"), csst=g_csst,
               mvcrl=g_mvcrl, cksm=g_cksm)
for k in ("cvb", "cvby", "cvbg"):
    SPECIAL[k] = g_cvb(k)
for k in ("cvd", "cvdy", "cvdg"):
    SPECIAL[k] = g_cvd(k)
for k in ("clm", "clmy", "clmh"):
    SPECIAL[k] = g_clm(k)
for k in ("m", "mr", "mfy", "ml", "mlr", "mlg", "mlgr", "mg", "mgrk"):
    SPECIAL[k] = g_mul(k)
for k in ("d", "dr", "dl", "dlr", "dlg", "dlgr", "dsg", "dsgr", "dsgf", "dsgfr"):
    SPECIAL[k] = g_div(k)
# STMH is left out: qemu 10.2 stores zeros (it shifts the register left instead of right before
# a 32-bit store); emu_tests.py checks it by hand
for k in ("lm", "stm", "lmg", "stmg", "lmh", "lmy", "stmy"):
    SPECIAL[k] = g_range(k)
for k in ("mvcl", "clcl", "mvcle", "clcle", "mvclu", "clclu"):
    SPECIAL[k] = g_long(k)
for k in ("srst", "srstu"):
    SPECIAL[k] = g_srst(k)
for k in ("mvst", "clst"):
    SPECIAL[k] = g_strop(k)
for k in ("cu12", "cu14", "cu21", "cu24", "cu41", "cu42"):
    SPECIAL[k] = g_cu(k)
for k in ("ap", "sp", "zap", "cp", "mp", "dp", "srp", "tp", "pack", "unpk", "mvo", "pka", "pku",
          "unpka", "unpku", "mvn", "mvz", "mvcin", "tr", "trt", "trtr", "ed", "edmk"):
    SPECIAL[k] = g_dec(k)
