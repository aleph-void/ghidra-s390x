"""P-code for general instructions outside the core tables (used by gen_semantics.py):
compare-double-and-swap and quadword loads/stores, decimal conversions, long moves and
compares, Unicode conversions, checksum, string search, PSW/FPC/access-register state.

The interruptible instructions (CU*, MVCLE, CKSM, SRST*) complete in one execution: processing
everything at once is a valid CPU-determined amount, and the condition code then reports the
final state (never 3). Exceptions (specification, data, fixed-point divide) are not raised.
Semantics follow the Principles of Operation; qemu-s390x (target/s390x/tcg) is the oracle.
"""
import re

# fields the semantics need beyond the table operands: name -> [(shift, bits, kind)]
EXTRA = {
    "csst": [(8, 4, "gpro")],           # R3 + 1 for function code 2
    "stpq": [(8, 4, "gpro")],           # R1 + 1
    "epsw": [(28, 4, "u")],             # R2 field: 0 means "not stored"
    "cksm": [(28, 4, "gpro")],          # R2 + 1
}
for _n in ("pack", "unpk", "mvo"):      # SS-b: L1, L2 (lengths - 1)
    EXTRA[_n] = [(8, 4, "u"), (12, 4, "u")]
for _n in ("mvcin", "unpka", "unpku", "pka", "pku", "ed", "edmk"):   # one 8-bit length - 1
    EXTRA[_n] = [(8, 8, "u")]
for _n in ("ap", "sp", "zap", "cp", "mp", "dp"):       # SS-b: L1, L2
    EXTRA[_n] = [(8, 4, "u"), (12, 4, "u")]
EXTRA["srp"] = [(8, 4, "u")]                          # L1 (I3 is an operand)

CAP = 0x1000   # unbounded string searches stop after this many units with cc 3 (CPU-determined)

def _set32(reg, val, tag):
    return f"local s32_{tag}:4 = {val}; {reg} = ({reg} & 0xffffffff00000000) | zext(s32_{tag});"

def cds(o, p, w):
    """CDS/CDSY (w 4), CDSG (w 8): R1:R1+1 compared with the 2w-byte operand; equal: R3:R3+1
    stored, cc 0; unequal: the operand loaded into R1:R1+1, cc 1."""
    W = 2 * w
    sel = (lambda r: f"{r}:4") if w == 4 else (lambda r: r)
    t = [f"local ea:8 = {o[2]}; local cur:{W} = *:{W} ea;",
         f"local cv:{W} = (zext({sel(o[0])}) << {8 * w}) | zext({sel(p[0])});",
         "if (cur != cv) goto <ne>;",
         f"local nv:{W} = (zext({sel(o[1])}) << {8 * w}) | zext({sel(p[1])});",
         f"*:{W} ea = nv; cc = 0; goto <done>;",
         "<ne>",
         f"local hi:{w} = cur({w}); local lo:{w} = cur:{w};"]
    if w == 4:
        t += [_set32(o[0], "hi", "h"), _set32(p[0], "lo", "l")]
    else:
        t += [f"{o[0]} = hi; {p[0]} = lo;"]
    t += ["cc = 1;", "<done>"]
    return "\n".join(t)

def csst(o, r3o):
    """COMPARE AND SWAP AND STORE: function code GR0 bits 56-63 (0: 4, 1: 8, 2: 16 bytes),
    storage characteristic GR0 bits 48-55 (store size 2**sc); the replacement value and the
    store value are left-aligned at the parameter list GR1 (16-byte aligned) and +16."""
    r3 = o[2]
    t = ["local fc:1 = r0:1; local sc8:8 = (r0 >> 8) & 0xff; local pl:8 = r1 & ~15;",
         f"local ad1:8 = {o[0]}; local ad2:8 = {o[1]}; local sv:16 = *:16 (pl + 16);",
         "if (fc == 1) goto <fc1>; if (fc == 2) goto <fc2>;",
         f"local ov4:4 = *:4 ad1; local cv4:4 = {r3}:4;",
         "if (ov4 != cv4) goto <ne4>; local nv4:4 = *:4 pl; *:4 ad1 = nv4; cc = 0; goto <st>;",
         "<ne4>", _set32(r3, "ov4", "o"), "cc = 1; goto <done>;",
         "<fc1>",
         f"local ov8:8 = *:8 ad1;",
         f"if (ov8 != {r3}) goto <ne8>; local nv8:8 = *:8 pl; *:8 ad1 = nv8; cc = 0; goto <st>;",
         f"<ne8> {r3} = ov8; cc = 1; goto <done>;",
         "<fc2>",
         f"local ov16:16 = *:16 ad1; local cv16:16 = (zext({r3}) << 64) | zext({r3o});",
         "if (ov16 != cv16) goto <ne16>; local nv16:16 = *:16 pl; *:16 ad1 = nv16; cc = 0; goto <st>;",
         f"<ne16> {r3} = ov16(8); {r3o} = ov16:8; cc = 1; goto <done>;",
         "<st>",
         "if (sc8 == 0) goto <s0>; if (sc8 == 1) goto <s1>; if (sc8 == 2) goto <s2>; if (sc8 == 3) goto <s3>;",
         "*:16 ad2 = sv; goto <done>;",
         "<s0> *:1 ad2 = sv(15); goto <done>;",
         "<s1> *:2 ad2 = sv(14); goto <done>;",
         "<s2> *:4 ad2 = sv(12); goto <done>;",
         "<s3> *:8 ad2 = sv(8);",
         "<done>"]
    return "\n".join(t)

def lpq(o, p):
    return f"local v:16 = *:16 {o[1]}; {o[0]} = v(8); {p[0]} = v:8;"

def stpq(o, r1o):
    return f"local v:16 = (zext({o[0]}) << 64) | zext({r1o}); *:16 {o[1]} = v;"

def lpd(o, p, w):
    """LPD/LPDG: R3 from the first operand, R3+1 from the second; cc 0 (fetched interlocked)."""
    t = [f"local va:{w} = *:{w} {o[1]}; local vb:{w} = *:{w} {o[2]};"]
    if w == 4:
        t += [_set32(o[0], "va", "a"), _set32(p[0], "vb", "b")]
    else:
        t += [f"{o[0]} = va; {p[0]} = vb;"]
    t.append("cc = 0;")
    return "\n".join(t)

def cvb(o, n, w):
    """CONVERT TO BINARY: n-byte packed decimal (2n-1 digits and a sign) to a w-byte signed
    integer in R1 (bits 32-63 for w 4). Sign B or D is negative."""
    t = [f"local p:{n} = *:{n} {o[1]}; local acc:16 = zext(0:8); local k:8 = 0;",
         "<lp>",
         f"local tp:{n} = p >> {8 * n - 4}; local d:1 = tp:1 & 0xf; acc = acc * 10 + zext(d); p = p << 4; k = k + 1;",
         f"if (k < {2 * n - 1}) goto <lp>;",
         f"local ts:{n} = p >> {8 * n - 4}; local sg:1 = ts:1 & 0xf; local neg:1 = (sg == 0xb) || (sg == 0xd);",
         "acc = zext(neg) * (-acc) + zext(!neg) * acc;"]
    t.append(_set32(o[0], "acc:4", "r") if w == 4 else f"{o[0]} = acc:8;")
    return "\n".join(t)

def cvd(o, n, w):
    """CONVERT TO DECIMAL: signed w-byte R1 (bits 32-63 for w 4) to n-byte packed decimal,
    sign C (plus) or D (minus)."""
    src = f"sext({o[0]}:4)" if w == 4 else f"sext({o[0]})"
    t = [f"local v:16 = {src}; local neg:1 = v s< 0; local mag:16 = zext(neg) * (-v) + zext(!neg) * v;",
         f"local dec:{n} = 0xc + zext(neg); local sh:{n} = 4;",
         "<lp>",
         (f"local dg:16 = mag % 10; local dgn:{n} = dg:{n}; " if n < 16 else "local dgn:16 = mag % 10; ") + "dec = dec | (dgn << sh); mag = mag / 10; sh = sh + 4;",
         f"if (sh < {8 * n}) goto <lp>;",
         f"*:{n} {o[1]} = dec;"]
    return "\n".join(t)

def clm(o, high):
    """CLM/CLMY/CLMH: the bytes of R1 bits 32-63 (CLMH: 0-31) selected by M3, left to right,
    against consecutive storage bytes; cc 0 equal (or M3 0), 1 first operand low, 2 high."""
    half = f"{o[0]}(4)" if high else f"{o[0]}:4"
    t = [f"local h:4 = {half}; local mv:8 = {o[1]}; local mk:1 = mv:1; local ea:8 = {o[2]};",
         "local done:1 = 0; cc = 0;"]
    for i in range(4):
        t.append(f"if ((mk & {8 >> i}) == 0) goto <m{i}>;")
        t.append(f"local hb{i}:4 = h >> {8 * (3 - i)}; local b{i}:1 = hb{i}:1; local s{i}:1 = *:1 ea; ea = ea + 1;")
        t.append(f"local d{i}:1 = !done && (b{i} != s{i}); cc = zext(d{i}) * (1 + zext(b{i} > s{i})) + zext(!d{i}) * cc;")
        t.append(f"done = done || d{i};")
        t.append(f"<m{i}>")
    return "\n".join(t)

def mvcle(o, p, unicode):
    """MVCLE/MVCLU: move R3 operand (address R3, length R3+1) to R1 (address R1, length R1+1),
    padding with the second-operand address bits 56-63 (MVCLU: 48-63; the pad byte alternates
    by the parity of the remaining length). cc compares the initial lengths."""
    t = [f"local dst:8 = {o[0]}; local dl:8 = {p[0]}; local src:8 = {o[1]}; local sl:8 = {p[1]};",
         f"local padv:8 = {o[2]}; local pad1:1 = padv:1; local padh:8 = padv >> 8; local pad2:1 = padh:1;",
         "cc = zext(dl < sl) + zext(dl > sl) * 2;",
         "if (dl == 0) goto <done>;",
         "<lp>",
         "if (sl == 0) goto <pad>;",
         "local b:1 = *:1 src; *:1 dst = b; src = src + 1; sl = sl - 1; goto <nx>;",
         "<pad>"]
    if unicode:
        t.append("if ((dl & 1) == 0) goto <pe>; *:1 dst = pad1; goto <nx>;\n<pe> *:1 dst = pad2;")
    else:
        t.append("*:1 dst = pad1;")
    t += ["<nx>",
          "dst = dst + 1; dl = dl - 1;",
          "if (dl != 0) goto <lp>;",
          "<done>",
          f"{o[0]} = dst; {p[0]} = dl; {o[1]} = src; {p[1]} = sl;"]
    return "\n".join(t)

def mvcrl(o):
    """MVCRL: move GR0 bits 56-63 + 1 bytes from right to left."""
    return "\n".join([f"local d:8 = {o[0]}; local s:8 = {o[1]}; local l:8 = r0 & 0xff;",
                      "<lp>",
                      "local b:1 = *:1 (s + l); *:1 (d + l) = b;",
                      "if (l == 0) goto <done>; l = l - 1; goto <lp>;",
                      "<done>"])

def cksm(o, p):
    """CHECKSUM: 32-bit end-around-carry sum of the second operand (address R2, length R2+1;
    a partial last word is padded on the right with zeros) added to R1 bits 32-63."""
    return "\n".join([
        f"local a:8 = {o[1]}; local l:8 = {p[1]}; local s:8 = zext({o[0]}:4);",
        "<lp>",
        "if (l < 4) goto <tail>;",
        "local w:4 = *:4 a; s = s + zext(w); a = a + 4; l = l - 4; goto <lp>;",
        "<tail>",
        "if (l == 0) goto <fold>;",
        "local t1:1 = *:1 a; local t2:1 = 0; local t3:1 = 0;",
        "if (l < 2) goto <tw>; t2 = *:1 (a + 1);",
        "if (l < 3) goto <tw>; t3 = *:1 (a + 2);",
        "<tw>",
        "s = s + ((zext(t1) << 24) | (zext(t2) << 16) | (zext(t3) << 8)); a = a + l; l = 0;",
        "<fold>",
        "s = (s & 0xffffffff) + (s >> 32);",
        "s = (s & 0xffffffff) + (s >> 32);",
        _set32(o[0], "s:4", "c"),
        f"{o[1]} = a; {p[1]} = l; cc = 0;"])

def srstu(o):
    """SEARCH STRING UNICODE: the 2-byte character in GR0 bits 48-63 from R2 up to the end R1
    (one extra byte when the address parities differ); found: R1 = its address, cc 1; not
    found: cc 2."""
    return "\n".join([
        f"local c:2 = r0:2; local st:8 = {o[1]}; local en:8 = {o[0]}; en = en + ((st ^ en) & 1); local cnt:8 = 0;",
        "<lp>",
        "if (st == en) goto <nf>;",
        f"if (cnt == {CAP}) goto <part>; cnt = cnt + 1;",
        "local v:2 = *:2 st;",
        f"if (v == c) goto <found>; st = st + 2; goto <lp>;",
        f"<found> {o[0]} = st; cc = 1; goto <done>;",
        f"<part> {o[1]} = st; cc = 3; goto <done>;",
        "<nf> cc = 2;",
        "<done>"])

# ---- Unicode conversions (CU12 CU14 CU21 CU24 CU41 CU42) ---------------------------------------
def _dec(kind):
    """Decode one character at src (slen bytes left) into c / il; <end0> when the source is
    exhausted (cc 0), <inv> on an invalid character (cc 2). enh: M3 well-formedness check."""
    if kind == 8:
        return """if (slen < 1) goto <end0>;
local s0:1 = *:1 src; local s1:1 = 0; local s2:1 = 0; local s3:1 = 0;
if (s0 > 0x7f) goto <u2>; c = zext(s0); il = 1; goto <dok>;
<u2>
local lim:1 = 0xbf + zext(enh) * 2;
if (s0 <= lim) goto <inv>;
if (s0 > 0xdf) goto <u3>;
if (slen < 2) goto <end0>;
s1 = *:1 (src + 1); c = (zext(s0 & 0x1f) << 6) | zext(s1 & 0x3f); il = 2;
if (enh && ((s1 & 0xc0) != 0x80)) goto <inv>; goto <dok>;
<u3>
if (s0 > 0xef) goto <u4>;
if (slen < 3) goto <end0>;
s1 = *:1 (src + 1); s2 = *:1 (src + 2);
c = (zext(s0 & 0x0f) << 12) | (zext(s1 & 0x3f) << 6) | zext(s2 & 0x3f); il = 3;
if (enh && (((s1 & 0xc0) != 0x80) || ((s2 & 0xc0) != 0x80) || (c < 0x800) || ((c >= 0xd800) && (c <= 0xdfff)))) goto <inv>;
goto <dok>;
<u4>
local lim4:1 = 0xf7 - zext(enh) * 3;
if (s0 > lim4) goto <inv>;
if (slen < 4) goto <end0>;
s1 = *:1 (src + 1); s2 = *:1 (src + 2); s3 = *:1 (src + 3);
c = (zext(s0 & 0x07) << 18) | (zext(s1 & 0x3f) << 12) | (zext(s2 & 0x3f) << 6) | zext(s3 & 0x3f); il = 4;
if (enh && (((s1 & 0xc0) != 0x80) || ((s2 & 0xc0) != 0x80) || ((s3 & 0xc0) != 0x80) || (c < 0x10000) || (c > 0x10ffff))) goto <inv>;
<dok>"""
    if kind == 16:
        return """if (slen < 2) goto <end0>;
local h0:2 = *:2 src;
if ((h0 & 0xfc00) == 0xd800) goto <sp>; c = zext(h0); il = 2; goto <dok>;
<sp>
if (slen < 4) goto <end0>;
local h1:2 = *:2 (src + 2);
c = ((zext((h0 >> 6) & 0xf) + 1) << 16) | (zext(h0 & 0x3f) << 10) | zext(h1 & 0x3ff); il = 4;
if (enh && ((h1 & 0xfc00) != 0xdc00)) goto <inv>;
<dok>"""
    return """if (slen < 4) goto <end0>;
c = *:4 src; il = 4;
if (((c >= 0xd800) && (c <= 0xdbff)) || (c > 0x10ffff)) goto <inv>;"""

def _enc(kind):
    """Store c at dst (dlen bytes left), ol = its length; <full> when it does not fit (cc 1)."""
    if kind == 8:
        return """ol = 1 + zext(c > 0x7f) + zext(c > 0x7ff) + zext(c > 0xffff);
if (dlen < ol) goto <full>;
local cq6:4 = c >> 6; local cq12:4 = c >> 12; local cq18:4 = c >> 18;
if (ol != 1) goto <e2>; *:1 dst = c:1; goto <eok>;
<e2>
if (ol != 2) goto <e3>;
local x0:1 = 0xc0 | (cq6:1 & 0x1f); local x1:1 = 0x80 | (c:1 & 0x3f);
*:1 dst = x0; *:1 (dst + 1) = x1; goto <eok>;
<e3>
if (ol != 3) goto <e4>;
local y0:1 = 0xe0 | (cq12:1 & 0x0f); local y1:1 = 0x80 | (cq6:1 & 0x3f); local y2:1 = 0x80 | (c:1 & 0x3f);
*:1 dst = y0; *:1 (dst + 1) = y1; *:1 (dst + 2) = y2; goto <eok>;
<e4>
local z0:1 = 0xf0 | (cq18:1 & 0x07); local z1:1 = 0x80 | (cq12:1 & 0x3f);
local z2:1 = 0x80 | (cq6:1 & 0x3f); local z3:1 = 0x80 | (c:1 & 0x3f);
*:1 dst = z0; *:1 (dst + 1) = z1; *:1 (dst + 2) = z2; *:1 (dst + 3) = z3;
<eok>"""
    if kind == 16:
        return """ol = 2 + zext(c > 0xffff) * 2;
if (dlen < ol) goto <full>;
if (ol != 2) goto <e4>; *:2 dst = c:2; goto <eok>;
<e4>
local w1:2 = 0xdc00 | (c:2 & 0x3ff);
local cq10:4 = c >> 10; local cq16:4 = c >> 16;
local w0:2 = 0xd800 | (cq10:2 & 0x3f) | (((cq16:2 & 0x1f) - 1) << 6);
*:2 dst = w0; *:2 (dst + 2) = w1;
<eok>"""
    return """ol = 4;
if (dlen < ol) goto <full>;
*:4 dst = c;"""

def cuxx(o, p, frm, to):
    m3 = o[2] if len(o) > 2 else "0"
    return "\n".join([
        f"local dst:8 = {o[0]}; local dlen:8 = {p[0]}; local src:8 = {o[1]}; local slen:8 = {p[1]};",
        f"local m3:8 = {m3}; local enh:1 = (m3 & 1) != 0;",
        "local c:4 = 0; local il:8 = 0; local ol:8 = 0;",
        "<top>",
        _dec(frm),
        _enc(to),
        "src = src + il; slen = slen - il; dst = dst + ol; dlen = dlen - ol; goto <top>;",
        "<end0> cc = 0; goto <done>;",
        "<full> cc = 1; goto <done>;",
        "<inv> cc = 2;",
        "<done>",
        f"{o[0]} = dst; {p[0]} = dlen; {o[1]} = src; {p[1]} = slen;"])

# ---- packed-decimal and character-format moves (processed right to left, byte by byte) ----------
def pack(o, x):
    """PACK: the rightmost byte has its nibbles swapped; then the digits (rightmost 4 bits) of
    the remaining second-operand bytes, right to left, two per first-operand byte; zeros when
    the second operand is exhausted."""
    return "\n".join([
        f"local pa1:8 = {o[0]}; local pa2:8 = {o[1]}; local i1:8 = {x[0]}; local i2:8 = {x[1]};",
        "local lb:1 = *:1 (pa2 + i2); *:1 (pa1 + i1) = (lb << 4) | (lb >> 4);",
        "<lp>",
        "if (i1 == 0) goto <done>; i1 = i1 - 1;",
        "local lo:1 = 0; local hi:1 = 0;",
        "if (i2 == 0) goto <st>; i2 = i2 - 1; lo = *:1 (pa2 + i2) & 0xf;",
        "if (i2 == 0) goto <st>; i2 = i2 - 1; hi = *:1 (pa2 + i2) & 0xf;",
        "<st>",
        "*:1 (pa1 + i1) = (hi << 4) | lo; goto <lp>;",
        "<done>"])

def unpk(o, x):
    """UNPK: the rightmost byte has its nibbles swapped; then every remaining digit of the second
    operand, right to left, becomes a zoned byte F0+digit; F0 when the second operand is
    exhausted."""
    return "\n".join([
        f"local pa1:8 = {o[0]}; local pa2:8 = {o[1]}; local i1:8 = {x[0]}; local i2:8 = {x[1]};",
        "local lb:1 = *:1 (pa2 + i2); *:1 (pa1 + i1) = (lb << 4) | (lb >> 4);",
        "local cur:1 = 0; local half:1 = 0;",
        "<lp>",
        "if (i1 == 0) goto <done>; i1 = i1 - 1;",
        "if (half != 0) goto <hi>;",
        "cur = 0; if (i2 == 0) goto <lo>; i2 = i2 - 1; cur = *:1 (pa2 + i2);",
        "<lo>",
        "*:1 (pa1 + i1) = 0xf0 | (cur & 0xf); half = 1; goto <lp>;",
        "<hi>",
        "*:1 (pa1 + i1) = 0xf0 | (cur >> 4); half = 0; goto <lp>;",
        "<done>"])

def mvo(o, x):
    """MVO: the second operand is placed to the left of the rightmost four bits of the first
    operand (a 4-bit shift left), padded with zeros on the left."""
    return "\n".join([
        f"local pa1:8 = {o[0]}; local pa2:8 = {o[1]}; local i1:8 = {x[0]}; local i2:8 = {x[1]};",
        "local sb:1 = *:1 (pa2 + i2); local db:1 = *:1 (pa1 + i1);",
        "*:1 (pa1 + i1) = (db & 0x0f) | (sb << 4);",
        "<lp>",
        "if (i1 == 0) goto <done>; i1 = i1 - 1;",
        "local nb:1 = sb >> 4; sb = 0;",
        "if (i2 == 0) goto <st>; i2 = i2 - 1; sb = *:1 (pa2 + i2);",
        "<st>",
        "*:1 (pa1 + i1) = nb | (sb << 4); goto <lp>;",
        "<done>"])

def mvcin(o, x):
    """MVCIN: the second-operand address designates its rightmost byte; the bytes are moved in
    reverse order."""
    return "\n".join([
        f"local pa1:8 = {o[0]}; local pa2:8 = {o[1]}; local n:8 = {x[0]}; local k:8 = 0;",
        "<lp>",
        "local b:1 = *:1 (pa2 - k); *:1 (pa1 + k) = b;",
        "if (k == n) goto <done>; k = k + 1; goto <lp>;",
        "<done>"])

def pkau(o, x, ss):
    """PKA/PKU: 16-byte packed result (sign C) from the rightmost 4 bits of each 1-byte (PKA) or
    2-byte (PKU) character of the second operand, right to left; 31 digits at most."""
    return "\n".join([
        f"local pa1:8 = {o[0]}; local pa2:8 = {o[1]}; local n:8 = {x[0]} + 1;",
        "local acc:16 = 0xc; local sh:8 = 4; local k:8 = n;",
        "<lp>",
        f"if (k == 0) goto <st>; if (sh == 128) goto <st>; k = k - {ss};",
        f"local ch:1 = *:1 (pa2 + k + {ss - 1}); local dg:16 = zext(ch & 0xf);",
        "acc = acc | (dg << sh); sh = sh + 4; goto <lp>;",
        "<st>",
        "*:16 pa1 = acc;"])

def unpkau(o, x, ds):
    """UNPKA/UNPKU: the 16-byte packed second operand to 1-byte (UNPKA) or 2-byte (UNPKU)
    characters 30+digit, right to left (a 32-character result has a leftmost '0'); cc 0 plus,
    1 minus, 3 invalid sign."""
    return "\n".join([
        f"local pa1:8 = {o[0]}; local pa2:8 = {o[1]}; local n:8 = {x[0]} + 1;",
        "local p:16 = *:16 pa2; local sg:1 = p:1 & 0xf;",
        "cc = zext(sg < 0xa) * 3 + zext((sg == 0xb) || (sg == 0xd));",
        "p = p >> 4; local k:8 = n;",
        "<lp>",
        f"if (k == 0) goto <done>; k = k - {ds};",
        f"local dg:{ds} = p:{ds} & 0xf; *:{ds} (pa1 + k) = 0x30 + dg; p = p >> 4; goto <lp>;",
        "<done>"])

def mvst(o):
    """MVST: move up to and including the terminator (GR0 bits 56-63); R1 = the address of the
    terminator in the first operand, cc 1."""
    return "\n".join([
        f"local d:8 = {o[0]}; local s:8 = {o[1]}; local t:1 = r0:1; local cnt:8 = 0;",
        "<lp>",
        f"if (cnt == {CAP}) goto <part>; cnt = cnt + 1;",
        "local b:1 = *:1 s; *:1 d = b;",
        "if (b == t) goto <done>; d = d + 1; s = s + 1; goto <lp>;",
        f"<part> {o[0]} = d; {o[1]} = s; cc = 3; goto <end>;",
        f"<done> {o[0]} = d; cc = 1;",
        "<end>"])

def srst(o):
    """SRST: search from R2 up to (not including) R1 for the byte in GR0 bits 56-63: found,
    R1 = its address and cc 1; not found, cc 2."""
    return "\n".join([
        f"local c:1 = r0:1; local st:8 = {o[1]}; local en:8 = {o[0]}; local cnt:8 = 0;",
        "<lp>",
        "if (st == en) goto <nf>;",
        f"if (cnt == {CAP}) goto <part>; cnt = cnt + 1;",
        "local v:1 = *:1 st;",
        "if (v == c) goto <found>; st = st + 1; goto <lp>;",
        f"<found> {o[0]} = st; cc = 1; goto <done>;",
        f"<part> {o[1]} = st; cc = 3; goto <done>;",
        "<nf> cc = 2;",
        "<done>"])

def clst(o):
    """CLST: compare until the terminator (GR0 bits 56-63) or a difference: equal, cc 0 and the
    registers unchanged; otherwise R1/R2 address the first difference and cc is 1 when the first
    operand is low (its terminator counts as lowest), 2 when high."""
    return "\n".join([
        f"local a:8 = {o[0]}; local b:8 = {o[1]}; local t:1 = r0:1; local cnt:8 = 0;",
        "<lp>",
        f"if (cnt == {CAP}) goto <part>; cnt = cnt + 1;",
        "local x:1 = *:1 a; local y:1 = *:1 b;",
        "if (x != y) goto <ne>;",
        "if (x == t) goto <eq>; a = a + 1; b = b + 1; goto <lp>;",
        "<eq> cc = 0; goto <done>;",
        "<ne>",
        "cc = zext(x == t) + zext(x != t) * (zext(y == t) * 2 + zext(y != t) * (1 + zext(x > y)));",
        f"{o[0]} = a; {o[1]} = b; goto <done>;",
        f"<part> {o[0]} = a; {o[1]} = b; cc = 3;",
        "<done>"])

def trxx(o, p, ssize, dsize):
    """TROO/TROT/TRTO/TRTT: translate the second operand (address R2, length R1+1, ssize-byte
    characters) through the table at GR1 (doubleword aligned) into the first operand (R1,
    dsize-byte characters), stopping before a function character equal to the test character
    in GR0 (cc 1) unless M3 bit 3 is set; cc 0 at the end of the operand."""
    m3 = o[2] if len(o) > 2 else "0"
    return "\n".join([
        f"local dst:8 = {o[0]}; local len:8 = {p[0]}; local src:8 = {o[1]}; local tbl:8 = r1 & ~7;",
        f"local m3:8 = {m3}; local notest:1 = (m3 & 1) != 0; local tst:{dsize} = r0:{dsize};",
        "cc = 0;",
        "if (len == 0) goto <done>;",
        "<lp>",
        f"local sv:{ssize} = *:{ssize} src; local fv:{dsize} = *:{dsize} (tbl + zext(sv) * {dsize});",
        "if (!notest && (fv == tst)) goto <hit>;",
        f"*:{dsize} dst = fv; len = len - {ssize}; src = src + {ssize}; dst = dst + {dsize};",
        "if (len != 0) goto <lp>; goto <done>;",
        "<hit> cc = 1;",
        "<done>",
        f"{o[0]} = dst; {p[0]} = len; {o[1]} = src;"])

# ---- packed-decimal arithmetic -----------------------------------------------------------------
# Operands are converted to 16-byte binary (31 digits < 2^104), computed, and stored back with
# the preferred signs C (plus) and D (minus). Data and decimal-divide exceptions are not raised.
def pd_load(t, addr, nexpr, tag):
    """p-code reading the packed operand at addr (nexpr bytes) into v{tag} (magnitude, 16 bytes)
    and n{tag} (negative)."""
    return "\n".join([
        f"local v{tag}:16 = zext(0:8); local k{tag}:8 = 0; local nb{tag}:8 = {nexpr};",
        f"<ld{tag}>",
        f"local b{tag}:1 = *:1 ({addr} + k{tag});",
        f"if (k{tag} + 1 == nb{tag}) goto <ls{tag}>;",
        f"v{tag} = v{tag} * 100 + zext(b{tag} >> 4) * 10 + zext(b{tag} & 0xf); k{tag} = k{tag} + 1; goto <ld{tag}>;",
        f"<ls{tag}>",
        f"v{tag} = v{tag} * 10 + zext(b{tag} >> 4);",
        f"local sg{tag}:1 = b{tag} & 0xf; local n{tag}:1 = (sg{tag} == 0xb) || (sg{tag} == 0xd);"])

def pd_store(addr, nexpr, mag, neg, tag):
    """p-code storing magnitude mag (16 bytes, already < 10^(2n-1)) and sign neg at addr."""
    return "\n".join([
        f"local m{tag}:16 = {mag}; local j{tag}:8 = {nexpr} - 1;",
        f"local d0{tag}:16 = m{tag} % 10; m{tag} = m{tag} / 10;",
        f"*:1 ({addr} + j{tag}) = (d0{tag}:1 << 4) | (0xc + zext({neg}));",
        f"<st{tag}>",
        f"if (j{tag} == 0) goto <sd{tag}>; j{tag} = j{tag} - 1;",
        f"local lo{tag}:16 = m{tag} % 10; m{tag} = m{tag} / 10; local hi{tag}:16 = m{tag} % 10; m{tag} = m{tag} / 10;",
        f"*:1 ({addr} + j{tag}) = (hi{tag}:1 << 4) | lo{tag}:1; goto <st{tag}>;",
        f"<sd{tag}>"])

def pow10(var, digits):
    """p-code: var (16 bytes) = 10^digits (digits an 8-byte expression)."""
    return (f"local {var}:16 = zext(1:8); local pc{var}:8 = {digits};\n<pw{var}>\n"
            f"if (pc{var} == 0) goto <pd{var}>; {var} = {var} * 10; pc{var} = pc{var} - 1; goto <pw{var}>;\n<pd{var}>")

def dec_arith(n, o, x):
    """AP, SP, ZAP, CP, MP, DP (SS-b; x = L1, L2 fields)."""
    t = [f"local pa1:8 = {o[0]}; local pa2:8 = {o[1]}; local l1:8 = {x[0]} + 1; local l2:8 = {x[1]} + 1;",
         pd_load(None, "pa2", "l2", "b")]
    if n != "zap":
        t.append(pd_load(None, "pa1", "l1", "a"))
    if n == "cp":
        t += ["local s1:16 = zext(!na) * va - zext(na) * va; local s2:16 = zext(!nb) * vb - zext(nb) * vb;",
              "gs_cc_flags(s1 == s2, s1 s< s2, s1 s> s2, 0:1);"]
        return "\n".join(t)
    if n == "mp":
        t += [pow10("cap", "2 * l1 - 1"),
              "local pr:16 = (va * vb) % cap;",
              pd_store("pa1", "l1", "pr", "na != nb", "p")]
        return "\n".join(t)
    if n == "dp":
        t += ["if (vb == 0) goto <dz>;",
              "local q:16 = va / vb; local r:16 = va % vb;",
              pow10("capq", "2 * (l1 - l2) - 1"),
              "q = q % capq;",
              pd_store("pa1", "l1 - l2", "q", "na != nb", "q"),
              pd_store("(pa1 + l1 - l2)", "l2", "r", "na", "r"),
              "<dz>"]
        return "\n".join(t)
    expr = {"ap": "s1 + s2", "sp": "s1 - s2", "zap": "s2"}[n]
    if n != "zap":
        t.append("local s1:16 = zext(!na) * va - zext(na) * va;")
    t += ["local s2:16 = zext(!nb) * vb - zext(nb) * vb;",
          f"local sv:16 = {expr}; local ng:1 = sv s< 0; local mg:16 = zext(!ng) * sv - zext(ng) * sv;",
          pow10("cap", "2 * l1 - 1"),
          "local ov:1 = mg >= cap; mg = mg % cap; local rn:1 = ng && ((mg != 0) || ov);",
          pd_store("pa1", "l1", "mg", "rn", "s"),
          "gs_cc_flags(!ov && (mg == 0), !ov && (mg != 0) && rn, !ov && (mg != 0) && !rn, ov);"]
    return "\n".join(t)

def srp(o, x):
    """SRP: shift the packed first operand by the 6-bit signed amount in the second-operand
    address (left: multiply, overflow when nonzero digits are lost; right: round with the
    digit I3 added to the leftmost digit shifted out); a zero result is positive."""
    return "\n".join([
        f"local pa1:8 = {o[0]}; local l1:8 = {x[0]} + 1; local amt:8 = {o[1]} & 63; local rd:8 = {o[2]};",
        pd_load(None, "pa1", "l1", "a"),
        pow10("cap", "2 * l1 - 1"),
        "local mg:16 = va; local ov:1 = 0;",
        "if (amt >= 32) goto <right>;",
        pow10("pl", "amt"),
        "if (pl < cap) goto <fits>; ov = mg != 0; mg = 0; goto <st>;",
        "<fits>",
        "local lim:16 = cap / pl; ov = mg >= lim; mg = (mg % lim) * pl; goto <st>;",
        "<right>",
        pow10("pr", "64 - amt - 1"),
        "mg = (mg / pr + zext(rd & 0xf)) / 10;",
        "<st>",
        "local rn:1 = na && ((mg != 0) || ov);",
        pd_store("pa1", "l1", "mg", "rn", "s"),
        "gs_cc_flags(!ov && (mg == 0), !ov && (mg != 0) && rn, !ov && (mg != 0) && !rn, ov);"])

def edit(o, x, mark):
    """ED/EDMK: edit packed digits of the second operand into the pattern (first operand,
    length L+1): digit selector 20, significance starter 21, field separator 22, other bytes
    are message characters; the leftmost byte is the fill character. A plus sign in the right
    half of a source byte turns significance off. cc: 0 last field zero, 1 nonzero with
    significance on (minus), 2 nonzero with significance off (plus). EDMK puts the address of
    the first digit made significant by a nonzero digit into GR1."""
    t = [f"local pa1:8 = {o[0]}; local pa2:8 = {o[1]}; local n:8 = {x[0]} + 1;",
         "local fill:1 = *:1 pa1; local sig:1 = 0; local nz:1 = 0; local half:1 = 0; local sb:1 = 0;",
         "local k:8 = 0;",
         "<lp>",
         "local pc:1 = *:1 (pa1 + k); local res:1 = pc;",
         "if ((pc == 0x20) || (pc == 0x21)) goto <dig>;",
         "if (pc == 0x22) goto <fs>;",
         "res = zext(sig) * pc + zext(!sig) * fill; goto <put>;",
         "<fs>",
         "res = fill; sig = 0; nz = 0; goto <put>;",
         "<dig>",
         "if (half != 0) goto <right>;",
         "sb = *:1 pa2; pa2 = pa2 + 1;",
         "local d:1 = sb >> 4; goto <use>;",
         "<right>",
         "d = sb & 0xf;",
         "<use>",
         "local was:1 = sig;",
         "res = zext(sig || (d != 0)) * (0xf0 | d) + zext(!(sig || (d != 0))) * fill;"]
    if mark:
        t.append("if (was || (d == 0)) goto <nm>; r1 = pa1 + k;\n<nm>")
    t += ["nz = nz || (d != 0); sig = sig || (d != 0) || (pc == 0x21);",
          "if (half != 0) goto <took>;",
          "local rs:1 = sb & 0xf;",
          "if (rs < 0xa) goto <keep>;",
          "sig = sig && ((rs == 0xb) || (rs == 0xd)); half = 0; goto <put>;",
          "<keep>",
          "half = 1; goto <put>;",
          "<took>",
          "half = 0;",
          "<put>",
          "*:1 (pa1 + k) = res; k = k + 1;",
          "if (k < n) goto <lp>;",
          "gs_cc_flags(!nz, nz && sig, nz && !sig, 0:1);"]
    return "\n".join(t)

# ---- PSW, FPC and access-register state --------------------------------------------------------
def epsw(o, r2n):
    """EXTRACT PSW: R1 bits 32-63 = PSW bits 0-31 (with the condition code, which this module
    keeps outside pswm, in bits 18-19), R2 bits 32-63 = PSW bits 32-63 unless the R2 field is 0."""
    return "\n".join([
        "local ph:8 = pswm >> 32; local hi:4 = ph:4; hi = (hi & 0xffffcfff) | (zext(cc) << 12);",
        _set32(o[0], "hi", "h"),
        f"local r2f:8 = {r2n}; if (r2f == 0) goto <done>;",
        "local lo:4 = pswm:4;",
        _set32(o[1], "lo", "l"),
        "<done>"])

def sam(n):
    """SAM24/31/64: PSW bits 31-32 (extended / basic addressing mode)."""
    ea, ba = {"sam24": (0, 0), "sam31": (0, 1), "sam64": (1, 1)}[n]
    return f"pswm = (pswm & 0xfffffffe7fffffff) | ({ea << 32:#x}) | ({ba << 31:#x});"

def sac(o):
    """SAC/SACF: address-space control (PSW bits 16-17) from bits 52-55 of the second-operand
    address: 0 primary, 1 secondary, 2 access-register, 3 home."""
    return (f"local code:8 = ({o[0]} >> 8) & 0xf; local asc:8 = ((code & 1) << 1) | ((code >> 1) & 1);\n"
            "pswm = (pswm & ~(3 << 46)) | (asc << 46);")

# ---- z17 and other general instructions (checked against the Principles of Operation,
#      SA22-7832-14, and hand-computed emulator tests: qemu-s390x lacks them) ------------------
for _n, _k in (("lxab", 0), ("lxah", 1), ("lxaf", 2), ("lxag", 3), ("lxaq", 4)):
    EXTRA[_n] = EXTRA["l" + _n] = [(12, 4, "u"), (12, 4, "gpr"), (16, 4, "u"), (16, 4, "gpr"), (20, 12, "u"), (32, 8, "s")]
for _n in ("trte", "trtre", "cuse"):
    EXTRA[_n] = [(24, 4, "u"), (28, 4, "u")]                 # R1, R2 numbers
EXTRA["plo"] = [(8, 4, "gpro"), (12, 4, "gpro")]          # R1 + 1, R3 + 1

def lxa(n, o, x):
    """LOAD (LOGICAL) INDEXED ADDRESS: R1 = B2 + (ext(X2 bits 32-63 + DX2) << k)."""
    k = {"b": 0, "h": 1, "f": 2, "g": 3, "q": 4}[n[-1]]
    xn, xr, bn, br, dl, dh = x
    ext = "zext" if n.startswith("ll") else "sext"
    return "\n".join([
        f"local dh4:4 = {dh}; local dl4:4 = {dl}; local dx:4 = (dh4 << 12) | dl4; local xi:4 = 0; local bv:8 = 0;",
        f"local xn:1 = {xn}; local bn:1 = {bn};",
        f"if (xn == 0) goto <nx>; xi = {xr}:4;\n<nx>",
        f"if (bn == 0) goto <nb>; bv = {br};\n<nb>",
        f"local ix:4 = xi + dx; {o[0]} = bv + ({ext}(ix) << {k});"])

def cal(n, o):
    """COMPARE AND LOAD: first operand (D1(B1)) equal to the third (R3): R3 = second operand,
    cc 0; else R3 = first operand, cc 1."""
    if n == "calg":
        return "\n".join([f"local a:8 = *:8 {o[1]};",
                          f"if (a != {o[0]}) goto <ne>; {o[0]} = *:8 {o[2]}; cc = 0; goto <done>;",
                          f"<ne> {o[0]} = a; cc = 1;", "<done>"])
    if n == "calgf":
        return "\n".join([f"local a:4 = *:4 {o[1]};",
                          f"if (a != {o[0]}:4) goto <ne>; {o[0]} = *:8 {o[2]}; cc = 0; goto <done>;",
                          f"<ne> {o[0]} = zext(a); cc = 1;", "<done>"])
    return "\n".join([f"local a:4 = *:4 {o[1]};",
                      f"if (a != {o[0]}:4) goto <ne>; local b:4 = *:4 {o[2]}; {_set32(o[0], 'b', 'e')} cc = 0; goto <done>;",
                      f"<ne> {_set32(o[0], 'a', 'n')} cc = 1;", "<done>"])

def bitdep(o, extract):
    """BIT DEPOSIT / BIT EXTRACT with the R3 mask, bits counted from the left (bit 0)."""
    if extract:
        body = ("if (((m >> k) & 1) == 0) goto <nx>; r = r | (((s >> k) & 1) << (63 - c)); c = c + 1;")
    else:
        body = ("if (((m >> k) & 1) == 0) goto <nx>; r = r | (((s >> (63 - c)) & 1) << k); c = c + 1;")
    return "\n".join([f"local s:8 = {o[1]}; local m:8 = {o[2]}; local r:8 = 0; local c:8 = 0; local k:8 = 64;",
                      "<lp> if (k == 0) goto <done>; k = k - 1;", body, "<nx> goto <lp>;",
                      f"<done> {o[0]} = r;"])

def trte(o, p, x, reverse):
    """TRANSLATE AND TEST (REVERSE) EXTENDED: arguments of 1 or 2 bytes (M3 A) from R1 (length
    R1+1) look up 1- or 2-byte function codes (M3 F) in the table at GR1; arguments above 255
    give 0 when M3 L is one. Stops at the first nonzero function code (stored in R2 unless R2
    is R1 or R1+1; cc 1) or at the end of the operand (cc 0)."""
    step = "-" if reverse else "+"
    return "\n".join([
        f"local m3:1 = {o[2]}:1; local A:1 = (m3 & 8) != 0; local F:1 = (m3 & 4) != 0; local L:1 = (m3 & 2) != 0;",
        f"local ad:8 = {o[0]}; local ln:8 = {p[0]}; local fc:2 = 0; local arg:2 = 0; local w:8 = 1 + zext(A);",
        "<lp> if (ln == 0) goto <end>;",
        "arg = zext(*:1 ad); if (!A) goto <aa1>; arg = *:2 ad;\n<aa1>",
        "fc = 0; if (L && (arg > 255)) goto <tt>;",
        "if (F) goto <ff2>; fc = zext(*:1 (r1 + zext(arg))); goto <tt>;",
        "<ff2> fc = *:2 (r1 + zext(arg) * 2);",
        f"<tt> if (fc != 0) goto <end>; ad = ad {step} w; ln = ln - w; goto <lp>;",
        f"<end> {o[0]} = ad; {p[0]} = ln; cc = zext(fc != 0);",
        f"local n1:1 = {x[0]}; local n2:1 = {x[1]};",
        f"if ((fc == 0) || (n2 == n1) || (n2 == n1 + 1)) goto <done>; {o[1]} = zext(fc);",
        "<done>"])

def cuse(o, p, x):
    """COMPARE UNTIL SUBSTRING EQUAL: GR0 bits 56-63 substring length, GR1 bits 56-63 pad byte;
    operands R1/R1+1 and R2/R2+1 compared byte by byte (the shorter one padded) until that many
    consecutive equal bytes: cc 0 with R1, R2 at the substring; cc 1 when the operands end
    inside a partial substring (registers at it); cc 2 when they end without one; cc 3 after
    4096 bytes without a partial substring (CPU-determined amount)."""
    return "\n".join([
        f"local sl:1 = r0:1; local pd:1 = r1:1; local ad1:8 = {o[0]}; local l1:8 = {p[0]}; local ad2:8 = {o[1]}; local l2:8 = {p[1]};",
        "local e1:8 = ad1; local e2:8 = ad2; local q1:8 = l1; local q2:8 = l2; local eq:1 = 0; local i:8 = 0; local b1:1 = 0; local b2:1 = 0;",
        "cc = 0; if (sl == 0) goto <done>; cc = 2; if ((l1 s<= 0) && (l2 s<= 0)) goto <done>;",
        f"local n1:1 = {x[0]}; local n2:1 = {x[1]};",
        f"if (n1 != n2) goto <lp>; cc = zext(l1 s< zext(sl)); goto <done>;",
        "<lp> if ((l1 s<= 0) && (l2 s<= 0)) goto <end>;",
        "if (eq == sl) goto <found>;",
        f"if ((eq == 0) && (i >= {CAP})) goto <part>;",
        "b1 = pd; if (l1 s<= 0) goto <nn1>; b1 = *:1 ad1;\n<nn1> b2 = pd; if (l2 s<= 0) goto <nn2>; b2 = *:1 ad2;\n<nn2>",
        "if (b1 != b2) goto <ne>; if (eq != 0) goto <inc>; e1 = ad1; e2 = ad2; q1 = l1; q2 = l2;\n<inc> eq = eq + 1; cc = 1; goto <adv>;",
        "<ne> eq = 0; cc = 2;",
        "<adv> i = i + 1; if (l1 s<= 0) goto <vv1>; ad1 = ad1 + 1; l1 = l1 - 1;\n<vv1> if (l2 s<= 0) goto <lp>; ad2 = ad2 + 1; l2 = l2 - 1; goto <lp>;",
        "<end> if (eq != sl) goto <fin>;",
        "<found> cc = 0;",
        "<fin> if ((cc >= 2) || (eq == 0)) goto <cur>;",
        f"{o[0]} = e1; {p[0]} = q1; {o[1]} = e2; {p[1]} = q2; goto <done>;",
        "<part> cc = 3;",
        f"<cur> {o[0]} = ad1; {p[0]} = l1; {o[1]} = ad2; {p[1]} = l2;",
        "<done>"])

def cfc(o):
    """COMPARE AND FORM CODEWORD (64-bit mode: 6-byte units, codeword in GR2)."""
    return "\n".join([
        f"local ea:8 = {o[0]}; local mx:8 = ea & 0x7ffe; local ds:1 = (ea & 1) != 0; local o1:6 = 0; local o3:6 = 0;",
        "<lp> local ix:8 = r2 & 0xffff; if (ix <= mx) goto <cmp>; cc = 0; r2 = r3 | 0x8000000000000000; goto <done>;",
        "<cmp> o1 = *:6 (r1 + ix); o3 = *:6 (r3 + ix); r2 = r2 + 6; if (o1 == o3) goto <lp>;",
        "local tm:6 = 0; local sw:1 = 0;",
        "if (o1 > o3) goto <gt>; if (ds) goto <ld>; cc = 1; tm = ~o3; goto <cw>;\n<ld> cc = 2; tm = o1; sw = 1; goto <cw>;",
        "<gt> if (ds) goto <gd>; cc = 2; tm = ~o1; sw = 1; goto <cw>;\n<gd> cc = 1; tm = o3;",
        "<cw> if (!sw) goto <ns>; local t1:8 = r1; r1 = r3; r3 = t1;",
        "<ns> r2 = (r2 << 48) | zext(tm);",
        "<done>"])

UPT = "\n".join([
    "local ix:8 = 0; local nc:8 = 0; local nd:8 = 0;",
    "<lp> ix = (r5 >> 1) & 0xfffffffffffffff0;",
    "if (ix != 0) goto <ck3>; cc = 1; goto <out>;",
    "<ck3> if ((r0 >> 63) == 0) goto <node>; cc = 3; goto <out>;",
    "<node> nc = *:8 (r4 + ix); nd = *:8 (r4 + ix + 8); r5 = ix;",
    "if (nc != r0) goto <cmp>; r2 = nc; r3 = nd; cc = 0; goto <done>;",
    "<cmp> if (nc < r0) goto <lp>;",
    "*:8 (r4 + ix) = r0; *:8 (r4 + ix + 8) = r1; r0 = nc; r1 = nd; goto <lp>;",
    "<out> r5 = ix;",
    "<done>"])

def plo(o, x):
    """PERFORM LOCKED OPERATION, function codes 0-23 (GR0 bits 56-63; bit 55 tests the code):
    compare and load / swap / double swap / swap and store (single, double, triple), with
    32-bit (register), 64-bit (parameter list at the fourth operand), 64-bit register and
    128-bit (parameter list) operands. The lock (GR1) needs no modelling: p-code is atomic."""
    r1, a2, r3, a4 = o
    r1o, r3o = x
    L = []
    cnt = [0]
    def _s32(r, v, t):
        cnt[0] += 1
        return _set32(r, v, f"p{cnt[0]}")
    L.append("local fc:1 = r0:1; if ((r0 & 0x100) == 0) goto <run>;")
    L.append("cc = 3 * zext(fc > 23); goto <done>;")
    L.append("<run> local pl:8 = " + a4 + "; local op2:8 = " + a2 + ";")
    def jt(k):
        return f"if (fc == {k}) goto <pf{k}>;"
    L.append(" ".join(jt(k) for k in range(24)) + " goto <done>;")
    def cmp_load(k, sz, kind):
        # kind: "r" register 32/64 (R1 vs op2; R3 <- op4), "p" param list 64, "x" param list 128
        if kind == "r":
            g = (lambda r: f"{r}:4") if sz == 4 else (lambda r: r)
            put = (lambda r, v: _s32(r, v, k)) if sz == 4 else (lambda r, v: f"{r} = {v};")
            return (f"<pf{k}> local v2_{k}:{sz} = *:{sz} op2; if ({g(r1)} != v2_{k}) goto <pn{k}>; "
                    f"local v4_{k}:{sz} = *:{sz} pl; {put(r3, f'v4_{k}')} cc = 0; goto <done>;\n"
                    f"<pn{k}> {put(r1, f'v2_{k}')} cc = 1; goto <done>;")
        off = 8 if kind == "p" else 0
        res = 40 if kind == "p" else 32
        return (f"<pf{k}> local v2_{k}:{sz} = *:{sz} op2; local c1_{k}:{sz} = *:{sz} (pl + {off}); "
                f"if (c1_{k} != v2_{k}) goto <pn{k}>; local a4_{k}:8 = *:8 (pl + 72); "
                f"*:{sz} (pl + {res}) = *:{sz} a4_{k}; cc = 0; goto <done>;\n"
                f"<pn{k}> *:{sz} (pl + {off}) = v2_{k}; cc = 1; goto <done>;")
    def swap_store(k, sz, kind, stores):
        # compare-and-swap with 0-3 extra stores (op3/op4, op5/op6, op7/op8)
        if kind == "r":
            g = (lambda r: f"{r}:4") if sz == 4 else (lambda r: r)
            put = (lambda r, v: _s32(r, v, k)) if sz == 4 else (lambda r, v: f"{r} = {v};")
            s = [f"<pf{k}> local v2_{k}:{sz} = *:{sz} op2; if ({g(r1)} != v2_{k}) goto <pn{k}>;"]
            if stores == 1 and k in (12, 14):        # CSST (32-bit / 64-bit register): R3 stored at op4
                s.append(f"*:{sz} pl = {g(r3)};")
            elif stores:
                for j in range(stores):           # op3/op5/op7 and their addresses from the parameter list
                    vo, ao = 56 + 32 * j + (4 if sz == 4 else 0), 72 + 32 * j
                    s.append(f"local s{j}_{k}:{sz} = *:{sz} (pl + {vo}); local d{j}_{k}:8 = *:8 (pl + {ao}); *:{sz} d{j}_{k} = s{j}_{k};")
            s.append(f"*:{sz} op2 = {g(r1o)}; cc = 0; goto <done>;")
            s.append(f"<pn{k}> {put(r1, f'v2_{k}')} cc = 1; goto <done>;")
            return "\n".join(s)
        off, rep = (8, 24) if kind == "p" else (0, 16)
        s = [f"<pf{k}> local v2_{k}:{sz} = *:{sz} op2; local c1_{k}:{sz} = *:{sz} (pl + {off}); if (c1_{k} != v2_{k}) goto <pn{k}>;",
             f"local r1_{k}:{sz} = *:{sz} (pl + {rep});"]
        for j in range(stores):
            vo, ao = (56 if kind == "p" else 48) + 32 * j, 72 + 32 * j
            s.append(f"local s{j}_{k}:{sz} = *:{sz} (pl + {vo}); local d{j}_{k}:8 = *:8 (pl + {ao}); *:{sz} d{j}_{k} = s{j}_{k};")
        s.append(f"*:{sz} op2 = r1_{k}; cc = 0; goto <done>;")
        s.append(f"<pn{k}> *:{sz} (pl + {off}) = v2_{k}; cc = 1; goto <done>;")
        return "\n".join(s)
    def dcs(k, sz, kind):
        if kind == "r":
            g = (lambda r: f"{r}:4") if sz == 4 else (lambda r: r)
            put = (lambda r, v, t: _s32(r, v, k)) if sz == 4 else (lambda r, v, t: f"{r} = {v};")
            return "\n".join([
                f"<pf{k}> local v2_{k}:{sz} = *:{sz} op2; if ({g(r1)} == v2_{k}) goto <pe{k}>; {put(r1, f'v2_{k}', 'a')} cc = 1; goto <done>;",
                f"<pe{k}> local v4_{k}:{sz} = *:{sz} pl; if ({g(r3)} == v4_{k}) goto <ps{k}>; {put(r3, f'v4_{k}', 'b')} cc = 2; goto <done>;",
                f"<ps{k}> *:{sz} pl = {g(r3o)}; *:{sz} op2 = {g(r1o)}; cc = 0; goto <done>;"])
        o1c, o1r, o3c, o3r = (8, 24, 40, 56) if kind == "p" else (0, 16, 32, 48)
        return "\n".join([
            f"<pf{k}> local v2_{k}:{sz} = *:{sz} op2; local c1_{k}:{sz} = *:{sz} (pl + {o1c}); if (c1_{k} == v2_{k}) goto <pe{k}>;",
            f"*:{sz} (pl + {o1c}) = v2_{k}; cc = 1; goto <done>;",
            f"<pe{k}> local a4_{k}:8 = *:8 (pl + 72); local v4_{k}:{sz} = *:{sz} a4_{k}; local c3_{k}:{sz} = *:{sz} (pl + {o3c});",
            f"if (c3_{k} == v4_{k}) goto <ps{k}>; *:{sz} (pl + {o3c}) = v4_{k}; cc = 2; goto <done>;",
            f"<ps{k}> local w3_{k}:{sz} = *:{sz} (pl + {o3r}); local w1_{k}:{sz} = *:{sz} (pl + {o1r}); *:{sz} a4_{k} = w3_{k}; *:{sz} op2 = w1_{k}; cc = 0; goto <done>;"])
    # function codes: 0 CL, 1 CLG, 2 CLGR, 3 CLX, 4 CS, 5 CSG, 6 CSGR, 7 CSX, 8 DCS, 9 DCSG,
    # 10 DCSGR, 11 DCSX, 12 CSST, 13 CSSTG, 14 CSSTGR, 15 CSSTX, 16 CSDST, 17 CSDSTG, 18 CSDSTGR,
    # 19 CSDSTX, 20 CSTST, 21 CSTSTG, 22 CSTSTGR, 23 CSTSTX
    kinds = [(4, "r"), (8, "p"), (8, "r"), (16, "x")]
    for j, (sz, kd) in enumerate(kinds):
        L.append(cmp_load(j, sz, kd))
        L.append(swap_store(4 + j, sz, kd, 0))
        L.append(dcs(8 + j, sz, kd))
        L.append(swap_store(12 + j, sz, kd, 1))
        L.append(swap_store(16 + j, sz, kd, 2))
        L.append(swap_store(20 + j, sz, kd, 3))
    L.append("<done>")
    return "\n".join(L)

def semantics(ctx):
    n, o, k = ctx["name"], ctx["ops"], ctx["kinds"]
    p = ctx["pairs"]
    x = ctx.get("extra", [])
    if n in ("cds", "cdsy") and 0 in p and 1 in p:
        return cds(o, p, 4)
    if n == "cdsg" and 0 in p and 1 in p:
        return cds(o, p, 8)
    if n == "csst" and x:
        return csst(o, x[0])
    if n == "lpq" and 0 in p:
        return lpq(o, p)
    if n == "stpq" and x:
        return stpq(o, x[0])
    if n in ("lpd", "lpdg") and 0 in p:
        return lpd(o, p, 4 if n == "lpd" else 8)
    if n in ("cvb", "cvby"):
        return cvb(o, 8, 4)
    if n == "cvbg":
        return cvb(o, 16, 8)
    if n in ("cvd", "cvdy"):
        return cvd(o, 8, 4)
    if n == "cvdg":
        return cvd(o, 16, 8)
    if n in ("clm", "clmy", "clmh"):
        return clm(o, n == "clmh")
    if n == "mgrk" and 0 in p:
        return (f"local pr:16 = sext({o[1]}) * sext({o[2]}); {o[0]} = pr(8); {p[0]} = pr:8;")
    if n in ("mvcle", "mvclu") and 0 in p and 1 in p:
        return mvcle(o, p, n == "mvclu")
    if n == "mvcrl":
        return mvcrl(o)
    if n == "cksm" and x:
        return cksm(o, {1: x[0]})
    if n == "srstu":
        return srstu(o)
    m = re.fullmatch(r"cu(1|2|4)(1|2|4)", n)
    if m and 0 in p and 1 in p:
        sz = {"1": 8, "2": 16, "4": 32}
        return cuxx(o, p, sz[m.group(1)], sz[m.group(2)])
    if n == "epsw" and x:
        return epsw(o, x[0])
    if n in ("sam24", "sam31", "sam64"):
        return sam(n)
    if n in ("sac", "sacf"):
        return sac(o)
    if n == "cpya":
        return f"{o[0]} = {o[1]};"
    if n == "efpc":            # bits 12-15 (an old optional R2 operand) are ignored
        return _set32(o[0], "fpc", "f")
    if n == "sfpc":
        return f"fpc = {o[0]}:4;"
    if n == "stfpc":
        return f"*:4 {o[0]} = fpc;"
    if n == "srnm":
        return f"local a:4 = {o[0]}:4; fpc = (fpc & ~3) | (a & 3);"
    if n == "srnmb":
        return f"local a:4 = {o[0]}:4; fpc = (fpc & ~7) | (a & 7);"
    if n == "srnmt":
        return f"local a:4 = {o[0]}:4; fpc = (fpc & ~0x70) | ((a & 7) << 4);"
    if n == "lfas":            # new FPC with the old flags (byte 1) ORed in
        return f"local v:4 = *:4 {o[0]}; fpc = v | (fpc & 0x00ff0000);"
    if n == "sfasr":
        return f"local v:4 = {o[0]}:4; fpc = v | (fpc & 0x00ff0000);"
    if n in ("ap", "sp", "zap", "cp", "mp", "dp") and x:
        return dec_arith(n, o, x)
    if n == "srp" and x:
        return srp(o, x)
    if n in ("ed", "edmk") and x:
        return edit(o, x, n == "edmk")
    if n in ("pack", "unpk", "mvo", "mvcin") and x:
        return {"pack": pack, "unpk": unpk, "mvo": mvo, "mvcin": mvcin}[n](o, x)
    if n in ("pka", "pku") and x:
        return pkau(o, x, 1 if n == "pka" else 2)
    if n in ("unpka", "unpku") and x:
        return unpkau(o, x, 1 if n == "unpka" else 2)
    m = re.fullmatch(r"tr(o|t)(o|t)", n)
    if m and 0 in p:
        return trxx(o, p, 1 if m.group(1) == "o" else 2, 1 if m.group(2) == "o" else 2)
    if n == "mvst":
        return mvst(o)
    if n == "srst":
        return srst(o)
    if n == "clst":
        return clst(o)
    if n == "clzg":            # z17: count leading zeros (64 for zero); cc unchanged
        return f"local v:8 = {o[1]}; {o[0]} = lzcount(v);"
    if n == "ctzg":            # z17: count trailing zeros (64 for zero)
        return f"local v:8 = {o[1]}; local m:8 = (v & -v) - 1; {o[0]} = popcount(m);"
    if n == "lgg":             # guarded-storage events are not modelled: a plain load
        return f"{o[0]} = *:8 {o[1]};"
    if re.fullmatch(r"l?lxa[bhfgq]", n) and x:
        return lxa(n, o, x)
    if n in ("cal", "calg", "calgf"):
        return cal(n, o)
    if n in ("bdepg", "bextg"):
        return bitdep(o, n == "bextg")
    if n in ("trte", "trtre") and 0 in p and x:
        return trte(o, p, x, n == "trtre")
    if n == "cuse" and 0 in p and 1 in p and x:
        return cuse(o, p, x)
    if n == "cfc":
        return cfc(o)
    if n == "upt":
        return UPT
    if n == "plo" and x:
        return plo(o, x)
    if n == "ntstg":           # nontransactional store: in p-code a plain store
        return f"*:8 {o[1]} = {o[0]};"
    if n == "mvcos":           # address-space and key controls (GR0) are not modelled
        return "\n".join([f"local d:8 = {o[0]}; local s:8 = {o[1]}; local tl:8 = {o[2]}; local n:8 = tl; cc = 0;",
                           "if (tl <= 4096) goto <mv>; n = 4096; cc = 3;",
                           "<mv> local i:8 = 0;\n<lp> if (i == n) goto <done>; *:1 (d + i) = *:1 (s + i); i = i + 1; goto <lp>;",
                           "<done>"])
    return None
