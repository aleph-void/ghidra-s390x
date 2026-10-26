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
for _n in ("mvcin", "unpka", "unpku", "pka", "pku"):   # one 8-bit length - 1
    EXTRA[_n] = [(8, 8, "u")]

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
    if n in ("pack", "unpk", "mvo", "mvcin") and x:
        return {"pack": pack, "unpk": unpk, "mvo": mvo, "mvcin": mvcin}[n](o, x)
    if n in ("pka", "pku") and x:
        return pkau(o, x, 1 if n == "pka" else 2)
    if n in ("unpka", "unpku") and x:
        return unpkau(o, x, 1 if n == "unpka" else 2)
    if n == "mvst":
        return mvst(o)
    if n == "srst":
        return srst(o)
    if n == "clst":
        return clst(o)
    if n == "lgg":             # guarded-storage events are not modelled: a plain load
        return f"{o[0]} = *:8 {o[1]};"
    return None
