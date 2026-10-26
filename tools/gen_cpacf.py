"""P-code for the message-security-assist (CPACF) instructions: engines and instruction
semantics (used by gen_table.py via gen_semantics.py; the engines are written to
data/languages/s390x_cpacf.sinc by `python3 tools/gen_cpacf.py`).

The algorithms (SHA-1/2/3, AES, DEA, GHASH ...) are long loops, so each one is a SLEIGH
subtable with an empty pattern (`name: is epsilon`) holding the p-code once; an instruction
that needs it says `build name;` and the .sla stores the code once however many instructions
use it. A subtable is built at most once per constructor, so every engine processes whole
operands (all blocks, and the padding for the "last" functions) and talks to the instruction
through scratch registers (cpa, cpl, ... in s390x.slaspec) and the scratch space `cpm`:

  cpm 0x000-0x0c7  chaining value / hash state (copied from and to the parameter block)
  cpm 0x100-0x37f  message schedule W
  cpm 0x400-0x67f  round constants K, tables
  cpm 0x800-0x8ff  padding buffer

Semantics follow the Principles of Operation (SA22-7832-14). Every operation completes in one
execution (condition code 0); a CPU-determined partial completion is never reported. Access
exceptions and the 24/31-bit addressing-mode wrap are not modelled; invalid function codes
and operand lengths are specification exceptions (trap_specification).
"""
import sys

# ---- constants (computed, not copied: checked against hashlib) -----------------------------
def primes(n):
    ps, c = [], 2
    while len(ps) < n:
        if all(c % p for p in ps):
            ps.append(c)
        c += 1
    return ps

def icbrt(n):
    lo, hi = 0, 1 << (n.bit_length() // 3 + 2)
    while lo < hi:
        m = (lo + hi + 1) // 2
        if m ** 3 <= n:
            lo = m
        else:
            hi = m - 1
    return lo

def isqrt(n):
    import math
    return math.isqrt(n)

K256 = [icbrt(p << 96) & 0xffffffff for p in primes(64)]
K512 = [icbrt(p << 192) & 0xffffffffffffffff for p in primes(80)]
RC = []
_lfsr = 1
def _rc():
    global _lfsr
    out = 0
    for j in range(7):
        bit = _lfsr & 1
        if bit:
            out |= 1 << ((1 << j) - 1)
        _lfsr = ((_lfsr << 1) ^ (0x71 if _lfsr & 0x80 else 0)) & 0xff
    return out
RC = [_rc() for _ in range(24)]
ROTC = [1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44]
PILN = [10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1]

# cpm layout
CV, W, KT, PB = 0x000, 0x100, 0x400, 0x800

def rot(x, n, bits):
    return f"(({x} >> {n}) | ({x} << {bits - n}))"

def rotl(x, n, bits):
    return f"(({x} << {n}) | ({x} >> {bits - n}))"

def st(addr, size, val):
    return f"*[cpm]:{size} {addr:#x}:4 = {val:#x};" if False else f"*[cpm]:{size} ({addr:#x}:4) = {val:#x};"

# ---- message-digest engines: SHA-1, SHA-256, SHA-512 ---------------------------------------
def md_engine(name, wb, bs, lenb, init, rounds_code, nsched, nwords, kinit):
    """cp_<L_name>: all blocks of the operand (cpa, cpl) into the chaining value in cpm; with
    cpfin the padded last block(s), the message bit length in cpbh:cpbl."""
    nw16 = bs // wb
    t = []
    t.append(f"{name}: is epsilon {{")
    t.append("  local src:1 = 0; local padded:1 = 0; local nb:4 = 0; local bo:4 = 0; local i:4 = 0; local j:4 = 0;")
    t.append(f"  local w:{wb} = 0; local b:1 = 0;")
    t.append(kinit)
    t.append(f"  <L_top> if (cpl < {bs}) goto <L_tail>; src = 0; goto <L_do>;")
    t.append(f"  <L_tail> if (cpfin == 0) goto <L_exit>; if (padded != 0) goto <L_exit>; padded = 1; src = 1;")
    # zero the pad buffer, copy the tail, 0x80, bit length
    t.append(f"  i = 0; <L_z> *[cpm]:8 ({PB:#x}:4 + i) = 0; i = i + 8; if (i < 256) goto <L_z>;")
    t.append(f"  i = 0; <L_c> if (zext(i) >= cpl) goto <L_cd>; b = *:1 (cpa + zext(i)); *[cpm]:1 ({PB:#x}:4 + i) = b; i = i + 1; goto <L_c>;")
    t.append(f"  <L_cd> j = i; *[cpm]:1 ({PB:#x}:4 + j) = 0x80; nb = 1; if (cpl + {1 + lenb} <= {bs}) goto <L_nb1>; nb = 2;")
    t.append(f"  <L_nb1> j = (nb * {bs}) - {lenb};")
    if lenb == 16:
        t.append(f"  *[cpm]:8 ({PB:#x}:4 + j) = cpbh; *[cpm]:8 ({PB:#x}:4 + j + 8) = cpbl;")
    else:
        t.append(f"  *[cpm]:8 ({PB:#x}:4 + j) = cpbl;")
    t.append(f"  bo = 0;")
    # stage the block into W[0..nw16)
    t.append(f"  <L_do> i = 0; <L_st> if (src != 0) goto <L_sb>; w = *:{wb} (cpa + (zext(i) * {wb})); goto <L_sw>;")
    t.append(f"  <L_sb> w = *[cpm]:{wb} ({PB:#x}:4 + bo + (i * {wb}));")
    t.append(f"  <L_sw> *[cpm]:{wb} ({W:#x}:4 + (i * {wb})) = w; i = i + 1; if (i < {nw16}) goto <L_st>;")
    t.append(rounds_code)
    t.append(f"  if (src != 0) goto <L_ab>; cpa = cpa + {bs}; cpl = cpl - {bs}; goto <L_top>;")
    t.append(f"  <L_ab> bo = bo + {bs}; nb = nb - 1; if (nb != 0) goto <L_do>; cpa = cpa + cpl; cpl = 0; goto <L_top>;")
    t.append("  <L_exit>")
    t.append("}")
    return "\n".join(t)

def sha256_rounds():
    t = []
    t.append(f"  i = 16; <L_ms> local w15:4 = *[cpm]:4 ({W:#x}:4 + ((i - 15) * 4)); local w2:4 = *[cpm]:4 ({W:#x}:4 + ((i - 2) * 4));")
    t.append(f"  local s0:4 = {rot('w15', 7, 32)} ^ {rot('w15', 18, 32)} ^ (w15 >> 3);")
    t.append(f"  local s1:4 = {rot('w2', 17, 32)} ^ {rot('w2', 19, 32)} ^ (w2 >> 10);")
    t.append(f"  w = *[cpm]:4 ({W:#x}:4 + ((i - 16) * 4)) + s0 + *[cpm]:4 ({W:#x}:4 + ((i - 7) * 4)) + s1;")
    t.append(f"  *[cpm]:4 ({W:#x}:4 + (i * 4)) = w; i = i + 1; if (i < 64) goto <L_ms>;")
    names = "abcdefgh"
    t.append("  local a:4 = 0; local b2:4 = 0; local c:4 = 0; local d:4 = 0; local e:4 = 0; local f:4 = 0; local g:4 = 0; local h:4 = 0;")
    t.append("  local t1:4 = 0; local t2:4 = 0; local s1r:4 = 0; local s0r:4 = 0; local chv:4 = 0; local maj:4 = 0;")
    vars_ = ["a", "b2", "c", "d", "e", "f", "g", "h"]
    for k, v in enumerate(vars_):
        t.append(f"  {v} = *[cpm]:4 ({CV + 4 * k:#x}:4);")
    t.append("  i = 0; <L_rd>")
    t.append(f"  s1r = {rot('e', 6, 32)} ^ {rot('e', 11, 32)} ^ {rot('e', 25, 32)}; chv = (e & f) ^ ((~e) & g);")
    t.append(f"  t1 = h + s1r + chv + *[cpm]:4 ({KT:#x}:4 + (i * 4)) + *[cpm]:4 ({W:#x}:4 + (i * 4));")
    t.append(f"  s0r = {rot('a', 2, 32)} ^ {rot('a', 13, 32)} ^ {rot('a', 22, 32)}; maj = (a & b2) ^ (a & c) ^ (b2 & c); t2 = s0r + maj;")
    t.append("  h = g; g = f; f = e; e = d + t1; d = c; c = b2; b2 = a; a = t1 + t2; i = i + 1; if (i < 64) goto <L_rd>;")
    for k, v in enumerate(vars_):
        t.append(f"  *[cpm]:4 ({CV + 4 * k:#x}:4) = *[cpm]:4 ({CV + 4 * k:#x}:4) + {v};")
    return "\n".join(t)

def sha512_rounds():
    t = []
    t.append(f"  i = 16; <L_ms> local w15:8 = *[cpm]:8 ({W:#x}:4 + ((i - 15) * 8)); local w2:8 = *[cpm]:8 ({W:#x}:4 + ((i - 2) * 8));")
    t.append(f"  local s0:8 = {rot('w15', 1, 64)} ^ {rot('w15', 8, 64)} ^ (w15 >> 7);")
    t.append(f"  local s1:8 = {rot('w2', 19, 64)} ^ {rot('w2', 61, 64)} ^ (w2 >> 6);")
    t.append(f"  w = *[cpm]:8 ({W:#x}:4 + ((i - 16) * 8)) + s0 + *[cpm]:8 ({W:#x}:4 + ((i - 7) * 8)) + s1;")
    t.append(f"  *[cpm]:8 ({W:#x}:4 + (i * 8)) = w; i = i + 1; if (i < 80) goto <L_ms>;")
    vars_ = ["a", "b2", "c", "d", "e", "f", "g", "h"]
    t.append("  local a:8 = 0; local b2:8 = 0; local c:8 = 0; local d:8 = 0; local e:8 = 0; local f:8 = 0; local g:8 = 0; local h:8 = 0;")
    t.append("  local t1:8 = 0; local t2:8 = 0; local s1r:8 = 0; local s0r:8 = 0; local chv:8 = 0; local maj:8 = 0;")
    for k, v in enumerate(vars_):
        t.append(f"  {v} = *[cpm]:8 ({CV + 8 * k:#x}:4);")
    t.append("  i = 0; <L_rd>")
    t.append(f"  s1r = {rot('e', 14, 64)} ^ {rot('e', 18, 64)} ^ {rot('e', 41, 64)}; chv = (e & f) ^ ((~e) & g);")
    t.append(f"  t1 = h + s1r + chv + *[cpm]:8 ({KT:#x}:4 + (i * 8)) + *[cpm]:8 ({W:#x}:4 + (i * 8));")
    t.append(f"  s0r = {rot('a', 28, 64)} ^ {rot('a', 34, 64)} ^ {rot('a', 39, 64)}; maj = (a & b2) ^ (a & c) ^ (b2 & c); t2 = s0r + maj;")
    t.append("  h = g; g = f; f = e; e = d + t1; d = c; c = b2; b2 = a; a = t1 + t2; i = i + 1; if (i < 80) goto <L_rd>;")
    for k, v in enumerate(vars_):
        t.append(f"  *[cpm]:8 ({CV + 8 * k:#x}:4) = *[cpm]:8 ({CV + 8 * k:#x}:4) + {v};")
    return "\n".join(t)

def sha1_rounds():
    t = []
    t.append(f"  i = 16; <L_ms> w = *[cpm]:4 ({W:#x}:4 + ((i - 3) * 4)) ^ *[cpm]:4 ({W:#x}:4 + ((i - 8) * 4)) ^ *[cpm]:4 ({W:#x}:4 + ((i - 14) * 4)) ^ *[cpm]:4 ({W:#x}:4 + ((i - 16) * 4));")
    t.append(f"  *[cpm]:4 ({W:#x}:4 + (i * 4)) = {rotl('w', 1, 32)}; i = i + 1; if (i < 80) goto <L_ms>;")
    t.append("  local a:4 = 0; local b2:4 = 0; local c:4 = 0; local d:4 = 0; local e:4 = 0; local f:4 = 0; local k:4 = 0; local tmp:4 = 0;")
    for k, v in enumerate(["a", "b2", "c", "d", "e"]):
        t.append(f"  {v} = *[cpm]:4 ({CV + 4 * k:#x}:4);")
    t.append("  i = 0; <L_rd>")
    t.append("  if (i >= 20) goto <L_r2>; f = (b2 & c) | ((~b2) & d); k = 0x5a827999; goto <L_rr>;")
    t.append("  <L_r2> if (i >= 40) goto <L_r3>; f = b2 ^ c ^ d; k = 0x6ed9eba1; goto <L_rr>;")
    t.append("  <L_r3> if (i >= 60) goto <L_r4>; f = (b2 & c) | (b2 & d) | (c & d); k = 0x8f1bbcdc; goto <L_rr>;")
    t.append("  <L_r4> f = b2 ^ c ^ d; k = 0xca62c1d6;")
    t.append(f"  <L_rr> tmp = {rotl('a', 5, 32)} + f + e + k + *[cpm]:4 ({W:#x}:4 + (i * 4));")
    t.append(f"  e = d; d = c; c = {rotl('b2', 30, 32)}; b2 = a; a = tmp; i = i + 1; if (i < 80) goto <L_rd>;")
    for k, v in enumerate(["a", "b2", "c", "d", "e"]):
        t.append(f"  *[cpm]:4 ({CV + 4 * k:#x}:4) = *[cpm]:4 ({CV + 4 * k:#x}:4) + {v};")
    return "\n".join(t)

def kinit_stores(table, size, base):
    return "\n".join(f"  *[cpm]:{size} ({base + size * i:#x}:4) = {v:#x};" for i, v in enumerate(table))



def bswap64(v):
    return (f"{v} = (({v} & 0x00ff00ff00ff00ff) << 8) | (({v} >> 8) & 0x00ff00ff00ff00ff); "
            f"{v} = (({v} & 0x0000ffff0000ffff) << 16) | (({v} >> 16) & 0x0000ffff0000ffff); "
            f"{v} = ({v} << 32) | ({v} >> 32);")

def keccak_engine():
    """cp_keccak: SHA-3 / SHAKE sponge on the 200-byte state at cpm CV (parameter-block byte
    order in, lanes as native integers inside); rate cprt, domain byte cpdm, mode cpmd (0
    SHA-3: one padded final block, 1 SHAKE: padding, then extended output cpo/cpn), padding
    state cpps. The permutation exists once, reached with a return selector."""
    BC, ROT, PIL, RCT = W, KT, KT + 0x20, KT + 0x40
    lane = lambda idx: f"*[cpm]:8 ({CV:#x}:4 + {idx})"
    t = ["cp_keccak: is epsilon {",
         "  local i:4 = 0; local j:4 = 0; local v:8 = 0; local r:4 = 0; local x:4 = 0; local y:4 = 0; local ret:1 = 0;",
         "  local tt:8 = 0; local bj:8 = 0; local b:1 = 0; local sh:8 = 0; local n:8 = 0; local t2:8 = 0; local t3:8 = 0;"]
    for i in range(0, 24, 8):
        t.append(f"  *[cpm]:8 ({ROT + i:#x}:4) = {int.from_bytes(bytes(ROTC[i:i + 8]), 'big'):#x};")
        t.append(f"  *[cpm]:8 ({PIL + i:#x}:4) = {int.from_bytes(bytes(PILN[i:i + 8]), 'big'):#x};")
    for i, c in enumerate(RC):
        t.append(f"  *[cpm]:8 ({RCT + 8 * i:#x}:4) = {c:#x};")
    t.append(f"  i = 0; <L_n1> v = {lane('i')}; {bswap64('v')} {lane('i')} = v; i = i + 8; if (i < 200) goto <L_n1>;")
    t.append("  <L_top> if (cpl < cprt) goto <L_tail>;")
    t.append(f"  i = 0; <L_a1> v = *:8 (cpa + zext(i)); {bswap64('v')} {lane('i')} = {lane('i')} ^ v; i = i + 8; if (zext(i) < cprt) goto <L_a1>;")
    t.append("  cpa = cpa + cprt; cpl = cpl - cprt; ret = 0; goto <L_perm>;")
    t.append("  <L_tail> if (cpfin == 0) goto <L_exit>; if (cpps != 0) goto <L_xof>;")
    t.append(f"  i = 0; <L_z> *[cpm]:8 ({PB:#x}:4 + i) = 0; i = i + 8; if (i < 200) goto <L_z>;")
    t.append(f"  i = 0; <L_c> if (zext(i) >= cpl) goto <L_cd>; b = *:1 (cpa + zext(i)); *[cpm]:1 ({PB:#x}:4 + i) = b; i = i + 1; goto <L_c>;")
    t.append(f"  <L_cd> *[cpm]:1 ({PB:#x}:4 + i) = cpdm; j = cprt:4 - 1; b = *[cpm]:1 ({PB:#x}:4 + j); *[cpm]:1 ({PB:#x}:4 + j) = b ^ 0x80;")
    t.append(f"  i = 0; <L_a2> v = *[cpm]:8 ({PB:#x}:4 + i); {bswap64('v')} {lane('i')} = {lane('i')} ^ v; i = i + 8; if (zext(i) < cprt) goto <L_a2>;")
    t.append("  cpa = cpa + cpl; cpl = 0; if (cpmd != 0) goto <L_shk>; ret = 1; goto <L_perm>;")
    t.append("  <L_shk> cpps = 1;")
    t.append("  <L_xof> if (cpn == 0) goto <L_exit>; ret = 2; goto <L_perm>;")
    t.append("  <L_xo2> n = cpn; if (n <= cprt) goto <L_n2>; n = cprt;")
    t.append(f"  <L_n2> i = 0; <L_o1> if (zext(i) >= n) goto <L_o2>; sh = zext(i & 7) << 3; v = {lane('(i & 0xf8)')}; v = v >> sh; b = v:1; *:1 (cpo + zext(i)) = b; i = i + 1; goto <L_o1>;")
    t.append("  <L_o2> cpo = cpo + n; cpn = cpn - n; goto <L_xof>;")
    # the permutation
    t.append("  <L_perm> r = 0;")
    t.append("  <L_r>")
    t.append(f"  x = 0; <L_t1> v = {lane('(x * 8)')} ^ {lane('(x * 8) + 40')} ^ {lane('(x * 8) + 80')} ^ {lane('(x * 8) + 120')} ^ {lane('(x * 8) + 160')};")
    t.append(f"  *[cpm]:8 ({BC:#x}:4 + (x * 8)) = v; x = x + 1; if (x < 5) goto <L_t1>;")
    t.append(f"  x = 0; <L_t2> tt = *[cpm]:8 ({BC:#x}:4 + (((x + 1) % 5) * 8)); tt = ((tt << 1) | (tt >> 63)) ^ *[cpm]:8 ({BC:#x}:4 + (((x + 4) % 5) * 8));")
    t.append(f"  y = 0; <L_t3> {lane('(y * 8) + (x * 8)')} = {lane('(y * 8) + (x * 8)')} ^ tt; y = y + 5; if (y < 25) goto <L_t3>;")
    t.append("  x = x + 1; if (x < 5) goto <L_t2>;")
    t.append(f"  tt = {lane('8')}; i = 0; <L_p> b = *[cpm]:1 ({PIL:#x}:4 + i); j = zext(b); bj = {lane('(j * 8)')};")
    t.append(f"  b = *[cpm]:1 ({ROT:#x}:4 + i); sh = zext(b); {lane('(j * 8)')} = (tt << sh) | (tt >> (64 - sh)); tt = bj; i = i + 1; if (i < 24) goto <L_p>;")
    t.append(f"  y = 0; <L_c1> x = 0; <L_c2> *[cpm]:8 ({BC:#x}:4 + (x * 8)) = {lane('(y * 8) + (x * 8)')}; x = x + 1; if (x < 5) goto <L_c2>;")
    t.append(f"  x = 0; <L_c3> t2 = *[cpm]:8 ({BC:#x}:4 + (((x + 1) % 5) * 8)); t3 = *[cpm]:8 ({BC:#x}:4 + (((x + 2) % 5) * 8)); t2 = ~t2;")
    t.append(f"  {lane('(y * 8) + (x * 8)')} = *[cpm]:8 ({BC:#x}:4 + (x * 8)) ^ (t2 & t3); x = x + 1; if (x < 5) goto <L_c3>;")
    t.append("  y = y + 5; if (y < 25) goto <L_c1>;")
    t.append(f"  {lane('0')} = {lane('0')} ^ *[cpm]:8 ({RCT:#x}:4 + (r * 8)); r = r + 1; if (r < 24) goto <L_r>;")
    t.append("  if (ret == 0) goto <L_top>; if (ret == 2) goto <L_xo2>;")
    t.append(f"  <L_exit> i = 0; <L_n3> v = {lane('i')}; {bswap64('v')} {lane('i')} = v; i = i + 8; if (i < 200) goto <L_n3>;")
    t.append("}")
    return "\n".join(t)

def ghash_engine():
    """cp_ghash: Y = (Y ^ X) * H over GF(2^128) for each 16-byte block (Y at cpm CV, H at CV+16)"""
    t = ["cp_ghash: is epsilon {",
         "  local y:16 = 0; local h:16 = 0; local x:16 = 0; local z:16 = 0; local vv:16 = 0; local rr:16 = 0; local i:4 = 0; local bit:16 = 0;",
         f"  y = *[cpm]:16 ({CV:#x}:4); h = *[cpm]:16 ({CV + 16:#x}:4); rr = zext(0xe1:1) << 120;",
         "  <L_top> if (cpl < 16) goto <L_exit>; x = *:16 cpa; x = x ^ y; z = 0; vv = h; i = 0;",
         "  <L_b> bit = (x >> (127 - i)) & 1; if (bit == 0) goto <L_s>; z = z ^ vv;",
         "  <L_s> if ((vv & 1) == 0) goto <L_n>; vv = (vv >> 1) ^ rr; goto <L_m>;",
         "  <L_n> vv = vv >> 1;",
         "  <L_m> i = i + 1; if (i < 128) goto <L_b>;",
         "  y = z; cpa = cpa + 16; cpl = cpl - 16; goto <L_top>;",
         f"  <L_exit> *[cpm]:16 ({CV:#x}:4) = y;",
         "}"]
    return "\n".join(t)

def _aes_sbox():
    def mul(a, b):
        r = 0
        while b:
            if b & 1:
                r ^= a
            a = ((a << 1) ^ 0x11b) if a & 0x80 else a << 1
            b >>= 1
        return r
    def inv(a):
        if a == 0:
            return 0
        for b in range(1, 256):
            if mul(a, b) == 1:
                return b
    sb = []
    for a in range(256):
        x = inv(a)
        y = x
        for _ in range(4):
            x = ((x << 1) | (x >> 7)) & 0xff
            y ^= x
        sb.append(y ^ 0x63)
    return sb

SBOX_T = _aes_sbox()
ISBOX_T = [0] * 256
for _i, _v in enumerate(SBOX_T):
    ISBOX_T[_v] = _i

IP = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7]
FP = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
      36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25]
DES_E = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
         24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]
DES_P = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25]
PC1 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
       63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4]
PC2 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
       41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]
DES_SH = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
DES_S = [
    [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8, 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5, 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1, 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9, 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6, 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8, 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6, 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2, 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
]

# cipher scratch layout (cpm)
KEYA, SBOX, ISBOX, RK, BLK, TMP, TMP2, MSG, J0A, LENS = 0x040, 0x1000, 0x1100, 0x1200, 0x1300, 0x1310, 0x1320, 0x1330, 0x1340, 0x1350
T_IP, T_FP, T_E, T_P, T_PC1, T_PC2, T_SH, T_SB, KS = 0x1400, 0x1440, 0x1480, 0x14c0, 0x14e0, 0x1520, 0x1560, 0x1600, 0x1800

def store_table(base, data):
    data = list(data) + [0] * (-len(data) % 8)
    return "\n".join(f"  *[cpm]:8 ({base + i:#x}:4) = {int.from_bytes(bytes(data[i:i + 8]), 'big'):#x};" for i in range(0, len(data), 8))

def perm(inp, nin, out, nout, tbl, tag):
    """out = permutation of the nin-bit value inp (8-byte local) by the byte table at cpm tbl
    (1-based positions from the most significant bit), nout bits"""
    return (f"{out} = 0; pi = 0; <L_{tag}> pt = *[cpm]:1 ({tbl:#x}:4 + pi); sh8 = zext(pt); sh8 = {nin} - sh8; "
            f"bit = ({inp} >> sh8) & 1; {out} = ({out} << 1) | bit; pi = pi + 1; if (pi < {nout}) goto <L_{tag}>;")

def ld_blk(addr, space="ram"):
    """BLK = bs bytes at addr (ram, or cpm for space cpm)"""
    if space == "ram":
        return (f"*[cpm]:8 ({BLK:#x}:4) = *:8 ({addr}); if (bs == 8) goto <L_lb{{u}}>; *[cpm]:8 ({BLK + 8:#x}:4) = *:8 ({addr} + 8); <L_lb{{u}}>")
    return (f"*[cpm]:8 ({BLK:#x}:4) = *[cpm]:8 ({addr}); if (bs == 8) goto <L_lb{{u}}>; *[cpm]:8 ({BLK + 8:#x}:4) = *[cpm]:8 ({addr} + 8); <L_lb{{u}}>")

def cipher_engine():
    """cp_cipher: AES / DEA / TDEA in the modes ECB (0), CBC (1), CFB (2), OFB (3), CTR (4) and
    CBC-MAC (7). Registers: cpalg 0 DEA, 1 TDEA-128, 2 TDEA-192, 3 AES; cpnk AES key words;
    cpdec modifier bit; cps feedback length (CFB); operands cpa -> cpo, cpl bytes (cpc counter
    vector for CTR); key at cpm KEYA, chaining value at cpm CV."""
    uid = [0]
    def U():
        uid[0] += 1
        return uid[0]
    t = ["cp_cipher: is epsilon {",
         "  local i:4 = 0; local j:4 = 0; local k:4 = 0; local n:4 = 0; local rnd:4 = 0; local nr:4 = 0; local src:4 = 0; local bs:4 = 0;",
         "  local q0:1 = 0; local q1:1 = 0; local q2:1 = 0; local q3:1 = 0; local b0:1 = 0; local b1:1 = 0; local b2:1 = 0; local b3:1 = 0;",
         "  local x0:1 = 0; local x1:1 = 0; local x2:1 = 0; local x3:1 = 0; local y0:1 = 0; local y1:1 = 0; local y2:1 = 0; local y3:1 = 0;",
         "  local z0:1 = 0; local z1:1 = 0; local z2:1 = 0; local z3:1 = 0; local w0:1 = 0; local w1:1 = 0; local w2:1 = 0; local w3:1 = 0;",
         "  local u:4 = 0; local v:4 = 0; local rcon:1 = 1; local dflag:1 = 0; local bret:1 = 0; local sh8:8 = 0;",
         "  local lh:4 = 0; local rh:4 = 0; local e48:8 = 0; local f32:8 = 0; local sbo:8 = 0; local bit:8 = 0; local pi:4 = 0; local pt:1 = 0;",
         "  local cd:8 = 0; local kk:8 = 0; local d1:8 = 0; local npass:1 = 0; local pass:1 = 0; local kidx:1 = 0; local rr:4 = 0; local six:8 = 0; local tq:8 = 0;",
         "  local a:1 = 0; local b:1 = 0; local c:1 = 0; local dd:1 = 0; local sg:4 = 0; local seg:4 = 0; local ptrc:8 = 0; local rv8:8 = 0; local d1x:8 = 0;",
         "  local cvv:4 = 0; local gh:16 = 0; local gt:16 = 0; local gx:16 = 0; local gz:16 = 0; local gv:16 = 0; local gin:16 = 0; local gout:16 = 0; local gct:16 = 0; local cb:16 = 0; local gbit:16 = 0; local gi:4 = 0; local gret:1 = 0;",
         "  local rpoly:16 = 0xe1; local lv:16 = 0; local rc16:16 = 0; local msg16:16 = 0; local icv16:16 = 0; local kx16:16 = 0; local msk16:16 = 0; local one16:16 = 1; local sh16:16 = 0; local m1:16 = 0;"]
    t.append(store_table(SBOX, SBOX_T))
    t.append(store_table(ISBOX, ISBOX_T))
    t.append(store_table(T_IP, IP)); t.append(store_table(T_FP, FP)); t.append(store_table(T_E, DES_E)); t.append(store_table(T_P, DES_P))
    t.append(store_table(T_PC1, PC1)); t.append(store_table(T_PC2, PC2)); t.append(store_table(T_SH, DES_SH))
    t.append(store_table(T_SB, [v for sb in DES_S for v in sb]))
    t.append("  bs = 16; if (cpalg == 3) goto <L_bsz>; bs = 8;\n  <L_bsz>")
    # ---- key schedule -------------------------------------------------------------------------
    t.append("  if (cpalg != 3) goto <L_dks>;")
    t.append("  nr = zext(cpnk) + 6; n = 4 * (nr + 1); i = 0;")
    t.append(f"  <L_k0> *[cpm]:4 ({RK:#x}:4 + (i * 4)) = *[cpm]:4 ({KEYA:#x}:4 + (i * 4)); i = i + 1; if (i < zext(cpnk)) goto <L_k0>;")
    t.append("  i = zext(cpnk); rcon = 1;")
    t.append(f"  <L_ks> u = *[cpm]:4 ({RK:#x}:4 + ((i - 1) * 4)); j = i % zext(cpnk); if (j != 0) goto <L_k1>;")
    t.append("  u = (u << 8) | (u >> 24); goto <L_sw>;")
    t.append("  <L_k1> if (cpnk <= 6) goto <L_k3>; if (j != 4) goto <L_k3>;")
    t.append(f"  <L_sw> q0 = *[cpm]:1 ({SBOX:#x}:4 + (u >> 24)); q1 = *[cpm]:1 ({SBOX:#x}:4 + ((u >> 16) & 0xff)); q2 = *[cpm]:1 ({SBOX:#x}:4 + ((u >> 8) & 0xff)); q3 = *[cpm]:1 ({SBOX:#x}:4 + (u & 0xff));")
    t.append("  u = (zext(q0) << 24) | (zext(q1) << 16) | (zext(q2) << 8) | zext(q3);")
    t.append("  if (j != 0) goto <L_k3>; u = u ^ (zext(rcon) << 24); rcon = (rcon << 1) ^ ((rcon >> 7) * 0x1b);")
    t.append(f"  <L_k3> *[cpm]:4 ({RK:#x}:4 + (i * 4)) = *[cpm]:4 ({RK:#x}:4 + ((i - zext(cpnk)) * 4)) ^ u; i = i + 1; if (i < n) goto <L_ks>;")
    t.append("  goto <L_ksdone>;")
    t.append("  <L_dks> npass = 1; if (cpalg == 0) goto <L_dk0>; npass = 2; if (cpalg == 1) goto <L_dk0>; npass = 3;")
    t.append("  <L_dk0> kidx = 0;")
    t.append(f"  <L_dk1> kk = *[cpm]:8 ({KEYA:#x}:4 + (zext(kidx) * 8));")
    t.append("  " + perm("kk", 64, "cd", 56, T_PC1, "p1"))
    t.append("  tq = cd >> 28; lh = tq:4 & 0xfffffff; rh = cd:4 & 0xfffffff; rr = 0;")
    t.append(f"  <L_dk2> pt = *[cpm]:1 ({T_SH:#x}:4 + rr); j = zext(pt); k = 0;")
    t.append("  <L_dk3> lh = ((lh << 1) | (lh >> 27)) & 0xfffffff; rh = ((rh << 1) | (rh >> 27)) & 0xfffffff; k = k + 1; if (k < j) goto <L_dk3>;")
    t.append("  cd = (zext(lh) << 28) | zext(rh);")
    t.append("  " + perm("cd", 56, "kk", 48, T_PC2, "p2"))
    t.append(f"  *[cpm]:8 ({KS:#x}:4 + (zext(kidx) * 128) + (rr * 8)) = kk; rr = rr + 1; if (rr < 16) goto <L_dk2>;")
    t.append("  kidx = kidx + 1; if (kidx < npass) goto <L_dk1>;")
    t.append("  <L_ksdone>")
    # ---- the operand loop ----------------------------------------------------------------------
    t.append("  rpoly = rpoly << 120; if (cpmd == 6) goto <L_m6>;")
    t.append("  <L_top> if (cpl == 0) goto <L_exit>;")
    t.append("  if (cpmd != 0) goto <L_m1>;")
    # ECB
    t.append("  " + ld_blk("cpa").format(u=U()))
    t.append("  dflag = cpdec; bret = 1; goto <L_blk>;")
    t.append("  <L_r1> " + f"*:8 cpo = *[cpm]:8 ({BLK:#x}:4); if (bs == 8) goto <L_ecbs>; *:8 (cpo + 8) = *[cpm]:8 ({BLK + 8:#x}:4);")
    t.append("  <L_ecbs> goto <L_adv>;")
    # CBC / MAC
    t.append("  <L_m1> if (cpmd != 1) goto <L_m2>;")
    t.append("  " + ld_blk("cpa").format(u=U()))
    t.append("  if (cpdec != 0) goto <L_cbd>;")
    t.append(f"  *[cpm]:8 ({BLK:#x}:4) = *[cpm]:8 ({BLK:#x}:4) ^ *[cpm]:8 ({CV:#x}:4); if (bs == 8) goto <L_cb1>; *[cpm]:8 ({BLK + 8:#x}:4) = *[cpm]:8 ({BLK + 8:#x}:4) ^ *[cpm]:8 ({CV + 8:#x}:4);")
    t.append("  <L_cb1> dflag = 0; bret = 2; goto <L_blk>;")
    t.append("  <L_r2> " + f"*[cpm]:8 ({CV:#x}:4) = *[cpm]:8 ({BLK:#x}:4); *:8 cpo = *[cpm]:8 ({BLK:#x}:4); if (bs == 8) goto <L_adv>; *[cpm]:8 ({CV + 8:#x}:4) = *[cpm]:8 ({BLK + 8:#x}:4); *:8 (cpo + 8) = *[cpm]:8 ({BLK + 8:#x}:4); goto <L_adv>;")
    t.append("  <L_cbd> " + f"*[cpm]:8 ({TMP2:#x}:4) = *[cpm]:8 ({BLK:#x}:4); *[cpm]:8 ({TMP2 + 8:#x}:4) = *[cpm]:8 ({BLK + 8:#x}:4); dflag = 1; bret = 3; goto <L_blk>;")
    t.append("  <L_r3> " + f"*[cpm]:8 ({BLK:#x}:4) = *[cpm]:8 ({BLK:#x}:4) ^ *[cpm]:8 ({CV:#x}:4); *:8 cpo = *[cpm]:8 ({BLK:#x}:4); *[cpm]:8 ({CV:#x}:4) = *[cpm]:8 ({TMP2:#x}:4);")
    t.append(f"  if (bs == 8) goto <L_adv>; *[cpm]:8 ({BLK + 8:#x}:4) = *[cpm]:8 ({BLK + 8:#x}:4) ^ *[cpm]:8 ({CV + 8:#x}:4); *:8 (cpo + 8) = *[cpm]:8 ({BLK + 8:#x}:4); *[cpm]:8 ({CV + 8:#x}:4) = *[cpm]:8 ({TMP2 + 8:#x}:4); goto <L_adv>;")
    # CFB: segments of cps bytes
    t.append("  <L_m2> if (cpmd != 2) goto <L_m3>;")
    t.append(f"  *[cpm]:8 ({BLK:#x}:4) = *[cpm]:8 ({CV:#x}:4); if (bs == 8) goto <L_f1>; *[cpm]:8 ({BLK + 8:#x}:4) = *[cpm]:8 ({CV + 8:#x}:4);")
    t.append("  <L_f1> dflag = 0; bret = 4; goto <L_blk>;")
    t.append("  <L_r4> sg = cps:4; j = 0;")
    t.append(f"  <L_f2> a = *:1 (cpa + zext(j)); b = *[cpm]:1 ({BLK:#x}:4 + j); c = a ^ b; *:1 (cpo + zext(j)) = c; if (cpdec == 0) goto <L_f3>; c = a;")
    t.append(f"  <L_f3> *[cpm]:1 ({TMP2:#x}:4 + j) = c; j = j + 1; if (j < sg) goto <L_f2>;")
    t.append(f"  j = 0; <L_f4> if (j >= bs - sg) goto <L_f5>; a = *[cpm]:1 ({CV:#x}:4 + j + sg); *[cpm]:1 ({CV:#x}:4 + j) = a; j = j + 1; goto <L_f4>;")
    t.append(f"  <L_f5> j = 0; <L_f6> a = *[cpm]:1 ({TMP2:#x}:4 + j); *[cpm]:1 ({CV:#x}:4 + (bs - sg) + j) = a; j = j + 1; if (j < sg) goto <L_f6>;")
    t.append("  cpa = cpa + cps; cpo = cpo + cps; cpl = cpl - cps; goto <L_top>;")
    # OFB
    t.append("  <L_m3> if (cpmd != 3) goto <L_m4>;")
    t.append(f"  *[cpm]:8 ({BLK:#x}:4) = *[cpm]:8 ({CV:#x}:4); if (bs == 8) goto <L_o1>; *[cpm]:8 ({BLK + 8:#x}:4) = *[cpm]:8 ({CV + 8:#x}:4);")
    t.append("  <L_o1> dflag = 0; bret = 5; goto <L_blk>;")
    t.append("  <L_r5> " + f"*[cpm]:8 ({CV:#x}:4) = *[cpm]:8 ({BLK:#x}:4); *:8 cpo = *:8 cpa ^ *[cpm]:8 ({BLK:#x}:4); if (bs == 8) goto <L_adv>; *[cpm]:8 ({CV + 8:#x}:4) = *[cpm]:8 ({BLK + 8:#x}:4); *:8 (cpo + 8) = *:8 (cpa + 8) ^ *[cpm]:8 ({BLK + 8:#x}:4); goto <L_adv>;")
    # CTR
    t.append("  <L_m4> if (cpmd != 4) goto <L_m7>;")
    t.append("  " + ld_blk("cpc").format(u=U()))
    t.append("  dflag = 0; bret = 6; goto <L_blk>;")
    t.append("  <L_r6> " + f"*:8 cpo = *:8 cpa ^ *[cpm]:8 ({BLK:#x}:4); if (bs == 8) goto <L_c6>; *:8 (cpo + 8) = *:8 (cpa + 8) ^ *[cpm]:8 ({BLK + 8:#x}:4);")
    t.append("  <L_c6> cpc = cpc + zext(bs); goto <L_adv>;")
    # CBC-MAC
    t.append("  <L_m7> if (cpmd != 7) goto <L_m8>;")
    t.append("  " + ld_blk("cpa").format(u=U()))
    t.append(f"  *[cpm]:8 ({BLK:#x}:4) = *[cpm]:8 ({BLK:#x}:4) ^ *[cpm]:8 ({CV:#x}:4); if (bs == 8) goto <L_g1>; *[cpm]:8 ({BLK + 8:#x}:4) = *[cpm]:8 ({BLK + 8:#x}:4) ^ *[cpm]:8 ({CV + 8:#x}:4);")
    t.append("  <L_g1> dflag = 0; bret = 7; goto <L_blk>;")
    t.append("  <L_r7> " + f"*[cpm]:8 ({CV:#x}:4) = *[cpm]:8 ({BLK:#x}:4); if (bs == 8) goto <L_adv>; *[cpm]:8 ({CV + 8:#x}:4) = *[cpm]:8 ({BLK + 8:#x}:4);")
    t.append("  <L_adv> cpa = cpa + zext(bs); cpo = cpo + zext(bs); cpl = cpl - zext(bs); goto <L_top>;")
    # ---- GCM (KMA): mode 6. Tag at CV, hash subkey at CV+16, J0 at J0A, the lengths block at LENS;
    #      counter value in cpbh; third operand (AAD) cpc / cpn; flags cphs cplaad cplpc cpdec (M)
    t.append("  <L_m6> if (cpmd != 6) goto <L_m8>;")
    t.append(f"  cvv = cpbh:4; gh = *[cpm]:16 ({CV + 16:#x}:4); cpcc = 0; cphf = 0;")
    t.append(f"  if (cphs != 0) goto <L_gh1>; *[cpm]:8 ({BLK:#x}:4) = 0; *[cpm]:8 ({BLK + 8:#x}:4) = 0; dflag = 0; bret = 10; goto <L_blk>;")
    t.append(f"  <L_r10> gh = *[cpm]:16 ({BLK:#x}:4); *[cpm]:16 ({CV + 16:#x}:4) = gh; cphf = 1;")
    t.append(f"  <L_gh1> gt = *[cpm]:16 ({CV:#x}:4);")
    # AAD: full blocks
    t.append("  <L_gA> if (cpn < 16) goto <L_gAt>; gx = gt ^ *:16 cpc; gret = 1; goto <L_ghm>;")
    t.append("  <L_gr1> gt = gz; cpc = cpc + 16; cpn = cpn - 16; goto <L_gA>;")
    t.append("  <L_gAt> if (cplaad == 0) goto <L_gstop>; if (cpn == 0) goto <L_gT>;")
    t.append(f"  *[cpm]:8 ({TMP:#x}:4) = 0; *[cpm]:8 ({TMP + 8:#x}:4) = 0; j = 0; <L_gA2> a = *:1 (cpc + zext(j)); *[cpm]:1 ({TMP:#x}:4 + j) = a; j = j + 1; if (zext(j) < cpn) goto <L_gA2>;")
    t.append(f"  gx = gt ^ *[cpm]:16 ({TMP:#x}:4); gret = 2; goto <L_ghm>;")
    t.append("  <L_gr2> gt = gz; cpc = cpc + cpn; cpn = 0;")
    # text: full blocks
    t.append("  <L_gT> if (cpl >= 16) goto <L_gTf>; if (cplpc == 0) goto <L_gstop>; if (cpl == 0) goto <L_gL>; goto <L_gTp>;")
    t.append(f"  <L_gTf> cvv = cvv + 1; cb = *[cpm]:16 ({J0A:#x}:4); cb = ((cb >> 32) << 32) | zext(cvv); *[cpm]:16 ({BLK:#x}:4) = cb; dflag = 0; bret = 11; goto <L_blk>;")
    t.append("  <L_r11> gin = *:16 cpa; gout = gin ^ *[cpm]:16 (" + f"{BLK:#x}:4); *:16 cpo = gout; gct = gout; if (cpdec == 0) goto <L_gc1>; gct = gin;")
    t.append("  <L_gc1> gx = gt ^ gct; gret = 3; goto <L_ghm>;")
    t.append("  <L_gr3> gt = gz; cpa = cpa + 16; cpo = cpo + 16; cpl = cpl - 16; goto <L_gT>;")
    # text: last partial block
    t.append("  <L_gTp> if (cplpc == 0) goto <L_gstop>;")
    t.append(f"  cvv = cvv + 1; cb = *[cpm]:16 ({J0A:#x}:4); cb = ((cb >> 32) << 32) | zext(cvv); *[cpm]:16 ({BLK:#x}:4) = cb; dflag = 0; bret = 12; goto <L_blk>;")
    t.append(f"  <L_r12> *[cpm]:8 ({TMP:#x}:4) = 0; *[cpm]:8 ({TMP + 8:#x}:4) = 0; *[cpm]:8 ({TMP2:#x}:4) = 0; *[cpm]:8 ({TMP2 + 8:#x}:4) = 0; j = 0;")
    t.append(f"  <L_gP> a = *:1 (cpa + zext(j)); b = *[cpm]:1 ({BLK:#x}:4 + j); c = a ^ b; *:1 (cpo + zext(j)) = c; *[cpm]:1 ({TMP:#x}:4 + j) = c; *[cpm]:1 ({TMP2:#x}:4 + j) = a; j = j + 1; if (zext(j) < cpl) goto <L_gP>;")
    t.append(f"  gct = *[cpm]:16 ({TMP:#x}:4); if (cpdec == 0) goto <L_gc2>; gct = *[cpm]:16 ({TMP2:#x}:4);")
    t.append("  <L_gc2> gx = gt ^ gct; gret = 4; goto <L_ghm>;")
    t.append("  <L_gr4> gt = gz; cpa = cpa + cpl; cpo = cpo + cpl; cpl = 0;")
    # last tag
    t.append(f"  <L_gL> gx = gt ^ *[cpm]:16 ({LENS:#x}:4); gret = 5; goto <L_ghm>;")
    t.append(f"  <L_gr5> gt = gz; *[cpm]:16 ({BLK:#x}:4) = *[cpm]:16 ({J0A:#x}:4); dflag = 0; bret = 13; goto <L_blk>;")
    t.append(f"  <L_r13> gt = gt ^ *[cpm]:16 ({BLK:#x}:4); cpcc = 0; goto <L_gend>;")
    t.append("  <L_gstop> cpcc = 2;")
    t.append(f"  <L_gend> *[cpm]:16 ({CV:#x}:4) = gt; cpbh = zext(cvv); goto <L_exit>;")
    # the GCM multiplication gz = gx * gh (bit 0 is the most significant bit)
    t.append("  <L_ghm> gz = 0; gv = gh; gi = 0;")
    t.append("  <L_gb> gbit = (gx >> (127 - gi)) & 1; if (gbit == 0) goto <L_gs>; gz = gz ^ gv;")
    t.append("  <L_gs> if ((gv & 1) == 0) goto <L_gn>; gv = (gv >> 1) ^ rpoly; goto <L_gm>;")
    t.append("  <L_gn> gv = gv >> 1;")
    t.append("  <L_gm> gi = gi + 1; if (gi < 128) goto <L_gb>;")
    t.append("  if (gret != 1) goto <L_gq2>; goto <L_gr1>;")
    t.append("  <L_gq2> if (gret != 2) goto <L_gq3>; goto <L_gr2>;")
    t.append("  <L_gq3> if (gret != 3) goto <L_gq4>; goto <L_gr3>;")
    t.append("  <L_gq4> if (gret != 4) goto <L_gq5>; goto <L_gr4>;")
    t.append("  <L_gq5> goto <L_gr5>;")
    # CMAC of the last block (PCC): subkeys from E(0), the (padded) message block at MSG
    t.append(f"  <L_m8> *[cpm]:8 ({BLK:#x}:4) = 0; *[cpm]:8 ({BLK + 8:#x}:4) = 0; dflag = 0; bret = 8; goto <L_blk>;")
    t.append("  <L_r8> if (bs == 8) goto <L_c8a>;")
    t.append(f"  lv = *[cpm]:16 ({BLK:#x}:4); rc16 = 0x87; msg16 = *[cpm]:16 ({MSG:#x}:4); icv16 = *[cpm]:16 ({CV:#x}:4); goto <L_c8b>;")
    t.append(f"  <L_c8a> lv = zext(*[cpm]:8 ({BLK:#x}:4)) << 64; rc16 = 0x1b; rc16 = rc16 << 64; msg16 = zext(*[cpm]:8 ({MSG:#x}:4)) << 64; icv16 = zext(*[cpm]:8 ({CV:#x}:4)) << 64;")
    t.append("  <L_c8b> m1 = lv >> 127; lv = lv << 1; if (m1 == 0) goto <L_c8c>; lv = lv ^ rc16;")
    t.append("  <L_c8c> kx16 = lv; m1 = lv >> 127; lv = lv << 1; if (m1 == 0) goto <L_c8d>; lv = lv ^ rc16;")
    t.append("  <L_c8d> sh8 = cps; if (sh8 == (zext(bs) << 3)) goto <L_c8e>;")
    t.append("  msk16 = 1; msk16 = msk16 << (128 - sh8); msk16 = msk16 - 1; msk16 = ~msk16; msg16 = (msg16 & msk16) | (one16 << (127 - sh8)); msg16 = msg16 ^ lv; goto <L_c8f>;")
    t.append("  <L_c8e> msg16 = msg16 ^ kx16;")
    t.append("  <L_c8f> msg16 = msg16 ^ icv16; if (bs == 8) goto <L_c8g>;")
    t.append(f"  *[cpm]:16 ({BLK:#x}:4) = msg16; goto <L_c8h>;")
    t.append(f"  <L_c8g> sh16 = msg16 >> 64; *[cpm]:8 ({BLK:#x}:4) = sh16:8;")
    t.append("  <L_c8h> dflag = 0; bret = 9; goto <L_blk>;")
    t.append(f"  <L_r9> *[cpm]:8 ({CV:#x}:4) = *[cpm]:8 ({BLK:#x}:4); if (bs == 8) goto <L_exit>; *[cpm]:8 ({CV + 8:#x}:4) = *[cpm]:8 ({BLK + 8:#x}:4); goto <L_exit>;")
    # ---- the block cipher ------------------------------------------------------------------------
    t.append("  <L_blk> if (cpalg != 3) goto <L_des>;")
    t.append("  nr = zext(cpnk) + 6; if (dflag != 0) goto <L_adec>;")
    ark = lambda r: (f"i = 0; <L_ark{r}> *[cpm]:4 ({BLK:#x}:4 + (i * 4)) = *[cpm]:4 ({BLK:#x}:4 + (i * 4)) ^ *[cpm]:4 ({RK:#x}:4 + (rnd * 16) + (i * 4)); i = i + 1; if (i < 4) goto <L_ark{r}>;")
    # encrypt
    t.append("  rnd = 0; " + ark("e0"))
    t.append("  rnd = 1;")
    t.append(f"  <L_aer> i = 0; <L_aes> src = (i & 3) + ((((i >> 2) + (i & 3)) & 3) << 2); a = *[cpm]:1 ({BLK:#x}:4 + src); b = *[cpm]:1 ({SBOX:#x}:4 + zext(a)); *[cpm]:1 ({TMP:#x}:4 + i) = b; i = i + 1; if (i < 16) goto <L_aes>;")
    t.append(f"  if (rnd == nr) goto <L_ael>; j = 0;")
    xt = lambda dst, src: f"{dst} = ({src} << 1) ^ (({src} >> 7) * 0x1b);"
    t.append(f"  <L_aem> q0 = *[cpm]:1 ({TMP:#x}:4 + (j * 4)); q1 = *[cpm]:1 ({TMP:#x}:4 + (j * 4) + 1); q2 = *[cpm]:1 ({TMP:#x}:4 + (j * 4) + 2); q3 = *[cpm]:1 ({TMP:#x}:4 + (j * 4) + 3);")
    t.append("  " + xt("x0", "q0") + " " + xt("x1", "q1") + " " + xt("x2", "q2") + " " + xt("x3", "q3"))
    t.append(f"  *[cpm]:1 ({BLK:#x}:4 + (j * 4)) = x0 ^ x1 ^ q1 ^ q2 ^ q3; *[cpm]:1 ({BLK:#x}:4 + (j * 4) + 1) = q0 ^ x1 ^ x2 ^ q2 ^ q3;")
    t.append(f"  *[cpm]:1 ({BLK:#x}:4 + (j * 4) + 2) = q0 ^ q1 ^ x2 ^ x3 ^ q3; *[cpm]:1 ({BLK:#x}:4 + (j * 4) + 3) = x0 ^ q0 ^ q1 ^ q2 ^ x3; j = j + 1; if (j < 4) goto <L_aem>;")
    t.append("  " + ark("e1"))
    t.append("  rnd = rnd + 1; goto <L_aer>;")
    t.append(f"  <L_ael> i = 0; <L_aec> *[cpm]:4 ({BLK:#x}:4 + (i * 4)) = *[cpm]:4 ({TMP:#x}:4 + (i * 4)) ^ *[cpm]:4 ({RK:#x}:4 + (rnd * 16) + (i * 4)); i = i + 1; if (i < 4) goto <L_aec>;")
    t.append("  goto <L_bdone>;")
    # decrypt
    t.append("  <L_adec> rnd = nr; " + ark("d0"))
    t.append("  rnd = nr - 1;")
    t.append(f"  <L_adr> i = 0; <L_ads> src = (i & 3) + (((((i >> 2) - (i & 3)) & 3)) << 2); a = *[cpm]:1 ({BLK:#x}:4 + src); b = *[cpm]:1 ({ISBOX:#x}:4 + zext(a)); *[cpm]:1 ({TMP:#x}:4 + i) = b; i = i + 1; if (i < 16) goto <L_ads>;")
    t.append(f"  i = 0; <L_adk> *[cpm]:4 ({BLK:#x}:4 + (i * 4)) = *[cpm]:4 ({TMP:#x}:4 + (i * 4)) ^ *[cpm]:4 ({RK:#x}:4 + (rnd * 16) + (i * 4)); i = i + 1; if (i < 4) goto <L_adk>;")
    t.append("  if (rnd == 0) goto <L_bdone>; j = 0;")
    def mulset(v, tag):
        # 9, 11, 13, 14 times v (1-byte locals p9..)
        return (f"{xt('m2', v)} {xt('m4', 'm2')} {xt('m8', 'm4')} "
                f"p9{tag} = m8 ^ {v}; p11{tag} = m8 ^ m2 ^ {v}; p13{tag} = m8 ^ m4 ^ {v}; p14{tag} = m8 ^ m4 ^ m2;")
    t.append("  local m2:1 = 0; local m4:1 = 0; local m8:1 = 0;")
    for v in "0123":
        t.append(f"  local p9{v}:1 = 0; local p11{v}:1 = 0; local p13{v}:1 = 0; local p14{v}:1 = 0;")
    t.append(f"  <L_adm> q0 = *[cpm]:1 ({BLK:#x}:4 + (j * 4)); q1 = *[cpm]:1 ({BLK:#x}:4 + (j * 4) + 1); q2 = *[cpm]:1 ({BLK:#x}:4 + (j * 4) + 2); q3 = *[cpm]:1 ({BLK:#x}:4 + (j * 4) + 3);")
    for v in "0123":
        t.append("  " + mulset(f"q{v}", v))
    t.append(f"  *[cpm]:1 ({BLK:#x}:4 + (j * 4)) = p140 ^ p111 ^ p132 ^ p93; *[cpm]:1 ({BLK:#x}:4 + (j * 4) + 1) = p90 ^ p141 ^ p112 ^ p133;")
    t.append(f"  *[cpm]:1 ({BLK:#x}:4 + (j * 4) + 2) = p130 ^ p91 ^ p142 ^ p113; *[cpm]:1 ({BLK:#x}:4 + (j * 4) + 3) = p110 ^ p131 ^ p92 ^ p143; j = j + 1; if (j < 4) goto <L_adm>;")
    t.append("  rnd = rnd - 1; goto <L_adr>;")
    # ---- DES / TDES
    t.append("  <L_des> npass = 1; if (cpalg == 0) goto <L_dnp>; npass = 3;")
    t.append(f"  <L_dnp> tq = *[cpm]:8 ({BLK:#x}:4); pass = 0;")
    t.append("  <L_dps> kidx = pass; d1 = zext(dflag); if (npass == 1) goto <L_dkx>;")
    t.append("  if (dflag == 0) goto <L_dkz>; kidx = 2 - pass;")
    t.append("  <L_dkz> if (pass != 1) goto <L_dkq>; d1 = 1 - d1;")
    t.append("  <L_dkq> if (cpalg != 1) goto <L_dkx>; if (kidx != 2) goto <L_dkx>; kidx = 0;")
    t.append("  <L_dkx> xin = tq;")
    t.append("  " + perm("xin", 64, "kk", 64, T_IP, "pip"))
    t.append("  lh = kk(4); rh = kk:4; rr = 0;")
    t.append("  <L_drd> rv8 = zext(rh);")
    t.append("  " + perm("rv8", 32, "e48", 48, T_E, "pe"))
    t.append(f"  j = rr; if (d1 == 0) goto <L_dsk>; j = 15 - rr;")
    t.append(f"  <L_dsk> e48 = e48 ^ *[cpm]:8 ({KS:#x}:4 + (zext(kidx) * 128) + (j * 8));")
    t.append("  f32 = 0; j = 0;")
    t.append(f"  <L_dsb> sh8 = zext(j); sh8 = 6 * sh8; sh8 = 42 - sh8; six = (e48 >> sh8) & 0x3f; k = six:4;")
    t.append(f"  n = ((k >> 4) & 2) | (k & 1); k = (k >> 1) & 0xf; pt = *[cpm]:1 ({T_SB:#x}:4 + (j * 64) + (n * 16) + k); f32 = (f32 << 4) | zext(pt); j = j + 1; if (j < 8) goto <L_dsb>;")
    t.append("  " + perm("f32", 32, "d1x", 32, T_P, "pp"))
    t.append("  u = lh ^ d1x:4; lh = rh; rh = u; rr = rr + 1; if (rr < 16) goto <L_drd>;")
    t.append("  xin = (zext(rh) << 32) | zext(lh);")
    t.append("  " + perm("xin", 64, "tq", 64, T_FP, "pfp"))
    t.append("  pass = pass + 1; if (pass < npass) goto <L_dps>;")
    t.append(f"  *[cpm]:8 ({BLK:#x}:4) = tq;")
    t.append("  <L_bdone> if (bret != 1) goto <L_b2>; goto <L_r1>;")
    for k in range(2, 14):
        t.append(f"  <L_b{k}> if (bret != {k}) goto <L_b{k + 1}>; goto <L_r{k}>;" if k < 13 else f"  <L_b13> goto <L_r13>;")
    t.append("  <L_exit>")
    t.append("}")
    return "\n".join(t)

def engines():
    out = ["# Generated by tools/gen_cpacf.py (message-security-assist engines); do not edit.", ""]
    out.append(md_engine("cp_sha1", 4, 64, 8, None, sha1_rounds(), 80, 16, ""))
    out.append(md_engine("cp_sha256", 4, 64, 8, None, sha256_rounds(), 64, 16, kinit_stores(K256, 4, KT)))
    out.append(md_engine("cp_sha512", 8, 128, 16, None, sha512_rounds(), 80, 16, kinit_stores(K512, 8, KT)))
    out.append(keccak_engine())
    out.append(ghash_engine())
    out.append(cipher_engine())
    return "\n".join(out) + "\n"

# ---- instruction semantics --------------------------------------------------------------------
def fcmask(codes):
    m = 0
    for c in codes:
        m |= 1 << (127 - c)
    return m

# KIMD / KLMD functions: code -> (engine id, chaining-value bytes, block bytes, message-bit-length bytes, domain byte)
MD = {1: (1, 20, 64, 8, 0), 2: (2, 32, 64, 8, 0), 3: (3, 64, 128, 16, 0),
      32: (4, 200, 144, 0, 0x06), 33: (4, 200, 136, 0, 0x06), 34: (4, 200, 104, 0, 0x06), 35: (4, 200, 72, 0, 0x06),
      36: (4, 200, 168, 0, 0x1f), 37: (4, 200, 136, 0, 0x1f), 65: (5, 32, 16, 0, 0)}
ENGINE = {1: "cp_sha1", 2: "cp_sha256", 3: "cp_sha512", 4: "cp_keccak", 5: "cp_ghash"}

# cipher functions: code -> (cpalg, cpnk, key bytes)
CIPHER = {1: (0, 0, 8), 2: (1, 0, 16), 3: (2, 0, 24), 18: (3, 4, 16), 19: (3, 6, 24), 20: (3, 8, 32)}
# instruction -> (mode, has chaining value in the parameter block)
CIPHER_INSN = {"km": (0, False), "kmc": (1, True), "kmf": (2, True), "kmo": (3, True), "kmctr": (4, False),
               "kmac": (7, True)}
KMA_FC = {18: (3, 4, 16), 19: (3, 6, 24), 20: (3, 8, 32)}

NAMES = {"kimd", "klmd", "km", "kmc", "kmf", "kmo", "kmctr", "kmac", "pcc", "kma"}

def semantics(ctx):
    n, o = ctx["name"], ctx["ops"]
    x = ctx.get("extra", [])
    if n in ("kimd", "klmd") and len(o) >= 2 and len(x) >= 4:
        return md_insn(n == "klmd", o, x)
    if n in CIPHER_INSN and len(x) >= 3:
        return cipher_insn(n, o, x)
    if n == "pcc":
        return pcc_insn(x)
    if n == "kma" and len(x) >= 5:
        return kma_insn(o, x)
    return None

def cipher_insn(n, o, x):
    """KM / KMC / KMF / KMO / KMCTR: R1 first operand address, R2 / R2+1 second operand
    (address / length), KMCTR: R3 the counter vector address. x: R2+1, R2 number, R1 number,
    (KMCTR) R3 number."""
    mode, has_cv = CIPHER_INSN[n]
    ctr = n == "kmctr"
    mac = n == "kmac"                   # no first operand
    r1a, r2a, r3a = o[0], (o[2] if ctr else o[1]), (o[1] if ctr else None)
    r2l = x[0]
    t = [f"local r2num:4 = {x[1]}; local r1num:4 = {x[2]};"]
    if ctr:
        t.append(f"local r3num:4 = {x[3]};")
    t.append("local fc:1 = r0:1 & 0x7f; local alg:1 = 0; local nk:1 = 0; local klen:4 = 0; local bsz:8 = 8; local ok:1 = 0; local ci:4 = 0; local lc:8 = 0;")
    t.append("if (fc != 0) goto <L_fn>;")
    mask = fcmask([0] + sorted(CIPHER))
    t.append(f"*:8 r1 = {mask >> 64:#x}:8; *:8 (r1 + 8) = {mask & ((1 << 64) - 1):#x}:8; cc = 0; goto <L_done>;")
    t.append("<L_fn>")
    regs_ok = "(((r2num & 1) == 0) && (r2num != 0)" + ("" if mac else " && ((r1num & 1) == 0) && (r1num != 0)")
    if ctr:
        regs_ok += " && ((r3num & 1) == 0) && (r3num != 0) && (r3num != r1num) && (r3num != r2num)"
    regs_ok += ")"
    t.append(f"if ({regs_ok}) goto <L_regok>; trap_specification(); goto <L_done>;\n<L_regok>")
    for fc, (alg, nk, klen) in sorted(CIPHER.items()):
        t.append(f"if (fc != {fc}) goto <L_g{fc}>; alg = {alg}; nk = {nk}; klen = {klen}; ok = 1; <L_g{fc}>")
    t.append("if (ok != 0) goto <L_valid>; trap_specification(); goto <L_done>;\n<L_valid>")
    t.append("if (alg != 3) goto <L_bs>; bsz = 16;\n<L_bs>")
    t.append("lc = bsz;")
    if n == "kmf":
        t.append("lc = (r0 >> 24) & 0xff; if ((lc != 0) && (lc <= bsz)) goto <L_lcok>; trap_specification(); goto <L_done>;\n<L_lcok>")
    t.append(f"if (({r2l} % lc) == 0) goto <L_lenok>; trap_specification(); goto <L_done>;\n<L_lenok>")
    t.append("ci = 0;")
    if has_cv:
        t.append(f"<L_cvc> *[cpm]:4 ({CV:#x}:4 + ci) = *:4 (r1 + zext(ci)); ci = ci + 4; if (zext(ci) < bsz) goto <L_cvc>;")
        t.append(f"ci = 0; <L_kc> *[cpm]:4 ({KEYA:#x}:4 + ci) = *:4 (r1 + bsz + zext(ci)); ci = ci + 4; if (ci < klen) goto <L_kc>;")
    else:
        t.append(f"<L_kc> *[cpm]:4 ({KEYA:#x}:4 + ci) = *:4 (r1 + zext(ci)); ci = ci + 4; if (ci < klen) goto <L_kc>;")
    t.append(f"cpa = {r2a}; cpl = {r2l}; cpo = {r1a}; cpmd = {mode}; cpdec = r0:1 >> 7; cpalg = alg; cpnk = nk; cps = lc;")
    if ctr:
        t.append(f"cpc = {r3a};")
    t.append("build cp_cipher;")
    if has_cv:
        t.append(f"ci = 0; <L_cvo> *:4 (r1 + zext(ci)) = *[cpm]:4 ({CV:#x}:4 + ci); ci = ci + 4; if (zext(ci) < bsz) goto <L_cvo>;")
    t.append(f"{r2a} = cpa; {r2l} = cpl;" + ("" if mac else f" {r1a} = cpo;"))
    if ctr:
        t.append(f"{r3a} = cpc;")
    t.append("cc = 0;\n<L_done>")
    return "\n".join(t)

def kma_insn(o, x):
    """KMA (GCM-AES): R1 output address, R2 / R2+1 text, R3 / R3+1 additional authenticated data.
    x: R2+1, R2 number, R1 number, R3 number, R3+1."""
    r1a, r3a, r2a = o[0], o[1], o[2]
    r2l, r3l = x[0], x[4]
    t = [f"local r2num:4 = {x[1]}; local r1num:4 = {x[2]}; local r3num:4 = {x[3]};"]
    t.append("local fc:1 = r0:1 & 0x7f; local nk:1 = 0; local klen:4 = 0; local ok:1 = 0; local ci:4 = 0; local fl:8 = r0;")
    t.append("if (fc != 0) goto <L_fn>;")
    mask = fcmask([0] + sorted(KMA_FC))
    t.append(f"*:8 r1 = {mask >> 64:#x}:8; *:8 (r1 + 8) = {mask & ((1 << 64) - 1):#x}:8; cc = 0; goto <L_done>;")
    t.append("<L_fn>")
    t.append("if (((r1num & 1) == 0) && (r1num != 0) && ((r2num & 1) == 0) && (r2num != 0) && ((r3num & 1) == 0) && (r3num != 0) && (r3num != r1num) && (r3num != r2num)) goto <L_regok>; trap_specification(); goto <L_done>;\n<L_regok>")
    for fc, (alg, nk, klen) in sorted(KMA_FC.items()):
        t.append(f"if (fc != {fc}) goto <L_g{fc}>; nk = {nk}; klen = {klen}; ok = 1; <L_g{fc}>")
    t.append("if (ok != 0) goto <L_valid>; trap_specification(); goto <L_done>;\n<L_valid>")
    t.append("if (((fl & 0x200) != 0) || ((fl & 0x100) == 0)) goto <L_flok>; trap_specification(); goto <L_done>;\n<L_flok>")
    t.append(f"ci = 0; <L_t> *[cpm]:4 ({CV:#x}:4 + ci) = *:4 (r1 + 16 + zext(ci)); ci = ci + 4; if (ci < 32) goto <L_t>;")
    t.append(f"ci = 0; <L_l> *[cpm]:4 ({LENS:#x}:4 + ci) = *:4 (r1 + 48 + zext(ci)); ci = ci + 4; if (ci < 16) goto <L_l>;")
    t.append(f"ci = 0; <L_j> *[cpm]:4 ({J0A:#x}:4 + ci) = *:4 (r1 + 64 + zext(ci)); ci = ci + 4; if (ci < 16) goto <L_j>;")
    t.append(f"ci = 0; <L_k> *[cpm]:4 ({KEYA:#x}:4 + ci) = *:4 (r1 + 80 + zext(ci)); ci = ci + 4; if (ci < klen) goto <L_k>;")
    t.append(f"cpa = {r2a}; cpl = {r2l}; cpo = {r1a}; cpc = {r3a}; cpn = {r3l}; cpmd = 6; cpdec = r0:1 >> 7; cpalg = 3; cpnk = nk;")
    t.append("cpbh = zext(*:4 (r1 + 12)); local sh10:8 = fl >> 10; local sh9:8 = fl >> 9; local sh8x:8 = fl >> 8; cphs = sh10:1 & 1; cplaad = sh9:1 & 1; cplpc = sh8x:1 & 1;")
    t.append("build cp_cipher;")
    t.append(f"ci = 0; <L_o> *:4 (r1 + 16 + zext(ci)) = *[cpm]:4 ({CV:#x}:4 + ci); ci = ci + 4; if (ci < 32) goto <L_o>;")
    t.append("*:4 (r1 + 12) = cpbh:4;")
    t.append(f"if (cphf == 0) goto <L_nh>; r0 = r0 | 0x400;\n<L_nh>")
    t.append(f"{r2a} = cpa; {r2l} = cpl; {r1a} = cpo; {r3a} = cpc; {r3l} = cpn;")
    t.append("cc = cpcc;\n<L_done>")
    return "\n".join(t)

def pcc_insn(x):
    """PCC: the CMAC of the last block (functions 1-3, 18-20): ML at 0, message at 8, ICV at 8 + bs
    (replaced by the CMAC), key at 8 + 2 bs"""
    t = ["local fc:1 = r0:1 & 0x7f; local alg:1 = 0; local nk:1 = 0; local klen:4 = 0; local bsz:8 = 8; local ok:1 = 0; local ci:4 = 0; local ml:8 = 0;"]
    t.append("if (fc != 0) goto <L_fn>;")
    mask = fcmask([0] + sorted(CIPHER))
    t.append(f"*:8 r1 = {mask >> 64:#x}:8; *:8 (r1 + 8) = {mask & ((1 << 64) - 1):#x}:8; cc = 0; goto <L_done>;")
    t.append("<L_fn>")
    for fc, (alg, nk, klen) in sorted(CIPHER.items()):
        t.append(f"if (fc != {fc}) goto <L_g{fc}>; alg = {alg}; nk = {nk}; klen = {klen}; ok = 1; <L_g{fc}>")
    t.append("if (ok != 0) goto <L_valid>; trap_specification(); goto <L_done>;\n<L_valid>")
    t.append("if (alg != 3) goto <L_bs>; bsz = 16;\n<L_bs>")
    t.append("ml = zext(*:1 r1); if (ml <= (bsz << 3)) goto <L_mlok>; cc = 2; goto <L_done>;\n<L_mlok>")
    t.append(f"ci = 0; <L_m> *[cpm]:4 ({MSG:#x}:4 + ci) = *:4 (r1 + 8 + zext(ci)); ci = ci + 4; if (zext(ci) < bsz) goto <L_m>;")
    t.append(f"ci = 0; <L_i> *[cpm]:4 ({CV:#x}:4 + ci) = *:4 (r1 + 8 + bsz + zext(ci)); ci = ci + 4; if (zext(ci) < bsz) goto <L_i>;")
    t.append(f"ci = 0; <L_k> *[cpm]:4 ({KEYA:#x}:4 + ci) = *:4 (r1 + 8 + (2 * bsz) + zext(ci)); ci = ci + 4; if (ci < klen) goto <L_k>;")
    t.append("cpl = 1; cpmd = 8; cpalg = alg; cpnk = nk; cps = ml; cpdec = 0;")
    t.append("build cp_cipher;")
    t.append(f"ci = 0; <L_o> *:4 (r1 + 8 + bsz + zext(ci)) = *[cpm]:4 ({CV:#x}:4 + ci); ci = ci + 4; if (zext(ci) < bsz) goto <L_o>;")
    t.append("cc = 0;\n<L_done>")
    return "\n".join(t)

def md_insn(last, o, x):
    """KIMD / KLMD. o[0] is R1 (the SHAKE output address for KLMD), o[1] R2 (operand address);
    x: R2+1, R2 number, R1 number, R1+1."""
    r1a, r2a = o[0], o[1]
    r2l, r1l = x[0], x[3]
    r2n, r1n = "r2num", "r1num"
    t = []
    t.append(f"local r2num:4 = {x[1]}; local r1num:4 = {x[2]};")
    t.append("local fc:1 = r0:1 & 0x7f; local eid:1 = 0; local cvlen:4 = 0; local bsz:8 = 0; local mbl:4 = 0; local dom:1 = 0;")
    t.append(f"local len0:8 = {r2l}; local ci:4 = 0; local ps:1 = 0; local nip:1 = 0; local shake:1 = 0;")
    t.append("if (fc != 0) goto <L_fn>;")
    mask = fcmask([0] + sorted(MD))
    t.append(f"*:8 r1 = {mask >> 64:#x}:8; *:8 (r1 + 8) = {mask & ((1 << 64) - 1):#x}:8; cc = 0; goto <L_done>;")
    t.append("<L_fn>")
    if not last:
        t.append("if ((r0 & 0x80) == 0) goto <L_b56>; trap_specification(); goto <L_done>;\n<L_b56>")
    t.append(f"if ((({r2n} & 1) == 0) && ({r2n} != 0)) goto <L_r2ok>; trap_specification(); goto <L_done>;\n<L_r2ok>")
    for fc, (eid, cvlen, bs, lenb, dom) in sorted(MD.items()):
        t.append(f"if (fc != {fc}) goto <L_g{fc}>; eid = {eid}; cvlen = {cvlen}; bsz = {bs}; mbl = {lenb}; dom = {dom:#x}; shake = {1 if fc in (36, 37) else 0}; <L_g{fc}>")
    t.append("if (eid != 0) goto <L_valid>; trap_specification(); goto <L_done>;\n<L_valid>")
    t.append("local fl:8 = r0 >> 8; nip = fl:1 >> 7; ps = fl:1 & 1; nip = nip & 1;")
    if not last:
        t.append(f"if (({r2l} % bsz) == 0) goto <L_lenok>; trap_specification(); goto <L_done>;\n<L_lenok>")
    else:
        # KLMD-SHAKE: first operand register pair, padding state rules
        t.append("if (shake == 0) goto <L_klok>;")
        t.append(f"if ((({r1n} & 1) == 0) && ({r1n} != 0) && ({r1n} != {r2n})) goto <L_r1ok>; trap_specification(); goto <L_done>;\n<L_r1ok>")
        t.append(f"if ((ps == 0) || ({r2l} == 0)) goto <L_klok>; trap_specification(); goto <L_done>;")
        t.append("<L_klok> if ((ps == 0) || (nip == 0)) goto <L_klok2>; trap_specification(); goto <L_done>;\n<L_klok2>")
    t.append(f"cpa = {r2a}; cpl = {r2l}; cpfin = {1 if last else 0}; cpbh = 0; cpbl = 0; cprt = bsz; cpdm = dom; cpps = ps; cpmd = shake;")
    t.append("cpo = 0; cpn = 0;")
    if last:
        t.append(f"if (shake == 0) goto <L_nsh>; cpo = {r1a}; cpn = {r1l};\n<L_nsh>")
    # chaining value (zeros for the SHA-3 family when NIP) into cpm
    t.append("ci = 0; if (nip == 0) goto <L_cin>; if (eid != 4) goto <L_cin>;")
    t.append(f"<L_zf> *[cpm]:4 ({CV:#x}:4 + ci) = 0; ci = ci + 4; if (ci < 200) goto <L_zf>; goto <L_cdone>;")
    t.append(f"<L_cin> *[cpm]:4 ({CV:#x}:4 + ci) = *:4 (r1 + zext(ci)); ci = ci + 4; if (ci < cvlen) goto <L_cin>;")
    t.append("<L_cdone>")
    if last:
        t.append("if (mbl == 0) goto <L_nm>; if (mbl == 16) goto <L_m16>; cpbl = *:8 (r1 + zext(cvlen)); goto <L_nm>;")
        t.append("<L_m16> cpbh = *:8 (r1 + zext(cvlen)); cpbl = *:8 (r1 + zext(cvlen) + 8);\n<L_nm>")
    for eid, eng in sorted(ENGINE.items()):
        t.append(f"if (eid != {eid}) goto <L_e{eid}>; build {eng}; goto <L_aft>;\n<L_e{eid}>")
    t.append("<L_aft> ci = 0;")
    t.append(f"<L_cout> *:4 (r1 + zext(ci)) = *[cpm]:4 ({CV:#x}:4 + ci); ci = ci + 4; if (ci < cvlen) goto <L_cout>;")
    t.append(f"{r2a} = cpa; {r2l} = cpl;")
    if last:
        t.append(f"if (shake == 0) goto <L_nsh2>; {r1a} = cpo; {r1l} = cpn;\n<L_nsh2>")
        t.append("r0 = (r0 & ~0x8100) | (zext(cpps) << 8); ")
    else:
        t.append("if (len0 == 0) goto <L_nn>; r0 = r0 & ~0x8000;\n<L_nn>")
    t.append("cc = 0;")
    t.append("<L_done>")
    return "\n".join(t)

if __name__ == "__main__":
    import os
    dst = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "languages", "s390x_cpacf.sinc")
    open(dst, "w").write(engines())
    print("wrote", os.path.normpath(dst))
