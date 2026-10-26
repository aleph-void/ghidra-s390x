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

def engines():
    out = ["# Generated by tools/gen_cpacf.py (message-security-assist engines); do not edit.", ""]
    out.append(md_engine("cp_sha1", 4, 64, 8, None, sha1_rounds(), 80, 16, ""))
    out.append(md_engine("cp_sha256", 4, 64, 8, None, sha256_rounds(), 64, 16, kinit_stores(K256, 4, KT)))
    out.append(md_engine("cp_sha512", 8, 128, 16, None, sha512_rounds(), 80, 16, kinit_stores(K512, 8, KT)))
    out.append(keccak_engine())
    out.append(ghash_engine())
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

NAMES = {"kimd", "klmd"}

def semantics(ctx):
    n, o = ctx["name"], ctx["ops"]
    x = ctx.get("extra", [])
    if n in ("kimd", "klmd") and len(o) >= 2 and len(x) >= 4:
        return md_insn(n == "klmd", o, x)
    return None

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
