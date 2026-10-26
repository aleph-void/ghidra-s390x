"""P-code for PERFORM FLOATING-POINT OPERATION (PFPO), used by gen_semantics.py.

PFPO convert floating-point radix (operation type 1) converts the second operand (FPR 4, with
FPR 6 for extended) to the format of the first (FPR 0, with FPR 2), between any two of HFP,
BFP and DFP in short, long and extended formats (the Principles of Operation, 9-35).

Every finite nonzero source is reduced to an exact value M * 2^E (HFP, BFP) or c * 10^q (DFP).
The conversion is correctly rounded by the PFPO rounding method (GR0 bits 60-63):

- to DFP: M * 2^E is evaluated exactly in a 5,120-byte integer (up to 38,000 bits: the extended
  BFP 2^-16494 needs 5^16494), divided down to 36 digits with a sticky digit, and rounded by
  gen_dfp.round_finite (subnormals, overflow, 8 rounding methods). The DFP preferred-quantum
  control (GR0 bit 59) selects the cohort member of an exact result.
- to BFP and HFP: c * 10^q becomes a 124-bit quotient with a sticky bit (exact 10^k, 2^s * c / 10^k);
  the binary or hexadecimal rounding then uses the rounding method, with gradual underflow for
  BFP and the HFP overflow/underflow controls (GR0 bits 58-59) for HFP.

Exceptions: the IEEE flags are not kept, but the condition code reports them (1: an exception was
recognized in nontrap form: invalid, overflow, underflow with an inexact result, inexact unless
suppressed by GR0 bit 56, quantum exception for DFP when GR0 bit 58 is one). Traps (FPC masks)
and the alternate-exception-action control are not modelled; the return code in GR1 is zero.
An invalid function is a specification exception (a trap pcodeop), or cc 3 with the test bit.
"""
import re
from gen_vector import Block, uid
import gen_dfp
from gen_dfp import FMT, big, lbl, decode, read_bits, write_bits, encode_finite, encode_special, \
    round_finite, ndigits, pow10

W = 5120       # bytes of the big integers (40,960 bits)
# SLEIGH temporaries are limited to 256 bytes, so the big integers live in registers
# (pfw0-pfw5, s390x.slaspec) and every operation on them is a single statement.

def pick(blk, idx, vals, size=8):
    return blk.local(size, " + ".join(f"zext({idx} == {i}) * {v}" for i, v in enumerate(vals)))

def bitlen_w(blk, reg, tmp):
    """index of the leading one bit of the nonzero big integer in reg (8-byte local); tmp: a
    scratch big register"""
    L = blk.local(8, "0")
    for j in range(15, -1, -1):
        lab = f"bl{blk.tag}_{j}_{L.split('_')[-1]}"
        blk.add(f"{tmp} = {reg} >> ({L} + {1 << j}); if ({tmp} == 0) goto <{lab}>; {L} = {L} + {1 << j};\n<{lab}>")
    return L

def pow_reg(blk, dst, base, n):
    """dst = base ^ n (base 5 or 10; n: 8-byte local >= 0): chunks of the largest power that
    fits a 64-bit constant, then single multiplications"""
    k = blk.local(8, n)
    l = lbl(blk, "pw")
    ch, const = (27, 5 ** 27) if base == "5" else (18, 10 ** 18)
    blk.add(f"{dst} = 1;\n<{l}a> if ({k} s< {ch}) goto <{l}b>; {dst} = {dst} * {const:#x}; {k} = {k} - {ch}; goto <{l}a>;\n"
            f"<{l}b> if ({k} s<= 0) goto <{l}e>; {dst} = {dst} * {base}; {k} = {k} - 1; goto <{l}b>;\n<{l}e>")

def bitlen16(blk, N):
    L = blk.local(8, "0")
    for j in range(6, -1, -1):
        blk.add(f"if (({N} >> ({L} + {1 << j})) == 0) goto <bs{blk.tag}_{j}_{L.split('_')[-1]}>; {L} = {L} + {1 << j};\n"
                f"<bs{blk.tag}_{j}_{L.split('_')[-1]}>")
    return L

def rounding_up(blk, sg, mode, lsb, guard, sticky):
    """(up, inexact): increment the truncated binary result?"""
    inx = blk.local(1, f"{guard} || {sticky}")
    up = blk.local(1, f"(({mode} == 0) && {guard} && ({sticky} || {lsb})) || "
                      f"(({mode} == 2) && {inx} && ({sg} == 0)) || (({mode} == 3) && {inx} && ({sg} != 0)) || "
                      f"(({mode} == 4) && {guard}) || (({mode} == 5) && {guard} && {sticky}) || "
                      f"(({mode} == 6) && {inx})")
    return up, inx

def shift_round(blk, sg, mode, N, st, drop):
    """N (16 bytes) shifted right by drop (signed 8-byte; left when <= 0) with rounding;
    returns (Q, inexact); the round-to-prepare-for-shorter-precision method (7) sets the last bit."""
    Q = blk.local(16, "zext(0:8)")
    guard, sticky = blk.local(1, "0"), blk.local(1, f"{st}")
    l = lbl(blk, "sr")
    blk.add(f"if ({drop} s> 0) goto <{l}r>; {Q} = {N} << (0 - {drop}); goto <{l}e>;\n<{l}r>")
    dd = blk.local(8, f"{drop}")
    blk.add(f"if ({dd} s<= 126) goto <{l}c>; {dd} = 126;\n<{l}c>")
    mask = blk.local(16, f"(zext(1:1) << ({dd} - 1)) - 1")
    blk.add(f"{Q} = {N} >> {dd}; {guard} = (({N} >> ({dd} - 1)) & 1) != 0; {sticky} = {sticky} || (({N} & {mask}) != 0);\n<{l}e>")
    up, inx = rounding_up(blk, sg, mode, f"(({Q} & 1) != 0)", guard, sticky)
    blk.add(f"{Q} = {Q} + zext({up}); if (({mode} != 7) || !{inx}) goto <{l}x>; {Q} = {Q} | 1;\n<{l}x>")
    return Q, inx


def tr(blk, n, expr, wide=16):
    """n-byte truncation of an expression of `wide` bytes"""
    t = blk.local(wide, expr)
    return blk.local(n, f"{t}:{n}")

def setv(blk, dst, n, expr, wide=16):
    t = blk.local(wide, expr)
    blk.add(f"{dst} = {t}:{n};")

def semantics(ctx):
    if ctx["name"] != "pfpo":
        return None
    blk = Block()
    done = lbl(blk, "pfd")
    # ---- GR0 fields ------------------------------------------------------------------------
    tb = tr(blk, 1, "(r0 >> 31) & 1", 8)
    otc = tr(blk, 1, "(r0 >> 24) & 0x7f", 8)
    c1 = tr(blk, 1, "r0 >> 16", 8)
    c2 = tr(blk, 1, "r0 >> 8", 8)
    inxs = tr(blk, 1, "(r0 >> 7) & 1", 8)
    b58 = tr(blk, 1, "(r0 >> 5) & 1", 8)
    b59 = tr(blk, 1, "(r0 >> 4) & 1", 8)
    rm = tr(blk, 1, "r0 & 0xf", 8)
    def cls(c):
        return blk.local(1, f"zext({c} <= 2) + zext(({c} >= 5) && ({c} <= 7)) * 2 + zext(({c} >= 8) && ({c} <= 10)) * 3")
    k1, k2 = cls(c1), cls(c2)      # 1 HFP, 2 BFP, 3 DFP (0: invalid)
    z1 = blk.local(1, f"{c1} - zext({k1} == 2) * 5 - zext({k1} == 3) * 8")
    z2 = blk.local(1, f"{c2} - zext({k2} == 2) * 5 - zext({k2} == 3) * 8")
    valid = blk.local(1, f"({otc} == 1) && ({k1} != 0) && ({k2} != 0) && ({k1} != {k2}) && "
                         f"!(({k1} == 2) && ((({b58} | {b59}) & 1) != 0)) && (({rm} == 0) || ({rm} == 1) || ({rm} >= 8))")
    blk.add(f"if ({valid}) goto <{done}v>;\n"
            f"if ({tb} != 0) goto <{done}i>; trap_specification(); goto <{done}>;\n"
            f"<{done}i> r1 = r1 & 0xffffffff00000000; cc = 3; goto <{done}>;\n<{done}v>\n"
            f"r1 = r1 & 0xffffffff00000000;\n"
            f"if ({tb} == 0) goto <{done}g>; cc = 0; goto <{done}>;\n<{done}g>")
    mode = blk.local(8, f"zext({rm} == 0) * zext((fpc >> 4) & 7) + zext({rm} == 1) * zext(fpc & 7) + "
                        f"zext({rm} >= 8) * zext({rm} - 8)")
    # ---- decode the source -------------------------------------------------------------------
    s, cl = blk.local(1, "0"), blk.local(1, "0")
    pay, M = blk.local(16, "zext(0:8)"), blk.local(16, "zext(0:8)")
    E = blk.local(8, "0")
    rdx = blk.local(1, "0")        # 1: the source is DFP (M * 10^E), else M * 2^E
    raw = blk.local(16, "zext(0:8)")
    l = lbl(blk, "sd")
    blk.add(f"if ({k2} == 3) goto <{l}dfp>;\n"
            f"if ({z2} != 0) goto <{l}a>; {raw} = zext(f4 >> 32); goto <{l}b>;\n"
            f"<{l}a> if ({z2} != 1) goto <{l}c>; {raw} = zext(f4); goto <{l}b>;\n"
            f"<{l}c> {raw} = (zext(f4) << 64) | zext(f6);\n<{l}b>\n"
            f"if ({k2} == 2) goto <{l}bfp>;")
    # HFP source
    ch = blk.local(8, "0")
    dd = pick(blk, z2, [6, 14, 28])
    hw = pick(blk, z2, [32, 64, 128])
    blk.add(f"if ({z2} == 2) goto <{l}hx>;")
    setv(blk, s, 1, f"({raw} >> ({hw} - 1)) & 1")
    setv(blk, ch, 8, f"({raw} >> ({hw} - 8)) & 0x7f")
    blk.add(f"{M} = {raw} & ((zext(1:1) << ({hw} - 8)) - 1); goto <{l}hh>;\n<{l}hx>")
    setv(blk, s, 1, "(zext(f4) >> 63) & 1")
    blk.add(f"{ch} = (f4 >> 56) & 0x7f;\n"
            f"{M} = (zext(f4 & 0x00ffffffffffffff) << 56) | zext(f6 & 0x00ffffffffffffff);\n"
            f"<{l}hh> {E} = 4 * ({ch} - 64) - 4 * {dd}; goto <{l}end>;")
    # BFP source
    blk.add(f"<{l}bfp>")
    fb = pick(blk, z2, [23, 52, 112])
    eb = pick(blk, z2, [8, 11, 15])
    bias = pick(blk, z2, [127, 1023, 16383])
    bw = pick(blk, z2, [32, 64, 128])
    ex = tr(blk, 8, f"({raw} >> {fb}) & ((zext(1:1) << {eb}) - 1)")
    exm = tr(blk, 8, f"(zext(1:1) << {eb}) - 1")
    fr = blk.local(16, f"{raw} & ((zext(1:1) << {fb}) - 1)")
    setv(blk, s, 1, f"({raw} >> ({bw} - 1)) & 1")
    blk.add(f"if ({ex} != {exm}) goto <{l}fin>;\n"
            f"{pay} = {fr} & ((zext(1:1) << ({fb} - 1)) - 1); {cl} = 1; if ({fr} == 0) goto <{l}end>;\n"
            f"{cl} = 3; if ((({fr} >> ({fb} - 1)) & 1) == 0) goto <{l}end>; {cl} = 2; goto <{l}end>;\n"
            f"<{l}fin> if ({ex} == 0) goto <{l}den>; {M} = {fr} | (zext(1:1) << {fb}); {E} = {ex} - {bias} - {fb}; goto <{l}end>;\n"
            f"<{l}den> {M} = {fr}; {E} = 1 - {bias} - {fb}; goto <{l}end>;")
    # DFP source
    blk.add(f"<{l}dfp> {rdx} = 1;")
    for zi, fmt in ((0, "s"), (1, "d"), (2, "x")):
        if zi == 0:
            blk.add(f"if ({z2} != 0) goto <{l}d1>;")
        elif zi == 1:
            blk.add(f"<{l}d1> if ({z2} != 1) goto <{l}d2>;")
        else:
            blk.add(f"<{l}d2>")
        bits = read_bits(blk, fmt, "f4", "fpr", "f6")
        d = decode(blk, fmt, bits)
        blk.add(f"{s} = {d.s}; {cl} = {d.cl}; {M} = {d.c}; {pay} = {d.c}; {E} = {d.q}; goto <{l}end>;")
    blk.add(f"<{l}end>")
    # ---- results -------------------------------------------------------------------------------
    inv, ovf, unf, inx, qtm = (blk.local(1, "0") for _ in range(5))
    sg = s
    z16 = blk.local(16, "zext(0:8)")
    tfb = pick(blk, z1, [23, 52, 112])
    teb = pick(blk, z1, [8, 11, 15])
    tw = pick(blk, z1, [32, 64, 128])
    store_l = lbl(blk, "st")
    t = lbl(blk, "tg")
    blk.add(f"if ({cl} == 0) goto <{t}fin>;")
    # NaN / infinity sources
    blk.add(f"if ({k1} != 1) goto <{t}ni>; {inv} = 1;")
    hx_hmax(blk, z1, sg, f"({cl} == 1)", store_l)
    blk.add(f"<{t}ni> if ({k1} != 2) goto <{t}nd>;")
    Rb = blk.local(16, f"(zext({sg}) << ({tw} - 1)) | (((zext(1:1) << {teb}) - 1) << {tfb})")
    fits = blk.local(1, f"{pay} < (zext(1:1) << ({tfb} - 1))")
    pl = blk.local(16, f"zext({fits}) * {pay}")
    blk.add(f"if ({cl} == 1) goto <{t}bs>; if ({cl} != 3) goto <{t}bq>; {inv} = 1;\n<{t}bq>\n"
            f"{Rb} = {Rb} | (zext(1:1) << ({tfb} - 1)) | {pl};\n<{t}bs>")
    bfp_store(blk, z1, Rb)
    blk.add(f"goto <{store_l}>;")
    blk.add(f"<{t}nd>")
    for zi, fmt in ((0, "s"), (1, "d"), (2, "x")):
        if zi == 0:
            blk.add(f"if ({z1} != 0) goto <{t}n1>;")
        elif zi == 1:
            blk.add(f"<{t}n1> if ({z1} != 1) goto <{t}n2>;")
        else:
            blk.add(f"<{t}n2>")
        P = FMT[fmt][0]
        kind = blk.local(1, f"zext({cl} == 1) + zext({cl} >= 2) * 2")
        fits = blk.local(1, f"{pay} < {big(10 ** (P - 1), 16)}")
        pl = blk.local(16, f"zext({fits}) * zext({cl} >= 2) * {pay}")
        blk.add(f"if ({cl} != 3) goto <{t}q{zi}>; {inv} = 1;\n<{t}q{zi}>")
        sb = encode_special(blk, fmt, sg, kind, pl)
        write_bits(blk, fmt, "f0", "f2", sb)
        blk.add(f"goto <{store_l}>;")
    # zero
    blk.add(f"<{t}fin> if ({M} != 0) goto <{t}nz>;\nif ({k1} != 1) goto <{t}zb>;")
    hfp_store(blk, z1, sg, z16, "0")
    blk.add(f"goto <{store_l}>;\n<{t}zb> if ({k1} != 2) goto <{t}zd>;")
    Rz = blk.local(16, f"zext({sg}) << ({tw} - 1)")
    bfp_store(blk, z1, Rz)
    blk.add(f"goto <{store_l}>;\n<{t}zd>")
    for zi, fmt in ((0, "s"), (1, "d"), (2, "x")):
        P, ec, cc_, bias_, n_ = FMT[fmt]
        emaxq = (3 << ec) - 1 - bias_
        if zi == 0:
            blk.add(f"if ({z1} != 0) goto <{t}z1>;")
        elif zi == 1:
            blk.add(f"<{t}z1> if ({z1} != 1) goto <{t}z2>;")
        else:
            blk.add(f"<{t}z2>")
        zq = blk.local(8, f"zext(({b59} & 1) == 0) * {emaxq}")
        zb = encode_finite(blk, fmt, sg, zq, blk.local(16, "zext(0:8)"))
        write_bits(blk, fmt, "f0", "f2", zb)
        blk.add(f"{qtm} = {zq} s> 0; goto <{store_l}>;")
    # ---- nonzero finite ----------------------------------------------------------------------
    blk.add(f"<{t}nz> if ({k1} != 3) goto <{t}tb>;")
    # target DFP: the value is M * 2^E (the source is HFP or BFP)
    Ew = blk.local(8, E)
    q = blk.local(8, "0")
    l2 = lbl(blk, "dn")
    blk.add(f"pfw0 = zext({M});\n"
            f"<{l2}tz> if ((pfw0:1 & 1) != 0) goto <{l2}go>; if ({Ew} s>= 0) goto <{l2}go>; pfw0 = pfw0 >> 1; {Ew} = {Ew} + 1; goto <{l2}tz>;\n<{l2}go>\n"
            f"if ({Ew} s< 0) goto <{l2}neg>; pfw1 = pfw0 << {Ew}; goto <{l2}red>;\n<{l2}neg>")
    kk = blk.local(8, f"0 - {Ew}")
    pow_reg(blk, "pfw2", "5", kk)
    blk.add(f"pfw1 = pfw0 * pfw2; {q} = 0 - {kk};\n<{l2}red>")
    sticky = blk.local(1, "0")
    rmd = blk.local(8, "0")
    blk.add(f"<{l2}ra> pfw2 = pfw1 >> 192; if (pfw2 == 0) goto <{l2}rb>; pfw2 = pfw1 % 1000000000000000000; {rmd} = pfw2:8; "
            f"{sticky} = {sticky} || ({rmd} != 0); pfw1 = pfw1 / 1000000000000000000; {q} = {q} + 18; goto <{l2}ra>;\n<{l2}rb>")
    V = blk.local(32, "pfw1:32")
    blk.add(f"<{l2}rc> if ({V} < {big(10 ** 36, 32)}) goto <{l2}rd>; {sticky} = {sticky} || (({V} % 10) != 0); {V} = {V} / 10; {q} = {q} + 1; goto <{l2}rc>;\n<{l2}rd>")
    q2f = blk.local(8, "0")
    for zi, fmt in ((0, "s"), (1, "d"), (2, "x")):
        P, ec, cc_, bias_, n_ = FMT[fmt]
        emaxq = (3 << ec) - 1 - bias_
        etiny = -bias_
        if zi == 0:
            blk.add(f"if ({z1} != 0) goto <{l2}f1>;")
        elif zi == 1:
            blk.add(f"<{l2}f1> if ({z1} != 1) goto <{l2}f2>;")
        else:
            blk.add(f"<{l2}f2>")
        fl = {}
        bits, zero, isinf = round_finite(blk, fmt, sg, q, V, 32, sticky, mode, fl)
        nd = ndigits(blk, V, 32)
        blk.add(f"{unf} = (({q} + {nd}) s< {etiny + P}) && {fl['inx']}; {ovf} = {fl['ovf']}; {inx} = {fl['inx']};")
        isfin = blk.local(1, f"!{isinf} && !{zero} && !{fl['inx']}")
        blk.add(f"if (!{isfin}) goto <{l2}k{zi}>;")
        d2 = decode(blk, fmt, bits)
        c2_, q2 = blk.local(16, d2.c), blk.local(8, d2.q)
        blk.add(f"<{l2}s{zi}> if (({c2_} % 10) != 0) goto <{l2}sd{zi}>; if ({q2} s>= {emaxq}) goto <{l2}sd{zi}>; {c2_} = {c2_} / 10; {q2} = {q2} + 1; goto <{l2}s{zi}>;\n<{l2}sd{zi}>")
        nd2 = ndigits(blk, blk.local(32, f"zext({c2_})"), 32)
        blk.add(f"if ((({b59} & 1) == 0) || ({q2} s<= 0)) goto <{l2}qq{zi}>;")
        room = blk.local(8, f"{P} - {nd2}")
        dq = blk.local(8, f"{q2}")
        blk.add(f"if ({dq} s<= {room}) goto <{l2}qc{zi}>; {dq} = {room};\n<{l2}qc{zi}>")
        pw = pow10(blk, dq, 16)
        blk.add(f"{c2_} = {c2_} * {pw}; {q2} = {q2} - {dq};\n<{l2}qq{zi}>")
        bits2 = encode_finite(blk, fmt, sg, q2, c2_)
        blk.add(f"{bits} = {bits2}; {q2f} = {q2};\n<{l2}k{zi}>")
        blk.add(f"{qtm} = {fl['inx']} || ({q2f} s> 0);")
        write_bits(blk, fmt, "f0", "f2", bits)
        blk.add(f"goto <{store_l}>;")
    # ---- target BFP / HFP: N * 2^E2 (124 bits) with a sticky bit -----------------------------
    blk.add(f"<{t}tb>")
    Nb = blk.local(16, "zext(0:8)")
    E2 = blk.local(8, "0")
    st = blk.local(1, "0")
    l3 = lbl(blk, "bn")
    blk.add(f"if ({rdx} == 0) goto <{l3}r2>;")
    blk.add(f"pfw0 = zext({M});\nif ({E} s< 0) goto <{l3}neg>;")
    pow_reg(blk, "pfw1", "10", E)
    blk.add(f"pfw2 = pfw0 * pfw1; {E2} = 0; goto <{l3}big>;\n<{l3}neg>")
    kk2 = blk.local(8, f"0 - {E}")
    sh = blk.local(8, f"(({kk2} * 33220) / 10000) + 124")
    pow_reg(blk, "pfw1", "10", kk2)
    blk.add(f"pfw3 = pfw0 << {sh}; pfw2 = pfw3 / pfw1; pfw4 = pfw3 % pfw1; {st} = pfw4 != 0; {E2} = 0 - {sh};\n<{l3}big>")
    Lw = bitlen_w(blk, "pfw2", "pfw3")
    sh2 = blk.local(8, f"{Lw} - 123")
    blk.add(f"if ({Lw} s<= 123) goto <{l3}fit>;\n"
            f"pfw3 = 1; pfw3 = pfw3 << {sh2}; pfw3 = pfw3 - 1; pfw4 = pfw2 & pfw3; {st} = {st} || (pfw4 != 0); "
            f"pfw2 = pfw2 >> {sh2}; {E2} = {E2} + {sh2};\n<{l3}fit>\n"
            f"{Nb} = pfw2:16; goto <{l3}go>;\n<{l3}r2> {Nb} = {M}; {E2} = {E};\n<{l3}go>")
    blk.add(f"if ({k1} != 2) goto <{l3}hfp>;")
    # target BFP
    bP = pick(blk, z1, [24, 53, 113])
    bbias = pick(blk, z1, [127, 1023, 16383])
    bfb = pick(blk, z1, [23, 52, 112])
    bw = pick(blk, z1, [32, 64, 128])
    emin = blk.local(8, f"1 - {bbias}")
    L = bitlen16(blk, Nb)
    e = blk.local(8, f"{E2} + {L}")
    U0 = blk.local(8, f"zext({e} s> {emin}) * {e} + zext({e} s<= {emin}) * {emin}")
    U = blk.local(8, f"{U0} - ({bP} - 1)")
    drop = blk.local(8, f"{U} - {E2}")
    Q, rinx = shift_round(blk, sg, mode, Nb, st, drop)
    tiny = blk.local(1, f"{e} s< {emin}")
    blk.add(f"if ({Q} != (zext(1:1) << {bP})) goto <{l3}nc>; {Q} = zext(1:1) << ({bP} - 1); {U} = {U} + 1;\n<{l3}nc>")
    ep = blk.local(8, f"{U} + {bP} - 1")
    Rb2 = blk.local(16, "zext(0:8)")
    toinf = blk.local(1, f"({mode} == 0) || ({mode} == 4) || ({mode} == 5) || ({mode} == 6) || "
                         f"(({mode} == 2) && ({sg} == 0)) || (({mode} == 3) && ({sg} != 0))")
    ebw = blk.local(8, f"{bw} - 1 - {bfb}")
    sgw = blk.local(16, f"zext({sg}) << ({bw} - 1)")
    blk.add(f"if ({ep} s<= {bbias}) goto <{l3}nov>; {ovf} = 1; {rinx} = 1;\n"
            f"if ({toinf}) goto <{l3}inf>; {Rb2} = {sgw} | (((zext(1:1) << {ebw}) - 2) << {bfb}) | ((zext(1:1) << {bfb}) - 1); goto <{l3}pk>;\n"
            f"<{l3}inf> {Rb2} = {sgw} | (((zext(1:1) << {ebw}) - 1) << {bfb}); goto <{l3}pk>;\n"
            f"<{l3}nov> if ({Q} >= (zext(1:1) << ({bP} - 1))) goto <{l3}nrm>;\n"
            f"{Rb2} = {sgw} | {Q}; goto <{l3}pk>;\n"
            f"<{l3}nrm> {Rb2} = {sgw} | (zext({ep} + {bbias}) << {bfb}) | ({Q} & ((zext(1:1) << {bfb}) - 1));\n"
            f"<{l3}pk>")
    blk.add(f"{inx} = {rinx}; {unf} = {tiny} && {rinx};")
    bfp_store(blk, z1, Rb2)
    blk.add(f"goto <{store_l}>;\n<{l3}hfp>")
    # target HFP
    hD = pick(blk, z1, [6, 14, 28])
    L = bitlen16(blk, Nb)
    e2 = blk.local(8, f"{E2} + {L} + 1")
    ch = blk.local(8, f"({e2} + 3) s>> 2")
    drop = blk.local(8, f"4 * {ch} - {E2} - 4 * {hD}")
    Q, rinx = shift_round(blk, sg, mode, Nb, st, drop)
    blk.add(f"if ({Q} != (zext(1:1) << (4 * {hD}))) goto <{l3}hc>; {Q} = zext(1:1) << (4 * {hD} - 4); {ch} = {ch} + 1;\n<{l3}hc>")
    chr_ = blk.local(8, f"{ch} + 64")
    blk.add(f"{inx} = {rinx};")
    fmax = blk.local(16, f"(zext(1:1) << (4 * {hD})) - 1")
    blk.add(f"if ({chr_} s> 127) goto <{l3}hov>; if ({chr_} s>= 0) goto <{l3}hok>;\n"
            f"{unf} = ({b59} & 1) != 0; {inx} = 1;")
    hfp_store(blk, z1, sg, z16, "0")
    blk.add(f"goto <{store_l}>;\n<{l3}hov>\n"
            f"{inv} = ({b58} & 1) == 0; {ovf} = ({b58} & 1) != 0; {inx} = 1;")
    hfp_store(blk, z1, sg, fmax, "1")
    blk.add(f"goto <{store_l}>;\n<{l3}hok>")
    hfp_store(blk, z1, sg, Q, "2", chr_)
    blk.add(f"goto <{store_l}>;")
    # ---- condition code ----------------------------------------------------------------------
    blk.add(f"<{store_l}>")
    quant = blk.local(1, f"({k1} == 3) && (({b58} & 1) != 0) && {qtm}")
    anyx = blk.local(1, f"{inv} || {ovf} || {unf} || ({inx} && (({inxs} & 1) == 0)) || {quant}")
    blk.add(f"gs_cc_flags(!{anyx}, {anyx}, 0:1, 0:1);")
    blk.add(f"<{done}>")
    return blk.text()

def bfp_store(blk, z1, R):
    """FPR 0 (pair 0, 2) = the BFP value R (16-byte local) of format z1"""
    l = lbl(blk, "bs")
    blk.add(f"if ({z1} != 0) goto <{l}a>; f0 = (f0 & 0xffffffff) | (zext({R}:4) << 32); goto <{l}e>;\n"
            f"<{l}a> if ({z1} != 1) goto <{l}b>; f0 = {R}:8; goto <{l}e>;\n"
            f"<{l}b> f0 = {R}(8); f2 = {R}:8;\n<{l}e>")

def hfp_store(blk, z1, sg, fr, kind, ch=None):
    """FPR 0 = an HFP value of format z1: kind '0' a zero of sign sg, '1' the largest value
    (fr the maximum fraction), '2' characteristic ch (8-byte local) and fraction fr (16-byte)."""
    l = lbl(blk, "hs")
    c = blk.local(8, "0" if kind == "0" else ("127" if kind == "1" else f"{ch}"))
    sg8 = blk.local(8, f"zext({sg})")
    lowc = blk.local(8, f"({c} - 14) & 0x7f")
    flo = blk.local(8, f"{fr}:8")
    fh = blk.local(16, f"{fr} >> 56")
    fhi = blk.local(8, f"{fh}:8")
    nz = blk.local(1, f"{fr} != 0")
    v32 = blk.local(8, f"({sg8} << 31) | (({c} & 0x7f) << 24) | ({flo} & 0xffffff)")
    blk.add(f"if ({z1} != 0) goto <{l}a>; f0 = (f0 & 0xffffffff) | (({v32} & 0xffffffff) << 32); goto <{l}e>;\n"
            f"<{l}a> if ({z1} != 1) goto <{l}b>; f0 = ({sg8} << 63) | (({c} & 0x7f) << 56) | ({flo} & 0x00ffffffffffffff); goto <{l}e>;\n"
            f"<{l}b> f0 = ({sg8} << 63) | (({c} & 0x7f) << 56) | ({fhi} & 0x00ffffffffffffff);\n"
            f"f2 = ({sg8} << 63) | (zext({nz}) * ({lowc} << 56)) | ({flo} & 0x00ffffffffffffff);\n<{l}e>")

def hx_hmax(blk, z1, sg, is_inf, store_l):
    """HFP target of a NaN or infinity source: the largest value, plus sign for a NaN, the
    source sign for an infinity."""
    sgn = blk.local(1, f"zext({is_inf}) * {sg}")
    D = pick(blk, z1, [6, 14, 28])
    fmax = blk.local(16, f"(zext(1:1) << (4 * {D})) - 1")
    hfp_store(blk, z1, sgn, fmax, "1")
    blk.add(f"goto <{store_l}>;")
