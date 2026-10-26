"""P-code for DEFLATE CONVERSION CALL (DFLTCC, B939): DFLTCC-QAF and DFLTCC-XPND (uncompressing).

XPND follows the Principles of Operation (SA22-7832-14, chapter 26): the DEFLATE decoder of RFC 1951 over the
second operand with the parameter-block state (new task, continuation flag, sub-byte boundary, incomplete-function
status and length, history length and offset, the check value (CRC-32 or Adler-32 of the uncompressed data) and the
compressed dynamic-Huffman table of a partly decoded block), an in-line history before the first operand or a
32 KiB circular history buffer (third operand), and the condition codes 0 (final block decoded), 1 (first operand
full), 2 (second operand exhausted, or an invalid-input condition with a nonzero operation-ending supplemental
code) and never 3. The operation stops only at element boundaries (a symbol or a block header), which is the
state the instruction description requires to resume from; the continuation-state buffer is not needed. Every
invalid-input condition reports the code FF ("no additional information", which the manual allows).

DFLTCC-GDHT and DFLTCC-CMPR are model-dependent (the duplicate-string search and the Huffman-table construction
are not specified) and stay named pcodeops s390_dfltcc_gdht / s390_dfltcc_cmpr; QAF reports all three functions.
"""

# cpm layout of the decoder tables
LENS, CLL = 0x5000, 0x5200                  # code lengths (lit + dist, 320), code-length code lengths (19)
CL_CNT, CL_SYM = 0x5300, 0x5320             # tables: counts (16 x 2 bytes), symbols (2 bytes each)
LT_CNT, LT_SYM = 0x5400, 0x5420
DT_CNT, DT_SYM = 0x5700, 0x5720
OFFS = 0x5800
LBASE, LEXT, DBASE, DEXT, CLORD = 0x5900, 0x5980, 0x59a0, 0x59e0, 0x5a00

LEN_BASE = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258]
LEN_EXT = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0]
DIST_BASE = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145,
             8193, 12289, 16385, 24577]
DIST_EXT = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13]
CL_ORDER = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15]

_U = [0]


def uid():
    _U[0] += 1
    return str(_U[0])


def bytes_stmts(base, data):
    out = []
    data = bytes(data) + bytes(-len(data) % 8)
    for i in range(0, len(data), 8):
        chunk = data[i:i + 8]
        out.append(f"*[cpm]:{len(chunk)} ({base + i:#x}:4) = {int.from_bytes(chunk, 'big'):#x};")
    return " ".join(out)


def words_stmts(base, vals):
    return bytes_stmts(base, b"".join(v.to_bytes(2, "big") for v in vals))


def getbits(dst, n, fail, const=True):
    """dst = the next n (<= 16) bits of the stream at rb / rp / rt, least significant first; goto fail on a shortage"""
    g = uid()
    skip0 = "" if const else f"if ({n} == 0) goto <L_gz{g}>; "
    return (f"{skip0}if ((rp + {n}) > rt) goto <L_{fail}>; gq = rp >> 3; gs = rp & 7; gw = zext(*:1 (rb + gq)); "
            f"if (((gs + {n} + 7) >> 3) < 2) goto <L_gb{g}>; gw = gw | (zext(*:1 (rb + gq + 1)) << 8); "
            f"if (((gs + {n} + 7) >> 3) < 3) goto <L_gb{g}>; gw = gw | (zext(*:1 (rb + gq + 2)) << 16); "
            f"<L_gb{g}> {dst} = (gw >> gs) & ((1 << {n}) - 1); rp = rp + {n}; goto <L_ge{g}>; " +
            ("" if const else f"<L_gz{g}> {dst} = 0; ") + f"<L_ge{g}>")


def st1(addr, expr):
    return f"ctmp = {expr}; *:1 ({addr}) = ctmp:1;"


def dfltcc_insn(o, x):
    """x: R1 + 1, R1 number, R2 + 1, R2 number, R3 number"""
    r1a, r2a, r3a = o[0], o[1], o[2]
    r1l, r2l = x[0], x[2]
    t = [f"local r1num:4 = {x[1]}; local r2num:4 = {x[3]}; local r3num:4 = {x[4]};"]
    A = t.append
    A("local fc:1 = r0:1 & 0x7f; local hbt:1 = (r0:1 >> 7) & 1;")
    A("local gq:8 = 0; local gs:8 = 0; local gw:8 = 0; local ix:4 = 0; local dfb:8 = 0; local dfw:8 = 0; local dfleft:8 = 0; local dfn:8 = 0; local dfret:1 = 0; local dfb4:4 = 0; local dfw4:4 = 0;")
    A("local dflb:4 = 0; local dfcc:4 = 0; local dfcs:4 = 0; local nt:1 = 0; local cf:1 = 0; local cvt:1 = 0; local sbb:8 = 0; local hl:8 = 0; local ho:8 = 0; local cv:8 = 0;")
    A("local rb:8 = 0; local rp:8 = 0; local rt:8 = 0; local sa:8 = 0; local sl:8 = 0; local da:8 = 0; local dl:8 = 0; local ebp:8 = 0; local st:1 = 0; local bfin:1 = 0; local ifl:8 = 0;")
    A("local oesc:1 = 0; local ccv:1 = 0; local sym:8 = 0; local dlen:8 = 0; local dist:8 = 0; local hv:8 = 0; local b:8 = 0; local produced:8 = 0; local xret:1 = 0;")
    A("local nlen:8 = 0; local ndist:8 = 0; local ncode:8 = 0; local sidx:8 = 0; local rep:8 = 0; local prevl:8 = 0; local ifs:1 = 0; local cdl:8 = 0; local dhs:8 = 0; local ctmp:8 = 0;")
    A("local bt:1 = 0; local hdr:8 = 0; local dcode:8 = 0; local dfirst:8 = 0; local dindex:8 = 0; local dcnt:8 = 0; local dl4:8 = 0; local cvx:8 = 0; local fromcd:1 = 0; local dynnew:1 = 0;")
    A("local pend:1 = 0; local resmc:1 = 0; local dtmp:8 = 0; local dret:1 = 0; local dfail:1 = 0; local dcc:4 = 0; local dcs:4 = 0; local sbp:8 = 0; local sbase:8 = 0; local stot:8 = 0; local cl:8 = 0; local ecb:8 = 0; local mc:8 = 0; local ixc:4 = 0; local prog:1 = 0; local b21:1 = 0;")
    A("if (fc != 0) goto <L_fn>;")
    A("*:8 r1 = 0xe800000000000000:8; *:8 (r1 + 8) = 0:8; *:8 (r1 + 16) = 0:8; *:8 (r1 + 24) = 0x8000000000000000:8; cc = 0; goto <L_done>;")
    A("<L_fn> if ((fc == 1) || (fc == 2) || (fc == 4)) goto <L_fok>; trap_specification(); goto <L_done>;\n<L_fok>")
    A("if ((((r1num & 1) == 0) && (r1num != 0)) && (((r2num & 1) == 0) && (r2num != 0)) && (r3num != 0) && (r3num != 1)) goto <L_rok>; trap_specification(); goto <L_done>;\n<L_rok>")
    A(f"if (fc == 4) goto <L_xpnd>; if (fc == 1) goto <L_gdht>; cc = s390_dfltcc_cmpr({r1a}, {r1l}, {r2a}, {r2l}, {r3a}); goto <L_done>;\n<L_gdht> cc = s390_dfltcc_gdht({r2a}, {r2l}); goto <L_done>;")
    # ============================================================ DFLTCC-XPND
    A("<L_xpnd> nt = (*:1 (r1 + 16) >> 7) & 1; cf = *:1 (r1 + 7) & 1; cvt = (*:1 (r1 + 16) >> 5) & 1;")
    A(f"if ((cf == 0) && ({r2l} == 0)) goto <L_xsp>; if ((hbt != 0) && (({r3a} & 0xfff) != 0)) goto <L_xsp>; goto <L_xok>; <L_xsp> trap_specification(); goto <L_done>;\n<L_xok>")
    A(words_stmts(LBASE, LEN_BASE) + " " + bytes_stmts(LEXT, LEN_EXT) + " " + words_stmts(DBASE, DIST_BASE) + " " + bytes_stmts(DEXT, DIST_EXT) + " " + bytes_stmts(CLORD, CL_ORDER))
    A("pend = 0; sbb = zext(*:1 (r1 + 18) & 7); hl = zext(*:2 (r1 + 44)); ho = zext(*:2 (r1 + 46)) & 0x7fff; cv = 0;")
    A("if (nt == 0) goto <L_x1>; sbb = 0; hl = 0; ho = 0; if (cvt == 0) goto <L_x0>; cv = 1; <L_x0> goto <L_x4>;")
    A("<L_x1> if (hl > 32768) goto <L_xbad2>; if ((*:1 (r1 + 1) & 0xf) != 0) goto <L_xbad1>; if (cvt == 0) goto <L_xc1>;")
    A("cv = (zext(*:1 (r1 + 48)) << 24) | (zext(*:1 (r1 + 49)) << 16) | (zext(*:1 (r1 + 50)) << 8) | zext(*:1 (r1 + 51)); goto <L_x4>;")
    A("<L_xc1> cv = (zext(*:1 (r1 + 51)) << 24) | (zext(*:1 (r1 + 50)) << 16) | (zext(*:1 (r1 + 49)) << 8) | zext(*:1 (r1 + 48));")
    A(f"<L_x4> sa = {r2a}; sl = {r2l}; da = {r1a}; dl = {r1l}; rb = sa; rp = sbb; rt = sl * 8; produced = 0; ifl = 0; bfin = 0; st = 0; fromcd = 0; dynnew = 0; oesc = 0; prog = 0;")
    A("cvx = cv; if (cvt != 0) goto <L_x6>; cvx = cv ^ 0xffffffff; <L_x6>")
    # resume state
    A("if (cf == 0) goto <L_xs0>; if (nt != 0) goto <L_xs0>; ifs = *:1 (r1 + 21) & 0xf; if (ifs < 8) goto <L_xs0>; if (ifs >= 0xe) goto <L_xs0>; bfin = ifs & 1;")
    A("if (ifs >= 0xc) goto <L_xsd>; if (ifs >= 0xa) goto <L_xsf>; st = 1; ifl = zext(*:2 (r1 + 22)); goto <L_xs0>;")
    A("<L_xsf> st = 2; goto <L_xs0>; <L_xsd> st = 3; fromcd = 1;")
    A("<L_xs0> if (dl != 0) goto <L_xgo>; ccv = 1; goto <L_xsave>;")
    A("<L_xgo> if (cf == 0) goto <L_xg1>; if (nt != 0) goto <L_xg1>; if (*:1 (r1 + 384) == 0) goto <L_xg1>; mc = zext(*:2 (r1 + 385)); dist = zext(*:2 (r1 + 387)); *:1 (r1 + 384) = 0; resmc = 1;\n<L_xg1> if (st == 0) goto <L_xblk>; if (st == 1) goto <L_xdata>; if (st == 2) goto <L_xfix>; goto <L_xdyn>;")
    # ---- block header
    A("<L_xblk> ebp = rp; " + getbits("hdr", "3", "xr2") + " bfin = hdr:1 & 1; bt = (hdr:1 >> 1) & 3; if (bt == 3) goto <L_xbadin>; if (bt == 0) goto <L_xsto>; if (bt == 1) goto <L_xfix>; goto <L_xdyn>;")
    A("<L_xsto> rp = (rp + 7) & ~7; " + getbits("ifl", "16", "xr2") + " " + getbits("hv", "16", "xr2"))
    A("if ((ifl ^ hv) != 0xffff) goto <L_xbadin>; st = 1;")
    A("<L_xdata> if (ifl == 0) goto <L_xbdone>; if (dl == 0) goto <L_xroom>; if ((rt - rp) < 8) goto <L_xr2d>; b = zext(*:1 (rb + (rp >> 3))); rp = rp + 8; ifl = ifl - 1; xret = 1; goto <L_xput>;")
    A("<L_xr2d> ccv = 2; goto <L_xsave>;")
    # ---- one output byte: store, check value, history
    A("<L_xput> *:1 da = b:1; da = da + 1; dl = dl - 1; produced = produced + 1; prog = 1; if (cvt != 0) goto <L_xad>; cvx = cvx ^ b;")
    for _ in range(8):
        A("ctmp = 0 - (cvx & 1); cvx = (cvx >> 1) ^ (0xedb88320 & ctmp);")
    A("goto <L_xhist>; <L_xad> hv = cvx & 0xffff; ctmp = (cvx >> 16) & 0xffff; hv = (hv + b) % 65521; ctmp = (ctmp + hv) % 65521; cvx = (ctmp << 16) | hv;")
    A(f"<L_xhist> if (hbt == 0) goto <L_xh1>; hv = (ho + hl) & 0x7fff; *:1 ({r3a} + hv) = b:1; if (hl < 32768) goto <L_xh1>; ho = (ho + 1) & 0x7fff; goto <L_xh2>;")
    A("<L_xh1> if (hl >= 32768) goto <L_xh2>; hl = hl + 1;")
    A("<L_xh2> if (xret == 1) goto <L_xdata>; if (xret == 2) goto <L_xlit>; goto <L_xcopy>;")
    # ---- fixed Huffman tables (built once per block)
    A(f"<L_xfix> st = 2; ix = 0; <L_xf1> if (ix >= 288) goto <L_xf2>; *[cpm]:1 ({LENS:#x}:4 + ix) = 8; if (ix < 144) goto <L_xf3>; *[cpm]:1 ({LENS:#x}:4 + ix) = 9; if (ix < 256) goto <L_xf3>; *[cpm]:1 ({LENS:#x}:4 + ix) = 7; if (ix < 280) goto <L_xf3>; *[cpm]:1 ({LENS:#x}:4 + ix) = 8; <L_xf3> ix = ix + 1; goto <L_xf1>;")
    A(f"<L_xf2> ix = 0; <L_xf4> if (ix >= 30) goto <L_xf5>; *[cpm]:1 ({LENS + 288:#x}:4 + ix) = 5; ix = ix + 1; goto <L_xf4>;")
    A(f"<L_xf5> dflb = {LENS:#x}; dfcc = {LT_CNT:#x}; dfcs = {LT_SYM:#x}; dfn = 288; dfret = 1; goto <L_dfcon>;")
    A(f"<L_dfr1> dflb = {LENS + 288:#x}; dfcc = {DT_CNT:#x}; dfcs = {DT_SYM:#x}; dfn = 30; dfret = 2; goto <L_dfcon>;")
    A("<L_dfr2> goto <L_xfx>;")
    A("<L_xfx> ")
    # ---- the Huffman symbol loop
    A("<L_xhufl> if (resmc == 0) goto <L_xhf>; resmc = 0; goto <L_xcopy>; <L_xhf> ebp = rp; dcc = " + f"{LT_CNT:#x}; dcs = {LT_SYM:#x}; dret = 1; goto <L_dec>;")
    A("<L_dc1> if (dfail == 1) goto <L_xr2s>; if (dfail != 0) goto <L_xbadin>; if (sym >= 256) goto <L_xnl>; if (dl == 0) goto <L_xroomb>; b = sym; xret = 2; goto <L_xput>;")
    A("<L_xlit> goto <L_xhufl>;")
    A("<L_xnl> if (sym == 256) goto <L_xbdone>; sym = sym - 257; if (sym >= 29) goto <L_xbadin>;")
    A(f"ix = sym:4; dlen = zext(*[cpm]:2 ({LBASE:#x}:4 + (ix * 2))); ecb = zext(*[cpm]:1 ({LEXT:#x}:4 + ix));")
    A(getbits("hv", "ecb", "xr2s", const=False) + " dlen = dlen + hv; dcc = " + f"{DT_CNT:#x}; dcs = {DT_SYM:#x}; dret = 2; goto <L_dec>;")
    A("<L_dc2> if (dfail == 1) goto <L_xr2s>; if (dfail != 0) goto <L_xbadin>; if (sym >= 30) goto <L_xbadin>;")
    A(f"ix = sym:4; dist = zext(*[cpm]:2 ({DBASE:#x}:4 + (ix * 2))); ecb = zext(*[cpm]:1 ({DEXT:#x}:4 + ix));")
    A(getbits("hv", "ecb", "xr2s", const=False) + " dist = dist + hv; if (dist > hl) goto <L_xbadin>;")
    A("mc = dlen; <L_xcopy> if (mc == 0) goto <L_xhufl>; if (dl != 0) goto <L_xcp0>; pend = 1; ccv = 1; goto <L_xsave>; <L_xcp0> mc = mc - 1; if (hbt == 0) goto <L_xcp1>; hv = (ho + hl - dist) & 0x7fff; b = zext(*:1 (" + f"{r3a} + hv)); goto <L_xput2>;")
    A("<L_xcp1> b = zext(*:1 (da - dist)); <L_xput2> xret = 3; goto <L_xput>;")
    # element start was ebp: a stop inside the symbol loop rolls the stream position back to it
    A("<L_xr2s> rp = ebp; ccv = 2; goto <L_xsave>;")
    A("<L_xroomb> rp = ebp; <L_xroom> ccv = 1; goto <L_xsave>;")
    A("<L_xr2> rp = ebp; ccv = 2; goto <L_xsave>;")
    # ---- dynamic block: read the table from the stream (new block) or from the CDHT field (resumed block)
    A("<L_xdyn> if (fromcd != 0) goto <L_xdcd>; dhs = rp; sbase = rb; stot = rt; goto <L_xdp>;")
    A("<L_xdcd> sbp = rp; sbase = rb; stot = rt; rb = r1 + 64; rp = 0; rt = 2304; goto <L_xdp>;")
    A("<L_xdp> " + getbits("nlen", "5", "xdsrc") + " " + getbits("ndist", "5", "xdsrc") + " " + getbits("ncode", "4", "xdsrc"))
    A("if (nlen > 29) goto <L_xdbad>; if (ndist > 29) goto <L_xdbad>; nlen = nlen + 257; ndist = ndist + 1; ncode = ncode + 4;")
    A(f"ix = 0; <L_xd1> if (ix >= 19) goto <L_xd2>; *[cpm]:1 ({CLL:#x}:4 + ix) = 0; ix = ix + 1; goto <L_xd1>;")
    A(f"<L_xd2> sidx = 0; <L_xd3> if (sidx >= ncode) goto <L_xd4>; " + getbits("hv", "3", "xdsrc") + f" ix = sidx:4; dfb = zext(*[cpm]:1 ({CLORD:#x}:4 + ix)); ix = dfb:4; *[cpm]:1 ({CLL:#x}:4 + ix) = hv:1; sidx = sidx + 1; goto <L_xd3>;")
    A(f"<L_xd4> dflb = {CLL:#x}; dfcc = {CL_CNT:#x}; dfcs = {CL_SYM:#x}; dfn = 19; dfret = 3; goto <L_dfcon>;")
    A("<L_dfr3> if (dfleft != 0) goto <L_xdbad>;")
    A(f"sidx = 0; prevl = 0; <L_xd5> if (sidx >= (nlen + ndist)) goto <L_xd9>; dcc = {CL_CNT:#x}; dcs = {CL_SYM:#x}; dret = 3; goto <L_dec>;")
    A("<L_dc3> if (dfail == 1) goto <L_xdsrc>; if (dfail != 0) goto <L_xdbad>; if (sym >= 16) goto <L_xd6>; ix = sidx:4; *[cpm]:1 (" + f"{LENS:#x}:4 + ix) = sym:1; prevl = sym; sidx = sidx + 1; goto <L_xd5>;")
    A("<L_xd6> if (sym != 16) goto <L_xd7>; if (sidx == 0) goto <L_xdbad>; " + getbits("rep", "2", "xdsrc") + " rep = rep + 3; goto <L_xd8>;")
    A("<L_xd7> prevl = 0; if (sym != 17) goto <L_xd7b>; " + getbits("rep", "3", "xdsrc") + " rep = rep + 3; goto <L_xd8>;")
    A("<L_xd7b> " + getbits("rep", "7", "xdsrc") + " rep = rep + 11;")
    A("<L_xd8> if ((sidx + rep) > (nlen + ndist)) goto <L_xdbad>; <L_xd8a> if (rep == 0) goto <L_xd5>; ix = sidx:4; *[cpm]:1 (" + f"{LENS:#x}:4 + ix) = prevl:1; sidx = sidx + 1; rep = rep - 1; goto <L_xd8a>;")
    A(f"<L_xd9> ix = 256; if (*[cpm]:1 ({LENS:#x}:4 + ix) == 0) goto <L_xdbad>;")
    # literal / length table from the first nlen lengths, distance table from the rest (copied down to LENS + 288)
    A(f"sidx = 0; <L_xda> if (sidx >= ndist) goto <L_xdb>; ix = sidx:4; dtmp = nlen + sidx; dfb4 = dtmp:4; *[cpm]:1 ({LENS + 320:#x}:4 + ix) = *[cpm]:1 ({LENS:#x}:4 + dfb4); sidx = sidx + 1; goto <L_xda>;")
    A(f"<L_xdb> dflb = {LENS:#x}; dfcc = {LT_CNT:#x}; dfcs = {LT_SYM:#x}; dfn = nlen; dfret = 4; goto <L_dfcon>;")
    A(f"<L_dfr4> if (dfleft != 0) goto <L_xdbad>; dflb = {LENS + 320:#x}; dfcc = {DT_CNT:#x}; dfcs = {DT_SYM:#x}; dfn = ndist; dfret = 5; goto <L_dfcon>;")
    A("<L_dfr5> if (dfleft == 0) goto <L_xde>; if (dfleft != 0) goto <L_xde>;")
    A("<L_xde> if (fromcd != 0) goto <L_xdf>; cdl = rp - dhs; dynnew = 1; goto <L_xdg>;")
    A("<L_xdf> rb = sbase; rp = sbp; rt = stot; fromcd = 0;")
    A("<L_xdg> st = 3; goto <L_xhufl>;")
    A("<L_xdsrc> if (fromcd != 0) goto <L_xdbad>; rp = ebp; ccv = 2; goto <L_xsave>;")
    A("<L_xdbad> oesc = 0xff; if (fromcd != 0) goto <L_xdb2>; rp = ebp; <L_xdb2> ccv = 2; goto <L_xsave>;")
    # ---- Huffman table construction (puff's construct): lengths at cpm dflb, dfn symbols; counts at dfcc, symbols at dfcs; dfleft = slack
    A("<L_dfcon> ix = 0; <L_dfc0> *[cpm]:2 (dfcc + (ix * 2)) = 0; ix = ix + 1; if (ix < 16) goto <L_dfc0>; sidx = 0;")
    A("<L_dfc1> if (sidx >= dfn) goto <L_dfc2>; ix = sidx:4; dfb = zext(*[cpm]:1 (dflb + ix)); dfb4 = dfb:4; dfw = zext(*[cpm]:2 (dfcc + (dfb4 * 2))); dfw = dfw + 1; *[cpm]:2 (dfcc + (dfb4 * 2)) = dfw:2; sidx = sidx + 1; goto <L_dfc1>;")
    A("<L_dfc2> dfleft = 1; ix = 1; <L_dfc3> if (ix > 15) goto <L_dfc4>; dfleft = dfleft << 1; dfw = zext(*[cpm]:2 (dfcc + (ix * 2))); dfleft = dfleft - dfw; if (dfleft s< 0) goto <L_xdbad>; ix = ix + 1; goto <L_dfc3>;")
    A(f"<L_dfc4> *[cpm]:2 ({OFFS + 2:#x}:4) = 0; ix = 1; <L_dfc5> if (ix >= 15) goto <L_dfc6>; dfw = zext(*[cpm]:2 ({OFFS:#x}:4 + (ix * 2))) + zext(*[cpm]:2 (dfcc + (ix * 2))); *[cpm]:2 ({OFFS:#x}:4 + (ix * 2) + 2) = dfw:2; ix = ix + 1; goto <L_dfc5>;")
    A(f"<L_dfc6> sidx = 0; <L_dfc7> if (sidx >= dfn) goto <L_dfcr>; ix = sidx:4; dfb = zext(*[cpm]:1 (dflb + ix)); if (dfb == 0) goto <L_dfc8>; dfb4 = dfb:4; dfw = zext(*[cpm]:2 ({OFFS:#x}:4 + (dfb4 * 2))); dfw4 = dfw:4; *[cpm]:2 (dfcs + (dfw4 * 2)) = sidx:2; dfw = dfw + 1; *[cpm]:2 ({OFFS:#x}:4 + (dfb4 * 2)) = dfw:2;")
    A("<L_dfc8> sidx = sidx + 1; goto <L_dfc7>;")
    A("<L_dfcr> if (dfret == 1) goto <L_dfr1>; if (dfret == 2) goto <L_dfr2>; if (dfret == 3) goto <L_dfr3>; if (dfret == 4) goto <L_dfr4>; goto <L_dfr5>;")
    # ---- decode one symbol with the tables at dcc / dcs (puff's decode), bit by bit
    A("<L_dec> dcode = 0; dfirst = 0; dindex = 0; dl4 = 1; dfail = 0;")
    A("<L_decl> if (dl4 > 15) goto <L_decbad>; if (rp >= rt) goto <L_decsh>; hv = (zext(*:1 (rb + (rp >> 3))) >> (rp & 7)) & 1; rp = rp + 1; dcode = dcode | hv; ix = dl4:4; dcnt = zext(*[cpm]:2 (dcc + (ix * 2)));")
    A("if (dcode >= (dfirst + dcnt)) goto <L_decn>; dtmp = dindex + (dcode - dfirst); ix = dtmp:4; sym = zext(*[cpm]:2 (dcs + (ix * 2))); goto <L_decd>;")
    A("<L_decn> dindex = dindex + dcnt; dfirst = (dfirst + dcnt) << 1; dcode = dcode << 1; dl4 = dl4 + 1; goto <L_decl>;")
    A("<L_decbad> dfail = 2; goto <L_decd>; <L_decsh> dfail = 1;")
    A("<L_decd> if (dret == 1) goto <L_dc1>; if (dret == 2) goto <L_dc2>; goto <L_dc3>;")
    # ---- block done
    A("<L_xbdone> if (bfin != 0) goto <L_xfin>; st = 0; goto <L_xblk>;")
    A("<L_xfin> ccv = 0; goto <L_xsave>;")
    # ---- invalid input
    A("<L_xbad1> oesc = 1; ccv = 2; goto <L_xinv>; <L_xbad2> oesc = 2; ccv = 2; goto <L_xinv>;")
    A("<L_xbadin> oesc = 0xff; rp = ebp; ccv = 2; if (produced != 0) goto <L_xsave>; if (rp > sbb) goto <L_xsave>; goto <L_xinv>;")
    A("<L_xinv> *:1 (r1 + 19) = oesc; cc = ccv; goto <L_done>;")
    # ---- write back the state, registers and condition code
    A("<L_xsave> ifs = 0; if (ccv == 0) goto <L_xs2>; ifs = 0xe; if (st == 0) goto <L_xs2>; ifs = 8 | bfin; if (st == 1) goto <L_xs2>; ifs = 0xa | bfin; if (st == 2) goto <L_xs2>; ifs = 0xc | bfin;")
    A("<L_xs2> *:1 (r1 + 384) = pend; if (pend == 0) goto <L_xs2p>; hv = mc; ctmp = hv >> 8; *:1 (r1 + 385) = ctmp:1; *:1 (r1 + 386) = hv:1; hv = dist; ctmp = hv >> 8; *:1 (r1 + 387) = ctmp:1; *:1 (r1 + 388) = hv:1;\n<L_xs2p> b21 = *:1 (r1 + 21); *:1 (r1 + 21) = (b21 & 0xf0) | ifs; *:1 (r1 + 2) = 0;")
    A("if (ccv != 0) goto <L_xs3>; ctmp = zext(*:1 (r1 + 7)) & 0xfe; goto <L_xs3b>; <L_xs3> ctmp = zext(*:1 (r1 + 7)) | 1; ctmp = ctmp & 0xff;")
    A("<L_xs3b> *:1 (r1 + 7) = ctmp:1; if (ccv == 0) goto <L_xs4>; ctmp = zext(*:1 (r1 + 16)) & 0x7f; *:1 (r1 + 16) = ctmp:1;")
    A("<L_xs4> ctmp = (zext(*:1 (r1 + 18)) & 0xf8) | (rp & 7); *:1 (r1 + 18) = ctmp:1; *:1 (r1 + 19) = oesc;")
    A("hv = 0; if (ccv == 0) goto <L_xs5>; if (st != 1) goto <L_xs5>; hv = ifl;")
    A("<L_xs5> ctmp = hv >> 8; *:1 (r1 + 22) = ctmp:1; *:1 (r1 + 23) = hv:1;")
    A("ctmp = hl >> 8; *:1 (r1 + 44) = ctmp:1; *:1 (r1 + 45) = hl:1; if (hbt == 0) goto <L_xs6>; ctmp = (zext(*:1 (r1 + 46)) & 0x80) | (ho >> 8); *:1 (r1 + 46) = ctmp:1; *:1 (r1 + 47) = ho:1;")
    A("<L_xs6> hv = cvx; if (cvt != 0) goto <L_xs7>; hv = cvx ^ 0xffffffff; *:1 (r1 + 48) = hv:1; ctmp = hv >> 8; *:1 (r1 + 49) = ctmp:1; ctmp = hv >> 16; *:1 (r1 + 50) = ctmp:1; ctmp = hv >> 24; *:1 (r1 + 51) = ctmp:1; goto <L_xs8>;")
    A("<L_xs7> *:1 (r1 + 51) = hv:1; ctmp = hv >> 8; *:1 (r1 + 50) = ctmp:1; ctmp = hv >> 16; *:1 (r1 + 49) = ctmp:1; ctmp = hv >> 24; *:1 (r1 + 48) = ctmp:1;")
    # the compressed dynamic-Huffman table: kept (or stored) for a partly decoded dynamic block, zeros otherwise
    A("<L_xs8> if (ccv == 0) goto <L_xsz>; if (st != 3) goto <L_xsz>; if (dynnew != 0) goto <L_xsn>; goto <L_xskd>;")
    A("<L_xsz> ix = 0; <L_xsa> *:1 (r1 + 64 + zext(ix)) = 0; ix = ix + 1; if (ix < 288) goto <L_xsa>; cdl = 0; goto <L_xsw>;")
    A("<L_xsn> ix = 0; <L_xsc> *:1 (r1 + 64 + zext(ix)) = 0; ix = ix + 1; if (ix < 288) goto <L_xsc>; ecb = 0;")
    A("<L_xsl> if (ecb >= cdl) goto <L_xsw>; hv = (zext(*:1 (sa + ((dhs + ecb) >> 3))) >> ((dhs + ecb) & 7)) & 1; if (hv == 0) goto <L_xse>; ctmp = zext(*:1 (r1 + 64 + (ecb >> 3))) | (1 << (ecb & 7)); *:1 (r1 + 64 + (ecb >> 3)) = ctmp:1;")
    A("<L_xse> ecb = ecb + 1; goto <L_xsl>;")
    A("<L_xskd> cdl = zext(*:1 (r1 + 57)) | ((zext(*:1 (r1 + 56)) & 0xf) << 8);")
    A("<L_xsw> ctmp = (zext(*:1 (r1 + 56)) & 0xf0) | (cdl >> 8); *:1 (r1 + 56) = ctmp:1; *:1 (r1 + 57) = cdl:1;")
    A(f"hv = rp >> 3; {r1a} = da; {r1l} = dl; {r2a} = sa + hv; {r2l} = sl - hv; cc = ccv; goto <L_done>;")
    A("<L_done>")
    return "\n".join(t)


NAMES = {"dfltcc"}


def semantics(ctx):
    if ctx["name"] == "dfltcc" and len(ctx.get("extra", [])) >= 5:
        return dfltcc_insn(ctx["ops"], ctx["extra"])
    return None
