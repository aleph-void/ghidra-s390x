"""P-code for COMPRESSION CALL (CMPSC, B263): compression and expansion with the Principles of
Operation's dictionary formats (SA22-7832-14, instruction description and Appendix D): compression
dictionary character entries and format-0 / format-1 sibling descriptors, expansion dictionary
unpreceded and preceded entries, symbol translation (ST), order preservation (OP) and entropy
encoding (EE). Written from the manual's flowcharts (figures 7-217 to 7-222); the unordered
compression process follows figure 7-217 exactly, including the continuation over identical leading
child characters; matching on additional extension characters that do not match ends the match, which
the architecture allows ("model dependent").

The operation runs to completion in one execution: it ends with condition code 0 (second operand
exhausted, or an all-zero codeword with entropy encoding) or 1 (first operand full), never 3. Zero
padding (ZP) is model dependent and not performed. The last partial byte of compressed data keeps the
bits to its right unchanged. Only the 64-bit addressing mode is modelled; dictionary errors that the
architecture reports as data exceptions are trap_data_exception (entropy descriptor validation, a zero
or unpadded entropy symbol-translation entry, runaway child / predecessor chains).
"""

LOCALS = (
    "local fc0:8 = r0; local m_ee:8 = 0; local m_op:8 = 0; local m_st:8 = 0; local m_f1:8 = 0; local m_ex:8 = 0; local m_bt:8 = 0; "
    "local m_cdss:8 = 0; local m_w:8 = 0; local m_dsz:8 = 0; local m_cd:8 = 0; local m_xd:8 = 0; local m_stt:8 = 0; local m_edp:8 = 0; local m_off:8 = 0; "
    "local m_cbn:8 = 0; local m_sa:8 = 0; local m_sl:8 = 0; local m_da:8 = 0; local m_dl:8 = 0; local m_p:8 = 0; local m_pi:8 = 0; local m_pe:8 = 0; "
    "local m_b0:8 = 0; local m_b1:8 = 0; local m_b2:8 = 0; local m_cct:8 = 0; local m_cptr:8 = 0; local m_act:8 = 0; local m_dd:8 = 0; local m_ncc:8 = 0; local m_ccoff:8 = 0; local m_sd:8 = 0; "
    "local m_flag:8 = 0; local m_sc:8 = 0; local m_cc:8 = 0; local m_j:8 = 0; local m_ci:8 = 0; local m_xj:8 = 0; local m_ca:8 = 0; local m_k:8 = 0; local m_sdi:8 = 0; local m_se:8 = 0; "
    "local m_ns:8 = 0; local m_more:8 = 0; local m_first:8 = 0; local m_y:8 = 0; local m_s0:8 = 0; local m_s1:8 = 0; local m_e:8 = 0; local m_idx:8 = 0; local m_adj:8 = 0; local m_cb0:8 = 0; local m_cb1:8 = 0; "
    "local m_cb2:8 = 0; local m_cact:8 = 0; local m_cx:8 = 0; local m_v:8 = 0; local m_acc:8 = 0; local m_nb:8 = 0; local m_mk:8 = 0; local m_sh:8 = 0; local m_t:8 = 0; local m_cwl:8 = 0; "
    "local m_lb:8 = 0; local m_bl:8 = 0; local m_cw:8 = 0; local m_cix:8 = 0; local m_sym:8 = 0; local m_cnt:8 = 0; local m_en:8 = 0; local m_cc2:1 = 0; local m_ent:8 = 0; "
    "local m_psl:8 = 0; local m_csl:8 = 0; local m_ofst:8 = 0; local m_pptr:8 = 0; local m_ee0:8 = 0; local m_loop:8 = 0; local m_ex1:8 = 0; local m_bit:8 = 0; local m_avail:8 = 0; local m_r1n:4 = 0; local m_r2n:4 = 0;"
)


def entry(addr_expr):
    return f"({addr_expr})"


# ---- the compression dictionary: parent entry fields into m_cct m_cptr m_act m_dd m_ncc m_ccoff m_sd, X bits in m_b0
def load_parent(alpha_test=True):
    return (
        "m_pe = m_cd + (m_pi * 8); m_b0 = zext(*:1 m_pe); m_b1 = zext(*:1 (m_pe + 1)); m_b2 = zext(*:1 (m_pe + 2)); "
        "m_cct = m_b0 >> 5; m_cptr = ((m_b1 & 0x1f) << 8) | m_b2; m_act = 0; m_dd = 0; m_ncc = 0; m_sd = 0; m_ccoff = 3; "
        "if (m_cct == 0) goto <L_lp1@>; if (m_cct != 1) goto <L_lp2@>; "
        "m_act = m_b1 >> 5; if (m_act > 4) goto <L_lp5@>; goto <L_lp6@>; <L_lp5@> m_act = 4; <L_lp6@> "
        "if (m_pi >= 256) goto <L_lp7@>; m_act = 0; <L_lp7@> m_ncc = 1; m_ccoff = 3 + m_act; goto <L_lp1@>; "
        "<L_lp2@> m_dd = (m_b1 >> 5) & 1; if (m_pi >= 256) goto <L_lp8@>; m_dd = 0; <L_lp8@> m_ccoff = 3 + m_dd; m_ncc = m_cct; "
        "if (m_dd != 0) goto <L_lp3@>; if (m_cct < 6) goto <L_lp1@>; m_ncc = 5; m_sd = 1; goto <L_lp1@>; "
        "<L_lp3@> if (m_cct < 5) goto <L_lp1@>; m_ncc = 4; m_sd = 1; <L_lp1@>"
    )


def load_child(idx):
    """child entry at index idx: number of additional extension characters in m_ca, entry address in m_se2"""
    return (
        f"m_pe = m_cd + ({idx} * 8); m_cb0 = zext(*:1 m_pe); m_cb1 = zext(*:1 (m_pe + 1)); m_cx = m_cb0 >> 5; m_ca = 0; "
        "if (m_cx > 1) goto <L_lc1@>; m_ca = m_cb1 >> 5; if (m_ca <= 4) goto <L_lc2@>; m_ca = 4; goto <L_lc2@>; "
        "<L_lc1@> m_ca = (m_cb1 >> 5) & 1; <L_lc2@>"
    )


def cc_char(j):
    return f"zext(*:1 (m_pe + m_ccoff + {j}))"


def sd_char_fmt0(k):
    return f"zext(*:1 (m_se + 1 + {k}))"


def sib_char(k):
    # format 1: characters 1-6 in bytes 2-7 of the compression dictionary entry, 7-14 in bytes 0-7 of the expansion dictionary entry
    return (f"m_k = {k}; if (m_k >= 6) goto <L_sx@>; m_sc = zext(*:1 (m_se + 2 + m_k)); goto <L_sy@>; "
            f"<L_sx@> m_sc = zext(*:1 (m_xd + (m_sdi * 8) + (m_k - 6))); <L_sy@>")


def examine_x(j):
    """X bit of child j (0-origin) of the parent in m_b0 / m_cct"""
    return (f"m_xj = 0; if (m_cct != 1) goto <L_xa@>; m_xj = (m_b0 >> 4) & 1; goto <L_xb@>; "
            f"<L_xa@> if ({j} >= 5) goto <L_xb@>; m_xj = (m_b0 >> (4 - {j})) & 1; <L_xb@>")


def load_sd():
    """sibling descriptor at m_sdi: m_ns siblings, m_more another SD follows, m_se its address"""
    return (
        "m_se = m_cd + (m_sdi * 8); m_s0 = zext(*:1 m_se); m_s1 = zext(*:1 (m_se + 1)); m_more = 0; "
        "if (m_f1 != 0) goto <L_sd1@>; m_ns = m_s0 >> 5; if (m_ns != 0) goto <L_sd2@>; m_ns = 7; m_more = 1; <L_sd2@> goto <L_sd3@>; "
        "<L_sd1@> m_ns = m_s0 >> 4; if (m_ns == 0) goto <L_sd4@>; if (m_ns < 15) goto <L_sd3@>; <L_sd4@> m_ns = 14; m_more = 1; <L_sd3@>"
    )


def sib_y(k):
    """Y (examine) bit of sibling k (0-origin) of the SD in m_sdi into m_y; parent's YY in m_b1 when the first SD"""
    return (
        "m_y = 1; if (m_f1 != 0) goto <L_yf1@>; "
        f"if ({k} >= 5) goto <L_yp0@>; m_y = (m_s0 >> (4 - {k})) & 1; goto <L_yd@>; "
        f"<L_yp0@> if (m_first == 0) goto <L_yd@>; m_y = (m_b1 >> (7 - ({k} - 5))) & 1; goto <L_yd@>; "
        f"<L_yf1@> if ({k} >= 12) goto <L_yp1@>; if ({k} >= 4) goto <L_yb1@>; m_y = (m_s0 >> (3 - {k})) & 1; goto <L_yd@>; "
        f"<L_yb1@> m_y = (m_s1 >> (7 - ({k} - 4))) & 1; goto <L_yd@>; "
        f"<L_yp1@> if (m_first == 0) goto <L_yd@>; m_y = (m_b1 >> (7 - ({k} - 12))) & 1; <L_yd@>"
    )


def uniq(text, tag):
    return text.replace("@", tag)


_COUNTER = [0]


class Gen:
    def __init__(self):
        self.t = []

    def add(self, s):
        _COUNTER[0] += 1
        self.t.append(uniq(s, f"{_COUNTER[0]}"))

    def raw(self, s):
        self.t.append(s)


def compress_unordered(g):
    """figure 7-217: sets m_idx (index symbol of the last match), m_p (source bytes consumed)"""
    A = g.add
    A("m_p = 1; m_pi = zext(*:1 m_sa);")
    g.raw("<L_n2> ")
    A(load_parent())
    g.raw("if (m_cct == 0) goto <L_nout>; m_flag = 1; if (m_p >= m_sl) goto <L_nout>; m_sc = zext(*:1 (m_sa + m_p)); m_j = 0;")
    g.raw("<L_n3> m_cc = " + cc_char("m_j") + "; if (m_sc != m_cc) goto <L_n3ne>; m_ci = m_cptr + m_j;")
    A(examine_x("m_j"))
    g.raw("if (m_xj != 0) goto <L_n3x>; m_idx = m_ci; m_p = m_p + 1; goto <L_nemit>;")
    g.raw("<L_n3x> ")
    A(load_child("m_ci"))
    A("m_pe = m_cd + (m_pi * 8); if (m_ca != 0) goto <L_n3a@>; m_pi = m_ci; m_p = m_p + 1; goto <L_n2>; <L_n3a@> "
      "if ((m_sl - m_p - 1) < m_ca) goto <L_n3f>; m_k = 0; <L_n3c@> m_s0 = zext(*:1 (m_sa + m_p + 1 + m_k)); "
      "m_e = zext(*:1 (m_cd + (m_ci * 8) + 3 + m_k)); if (m_s0 != m_e) goto <L_n3f>; m_k = m_k + 1; if (m_k < m_ca) goto <L_n3c@>; "
      "m_pi = m_ci; m_p = m_p + 1 + m_ca; goto <L_n2>;")
    # a failed comparison on additional extension characters: go on with the next child only while the children seen are identical
    g.raw("<L_n3f> if (m_flag == 0) goto <L_nout>; m_pe = m_cd + (m_pi * 8); m_j = m_j + 1; if (m_j >= m_ncc) goto <L_nout>; goto <L_n3>;")
    g.raw("<L_n3ne> m_flag = 0; m_j = m_j + 1; if (m_j < m_ncc) goto <L_n3>; if (m_sd == 0) goto <L_nout>;")
    # sibling descriptors
    g.raw("m_sdi = m_cptr + m_ncc; m_first = 1; <L_n4> ")
    A(load_sd())
    g.raw("m_k = 0;")
    g.raw("<L_n4l> ")
    A("if (m_f1 != 0) goto <L_sf1@>; m_sc = zext(*:1 (m_se + 1 + m_k)); goto <L_sf2@>; "
      "<L_sf1@> if (m_k >= 6) goto <L_sf3@>; m_sc = zext(*:1 (m_se + 2 + m_k)); goto <L_sf2@>; "
      "<L_sf3@> m_sc = zext(*:1 (m_xd + (m_sdi * 8) + (m_k - 6))); <L_sf2@>")
    g.raw("m_cc = zext(*:1 (m_sa + m_p)); if (m_cc != m_sc) goto <L_n4ne>; m_ci = m_sdi + 1 + m_k;")
    A(sib_y("m_k"))
    g.raw("if (m_y != 0) goto <L_n4x>; m_idx = m_ci; m_p = m_p + 1; goto <L_nemit>;")
    g.raw("<L_n4x> ")
    A(load_child("m_ci"))
    A("if (m_ca != 0) goto <L_n4a@>; m_pi = m_ci; m_p = m_p + 1; goto <L_n2>; <L_n4a@> "
      "if ((m_sl - m_p - 1) < m_ca) goto <L_nout>; m_j = 0; <L_n4c@> m_s0 = zext(*:1 (m_sa + m_p + 1 + m_j)); "
      "m_e = zext(*:1 (m_cd + (m_ci * 8) + 3 + m_j)); if (m_s0 != m_e) goto <L_nout>; m_j = m_j + 1; if (m_j < m_ca) goto <L_n4c@>; "
      "m_pi = m_ci; m_p = m_p + 1 + m_ca; goto <L_n2>;")
    g.raw("<L_n4ne> m_k = m_k + 1; if (m_k < m_ns) goto <L_n4l>; if (m_more == 0) goto <L_nout>; m_sdi = m_sdi + m_ns + 1; m_first = 0; goto <L_n4>;")
    g.raw("<L_nout> m_idx = m_pi; <L_nemit>")


def compress_ordered(g):
    """figure 7-218: sets m_idx, m_adj (0, 1: interchange symbol + 1, 2: - 1) and m_p"""
    A = g.add
    A("m_p = 1; m_pi = zext(*:1 m_sa); m_adj = 0;")
    g.raw("<L_o2> ")
    A(load_parent())
    g.raw("if (m_cct == 0) goto <L_oout>; if (m_p >= m_sl) goto <L_oout>; m_sc = zext(*:1 (m_sa + m_p)); m_j = 0;")
    g.raw("<L_o3l> m_cc = " + cc_char("m_j") + "; if (m_sc > m_cc) goto <L_o4>; m_ci = m_cptr + m_j; if (m_sc != m_cc) goto <L_o7>;")
    A(examine_x("m_j"))
    g.raw("if (m_xj != 0) goto <L_o5>; m_idx = m_ci; m_p = m_p + 1; goto <L_oemit>;")
    g.raw("<L_o5> ")
    A(load_child("m_ci"))
    A("m_pe = m_cd + (m_pi * 8); if (m_ca != 0) goto <L_o5a@>; m_pi = m_ci; m_p = m_p + 1; goto <L_o2>; <L_o5a@> m_k = 0; "
      "<L_o5c@> if ((m_p + 1 + m_k) >= m_sl) goto <L_o7>; m_s0 = zext(*:1 (m_sa + m_p + 1 + m_k)); "
      "m_e = zext(*:1 (m_cd + (m_ci * 8) + 3 + m_k)); if (m_s0 > m_e) goto <L_o4>; if (m_s0 != m_e) goto <L_o7>; m_k = m_k + 1; if (m_k < m_ca) goto <L_o5c@>; "
      "m_pi = m_ci; m_p = m_p + 1 + m_ca; goto <L_o2>;")
    g.raw("<L_o4> m_pe = m_cd + (m_pi * 8); m_j = m_j + 1; if (m_j < m_ncc) goto <L_o3l>; if (m_sd != 0) goto <L_o6>; m_idx = m_cptr + m_ncc - 1; m_adj = 1; goto <L_oemit>;")
    g.raw("<L_o7> m_idx = m_ci; m_adj = 2; goto <L_oemit>;")
    g.raw("<L_o6> m_sdi = m_cptr + m_ncc; m_first = 1; <L_o6a> ")
    A(load_sd())
    g.raw("m_k = 0;")
    g.raw("<L_o6c> ")
    A("if (m_f1 != 0) goto <L_sf1@>; m_e = zext(*:1 (m_se + 1 + m_k)); goto <L_sf2@>; "
      "<L_sf1@> if (m_k >= 6) goto <L_sf3@>; m_e = zext(*:1 (m_se + 2 + m_k)); goto <L_sf2@>; "
      "<L_sf3@> m_e = zext(*:1 (m_xd + (m_sdi * 8) + (m_k - 6))); <L_sf2@>")
    g.raw("if (m_sc > m_e) goto <L_o6n>; m_ci = m_sdi + 1 + m_k; if (m_sc != m_e) goto <L_o7>;")
    A(sib_y("m_k"))
    g.raw("if (m_y != 0) goto <L_o6x>; m_idx = m_ci; m_p = m_p + 1; goto <L_oemit>;")
    g.raw("<L_o6x> ")
    A(load_child("m_ci"))
    A("m_pe = m_cd + (m_pi * 8); if (m_ca != 0) goto <L_o6y@>; m_pi = m_ci; m_p = m_p + 1; goto <L_o2>; <L_o6y@> m_j = 0; "
      "<L_o6z@> if ((m_p + 1 + m_j) >= m_sl) goto <L_o7>; m_s0 = zext(*:1 (m_sa + m_p + 1 + m_j)); "
      "m_e = zext(*:1 (m_cd + (m_ci * 8) + 3 + m_j)); if (m_s0 > m_e) goto <L_o6n>; if (m_s0 != m_e) goto <L_o7>; m_j = m_j + 1; if (m_j < m_ca) goto <L_o6z@>; "
      "m_pi = m_ci; m_p = m_p + 1 + m_ca; goto <L_o2>;")
    g.raw("<L_o6n> m_k = m_k + 1; if (m_k < m_ns) goto <L_o6c>; if (m_more == 0) goto <L_o6e>; m_sdi = m_sdi + m_ns + 1; m_first = 0; goto <L_o6a>;")
    g.raw("<L_o6e> m_idx = m_sdi + m_ns; m_adj = 1; goto <L_oemit>;")
    g.raw("<L_oout> m_idx = m_pi; <L_oemit>")


def cmpsc_insn(o, x):
    """x: R1 + 1, R1 number, R2 + 1, R2 number"""
    r1a, r2a = o[0], o[1]
    r1l, r2l = x[0], x[2]
    t = [f"local r1num:4 = {x[1]}; local r2num:4 = {x[3]};", LOCALS]
    A = t.append
    A("if ((((r1num & 1) == 0) && (r1num != 0)) && (((r2num & 1) == 0) && (r2num != 0))) goto <L_rok>; trap_specification(); goto <L_done>;\n<L_rok>")
    A("m_ee = (fc0 >> 19) & 1; m_op = (fc0 >> 18) & 1; m_st = (fc0 >> 16) & 1; m_f1 = (fc0 >> 9) & 1; m_ex = (fc0 >> 8) & 1; m_cdss = (fc0 >> 12) & 0xf;")
    A("if (m_ee != 0) goto <L_cdok>; if ((m_cdss >= 1) && (m_cdss <= 5)) goto <L_cdok>; trap_specification(); goto <L_done>;\n<L_cdok>")
    A("m_w = m_cdss + 8; m_dsz = 4096 << (m_cdss - 1); m_cd = r1 & 0xfffffffffffff000; m_cbn = r1 & 7; m_off = (r1 >> 3) & 0x1ff; m_off = m_off << 7;")
    A("m_xd = m_cd; if (m_ex != 0) goto <L_xd1>; m_xd = m_cd + m_dsz;\n<L_xd1>")
    A("m_edp = m_cd + m_off; m_stt = m_cd + m_off; if (m_ee == 0) goto <L_s1>; m_stt = m_edp + 32;\n<L_s1>")
    A(f"m_sa = {r2a}; m_sl = {r2l}; m_da = {r1a}; m_dl = {r1l};")
    # ---- entropy descriptor validation (figure 7-220), for both operations
    A("if (m_ee == 0) goto <L_eev>; m_lb = 2; m_cnt = 0; m_bl = 1; m_en = m_off >> 3; m_en = m_en + 1;")
    A("<L_ev1> m_e = zext(*:2 (m_edp + ((m_bl - 1) * 2))); if (m_lb < m_e) goto <L_dex>; m_lb = m_lb - m_e; m_cnt = m_cnt + m_e; if (m_cnt > m_en) goto <L_dex>; m_bl = m_bl + 1; m_lb = m_lb * 2; if (m_bl <= 16) goto <L_ev1>;")
    A("if (m_lb != 0) goto <L_dex>; if (m_cnt != m_en) goto <L_dex>; goto <L_eev>;")
    A("<L_dex> trap_data_exception(); goto <L_done>;\n<L_eev>")
    A("if (m_ex != 0) goto <L_expand>;")
    # ================================================================ compression
    A("<L_cstart> if (m_sl == 0) goto <L_cc0>; if (m_ee != 0) goto <L_cee>; m_avail = (m_dl * 8) - m_cbn; if (m_dl == 0) goto <L_cc1>; if (m_avail < m_w) goto <L_cc1>; goto <L_cmatch>;")
    A("<L_cee> if (m_dl == 0) goto <L_cc1>;")
    A("<L_cmatch> if (m_op != 0) goto <L_cord>;")
    g = Gen()
    compress_unordered(g)
    A("\n".join(g.t))
    A("m_adj = 0; goto <L_cemit>;")
    A("<L_cord>")
    g = Gen()
    compress_ordered(g)
    A("\n".join(g.t))
    # translate and emit
    A("<L_cemit> m_v = m_idx; if (m_ee != 0) goto <L_cent>; if ((m_st == 0) && (m_op == 0)) goto <L_cput>;")
    A("m_t = zext(*:2 (m_stt + (m_idx * 2))); m_v = m_t & ((1 << m_w) - 1); if (m_adj == 0) goto <L_cput>; if (m_adj == 1) goto <L_cinc>; m_v = (m_v - 1) & ((1 << m_w) - 1); goto <L_cput>;")
    A("<L_cinc> m_v = (m_v + 1) & ((1 << m_w) - 1); goto <L_cput>;")
    # entropy: codeword emission (figure 7-222)
    A("<L_cent> m_t = zext(*:2 (m_stt + (m_idx * 2))); if (m_t == 0) goto <L_dex>; m_lb = 2; m_bl = 1; "
      "<L_ce1> m_e = zext(*:2 (m_edp + ((m_bl - 1) * 2))); if (m_lb < m_e) goto <L_dex>; m_lb = m_lb - m_e; m_cw = m_t >> (16 - m_bl); if (m_cw >= m_lb) goto <L_ce2>; m_bl = m_bl + 1; m_lb = m_lb * 2; if (m_bl <= 16) goto <L_ce1>; goto <L_dex>;")
    A("<L_ce2> if ((m_t & ((1 << (16 - m_bl)) - 1)) != 0) goto <L_dex>; m_w = m_bl; m_v = m_cw; m_avail = (m_dl * 8) - m_cbn; if (m_avail < m_w) goto <L_cc1>;")
    # store the symbol: m_w bits at bit m_cbn of the first operand
    A("<L_cput> m_nb = (m_cbn + m_w + 7) >> 3; m_sh = 24 - m_cbn - m_w; m_acc = zext(*:1 m_da) << 16; if (m_nb < 2) goto <L_cp1>; m_acc = m_acc | (zext(*:1 (m_da + 1)) << 8); if (m_nb < 3) goto <L_cp1>; m_acc = m_acc | zext(*:1 (m_da + 2));")
    A("<L_cp1> m_mk = ((1 << m_w) - 1) << m_sh; m_acc = (m_acc & (0xffffff ^ m_mk)) | (m_v << m_sh);")
    A("m_bt = (m_acc >> 16) & 0xff; *:1 m_da = m_bt:1; if (m_nb < 2) goto <L_cp2>; m_bt = (m_acc >> 8) & 0xff; *:1 (m_da + 1) = m_bt:1; if (m_nb < 3) goto <L_cp2>; m_bt = m_acc & 0xff; *:1 (m_da + 2) = m_bt:1;")
    A("<L_cp2> m_cbn = m_cbn + m_w; m_da = m_da + (m_cbn >> 3); m_dl = m_dl - (m_cbn >> 3); m_cbn = m_cbn & 7; m_sa = m_sa + m_p; m_sl = m_sl - m_p; ")
    A("if (m_ee == 0) goto <L_cstart>; m_w = 0; goto <L_cstart>;")
    A("<L_cc0> m_cc2 = 0; goto <L_fin>;\n<L_cc1> m_cc2 = 1; goto <L_fin>;")
    # ================================================================ expansion
    A("<L_expand> m_avail = (m_sl * 8) - m_cbn;")
    A("<L_xstart> m_avail = (m_sl * 8) - m_cbn; if (m_ee != 0) goto <L_xee>; if (m_avail < m_w) goto <L_xc0>; if (m_dl == 0) goto <L_xc1>;")
    # read the index symbol
    A("m_nb = (m_cbn + m_w + 7) >> 3; m_acc = zext(*:1 m_sa) << 16; if (m_nb < 2) goto <L_xr1>; m_acc = m_acc | (zext(*:1 (m_sa + 1)) << 8); if (m_nb < 3) goto <L_xr1>; m_acc = m_acc | zext(*:1 (m_sa + 2));")
    A("<L_xr1> m_idx = (m_acc >> (24 - m_cbn - m_w)) & ((1 << m_w) - 1); m_bl = m_w; goto <L_xhave>;")
    # entropy codeword conversion (figure 7-221)
    A("<L_xee> if (m_avail == 0) goto <L_xc0>; if (m_dl == 0) goto <L_xc1>; m_lb = 2; m_cix = 0; m_bl = 1; m_cw = 0;")
    A("<L_xe1> if (m_avail < m_bl) goto <L_xc0>; m_e = zext(*:2 (m_edp + ((m_bl - 1) * 2))); m_lb = m_lb - m_e; "
      "m_t = zext(*:1 (m_sa + ((m_cbn + m_bl - 1) >> 3))); m_t = (m_t >> (7 - ((m_cbn + m_bl - 1) & 7))) & 1; m_cw = (m_cw << 1) | m_t; m_cix = m_cix + m_e; "
      "if (m_cw >= m_lb) goto <L_xe2>; m_bl = m_bl + 1; m_lb = m_lb * 2; if (m_bl <= 16) goto <L_xe1>; goto <L_dex>;")
    A("<L_xe2> if (m_cw == 0) goto <L_xc0>; m_idx = m_cix - (m_cw - (m_lb - 1));")
    A("<L_xhave> m_ent = 0; if (m_ee != 0) goto <L_xent>; if (m_idx >= 256) goto <L_xent>; if (m_dl == 0) goto <L_xc1>; m_bt = m_idx; *:1 m_da = m_bt:1; m_da = m_da + 1; m_dl = m_dl - 1; goto <L_xadv>;")
    A("<L_xent> m_e = zext(*:1 (m_xd + (m_idx * 8))); m_psl = m_e >> 5; m_loop = 0; if (m_psl != 0) goto <L_xpre>;")
    A("m_csl = m_e & 7; if (m_csl == 0) goto <L_dex>; if (m_dl < m_csl) goto <L_xc1>; m_k = 0; "
      "<L_xu1> *:1 (m_da + m_k) = *:1 (m_xd + (m_idx * 8) + 1 + m_k); m_k = m_k + 1; if (m_k < m_csl) goto <L_xu1>; m_da = m_da + m_csl; m_dl = m_dl - m_csl; goto <L_xadv>;")
    # preceded entry: symbol length psl + ofst for the first entry, characters at the entry's own offset
    A("<L_xpre> m_ofst = zext(*:1 (m_xd + (m_idx * 8) + 7)); m_cnt = m_psl + m_ofst; if (m_dl < m_cnt) goto <L_xc1>; m_sym = m_cnt; m_ent = m_idx;")
    A("<L_xp1> m_loop = m_loop + 1; if (m_loop > 300) goto <L_dex>; m_e = zext(*:1 (m_xd + (m_ent * 8))); m_psl = m_e >> 5; if (m_psl == 0) goto <L_xp3>; if (m_psl <= 5) goto <L_xp6>; m_psl = 5; <L_xp6>")
    A("m_ofst = zext(*:1 (m_xd + (m_ent * 8) + 7)); m_k = 0; <L_xp2> *:1 (m_da + m_ofst + m_k) = *:1 (m_xd + (m_ent * 8) + 2 + m_k); m_k = m_k + 1; if (m_k < m_psl) goto <L_xp2>;")
    A("m_pptr = ((zext(*:1 (m_xd + (m_ent * 8))) & 0x1f) << 8) | zext(*:1 (m_xd + (m_ent * 8) + 1)); m_pptr = m_pptr >> 0; m_ent = m_pptr; if (m_ee != 0) goto <L_xp1>; if (m_ent >= 256) goto <L_xp1>;")
    A("m_bt = m_ent; *:1 (m_da + (m_ofst - 1)) = m_bt:1; goto <L_xp4>;")
    A("<L_xp3> m_csl = m_e & 7; m_k = 0; <L_xp5> *:1 (m_da + m_k) = *:1 (m_xd + (m_ent * 8) + 1 + m_k); m_k = m_k + 1; if (m_k < m_csl) goto <L_xp5>;")
    A("<L_xp4> m_da = m_da + m_sym; m_dl = m_dl - m_sym;")
    A("<L_xadv> m_cbn = m_cbn + m_bl; m_sa = m_sa + (m_cbn >> 3); m_sl = m_sl - (m_cbn >> 3); m_cbn = m_cbn & 7; if (m_dl != 0) goto <L_xstart>;")
    A("m_avail = (m_sl * 8) - m_cbn; if (m_ee != 0) goto <L_xz>; if (m_avail < m_w) goto <L_xc0>; goto <L_xc1>;\n<L_xz> if (m_avail == 0) goto <L_xc0>; goto <L_xc1>;")
    A("<L_xc0> m_cc2 = 0; goto <L_fin>;\n<L_xc1> m_cc2 = 1;")
    # ---- registers and condition code
    A(f"<L_fin> {r1a} = m_da; {r1l} = m_dl; {r2a} = m_sa; {r2l} = m_sl; r1 = (r1 & 0xfffffffffffffff8) | m_cbn; cc = m_cc2;\n<L_done>")
    return "\n".join(t)


NAMES = {"cmpsc"}


def semantics(ctx):
    if ctx["name"] == "cmpsc" and len(ctx.get("extra", [])) >= 4:
        return cmpsc_insn(ctx["ops"], ctx["extra"])
    return None
