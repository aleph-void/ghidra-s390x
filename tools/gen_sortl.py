"""P-code for SORT LISTS (SORTL, B938): SORTL-QAF, SORTL-SFLR and SORTL-SVLR.

The instruction is a k-way merge of up to 128 input lists (parameter block, format 0) into
output lists at the first operand, following the Principles of Operation (SA22-7832-14, chapter
26): each unit of operation selects, among the heads of the active input lists, the record with
the smallest (ascending) or largest (descending) key, where a key that equals another is taken
from the input list with the higher number first. With merge mode 0 the records form output
lists: the next record continues the most recent output list when some head does not break the
sort order against the previous key, and starts a new output list otherwise; an
output-list delineation (address and length) is stored at the second operand for each completed
list. With merge mode 1 the input lists are presorted and one output list results.

The operation runs to completion in one execution. It ends early with the conditions the
architecture defines for the program: condition code 1 (first or second operand too short),
condition code 2 (an incomplete input list, or an input list that became empty while the
empty-input-lists control asks to stop), and never with condition code 3 (a CPU-determined
stopping point). The continuation-state buffer (parameter block bytes 64-575, model dependent
by definition) holds: byte 64 an output list is open, byte 65 the next record must start a new
output list, bytes 72-79 and 80-87 the open list's start address and length. The key of the
last record stored goes to the continuation-record-recall buffer. The 24/31-bit addressing
modes and access exceptions are not modelled; a bad parameter block or record is
trap_data_exception, a bad register or alignment trap_specification.
"""

PREVK = 0x3000          # scratch space cpm: key of the previous record (up to 4096 bytes)

LOCALS = (
    "local fc:1 = r0:1 & 0x7f; local qmm:1 = 0; local qsv:1 = 0; local qasc:1 = 1; local qcf:1 = 0; local qel:1 = 0; "
    "local qnis:8 = 0; local qail:8 = 0; local qkl:8 = 0; local qpl:8 = 0; local qfix:8 = 0; local qn:8 = 0; "
    "local qbest:8 = 0; local qhs:1 = 0; local qbad:8 = 0; local qbrl:8 = 0; local qad:8 = 0; local qln:8 = 0; local qrl:8 = 0; "
    "local qne:8 = 0; local qcont:1 = 0; local qc:1 = 0; local qx:8 = 0; local qy:8 = 0; local qci:8 = 0; local qj:4 = 0; "
    "local qop:1 = 0; local qfn:1 = 0; local qos:8 = 0; local qol:8 = 0; local qplaced:8 = 0; local qcrrb:8 = 0; "
    "local qa1:8 = 0; local ql1:8 = 0; local qa2:8 = 0; local ql2:8 = 0; local qcc:1 = 0; local qcfo:1 = 0; "
    "local qiilf:1 = 0; local qiiln:1 = 0; local qeilf:1 = 0; local qeiln:1 = 0; local qeilp:1 = 0; local qeilw:8 = 0; "
    "local qb:1 = 0; local qnl:8 = 0; local qb40:1 = 0; local qb46:1 = 0; local qb7:1 = 0; local qpb:2 = 0; local qp0:1 = 0; local qp1:1 = 0; local qt:8 = 0;"
)


def cmp_ram_ram(a, b, tag):
    """qc = 0 equal, 1 key at a < key at b, 2 greater (unsigned big-endian), qkl bytes"""
    return (f"qci = 0; qc = 0; <L_ca{tag}> if (qci >= qkl) goto <L_cd{tag}>; qx = *:8 ({a} + qci); qy = *:8 ({b} + qci); "
            f"if (qx == qy) goto <L_cn{tag}>; qc = 1; if (qx < qy) goto <L_cd{tag}>; qc = 2; goto <L_cd{tag}>; "
            f"<L_cn{tag}> qci = qci + 8; goto <L_ca{tag}>; <L_cd{tag}>")


def cmp_ram_prev(a, tag):
    return (f"qci = 0; qj = 0; qc = 0; <L_pa{tag}> if (qci >= qkl) goto <L_pd{tag}>; qx = *:8 ({a} + qci); qy = *[cpm]:8 ({PREVK:#x}:4 + qj); "
            f"if (qx == qy) goto <L_pn{tag}>; qc = 1; if (qx < qy) goto <L_pd{tag}>; qc = 2; goto <L_pd{tag}>; "
            f"<L_pn{tag}> qci = qci + 8; qj = qj + 8; goto <L_pa{tag}>; <L_pd{tag}>")


def store_old(r2l):
    """store the delineation of the open output list at the second operand (needs 16 bytes)"""
    return ("*:8 qa2 = qos; *:8 (qa2 + 8) = qol; qa2 = qa2 + 16; ql2 = ql2 - 16; qop = 0;")


def sortl_insn(o, x):
    """x: R1 + 1, R1 number, R2 + 1, R2 number"""
    r1a, r2a = o[0], o[1]
    r1l, r2l = x[0], x[2]
    t = [f"local r1num:4 = {x[1]}; local r2num:4 = {x[3]};", LOCALS]
    t.append("if (fc != 0) goto <L_fn>;")
    t.append("*:8 r1 = 0xe000000000000000:8; *:8 (r1 + 8) = 0:8; *:8 (r1 + 16) = 0x3800000000000000:8; *:8 (r1 + 24) = 0x8000000000000000:8; cc = 0; goto <L_done>;")
    t.append("<L_fn> if ((fc == 1) || (fc == 2)) goto <L_fok>; trap_specification(); goto <L_done>;\n<L_fok>")
    t.append("qsv = (fc == 2); qmm = (r0:1 >> 7) & 1;")
    t.append(f"if ((((r1num & 1) == 0) && (r1num != 0)) && (((r2num & 1) == 0) && (r2num != 0))) goto <L_rok>; trap_specification(); goto <L_done>;\n<L_rok>")
    t.append(f"if ((r1 & 7) != 0) goto <L_sbad>; if (({r1a} & 7) != 0) goto <L_sbad>; if (qmm != 0) goto <L_sok>; if (({r2a} & 7) == 0) goto <L_sok>;")
    t.append("<L_sbad> trap_specification(); goto <L_done>;\n<L_sok>")
    # parameter block: version number, key / payload lengths, sort order, continuation flag, control fields
    t.append("qp0 = *:1 r1; qp1 = *:1 (r1 + 1);")
    t.append("qnis = 0; if (qp0 != 0x20) goto <L_n1>; qnis = 32;\n<L_n1> if (qp0 != 0x10) goto <L_n2>; qnis = 64;\n<L_n2> if (qp0 != 0x08) goto <L_n3>; qnis = 128;\n<L_n3>")
    t.append("if ((qnis != 0) && ((qp1 & 0xf) == 0)) goto <L_pbok>; trap_data_exception(); goto <L_done>;\n<L_pbok>")
    t.append("qkl = zext(*:2 (r1 + 10)); qpl = zext(*:2 (r1 + 14));")
    t.append("if ((qkl == 0) || ((qkl & 7) != 0) || (qkl > 4096)) goto <L_dex>;")
    t.append("qfix = qkl + qpl; if (qsv != 0) goto <L_kok>; if (((qpl & 7) != 0) || (qfix > 4096)) goto <L_dex>;\n<L_kok>")
    t.append("qail = zext(*:1 (r1 + 33) & 0x7f); if (qail < qnis) goto <L_aok>;\n<L_dex> trap_data_exception(); goto <L_done>;\n<L_aok>")
    t.append("qb7 = *:1 (r1 + 7); qasc = (qb7 & 0x80) == 0; qcf = qb7 & 1; qel = *:1 (r1 + 40) & 0xc0;")
    t.append("qn = 0; <L_al> if ((*:8 (r1 + 576 + (qn * 16)) & 7) != 0) goto <L_dex>; qn = qn + 1; if (qn <= qail) goto <L_al>;")
    t.append("qcrrb = *:8 (r1 + 56); qcrrb = qcrrb & 0xfffffffffffff000;")
    t.append(f"qa1 = {r1a}; ql1 = {r1l}; qa2 = {r2a}; ql2 = {r2l}; qplaced = 0; qeilp = 0; qop = 0; qfn = 0;")
    t.append("if (qcf == 0) goto <L_begin>; qop = *:1 (r1 + 64); qfn = *:1 (r1 + 65); qos = *:8 (r1 + 72); qol = *:8 (r1 + 80);\n<L_begin>")
    t.append("qcont = 0; if (qmm != 0) goto <L_nc>;")
    # a list left open when the previous execution ended with condition code 1 (or by the control) is completed first
    t.append("if ((qop == 0) || (qfn == 0)) goto <L_nopend>; if (ql2 < 16) goto <L_end1>; " + store_old(r2l) + "\n<L_nopend>")
    t.append("if ((qop == 0) || (qfn != 0)) goto <L_nc>; qcont = 1; qci = 0; qj = 0;")
    t.append(f"<L_lp> *[cpm]:8 ({PREVK:#x}:4 + qj) = *:8 (qcrrb + qci); qci = qci + 8; qj = qj + 8; if (qci < qkl) goto <L_lp>;")
    t.append("<L_nc>")
    # ---- one unit of operation
    t.append("<L_unit> qhs = 0; qne = 0; qn = 0;")
    t.append("<L_scan> qln = *:8 (r1 + 584 + (qn * 16)); if (qln == 0) goto <L_snext>; qad = *:8 (r1 + 576 + (qn * 16));")
    t.append("qrl = qfix; if (qsv == 0) goto <L_haverl>; if (qln < (qkl + 8)) goto <L_incomp>;")
    t.append("qpl = zext(*:2 (qad + qkl + 6)); if (((qpl & 7) != 0) || ((qkl + qpl) > 4088)) goto <L_dex>; qrl = qkl + 8 + qpl;")
    t.append("<L_haverl> if (qln < qrl) goto <L_incomp>; qne = qne + 1; if (qcont == 0) goto <L_nq>;")
    t.append(cmp_ram_prev("qad", "1"))
    t.append("if (qasc == 0) goto <L_qd>; if (qc == 1) goto <L_snext>; goto <L_nq>;\n<L_qd> if (qc == 2) goto <L_snext>;")
    t.append("<L_nq> if (qhs != 0) goto <L_cmpb>; <L_take> qhs = 1; qbest = qn; qbad = qad; qbrl = qrl; goto <L_snext>;")
    t.append("<L_cmpb> " + cmp_ram_ram("qad", "qbad", "2"))
    t.append("if (qasc == 0) goto <L_bd>; if (qc != 2) goto <L_take>; goto <L_snext>;\n<L_bd> if (qc != 1) goto <L_take>;")
    t.append("<L_snext> qn = qn + 1; if (qn <= qail) goto <L_scan>;")
    t.append("if (qne == 0) goto <L_done0>; if (qeilp != 0) goto <L_endeil>; if (qhs != 0) goto <L_sel>; qcont = 0; goto <L_unit>;")
    # ---- place the selected record
    t.append("<L_sel> if (qmm != 0) goto <L_room>; if (qcont != 0) goto <L_room>; if (qop == 0) goto <L_room>;")
    t.append("if (ql2 < 16) goto <L_end1n>; " + store_old(r2l))
    t.append("<L_room> if (ql1 >= qbrl) goto <L_place>; qfn = 1; goto <L_end1>;\n<L_end1n> qfn = 1; goto <L_end1>;")
    t.append("<L_place> qci = 0; <L_cpy> *:8 (qa1 + qci) = *:8 (qbad + qci); qci = qci + 8; if (qci < qbrl) goto <L_cpy>;")
    t.append("if (qmm != 0) goto <L_nokey>; qci = 0; qj = 0;")
    t.append(f"<L_ck> *[cpm]:8 ({PREVK:#x}:4 + qj) = *:8 (qbad + qci); qci = qci + 8; qj = qj + 8; if (qci < qkl) goto <L_ck>;")
    t.append("if (qcont != 0) goto <L_cont>; qop = 1; qos = qa1; qol = qbrl; goto <L_nokey>;\n<L_cont> qol = qol + qbrl;")
    t.append("<L_nokey> qa1 = qa1 + qbrl; ql1 = ql1 - qbrl; qplaced = qplaced + 1;")
    t.append("qt = *:8 (r1 + 576 + (qbest * 16)); *:8 (r1 + 576 + (qbest * 16)) = qt + qbrl; qnl = *:8 (r1 + 584 + (qbest * 16)) - qbrl; *:8 (r1 + 584 + (qbest * 16)) = qnl;")
    t.append("qcont = 0; if (qmm != 0) goto <L_c2>; qcont = 1;\n<L_c2> if (qnl != 0) goto <L_unit>;")
    t.append("if (qbest != 0) goto <L_eo>; if ((qel & 0x80) == 0) goto <L_unit>; goto <L_eset>;\n<L_eo> if ((qel & 0x40) == 0) goto <L_unit>;")
    t.append("<L_eset> qeilp = 1; qeilw = qbest; goto <L_unit>;")
    # ---- endings
    t.append("<L_done0> if (qmm != 0) goto <L_n0>; if (qop == 0) goto <L_n0>; if (ql2 < 16) goto <L_pend>; " + store_old(r2l) + "\n<L_n0> qcc = 0; qcfo = 0; goto <L_fin>;")
    t.append("<L_pend> qfn = 1; goto <L_end1>;")
    t.append("<L_end1> qcc = 1; qcfo = 1; goto <L_fin>;")
    t.append("<L_endeil> qcc = 2; qcfo = 1; qeilf = 0; qeiln = 0; qfn = 1; if (qel != 0xc0) goto <L_fin>; qeilf = 1; qeiln = qeilw:1; qfn = 0; goto <L_fin>;")
    t.append("<L_incomp> qcc = 2; qcfo = 1; qiilf = 1; qiiln = qn:1; qfn = 0; goto <L_fin>;")
    # ---- parameter block, registers and condition code
    t.append("<L_fin> *:1 (r1 + 2) = 0; qb7 = *:1 (r1 + 7); qb7 = (qb7 & 0xfe) | qcfo; *:1 (r1 + 7) = qb7;")
    t.append("qb40 = *:1 (r1 + 40) & 0xdf; if (qeilf == 0) goto <L_e0>; qb40 = qb40 | 0x20;\n<L_e0> *:1 (r1 + 40) = qb40; *:1 (r1 + 41) = qeiln;")
    t.append("qb46 = *:1 (r1 + 46) & 0x7f; if (qiilf == 0) goto <L_i0>; qb46 = qb46 | 0x80;\n<L_i0> *:1 (r1 + 46) = qb46; *:1 (r1 + 47) = qiiln;")
    t.append("*:1 (r1 + 64) = qop; *:1 (r1 + 65) = qfn; *:8 (r1 + 72) = qos; *:8 (r1 + 80) = qol;")
    t.append("if (qmm != 0) goto <L_nr>; if (qplaced == 0) goto <L_nr>; if (qcfo == 0) goto <L_nr>; qci = 0; qj = 0;")
    t.append(f"<L_sk> *:8 (qcrrb + qci) = *[cpm]:8 ({PREVK:#x}:4 + qj); qci = qci + 8; qj = qj + 8; if (qci < qkl) goto <L_sk>;")
    t.append(f"<L_nr> {r1a} = qa1; {r1l} = ql1; if (qmm != 0) goto <L_n2r>; {r2a} = qa2; {r2l} = ql2;")
    t.append("<L_n2r> cc = qcc;\n<L_done>")
    return "\n".join(t)


NAMES = {"sortl"}


def semantics(ctx):
    if ctx["name"] == "sortl" and len(ctx.get("extra", [])) >= 4:
        return sortl_insn(ctx["ops"], ctx["extra"])
    return None
