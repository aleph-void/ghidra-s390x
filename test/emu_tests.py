#!/usr/bin/env python3
"""s390x p-code emulator tests: short sequences with hand-computed results.

  emu_tests.py <outdir>     writes emu.bin (raw big-endian image loaded at 0) and emu.txt

The sequences are assembled with llvm-mc (LLVM_MC, default llvm-mc; -mcpu=arch15, i.e. z17) into one image,
each test at its own label; DATA (0x8000-0xffff) is scratch memory inside the image.
emu.txt lines (read by EmuCheck.java):
  <name> <start-hex> <stop-hex> <init|-> <expect>
init/expect are comma-separated "reg=hex" or "m<size>:<addr-hex>=hex" items (memory values are
big-endian). Every expected value was worked out by hand from the z/Architecture Principles of
Operation (SA22-7832-14) instruction descriptions, not by running the module.
"""
import os, subprocess, sys, tempfile
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

DATA = 0x8000

tests = []      # (name, asm, init, expect)
def T(name, asm, init, expect):
    tests.append((name, asm.strip(), init, expect))

# ---- integer arithmetic and condition codes -------------------------------------------------
# 32-bit ops change bits 32-63 only; cc 0 zero, 1 < 0, 2 > 0, 3 overflow
T("ar", "ar %r1,%r2", "r1=1111111100000005,r2=2222222200000007", "r1=111111110000000c,cc=2")
T("ar_overflow", "ar %r1,%r2", "r1=7fffffff,r2=1", "r1=80000000,cc=3")
T("agr_zero", "agr %r1,%r2", "r1=ffffffffffffffff,r2=1", "r1=0,cc=0")
# logical add: cc 0 zero/no carry, 1 nonzero/no carry, 2 zero/carry, 3 nonzero/carry
T("alr_carry", "alr %r1,%r2", "r1=ffffffff,r2=1", "r1=0,cc=2")
# logical subtract: cc 1 nonzero with borrow
T("slgr_borrow", "slgr %r1,%r2", "r1=5,r2=7", "r1=fffffffffffffffe,cc=1")
T("msgr", "msgr %r1,%r2", "r1=fffffffffffffffd,r2=7", "r1=ffffffffffffffeb")
# 128-by-64 unsigned divide of r2:r3 by r4: 100 / 7 = 14 remainder 2
T("dlgr", "dlgr %r2,%r4", "r2=0,r3=64,r4=7", "r2=2,r3=e")
T("ngr", "ngr %r1,%r2", "r1=f0f0,r2=ff00", "r1=f000,cc=1")
T("sllg", "sllg %r1,%r2,4", "r2=8000000000000001", "r1=10")
T("srag", "srag %r1,%r2,4", "r2=8000000000000000", "r1=f800000000000000,cc=1")
T("lgfr", "lgfr %r1,%r2", "r2=1234567880000000", "r1=ffffffff80000000")
# leftmost one at bit 19 -> r2 = 19, r3 = r2 input with that bit cleared, cc 2
T("flogr", "flogr %r2,%r4", "r4=0000100000000001", "r2=13,r3=1,cc=2")
# ICM mask 0101 inserts bytes into bits 40-47 and 56-63; leftmost inserted bit 1 -> cc 1
T("icm", "icm %r1,5,0(%r2)", f"r2={DATA:x},m2:{DATA:x}=aabb", "r1=aa00bb,cc=1")

# z17 count leading/trailing zeros (64 for a zero operand)
T("clzg", "clzg %r1,%r2", "r2=0000100000000001", "r1=13")
T("ctzg", "ctzg %r1,%r2\nctzg %r3,%r4", "r2=10,r4=0", "r1=4,r3=40")

# ---- loads and stores per addressing mode ---------------------------------------------------
T("lg_bxd", "lg %r1,8(%r2,%r3)", f"r2=100,r3={DATA:x},m8:{DATA + 0x108:x}=1122334455667788",
  "r1=1122334455667788")
T("st_32", "st %r1,0(%r2)", f"r1=aabbccdd11223344,r2={DATA:x}", f"m4:{DATA:x}=11223344")
T("ly_negdisp", "ly %r1,-4(%r2)", f"r2={DATA + 0x10:x},m4:{DATA + 0xc:x}=cafef00d", "r1=cafef00d")
T("stmg_lmg", "stmg %r6,%r8,0(%r15)\nlmg %r1,%r3,0(%r15)", f"r6=1,r7=2,r8=3,r15={DATA:x}",
  f"r1=1,r2=2,r3=3,m8:{DATA + 8:x}=2")
# register range wraps from r15 to r0: r15, r0, r1 get the low words, high halves unchanged
T("lmy_wrap", "lmy %r15,%r1,0(%r2)",
  f"r2={DATA:x},r15=aaaaaaaa00000000,m4:{DATA:x}=1,m4:{DATA + 4:x}=2,m4:{DATA + 8:x}=3",
  "r15=aaaaaaaa00000001,r0=2,r1=3")
T("mvc", "mvc 0(4,%r2),0(%r3)", f"r2={DATA:x},r3={DATA + 0x20:x},m4:{DATA + 0x20:x}=deadbeef",
  f"m4:{DATA:x}=deadbeef")
# first operand low: cc 1
T("clc", "clc 0(2,%r2),0(%r3)", f"r2={DATA:x},r3={DATA + 0x20:x},m2:{DATA:x}=0102,m2:{DATA + 0x20:x}=0103",
  "cc=1")
T("larl", "larl %r1,.+0x10", "", "r1=@+10")
# primary-space mode: LAE sets access register R1 to 0
T("lae", "lae %r1,4(%r2,%r3)", "r2=10,r3=20,a1=5", "r1=34,a1=0")

# ---- branches, calls, returns ---------------------------------------------------------------
T("brct_loop", """
  lghi %r1,5
  lghi %r2,0
0:aghi %r2,3
  brct %r1,0b
""", "", "r1=0,r2=f")
# branches read the condition flags set by the compare
T("cgr_jh_taken", """
  cgr %r1,%r2
  jh 1f
  lghi %r3,1
1:nopr
""", "r1=5,r2=3", "r3=0,cc=2")
T("clr_jnl_not_taken", """
  clr %r1,%r2
  jnl 1f
  lghi %r3,1
1:nopr
""", "r1=ffffffff00000001,r2=2", "r3=1,cc=1")
# compare and trap: no trap when the condition is false, condition code unchanged
T("cgrt_no_trap", "cgrt %r1,%r2,8", "r1=1,r2=2,cc=2", "cc=2")
T("bras_call_return", """
  bras %r14,1f
  j 2f
1:lghi %r2,42
  br %r14
2:nopr
""", "", "r2=2a")
T("cgrj_taken", """
  lghi %r3,1
  cgrj %r1,%r2,4,1f
  lghi %r3,2
1:nopr
""", "r1=fffffffffffffffe,r2=1", "r3=1")
# 64-bit addressing mode (PSW bits 31-32 set): link is the updated address with a one in bit 63
T("bassm_64", """
  larl %r1,1f
  oill %r1,1
  bassm %r14,%r1
  lghi %r3,7
1:lghi %r2,9
""", "pswm=180000000", "r2=9,r3=0,r14=@+d")

# ---- storage-to-storage, decimal and string instructions (qemu-s390x 10.2 gets the first five
# wrong, so these hand-computed results are their only check)
# CSST function code 0: R3 bits 32-63 compared; equal: replacement word stored, then the
# 4-byte store value (storage characteristic 2); unequal: the old word into R3 bits 32-63
T("csst_fc0_equal", "csst 0(%r4),64(%r4),%r2",
  f"r0=200,r1={DATA + 0x100:x},r2=ffffffff55667788,r4={DATA:x},m4:{DATA:x}=55667788,"
  f"m4:{DATA + 0x100:x}=11223344,m4:{DATA + 0x110:x}=aabbccdd",
  f"m4:{DATA:x}=11223344,m4:{DATA + 0x40:x}=aabbccdd,r2=ffffffff55667788,cc=0")
T("csst_fc0_unequal", "csst 0(%r4),64(%r4),%r2",
  f"r0=200,r1={DATA + 0x100:x},r2=ffffffff00000001,r4={DATA:x},m4:{DATA:x}=55667788,"
  f"m4:{DATA + 0x100:x}=11223344",
  f"m4:{DATA:x}=55667788,r2=ffffffff55667788,cc=1")
T("stmh", "stmh %r1,%r2,0(%r3)", f"r1=1111111122222222,r2=3333333344444444,r3={DATA:x}",
  f"m8:{DATA:x}=1111111133333333")
# UNPK 12 3C -> F0 F1 F2 C3 (the leftmost source byte supplies digits 1 and 2)
T("unpk", "unpk 0(4,%r2),0(2,%r3)", f"r2={DATA:x},r3={DATA + 0x20:x},m2:{DATA + 0x20:x}=123c",
  f"m4:{DATA:x}=f0f1f2c3")
# PKA "123" -> 16-byte packed +123
T("pka", "pka 0(%r2),0(3,%r3)", f"r2={DATA:x},r3={DATA + 0x20:x},m3:{DATA + 0x20:x}=313233",
  f"m8:{DATA:x}=0,m8:{DATA + 8:x}=123c")
# MVCLE: "ABC" into 6 bytes padded with 0x40; cc 2 (first operand longer)
T("mvcle", "mvcle %r2,%r4,0x40",
  f"r2={DATA:x},r3=6,r4={DATA + 0x20:x},r5=3,m3:{DATA + 0x20:x}=c1c2c3",
  f"m4:{DATA:x}=c1c2c340,m2:{DATA + 4:x}=4040,r2={DATA + 6:x},r3=0,r4={DATA + 0x23:x},r5=0,cc=2")
# CU12: UTF-8 C3 A9 41 ("\u00e9A") -> UTF-16 00E9 0041, source exhausted: cc 0
T("cu12", "cu12 %r2,%r4",
  f"r2={DATA:x},r3=10,r4={DATA + 0x20:x},r5=3,m3:{DATA + 0x20:x}=c3a941",
  f"m4:{DATA:x}=00e90041,r2={DATA + 4:x},r3=c,r4={DATA + 0x23:x},r5=0,cc=0")
# CKSM: 00010002 + 0003 padded to 00030000 = 00040002
T("cksm", "cksm %r1,%r2", f"r2={DATA:x},r3=6,m6:{DATA:x}=000100020003",
  f"r1=40002,r2={DATA + 6:x},r3=0,cc=0")
# packed decimal arithmetic (qemu-s390x does not implement it; test/model_diff.py checks
# random operands against reference models)
T("ap", "ap 0(4,%r2),0(2,%r3)", f"r2={DATA:x},r3={DATA + 0x20:x},m4:{DATA:x}=0000123c,m2:{DATA + 0x20:x}=456c",
  f"m4:{DATA:x}=0000579c,cc=2")
T("sp_negative", "sp 0(4,%r2),0(2,%r3)", f"r2={DATA:x},r3={DATA + 0x20:x},m4:{DATA:x}=0000123c,m2:{DATA + 0x20:x}=456c",
  f"m4:{DATA:x}=0000333d,cc=1")
T("mp", "mp 0(4,%r2),0(2,%r3)", f"r2={DATA:x},r3={DATA + 0x20:x},m4:{DATA:x}=0000012c,m2:{DATA + 0x20:x}=012d",
  f"m4:{DATA:x}=0000144d")
# 100 / 7 = 14 remainder 2: quotient in the left 2 bytes, remainder in the right 2
T("dp", "dp 0(4,%r2),0(2,%r3)", f"r2={DATA:x},r3={DATA + 0x20:x},m4:{DATA:x}=0000100c,m2:{DATA + 0x20:x}=007c",
  f"m4:{DATA:x}=014c002c")
T("srp_left", "srp 0(4,%r2),2,0", f"r2={DATA:x},m4:{DATA:x}=0000123c", f"m4:{DATA:x}=0012300c,cc=2")
# right by 2 (shift amount 62 = -2) rounding with 5: 12345 -> 123
T("srp_right_round", "srp 0(4,%r2),62,5", f"r2={DATA:x},m4:{DATA:x}=0012345c", f"m4:{DATA:x}=0000123c,cc=2")
# EDIT: pattern " dd,d(d d.dd" on +12345 -> "    123.45" (fill blank), cc 2
T("ed", "ed 0(10,%r2),0(%r3)",
  f"r2={DATA:x},r3={DATA + 0x20:x},m8:{DATA:x}=4020206b2021204b,m2:{DATA + 8:x}=2020,m4:{DATA + 0x20:x}=0012345c",
  f"m8:{DATA:x}=40404040f1f2f34b,m2:{DATA + 8:x}=f4f5,cc=2")
# EDMK on -12 with a CR suffix: significance from the starter position's nonzero digit,
# minus sign keeps it on (CR kept); GR1 = address of the first significant digit; cc 1
T("edmk_minus", "edmk 0(6,%r2),0(%r3)",
  f"r1=0,r2={DATA:x},r3={DATA + 0x20:x},m6:{DATA:x}=40202120c3d9,m2:{DATA + 0x20:x}=012d",
  f"m6:{DATA:x}=4040f1f2c3d9,r1={DATA + 2:x},cc=1")
# zero field: fill '*' until the starter, then 0; cc 0; EDMK leaves GR1 unchanged
T("edmk_zero", "edmk 0(4,%r2),0(%r3)",
  f"r1=77,r2={DATA:x},r3={DATA + 0x20:x},m4:{DATA:x}=5c202120,m2:{DATA + 0x20:x}=000c",
  f"m4:{DATA:x}=5c5c5cf0,r1=77,cc=0")
T("cdsg_equal", "cdsg %r2,%r4,0(%r6)",
  f"r2=1,r3=2,r4=3,r5=4,r6={DATA:x},m8:{DATA:x}=1,m8:{DATA + 8:x}=2",
  f"m8:{DATA:x}=3,m8:{DATA + 8:x}=4,r2=1,r3=2,cc=0")
# TROT stops at a 2-byte function character equal to GR0 bits 48-63 (qemu 10.2 compares 56-63)
T("trot_test_char", "trot %r2,%r4,0",
  f"r0=5678,r1={DATA + 0x100:x},r2={DATA + 0x200:x},r3=2,r4={DATA:x},m2:{DATA:x}=0102,"
  f"m2:{DATA + 0x102:x}=1234,m2:{DATA + 0x104:x}=5678",
  f"m2:{DATA + 0x200:x}=1234,r2={DATA + 0x202:x},r3=1,r4={DATA + 1:x},cc=1")
T("srst_found", "srst %r1,%r2", f"r0=2e,r1={DATA + 0x10:x},r2={DATA:x},m4:{DATA:x}=61622e63",
  f"r1={DATA + 2:x},r2={DATA:x},cc=1")

# ---- floating point and vector --------------------------------------------------------------
# hexadecimal floating point (1.0 = 41100000..., 2.0 = 41200000...)
T("hfp_adr", "adr %f0,%f2", "f0=4110000000000000,f2=4120000000000000", "f0=4130000000000000,cc=2")
T("hfp_sdr_cancel", "sdr %f0,%f2", "f0=4110000000000000,f2=4110000000000000", "f0=0,cc=0")
T("hfp_mdr", "mdr %f0,%f2", "f0=4120000000000000,f2=4130000000000000", "f0=4160000000000000")
T("hfp_ddr", "ddr %f0,%f2", "f0=4110000000000000,f2=4120000000000000", "f0=4080000000000000")
T("hfp_her", "her %f0,%f2", "f2=4110000000000000", "f0=4080000000000000")
T("hfp_cdfr", "cdfr %f0,%r1", "r1=ffffffff", "f0=c110000000000000")
T("hfp_cfdr_trunc", "cfdr %r1,5,%f0", "f0=4128000000000000", "r1=2,cc=2")
T("hfp_sqdr", "sqdr %f0,%f2", "f2=4140000000000000", "f0=4120000000000000")
T("hfp_cdr_low", "cdr %f0,%f2", "f0=4110000000000000,f2=4120000000000000", "cc=1")
T("adbr", "adbr %f0,%f2", "f0=3ff8000000000000,f2=4002000000000000", "f0=400e000000000000,cc=2")
T("cdgbr", "cdgbr %f0,%r1", "r1=fffffffffffffffe", "f0=c000000000000000")
T("vag", "vag %v1,%v2,%v3",
  "v2=000000000000000100000000000000ff,v3=ffffffffffffffff0000000000000001",
  "v1=00000000000000000000000000000100")
# find-element-equal on bytes: first equal pair is at byte 5
T("vfeeb", "vfeeb %v1,%v2,%v3",
  "v2=000102030405060708090a0b0c0d0e0f,v3=ffffffffff05060708090a0b0c0d0e0f",
  "v1=00000000000000050000000000000000")
# string range compare: bytes in 'a'..'z' (control: >= then <=), result index of first match
T("vstrcb", "vstrcb %v1,%v2,%v3,%v4,0",
  "v2=41424344616263640000000000000000,v3=617a0000000000000000000000000000,"
  "v4=a0c00000000000000000000000000000",
  "v1=00000000000000040000000000000000")

# ---- z17 general instructions, PLO, TRTE, CUSE, CFC, UPT (qemu-s390x lacks them) -----------
# LOAD INDEXED ADDRESS: B2 + (ext32(X2 bits 32-63 + DX2) << k)
T("lxaf", "lxaf %r1,4(%r2,%r3)", f"r2=12345678fffffffe,r3={DATA:x}", f"r1={DATA + 8:x}")
T("llxah", "llxah %r1,0(%r2,%r3)", "r2=ffffffff,r3=10", "r1=20000000e")
T("lxab_base_only", "lxab %r1,-1(%r2)", "r2=100", "r1=ff")
# COMPARE AND LOAD: equal -> R3 = second operand, cc 0; unequal -> R3 = first operand, cc 1
T("cal_eq", "cal %r1,0(%r2),8(%r2)", f"r1=aaaaaaaa00000005,r2={DATA:x},m4:{DATA:x}=5,m4:{DATA + 8:x}=abc",
  "r1=aaaaaaaa00000abc,cc=0")
T("cal_ne", "cal %r1,0(%r2),8(%r2)", f"r1=aaaaaaaa00000006,r2={DATA:x},m4:{DATA:x}=5", "r1=aaaaaaaa00000005,cc=1")
T("calgf_ne", "calgf %r1,0(%r2),8(%r2)", f"r1=ffffffffffffffff,r2={DATA:x},m4:{DATA:x}=7", "r1=7,cc=1")
T("calg_eq", "calg %r1,0(%r2),8(%r2)", f"r1=1122,r2={DATA:x},m8:{DATA:x}=1122,m8:{DATA + 8:x}=ffff",
  "r1=ffff,cc=0")
# BIT DEPOSIT / EXTRACT, mask bits 56-59, bits counted from the left
T("bdepg", "bdepg %r1,%r2,%r3", "r2=a000000000000000,r3=f0", "r1=a0")
T("bextg", "bextg %r1,%r2,%r3", "r2=a0,r3=f0", "r1=a000000000000000")
# TRTE M3=0: table at GR1; arguments 01 02 03, fc(03) = 55 stops at the third byte
T("trte", "trte %r2,%r4,0",
  f"r1={DATA:x},r2={DATA + 0x100:x},r3=3,m1:{DATA + 3:x}=55,m4:{DATA + 0x100:x}=01020304",
  f"r2={DATA + 0x102:x},r3=1,r4=55,cc=1")
# A and F: 2-byte arguments and function codes; fc(0002) at table + 4
T("trte_af", "trte %r2,%r4,12",
  f"r1={DATA:x},r2={DATA + 0x100:x},r3=4,m2:{DATA + 4:x}=1234,m4:{DATA + 0x100:x}=00010002",
  f"r2={DATA + 0x102:x},r3=2,r4=1234,cc=1")
T("trtre", "trtre %r2,%r4,0",
  f"r1={DATA:x},r2={DATA + 0x102:x},r3=3,m1:{DATA + 3:x}=55,m4:{DATA + 0x100:x}=03010200",
  f"r2={DATA + 0x100:x},r3=1,r4=55,cc=1")
# CUSE: substring length 2 found at offset 2 of both operands
T("cuse_found", "cuse %r2,%r4",
  f"r0=2,r1=40,r2={DATA:x},r3=4,r4={DATA + 0x10:x},r5=4,m4:{DATA:x}=abcd1122,m4:{DATA + 0x10:x}=abee1122",
  f"r2={DATA + 2:x},r3=2,r4={DATA + 0x12:x},r5=2,cc=0")
T("cuse_not_found", "cuse %r2,%r4",
  f"r0=1,r1=40,r2={DATA:x},r3=2,r4={DATA + 0x10:x},r5=2,m2:{DATA:x}=0102,m2:{DATA + 0x10:x}=0304",
  f"r2={DATA + 2:x},r3=0,r4={DATA + 0x12:x},r5=0,cc=2")
# CFC: 6-byte units; op1 000000000001 < op3 000000000002, ascending: cc 1, codeword ~op3
T("cfc_low", "cfc 12", f"r1={DATA:x},r2=0,r3={DATA + 0x20:x},m2:{DATA + 4:x}=0001,m2:{DATA + 0x24:x}=0002",
  "r2=6fffffffffffd,cc=1")
T("cfc_equal", "cfc 12", f"r1={DATA:x},r2=0,r3={DATA + 0x40:x}", f"r2={0x8000000000000000 | DATA + 0x40:x},cc=0")
# UPT: one node (codeword 5) above GR0 (3): swapped, then the tree start: cc 1
T("upt", "upt", f"r0=3,r1=33,r4={DATA:x},r5=20,m8:{DATA + 0x10:x}=5,m8:{DATA + 0x18:x}=55",
  f"r0=5,r1=55,r5=0,cc=1,m8:{DATA + 0x10:x}=3,m8:{DATA + 0x18:x}=33")
# PERFORM LOCKED OPERATION
T("plo_cl", "plo %r2,0(%r4),%r6,8(%r4)", f"r0=0,r2=7,r4={DATA:x},r6=ffffffff00000000,m4:{DATA:x}=7,m4:{DATA + 8:x}=99",
  "r6=ffffffff00000099,cc=0")
T("plo_cs", "plo %r2,0(%r4),%r6,8(%r4)", f"r0=4,r2=7,r3=abc,r4={DATA:x},m4:{DATA:x}=7", f"m4:{DATA:x}=abc,cc=0")
T("plo_cs_ne", "plo %r2,0(%r4),%r6,8(%r4)", f"r0=4,r2=8,r4={DATA:x},m4:{DATA:x}=7", "r2=7,cc=1")
T("plo_dcs", "plo %r2,0(%r4),%r6,8(%r4)",
  f"r0=8,r2=7,r3=77,r4={DATA:x},r6=9,r7=99,m4:{DATA:x}=7,m4:{DATA + 8:x}=9", f"m4:{DATA:x}=77,m4:{DATA + 8:x}=99,cc=0")
T("plo_csg_pl", "plo %r2,0(%r4),%r6,256(%r4)",
  f"r0=5,r4={DATA:x},m8:{DATA:x}=1111,m8:{DATA + 0x108:x}=1111,m8:{DATA + 0x118:x}=2222", f"m8:{DATA:x}=2222,cc=0")
T("plo_csstg", "plo %r2,0(%r4),%r6,256(%r4)",
  f"r0=d,r4={DATA:x},m8:{DATA:x}=1,m8:{DATA + 0x108:x}=1,m8:{DATA + 0x118:x}=5,m8:{DATA + 0x138:x}=77,"
  f"m8:{DATA + 0x148:x}={DATA + 0x80:x}", f"m8:{DATA:x}=5,m8:{DATA + 0x80:x}=77,cc=0")
T("plo_test", "plo %r2,0(%r4),%r6,8(%r4)", f"r0=118,r4={DATA:x}", "cc=3")
T("ntstg", "ntstg %r1,0(%r2)", f"r1=1122334455667788,r2={DATA:x}", f"m8:{DATA:x}=1122334455667788")
T("mvcos", "mvcos 0(%r2),16(%r2),%r3", f"r2={DATA:x},r3=4,m4:{DATA + 0x10:x}=cafef00d", f"m4:{DATA:x}=cafef00d,cc=0")
T("mvck", "mvck 0(%r1,%r2),16(%r2),%r3", f"r1=4,r2={DATA:x},m4:{DATA + 0x10:x}=cafef00d", f"m4:{DATA:x}=cafef00d,cc=0")
T("mvcsk", "mvcsk 0(%r2),16(%r2)", f"r0=1,r2={DATA:x},m4:{DATA + 0x10:x}=cafef00d", f"m4:{DATA:x}=cafe0000")
T("tam", "sam31\ntam", "", "cc=1")
T("sacf_home", "sacf 0x300", "pswm=0", "pswm=c00000000000")
# PERFORM FLOATING-POINT OPERATION: GR0 = 01 (type) | first-operand format | second-operand
# format | flags/rounding; formats 0-2 HFP, 5-7 BFP, 8-a DFP (short, long, extended)
T("pfpo_dfp_to_bfp", "pfpo", "r0=1060900,r1=ffffffffffffffff,f4=2234000000000015",
  "f0=3ff8000000000000,cc=0,r1=ffffffff00000000")
T("pfpo_bfp_to_dfp_exact", "pfpo", "r0=1090500,f4=3f00000000000000", "f0=2234000000000005,cc=0")
# exact 1000: DPQC = 0 selects the largest quantum (1q3), DPQC = 1 the quantum 1 (1000q0)
T("pfpo_dpqc0", "pfpo", "r0=1090500,f4=447a000000000000", "f0=2244000000000001,cc=0")
T("pfpo_dpqc1", "pfpo", "r0=1090510,f4=447a000000000000", "f0=2238000000000400,cc=0")
# 0.1 (BFP long) is not exact in 7 decimal digits: 0.1000000, inexact: cc 1
T("pfpo_inexact", "pfpo", "r0=1080600,f4=3fb999999999999a", "f0=25e0000000000000,cc=1")
# the test bit: valid function cc 0 (return code stored), invalid cc 3
T("pfpo_test_valid", "pfpo", "r0=81060900,r1=1111111122222222,f0=5", "cc=0,r1=1111111100000000,f0=5")
T("pfpo_test_invalid", "pfpo", "r0=81050500", "cc=3")
# BFP infinity to HFP: invalid operation, the largest HFP number (cc 1)
T("pfpo_inf_to_hfp", "pfpo", "r0=1010600,f4=7ff0000000000000", "f0=7fffffffffffffff,cc=1")
T("pfpo_dfp_to_hfp", "pfpo", "r0=1000900,f4=2238000000000001", "f0=4110000000000000,cc=0")
# ---- decimal floating point and vector packed decimal --------------------------------------
# long DFP 1, 2, 3: biased exponent 398 (combination 01000, continuation 8e), coefficient declet
T("adtr", "adtr %f0,%f2,%f4", "f2=2238000000000001,f4=2238000000000002", "f0=2238000000000003,cc=2")
# +123 - 877 = -754
T("vap", "vap %v1,%v2,%v3,31,1", "v2=0000000000000000000000000000123c,v3=0000000000000000000000000000877d",
  "v1=0000000000000000000000000000754d,cc=1")

# ---- message-security-assist: expected values from hashlib -------------------------------------
import hashlib, struct as _st
def _sha(alg, msg, mbl_len, iv_words, wsz):
    return alg(msg).digest()
_IV256 = bytes.fromhex("6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19")
_IV1 = bytes.fromhex("67452301efcdab8998badcfe10325476c3d2e1f0")
_IV512 = bytes.fromhex("6a09e667f3bcc908bb67ae8584caa73b3c6ef372fe94f82ba54ff53a5f1d36f1510e527fade682d19b05688c2b3e6c1f1f83d9abfb41bd6b5be0cd19137e2179")
for _nm, _fc, _alg, _iv, _mbl in (("sha1", 1, hashlib.sha1, _IV1, 8), ("sha256", 2, hashlib.sha256, _IV256, 8), ("sha512", 3, hashlib.sha512, _IV512, 16)):
    _msg = b"abc"
    _blk = _alg(b"").block_size
    _p = DATA
    _m = DATA + 0x80
    T(f"klmd_{_nm}", "klmd %r0,%r4",
      f"r0={_fc:x},r1={_p:x},r4={_m:x},r5=3,m{len(_iv) + _mbl}:{_p:x}={(_iv + (24).to_bytes(_mbl, 'big')).hex()},m3:{_m:x}={_msg.hex()}",
      f"m{len(_iv)}:{_p:x}={_alg(_msg).hexdigest()},r4={_m + 3:x},r5=0,cc=0")
    # two blocks: KIMD of the first block, KLMD of the rest
    _msg2 = bytes(range(1, 101))
    _first, _rest = _msg2[:_blk], _msg2[_blk:]
    _h = _alg()
    _h.update(_first)
    # chaining value after the first block, from hashlib's internal state is not exposed: use
    # the whole message through KLMD instead
    T(f"klmd_{_nm}_long", "klmd %r0,%r4",
      f"r0={_fc:x},r1={_p:x},r4={_m:x},r5={len(_msg2):x},m{len(_iv) + _mbl}:{_p:x}={(_iv + (8 * len(_msg2)).to_bytes(_mbl, 'big')).hex()},m{len(_msg2)}:{_m:x}={_msg2.hex()}",
      f"m{len(_iv)}:{_p:x}={_alg(_msg2).hexdigest()},r4={_m + len(_msg2):x},r5=0,cc=0")
T("kimd_query", "kimd %r0,%r4", f"r0=0,r1={DATA:x}", f"m16:{DATA:x}=f0000000fc0000004000000000000000")

import struct, cpacf_model as CM
from cryptography.hazmat.primitives.ciphers import algorithms
_P, _M, _O = DATA, DATA + 0x100, DATA + 0x400
# KIMD intermediate chaining values (checked against the model's compression functions)
_blk = bytes(range(64))
_cv = struct.pack(">8I", *CM.sha256_compress(list(struct.unpack(">8I", _IV256)), _blk))
T("kimd_sha256", "kimd %r0,%r4", f"r0=2,r1={_P:x},r4={_M:x},r5=40,m32:{_P:x}={_IV256.hex()},m64:{_M:x}={_blk.hex()}",
  f"m32:{_P:x}={_cv.hex()},r4={_M + 64:x},r5=0,cc=0")
_blk5 = bytes(range(128))
_cv5 = struct.pack(">8Q", *CM.sha512_compress(list(struct.unpack(">8Q", _IV512)), _blk5))
T("kimd_sha512", "kimd %r0,%r4", f"r0=3,r1={_P:x},r4={_M:x},r5=80,m64:{_P:x}={_IV512.hex()},m128:{_M:x}={_blk5.hex()}",
  f"m64:{_P:x}={_cv5.hex()},r4={_M + 128:x},r5=0,cc=0")
_cv1 = struct.pack(">5I", *CM.sha1_compress(list(struct.unpack(">5I", _IV1)), _blk))
T("kimd_sha1", "kimd %r0,%r4", f"r0=1,r1={_P:x},r4={_M:x},r5=40,m20:{_P:x}={_IV1.hex()},m64:{_M:x}={_blk.hex()}",
  f"m20:{_P:x}={_cv1.hex()},r4={_M + 64:x},r5=0,cc=0")
# SHA-3: the sponge with the leftmost "rate" bytes of the state; KLMD pads and digests
for _nm, _fc, _alg, _rate in (("sha3_224", 32, hashlib.sha3_224, 144), ("sha3_256", 33, hashlib.sha3_256, 136),
                              ("sha3_384", 34, hashlib.sha3_384, 104), ("sha3_512", 35, hashlib.sha3_512, 72)):
    for _msg in (b"abc", bytes(range(250))):
        T(f"klmd_{_nm}_{len(_msg)}", "klmd %r0,%r4", f"r0={_fc:x},r1={_P:x},r4={_M:x},r5={len(_msg):x},m200:{_P:x}={'00' * 200},m{len(_msg)}:{_M:x}={_msg.hex()}",
          f"m{_alg().digest_size}:{_P:x}={_alg(_msg).hexdigest()},r4={_M + len(_msg):x},r5=0,cc=0")
    _blk3 = bytes(range(_rate))
    T(f"kimd_{_nm}_nip", "kimd %r0,%r4", f"r0={_fc | 0x8000:x},r1={_P:x},r4={_M:x},r5={_rate:x},m200:{_P:x}={'ff' * 200},m{_rate}:{_M:x}={_blk3.hex()}",
      f"m200:{_P:x}={CM.keccak_absorb(bytes(200), _blk3).hex()},r0={_fc:x},r5=0,cc=0")
# SHAKE: padding state in GR0 bit 55, extended output into the first operand
for _nm, _fc, _alg in (("shake128", 36, hashlib.shake_128), ("shake256", 37, hashlib.shake_256)):
    for _msg, _n in ((b"abc", 50), (bytes(range(200)), 400)):
        T(f"klmd_{_nm}_{len(_msg)}_{_n}", "klmd %r2,%r4",
          f"r0={_fc:x},r1={_P:x},r2={_O:x},r3={_n:x},r4={_M:x},r5={len(_msg):x},m200:{_P:x}={'00' * 200},m{len(_msg)}:{_M:x}={_msg.hex()}",
          f"m{_n}:{_O:x}={_alg(_msg).hexdigest(_n)},r2={_O + _n:x},r3=0,r4={_M + len(_msg):x},r5=0,r0={_fc | 0x100:x},cc=0")
# GHASH (KIMD 65): Y = ((Y ^ X0) * H ^ X1) * H
_Y, _H = bytes(range(16)), bytes(range(100, 116))
_X = bytes(range(200, 232))
_y = int.from_bytes(_Y, "big")
for _k in range(2):
    _y = CM.ghash_mul(_y ^ int.from_bytes(_X[16 * _k:16 * _k + 16], "big"), int.from_bytes(_H, "big"))
T("kimd_ghash", "kimd %r0,%r4", f"r0=41,r1={_P:x},r4={_M:x},r5=20,m32:{_P:x}={(_Y + _H).hex()},m32:{_M:x}={_X.hex()}",
  f"m16:{_P:x}={_y.to_bytes(16, 'big').hex()},m16:{_P + 16:x}={_H.hex()},r5=0,cc=0")


# ---- ciphers: KM / KMC / KMF / KMO / KMCTR with DEA, TDEA and AES (cryptography is the oracle) -------
_CF = {"dea": (1, 8), "tdea128": (2, 16), "tdea192": (3, 24), "aes128": (18, 16), "aes192": (19, 24), "aes256": (20, 32)}
_IN, _OUT, _CTR = DATA + 0x100, DATA + 0x300, DATA + 0x500
def _cipher_tests():
    for nm, (fc, kl) in _CF.items():
        alg = "aes" if nm.startswith("aes") else nm
        key = bytes((7 * i + fc) & 0xff for i in range(kl))
        bs = 16 if alg == "aes" else 8
        iv = bytes((11 * i + 3) & 0xff for i in range(bs))
        data = bytes((5 * i + 1) & 0xff for i in range(4 * bs))
        n = len(data)
        for dec in (0, 1):
            m = 0x80 if dec else 0
            r0 = f"r0={fc | m:x}"
            regs = f"{r0},r1={DATA:x},r2={_OUT:x},r4={_IN:x},r5={n:x}"
            end = f"r2={_OUT + n:x},r4={_IN + n:x},r5=0,cc=0"
            out, _ = CM.mode_ecb(alg, key, data, dec)
            T(f"km_{nm}_{'dec' if dec else 'enc'}", "km %r2,%r4", f"{regs},m{kl}:{DATA:x}={key.hex()},m{n}:{_IN:x}={data.hex()}",
              f"m{n}:{_OUT:x}={out.hex()},{end}")
            out, cv = CM.mode_cbc(alg, key, iv, data, dec)
            T(f"kmc_{nm}_{'dec' if dec else 'enc'}", "kmc %r2,%r4", f"{regs},m{bs + kl}:{DATA:x}={(iv + key).hex()},m{n}:{_IN:x}={data.hex()}",
              f"m{n}:{_OUT:x}={out.hex()},m{bs}:{DATA:x}={cv.hex()},{end}")
            for s in sorted({1, bs // 2, bs}):
                out, cv = CM.mode_cfb(alg, key, iv, data, dec, s)
                T(f"kmf_{nm}_{'dec' if dec else 'enc'}_s{s}", "kmf %r2,%r4",
                  f"r0={fc | m | (s << 24):x},r1={DATA:x},r2={_OUT:x},r4={_IN:x},r5={n:x},m{bs + kl}:{DATA:x}={(iv + key).hex()},m{n}:{_IN:x}={data.hex()}",
                  f"m{n}:{_OUT:x}={out.hex()},m{bs}:{DATA:x}={cv.hex()},{end}")
        out, cv = CM.mode_ofb(alg, key, iv, data)
        T(f"kmo_{nm}", "kmo %r2,%r4", f"r0={fc:x},r1={DATA:x},r2={_OUT:x},r4={_IN:x},r5={n:x},m{bs + kl}:{DATA:x}={(iv + key).hex()},m{n}:{_IN:x}={data.hex()}",
          f"m{n}:{_OUT:x}={out.hex()},m{bs}:{DATA:x}={cv.hex()},r2={_OUT + n:x},r4={_IN + n:x},r5=0,cc=0")
        ctrs = b"".join(((0x0123456789abcdef0011223344556677 + i) & ((1 << (8 * bs)) - 1)).to_bytes(bs, "big") for i in range(4))
        out, _ = CM.mode_ctr(alg, key, ctrs, data)
        T(f"kmctr_{nm}", "kmctr %r2,%r6,%r4", f"r0={fc:x},r1={DATA:x},r2={_OUT:x},r4={_IN:x},r5={n:x},r6={_CTR:x},m{kl}:{DATA:x}={key.hex()},m{n}:{_IN:x}={data.hex()},m{n}:{_CTR:x}={ctrs.hex()}",
          f"m{n}:{_OUT:x}={out.hex()},r2={_OUT + n:x},r4={_IN + n:x},r5=0,r6={_CTR + n:x},cc=0")
_cipher_tests()
T("km_query", "km %r2,%r4", f"r0=0,r1={DATA:x}", f"m16:{DATA:x}=f0003800000028000000280000000000")

# ---- KMAC (CBC-MAC of full blocks) and PCC (CMAC of the last block), checked against CMAC ----------
from cryptography.hazmat.primitives import cmac as _cmac
def _mac_tests():
    for nm, (fc, kl) in _CF.items():
        alg = "aes" if nm.startswith("aes") else nm
        key = bytes((13 * i + fc) & 0xff for i in range(kl))
        bs = 16 if alg == "aes" else 8
        data = bytes((3 * i + 7) & 0xff for i in range(3 * bs))
        zero = bytes(bs)
        out, cv = CM.mode_cbc(alg, key, zero, data, 0)
        T(f"kmac_{nm}", "kmac %r0,%r4", f"r0={fc:x},r1={DATA:x},r4={_IN:x},r5={len(data):x},m{bs + kl}:{DATA:x}={(zero + key).hex()},m{len(data)}:{_IN:x}={data.hex()}",
          f"m{bs}:{DATA:x}={cv.hex()},r4={_IN + len(data):x},r5=0,cc=0")
        # PCC over the last (partial) block after KMAC over two blocks: equals the CMAC of the whole message
        if alg == "aes":
            ca = algorithms.AES(key)
        else:
            ca = CM.TripleDES({"dea": key * 3, "tdea128": key + key[:8], "tdea192": key}[alg])
        for ml in (0, 8, bs * 8 - 8, bs * 8, 5, bs * 8 - 3):
            nb = (ml + 7) // 8
            last = bytes((17 * i + 5) & 0xff for i in range(nb)) + bytes(bs - nb)
            if ml % 8:
                last = last[:nb - 1] + bytes([last[nb - 1] & (0xff << (8 - ml % 8)) & 0xff]) + bytes(bs - nb)
            pre = data[:2 * bs]
            _, cv2 = CM.mode_cbc(alg, key, zero, pre, 0)
            expect = CM.cmac_last(alg, key, cv2, last, ml)
            if ml % 8 == 0 and ml > 0:       # (an empty last block after full blocks is not a CMAC message)
                c = _cmac.CMAC(ca)
                c.update(pre + last[:nb])
                assert c.finalize() == expect, (nm, ml)
            blk = bytes([ml]) + bytes(7) + last + cv2 + key
            T(f"pcc_{nm}_ml{ml}", "pcc", f"r0={fc:x},r1={DATA:x},m{len(blk)}:{DATA:x}={blk.hex()}",
              f"m{bs}:{DATA + 8 + bs:x}={expect.hex()},cc=0")
        T(f"pcc_{nm}_toolong", "pcc", f"r0={fc:x},r1={DATA:x},m1:{DATA:x}={bs * 8 + 1:02x}", "cc=2")
_mac_tests()


def _kma_tests():
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.ciphers import Cipher, modes
    AAD = DATA + 0x700
    for nm, (fc, kl) in (("aes128", (18, 16)), ("aes192", (19, 24)), ("aes256", (20, 32))):
        key = bytes((5 * i + fc) & 0xff for i in range(kl))
        iv = bytes((11 * i + 3) & 0xff for i in range(12))
        hk = Cipher(algorithms.AES(key), modes.ECB()).encryptor().update(bytes(16))
        for na, npt in ((0, 0), (5, 0), (16, 16), (33, 35), (20, 1), (0, 17), (48, 64)):
            aad = bytes((7 * i + 1) & 0xff for i in range(na))
            pt = bytes((13 * i + 9) & 0xff for i in range(npt))
            ct = AESGCM(key).encrypt(iv, pt, aad)
            c, tag = ct[:-16], ct[-16:]
            for dec in (0, 1):
                for hs in (0, 1):
                    src, dst = (c, pt) if dec else (pt, c)
                    blk = bytes(12) + (1).to_bytes(4, "big") + bytes(16) + (hk if hs else bytes(16)) + (na * 8).to_bytes(8, "big") \
                        + (npt * 8).to_bytes(8, "big") + iv + (1).to_bytes(4, "big") + key
                    r0 = fc | 0x200 | 0x100 | (0x80 if dec else 0) | (0x400 if hs else 0)
                    init = f"r0={r0:x},r1={DATA:x},r2={_OUT:x},r4={_IN:x},r5={npt:x},r6={AAD:x},r7={na:x},m{len(blk)}:{DATA:x}={blk.hex()}"
                    if npt:
                        init += f",m{npt}:{_IN:x}={src.hex()}"
                    if na:
                        init += f",m{na}:{AAD:x}={aad.hex()}"
                    # the counter value after the last block is 1 + the number of blocks
                    cvend = 1 + (npt + 15) // 16
                    exp = f"r0={r0 | 0x400:x},r2={_OUT + npt:x},r4={_IN + npt:x},r5=0,r6={AAD + na:x},r7=0,cc=0,m16:{DATA + 16:x}={tag.hex()},m4:{DATA + 12:x}={cvend:08x},m16:{DATA + 32:x}={hk.hex()}"
                    if npt:
                        exp += f",m{npt}:{_OUT:x}={dst.hex()}"
                    T(f"kma_{nm}_a{na}_p{npt}_d{dec}_h{hs}", "kma %r2,%r6,%r4", init, exp)
        # partial processing: AAD < 16 without LAAD -> cc 2 and nothing consumed except full blocks; text < 16 without LPC
        blk = bytes(12) + (1).to_bytes(4, "big") + bytes(16) + hk + bytes(16) + iv + (1).to_bytes(4, "big") + key
        T(f"kma_{nm}_cc2aad", "kma %r2,%r6,%r4", f"r0={fc | 0x400:x},r1={DATA:x},r2={_OUT:x},r4={_IN:x},r5=10,r6={AAD:x},r7=7,m{len(blk)}:{DATA:x}={blk.hex()}",
          f"cc=2,r5=10,r7=7,r2={_OUT:x},r4={_IN:x},r6={AAD:x}")
        aad = bytes(range(32)); pt = bytes(range(50, 83))
        ct = AESGCM(key).encrypt(iv, pt, aad)
        # LAAD but not LPC: the 32 text bytes (two blocks) are processed, one byte remains, cc 2
        T(f"kma_{nm}_cc2text", "kma %r2,%r6,%r4", f"r0={fc | 0x600:x},r1={DATA:x},r2={_OUT:x},r4={_IN:x},r5=21,r6={AAD:x},r7=14,m{len(blk)}:{DATA:x}={blk.hex()},m32:{AAD:x}={aad.hex()},m33:{_IN:x}={pt.hex()}",
          f"cc=2,r5=1,r7=0,r2={_OUT + 32:x},r4={_IN + 32:x},r6={AAD + 20:x},m32:{_OUT:x}={ct[:32].hex()},m4:{DATA + 12:x}=00000003")
_kma_tests()
T("kma_query", "kma %r2,%r6,%r4", f"r0=0,r1={DATA:x}", f"m16:{DATA:x}=" + "%032x" % (sum(1 << (127 - c) for c in (0, 18, 19, 20))))

def _gf_dbl(x):
    x <<= 1
    return (x ^ 0x87) & ((1 << 128) - 1) if x >> 128 else x
def _gf_mul(a, b):
    z = 0
    while b:
        if b & 1:
            z ^= a
        a = _gf_dbl(a)
        b >>= 1
    return z
def _gf_pow2(j):
    r, p = 1, 2
    while j:
        if j & 1:
            r = _gf_mul(r, p)
        p = _gf_mul(p, p)
        j >>= 1
    return r
def _le(b):
    return int.from_bytes(b, "little")
def _leb(x):
    return x.to_bytes(16, "little")
def _xts_tests():
    from cryptography.hazmat.primitives.ciphers import Cipher, modes
    def aes_e(key, blk):
        return Cipher(algorithms.AES(key), modes.ECB()).encryptor().update(blk)
    for nm, fc, fcf, kl in (("128", 50, 82, 16), ("256", 52, 84, 32)):
        k1 = bytes((9 * i + fc) & 0xff for i in range(kl))
        k2 = bytes((17 * i + 3) & 0xff for i in range(kl))
        tw = bytes((23 * i + 5) & 0xff for i in range(16))
        n = 5 * 16
        data = bytes((29 * i + 11) & 0xff for i in range(n))
        for dec in (0, 1):
            ci = Cipher(algorithms.AES(k1 + k2), modes.XTS(tw))
            out = (ci.decryptor() if dec else ci.encryptor()).update(data)
            m = 0x80 if dec else 0
            t0 = aes_e(k2, tw)
            outp = _leb(_gf_mul(_le(t0), _gf_pow2(5)))
            T(f"kmxts_{nm}_d{dec}", "km %r2,%r4", f"r0={fc | m:x},r1={DATA:x},r2={_OUT:x},r4={_IN:x},r5={n:x},m{kl + 16}:{DATA:x}={(k1 + t0).hex()},m{n}:{_IN:x}={data.hex()}",
              f"m{n}:{_OUT:x}={out.hex()},m16:{DATA + kl:x}={outp.hex()},r2={_OUT + n:x},r4={_IN + n:x},r5=0,cc=0")
            # full XTS from a given next alpha power (block 3 onwards)
            for nap_e in (0, 3):
                nap = _leb(1 << 0) if nap_e == 0 else _leb(_gf_pow2(nap_e))
                if nap_e:
                    pre = bytes(16 * nap_e)
                    ci = Cipher(algorithms.AES(k1 + k2), modes.XTS(tw))
                    full = (ci.decryptor() if dec else ci.encryptor()).update(pre + data)
                    out2 = full[16 * nap_e:]
                else:
                    out2 = out
                nap_out = _leb(_gf_mul(_le(nap), _gf_pow2(5)))
                T(f"kmfull_{nm}_d{dec}_nap{nap_e}", "km %r2,%r4", f"r0={fcf | m:x},r1={DATA:x},r2={_OUT:x},r4={_IN:x},r5={n:x},m{2 * kl + 32}:{DATA:x}={(k1 + k2 + tw + nap).hex()},m{n}:{_IN:x}={data.hex()}",
                  f"m{n}:{_OUT:x}={out2.hex()},m16:{DATA + 2 * kl + 16:x}={nap_out.hex()},m16:{DATA + 2 * kl:x}={tw.hex()},r2={_OUT + n:x},r4={_IN + n:x},r5=0,cc=0")
        # PCC-Compute-XTS-Parameter
        e = _le(aes_e(k1, tw))
        for j in (0, 1, 5, 1000003, (1 << 70) + 12345, (1 << 127) + 1):
            exp = _leb(_gf_mul(e, _gf_pow2(j)))
            pb = k1 + tw + j.to_bytes(16, "big") + bytes(16) + bytes(16)
            exp_t = "00000000000000000000000000000000" if j == 0 else "%032x" % 128
            T(f"pcc_xts{nm}_j{j}", "pcc", f"r0={fc:x},r1={DATA:x},m{len(pb)}:{DATA:x}={pb.hex()}",
              f"m16:{DATA + kl + 48:x}={exp.hex()},m16:{DATA + kl + 32:x}={exp_t},cc=0")
        # resumed with a partial value
        for t, jj, part in ((100, 5, 0), (126, 5, 4), (127, 5, 4)):
            pb = k1 + tw + jj.to_bytes(16, "big") + t.to_bytes(16, "big") + _leb(_gf_mul(e, _gf_pow2(part)))
            T(f"pcc_xts{nm}_resume{t}", "pcc", f"r0={fc:x},r1={DATA:x},m{len(pb)}:{DATA:x}={pb.hex()}",
              f"m16:{DATA + kl + 48:x}={_leb(_gf_mul(e, _gf_pow2(jj))).hex()},m16:{DATA + kl + 32:x}={'%032x' % 128},cc=0")
        pb = k1 + tw + (5).to_bytes(16, "big") + (200).to_bytes(16, "big") + bytes(16)
        T(f"pcc_xts{nm}_cc2", "pcc", f"r0={fc:x},r1={DATA:x},m{len(pb)}:{DATA:x}={pb.hex()}", "cc=2")
_xts_tests()

def _hmac_tests():
    import hmac as _hmac
    IV = {112: [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4],
          113: list(struct.unpack(">8I", _IV256)),
          114: [0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939, 0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4],
          115: list(struct.unpack(">8Q", _IV512))}
    V = {112: ("sha224", 64, 28), 113: ("sha256", 64, 32), 114: ("sha384", 128, 48), 115: ("sha512", 128, 64)}
    def comp(fc, st, blk):
        return CM.sha256_compress(st, blk) if fc < 114 else CM.sha512_compress(st, blk)
    def pack(fc, st):
        return struct.pack(">8I" if fc < 114 else ">8Q", *st)
    def pad(fc, msg, total):
        bs = V[fc][1]
        lb = 8 if bs == 64 else 16
        m = msg + b"\x80"
        m += bytes(-(len(m) + lb) % bs) + (total * 8).to_bytes(lb, "big")
        return [m[i:i + bs] for i in range(0, len(m), bs)]
    def hmac_state(fc, key, msg):
        name, bs, dl = V[fc]
        st = list(IV[fc])
        st = comp(fc, st, bytes(b ^ 0x36 for b in key))
        for b in pad(fc, msg, bs + len(msg)):
            st = comp(fc, st, b)
        inner = pack(fc, st)[:dl]
        st = comp(fc, list(IV[fc]), bytes(b ^ 0x5c for b in key))
        for b in pad(fc, inner, bs + dl):
            st = comp(fc, st, b)
        out = pack(fc, st)
        assert out[:dl] == _hmac.new(key, msg, name).digest(), fc
        return out
    for fc, (name, bs, dl) in V.items():
        cvl = 32 if bs == 64 else 64
        il = 8 if bs == 64 else 16
        key = bytes((31 * i + fc) & 0xff for i in range(bs))
        for ln in (0, 5, bs - 1, bs, bs + 3, 2 * bs + 7):
            msg = bytes((7 * i + 3) & 0xff for i in range(ln))
            pb = bytes(cvl) + (ln * 8).to_bytes(il, "big") + key
            r0 = fc
            init = f"r0={r0:x},r1={DATA:x},r4={_IN:x},r5={ln:x},m{len(pb)}:{DATA:x}={pb.hex()}"
            if ln:
                init += f",m{ln}:{_IN:x}={msg.hex()}"
            T(f"hmac_{name}_{ln}", "kmac %r0,%r4", init, f"m{cvl}:{DATA:x}={hmac_state(fc, key, msg).hex()},r0={r0 | 0x8000:x},r4={_IN + ln:x},r5=0,cc=0")
        # intermediate parts: first two blocks with IKP=0 / IIMP=1, then the rest with IKP=1 / IIMP=0
        msg = bytes((11 * i + 1) & 0xff for i in range(3 * bs + 9))
        part1, rest = msg[:2 * bs], msg[2 * bs:]
        st = comp(fc, list(IV[fc]), bytes(b ^ 0x36 for b in key))
        for i in range(0, 2 * bs, bs):
            st = comp(fc, st, part1[i:i + bs])
        pb = bytes(cvl) + (len(msg) * 8).to_bytes(il, "big") + key
        T(f"hmac_{name}_part1", "kmac %r0,%r4", f"r0={fc | 0x4000:x},r1={DATA:x},r4={_IN:x},r5={len(part1):x},m{len(pb)}:{DATA:x}={pb.hex()},m{len(part1)}:{_IN:x}={part1.hex()}",
          f"m{cvl}:{DATA:x}={pack(fc, st).hex()},r0={fc | 0xc000:x},r4={_IN + len(part1):x},r5=0,cc=0")
        pb2 = pack(fc, st) + (len(msg) * 8).to_bytes(il, "big") + key
        T(f"hmac_{name}_part2", "kmac %r0,%r4", f"r0={fc | 0x8000:x},r1={DATA:x},r4={_IN:x},r5={len(rest):x},m{len(pb2)}:{DATA:x}={pb2.hex()},m{len(rest)}:{_IN:x}={rest.hex()}",
          f"m{cvl}:{DATA:x}={hmac_state(fc, key, msg).hex()},r0={fc | 0x8000:x},r4={_IN + len(rest):x},r5=0,cc=0")
_hmac_tests()
T("kmac_query", "kmac %r0,%r4", f"r0=0,r1={DATA:x}", f"m16:{DATA:x}=f0003800000000000000000000000f00".replace("f0003800000000000000000000000f00", "f000380000000000" + "0000000000" + "00f000"))

def _prno_tests():
    sha = lambda b: hashlib.sha512(b).digest()
    M = (1 << 888) - 1
    def hash_df(data):
        return (sha(b"\x01" + (888).to_bytes(4, "big") + data) + sha(b"\x02" + (888).to_bytes(4, "big") + data))[:111]
    def seed(v_old, ctr, inp):
        mat = (b"\x01" + v_old if ctr else b"") + inp
        v = hash_df(mat)
        return v, hash_df(b"\x00" + v)
    def generate(v, c, ctr, n):
        out, x = b"", int.from_bytes(v, "big")
        for _ in range((n + 63) // 64):
            out += sha(x.to_bytes(111, "big"))
            x = (x + 1) & M
        h = int.from_bytes(sha(b"\x03" + v), "big")
        nv = (int.from_bytes(v, "big") + int.from_bytes(c, "big") + h + ctr) & M
        return out[:n], nv.to_bytes(111, "big")
    PB = DATA
    def blk(ctr, strm, v, c):
        return bytes(4) + ctr.to_bytes(4, "big") + strm.to_bytes(8, "big") + b"\x00" + v + b"\x00" + c
    inp = bytes((13 * i + 5) & 0xff for i in range(40))
    v1, c1 = seed(b"", 0, inp)
    T("prno_instantiate", "prno %r2,%r4", f"r0=83,r1={PB:x},r4={_IN:x},r5={len(inp):x},m240:{PB:x}={bytes(240).hex()},m{len(inp)}:{_IN:x}={inp.hex()}",
      f"m240:{PB:x}={blk(1, 0, v1, c1).hex()},cc=0")
    v0 = bytes((7 * i + 1) & 0xff for i in range(111)); c0 = bytes((11 * i + 3) & 0xff for i in range(111))
    for ln in (0, 1, 47, 512):
        inp2 = bytes((17 * i + 9) & 0xff for i in range(ln))
        v2, c2 = seed(v0, 5, inp2)
        init = f"r0=83,r1={PB:x},r4={_IN:x},r5={ln:x},m240:{PB:x}={blk(5, 100, v0, c0).hex()}" + (f",m{ln}:{_IN:x}={inp2.hex()}" if ln else "")
        T(f"prno_reseed_{ln}", "prno %r2,%r4", init, f"m240:{PB:x}={blk(1, 100, v2, c2).hex()},cc=0")
    for n in (0, 1, 63, 64, 65, 130, 200):
        out, nv = generate(v0, c0, 3, n)
        init = f"r0=3,r1={PB:x},r2={_OUT:x},r3={n:x},m240:{PB:x}={blk(3, 7, v0, c0).hex()}"
        exp = f"m240:{PB:x}={blk(4, 7 + n, nv, c0).hex()},r2={_OUT:x},r3=0,cc=0" + (f",m{n}:{_OUT:x}={out.hex()}" if n else "")
        T(f"prno_generate_{n}", "prno %r2,%r4", init, exp)
    # carry through the 888-bit value: V = 2^888 - 2 gives blocks V, V+1, V+2 = 0
    vmax = ((1 << 888) - 2).to_bytes(111, "big")
    out, nv = generate(vmax, c0, 1, 192)
    T("prno_generate_wrap", "prno %r2,%r4", f"r0=3,r1={PB:x},r2={_OUT:x},r3=c0,m240:{PB:x}={blk(1, 0, vmax, c0).hex()}",
      f"m240:{PB:x}={blk(2, 192, nv, c0).hex()},m192:{_OUT:x}={out.hex()},r3=0,cc=0")
    T("prno_query", "prno %r2,%r4", f"r0=0,r1={DATA:x}", f"m16:{DATA:x}=9000000000000000000000000000a000")
_prno_tests()
T("prno_trng_ratio", "prno %r2,%r4", f"r0=70,r1={DATA:x}", f"m8:{DATA:x}=0000000100000001,cc=0")
T("prno_trng_empty", "prno %r2,%r4", f"r0=72,r1={DATA:x},r2={_OUT:x},r3=0,r4={_IN:x},r5=0", f"r2={_OUT:x},r3=0,r4={_IN:x},r5=0,cc=0")

def _sortl_tests():
    import random, sortl_model as SM
    PB, LB, O1, O2, CR = DATA, DATA + 0x1000, DATA + 0x6000, DATA + 0x7800, DATA + 0x9000
    def build(nis, keylen, paylen, asc, cf, ail, eil, lists, csb=None):
        pb = bytearray(576 + 16 * nis)
        pb[0] = {32: 0x20, 64: 0x10, 128: 0x08}[nis]
        pb[10:12] = keylen.to_bytes(2, "big"); pb[14:16] = paylen.to_bytes(2, "big")
        pb[7] = (0 if asc else 0x80) | cf
        pb[33] = ail; pb[40] = eil << 6
        pb[56:64] = CR.to_bytes(8, "big")
        if csb:
            pb[64] = csb["open"]; pb[65] = csb["fn"]
            pb[72:80] = (O1 + csb["start"]).to_bytes(8, "big"); pb[80:88] = csb["len"].to_bytes(8, "big")
        addrs = []
        for i, d in enumerate(lists):
            a = LB + 0x400 * i
            addrs.append(a)
            pb[576 + 16 * i: 584 + 16 * i] = a.to_bytes(8, "big")
            pb[584 + 16 * i: 592 + 16 * i] = len(d).to_bytes(8, "big")
        return bytes(pb), addrs
    def case(name, lists, keylen=8, paylen=0, asc=True, mm=0, svlr=False, eil=0, op1=0x1000, op2=0x400, nis=32, cf=0, state=None, prev=None, off=0):
        ail = len(lists) - 1
        pb, addrs = build(nis, keylen, paylen, asc, cf, ail, eil, lists, state)
        r = SM.run(lists, keylen, paylen, asc, mm, svlr, eil, op1, op2, state, prev, off)
        init = f"r0={(2 if svlr else 1) | (0x80 if mm else 0):x},r1={PB:x},r2={O1 + off:x},r3={op1:x},r4={O2:x},r5={op2:x},m{len(pb)}:{PB:x}={pb.hex()}"
        for a, d in zip(addrs, lists):
            if d:
                init += f",m{len(d)}:{a:x}={d.hex()}"
        if prev is not None:
            init += f",m{len(prev)}:{CR:x}={prev.hex()}"
        exp = f"cc={r['cc']},r2={O1 + off + len(r['out']):x},r3={r['op1']:x}"
        if mm == 0:
            exp += f",r4={O2 + 16 * len(r['olds']):x},r5={r['op2']:x}"
        if r["out"]:
            exp += f",m{len(r['out'])}:{O1 + off:x}={r['out'].hex()}"
        if mm == 0 and r["olds"]:
            exp += f",m{16 * len(r['olds'])}:{O2:x}=" + "".join(((O1 + st).to_bytes(8, "big") + ln.to_bytes(8, "big")).hex() for st, ln in r["olds"])
        for i, (a, d) in enumerate(zip(addrs, lists)):
            exp += f",m8:{PB + 576 + 16 * i:x}={(a + r['used'][i]):016x},m8:{PB + 584 + 16 * i:x}={len(d) - r['used'][i]:016x}"
        cf_out = 0 if r["cc"] == 0 else 1
        exp += f",m1:{PB + 7:x}={(0 if asc else 0x80) | cf_out:02x},m1:{PB + 41:x}={r['eiln']:02x},m1:{PB + 47:x}={r['iiln']:02x}"
        exp += f",m1:{PB + 64:x}={int(r['op']):02x},m1:{PB + 65:x}={int(r['fn']):02x}"
        if r["cc"] != 0 and r["placed"] and mm == 0:
            exp += f",m{keylen}:{CR:x}={r['prev'].hex()}"
        T(name, "sortl %r2,%r4", init, exp)
        return r
    recs = lambda vals, kl=8, pay=b"": b"".join(v.to_bytes(kl, "big") + pay for v in vals)
    # the manual's examples (figures 26-108 and 26-109)
    case("sortl_fig108", [recs([5, 1, 17, 3]), recs([10, 8, 2, 14]), recs([99, 6, 88, 20])])
    case("sortl_fig109", [recs([5, 1]), recs([10, 8]), recs([99, 6]), recs([17, 3]), recs([2, 14]), recs([88, 20])])
    case("sortl_desc", [recs([5, 1, 17, 3]), recs([10, 8, 2, 14]), recs([99, 6, 88, 20])], asc=False)
    case("sortl_merge", [recs([1, 5, 9]), recs([2, 5, 6, 40]), recs([3, 5, 7])], mm=1)
    case("sortl_merge_desc_payload", [recs([9, 5, 1], 8, b"AAAAAAAA"), recs([40, 6, 5, 2], 8, b"BBBBBBBB"), recs([7, 5, 3], 8, b"CCCCCCCC")], paylen=8, mm=1, asc=False)
    # equal keys: the list with the higher number comes first
    case("sortl_ties", [recs([4, 4], 8, b"11111111"), recs([4, 4], 8, b"22222222"), recs([4], 8, b"33333333")], paylen=8)
    case("sortl_key16", [recs([3, 1, 2], 16), recs([9, 0], 16)], keylen=16)
    # variable-length records: key, 8-byte payload length, payload
    def vl(vals):
        return b"".join(v.to_bytes(8, "big") + (8 * (v % 3)).to_bytes(8, "big") + bytes([v & 0xff]) * (8 * (v % 3)) for v in vals)
    case("sortl_svlr", [vl([5, 3, 9]), vl([4, 8, 2]), vl([1, 7])], svlr=True)
    case("sortl_svlr_merge", [vl([1, 3, 9]), vl([2, 8, 20])], svlr=True, mm=1)
    # condition codes: a short first operand (1), a short second operand (1), an empty list (2), an incomplete list (2)
    lists = [recs([5, 1, 17, 3]), recs([10, 8, 2, 14]), recs([99, 6, 88, 20])]
    case("sortl_cc1_op1", lists, op1=0x48)
    case("sortl_cc1_op2", lists, op2=0x20)
    case("sortl_cc1_op2_tail", lists, op2=0x30)
    case("sortl_cc2_eil0", lists, eil=2)
    case("sortl_cc2_eilN", lists, eil=1)
    case("sortl_cc2_eil11", lists, eil=3)
    case("sortl_cc2_incomplete", [recs([5, 1, 17]) + b"\x00" * 8, recs([10, 8]) + b"\x01" * 8 + b"\x02" * 3])
    # resume after a short first operand, from the model's own state
    r = SM.run(lists, 8, 0, True, 0, False, 0, 0x48, 0x400)
    rest = [d[u:] for d, u in zip(lists, r["used"])]
    case("sortl_resume", rest, state=dict(open=int(r["op"]), fn=int(r["fn"]), start=r["start"], len=r["len"]), prev=r["prev"], cf=1, off=len(r["out"]))
    # random lists
    rnd = random.Random(1234)
    for i in range(6):
        nl = rnd.choice([2, 5, 9])
        kl = rnd.choice([8, 16])
        pay = rnd.choice([0, 8, 16])
        lst = [b"".join(rnd.randrange(0, 40).to_bytes(kl, "big") + bytes(rnd.randrange(256) for _ in range(pay)) for _ in range(rnd.randrange(0, 7))) for _ in range(nl)]
        case(f"sortl_rand{i}", lst, keylen=kl, paylen=pay, asc=bool(i & 1), mm=0)
_sortl_tests()
T("sortl_query", "sortl %r2,%r4", f"r0=0,r1={DATA:x}", f"m32:{DATA:x}=" + "e0" + "00" * 15 + "38" + "00" * 7 + "8000" + "00" * 6)

def _cmpsc_tests():
    import random, cmpsc_model as CM2
    DICT, SRC, DST = 0x40000, 0x60000, 0x64000
    def bits_to_bytes(bits, cbn, init):
        """overlay bits at bit cbn of the bytes in init (bits to the right in the last byte unchanged)"""
        buf = bytearray(init)
        for i, b in enumerate(bits):
            pos = cbn + i
            mask = 0x80 >> (pos & 7)
            buf[pos >> 3] = (buf[pos >> 3] & ~mask & 0xff) | (mask if b else 0)
        return bytes(buf)
    def hexs(entries):
        return b"".join(entries).hex()
    def ctest(name, comp, exp, data, cdss, f1=0, cbn=0, room=0x100, op=0, st=None, ee=None, offv=None, dictbytes=None):
        w = cdss + 8
        n = len(comp)
        if ee is not None:
            ed, cws = ee
            res = CM2.compress(comp, exp, data, bool(f1), w, None, False, (ed, cws), room, cbn)
        else:
            res = CM2.compress(comp, exp, data, bool(f1), w, st, bool(op), None, room, cbn)
        r0 = (cdss << 12) | (f1 << 9) | (op << 18) | ((1 << 16) if (st is not None and not op) else 0) | ((1 << 19) if ee else 0)
        off = n * 8
        gr1 = DICT | cbn
        if st is not None or ee is not None or op:
            gr1 |= (off >> 7) << 3
        init = f"r0={r0:x},r1={gr1:x},r2={DST:x},r3={room:x},r4={SRC:x},r5={len(data):x},m{n * 8}:{DICT:x}={hexs(comp)}"
        if f1:
            init += f",m{n * 8}:{DICT + n * 8:x}={hexs(exp)}"
        if ee is not None:
            init += f",m32:{DICT + off:x}={b''.join(v.to_bytes(2, 'big') for v in ed).hex()}"
            stt_bytes = b"".join(((cws[i][0] << (16 - cws[i][1])) & 0xffff).to_bytes(2, "big") for i in range(n))
            init += f",m{len(stt_bytes)}:{DICT + off + 32:x}={stt_bytes.hex()}"
        elif st is not None or op:
            stt_bytes = b"".join(v.to_bytes(2, "big") for v in (st + [0] * (n - len(st))))
            init += f",m{len(stt_bytes)}:{DICT + off:x}={stt_bytes.hex()}"
        if data:
            init += f",m{len(data)}:{SRC:x}={data.hex()}"
        pattern = bytes((0xA5 ^ (i * 37)) & 0xff for i in range(room))
        if room:
            init += f",m{room}:{DST:x}={pattern.hex()}"
        nbits = len(res["bits"])
        total = cbn + nbits
        out = bits_to_bytes(res["bits"], cbn, pattern)
        nb = (total + 7) // 8
        gr1_out = (gr1 & ~7) | (total & 7)
        exp_s = f"cc={res['cc']},r1={gr1_out:x},r2={DST + total // 8:x},r3={room - total // 8:x},r4={SRC + res['consumed']:x},r5={len(data) - res['consumed']:x}"
        if nb:
            exp_s += f",m{nb}:{DST:x}={out[:nb].hex()}"
        T(name, "cmpsc %r2,%r4", init, exp_s)
        return res
    def etest(name, exp, bits, cdss, cbn=0, room=0x200, ee=None, ed=None, dictn=None):
        w = cdss + 8
        n = len(exp)
        total = cbn + len(bits)
        nbytes = (total + 7) // 8
        src = bits_to_bytes([1, 0, 1, 1, 0, 1, 0][:cbn] + bits, 0, bytes(nbytes)) if False else None
        # source bytes: cbn pattern bits, the compressed bits, zero padding
        pre = [(0xB5 >> (7 - i)) & 1 for i in range(cbn)]
        allbits = pre + bits + [0] * (nbytes * 8 - total)
        sbytes = bytes(int("".join(map(str, allbits[i:i + 8])), 2) for i in range(0, len(allbits), 8))
        out, used, cc = CM2.expand(exp, bits, w, room, ee, ed)
        r0 = (cdss << 12) | (1 << 8) | ((1 << 19) if ee else 0)
        off = n * 8
        gr1 = DICT | cbn
        if ee:
            gr1 |= (off >> 7) << 3
        init = f"r0={r0:x},r1={gr1:x},r2={DST:x},r3={room:x},r4={SRC:x},r5={nbytes:x},m{n * 8}:{DICT:x}={hexs(exp)}"
        if ee:
            init += f",m32:{DICT + off:x}={b''.join(v.to_bytes(2, 'big') for v in ed).hex()}"
        if nbytes:
            init += f",m{nbytes}:{SRC:x}={sbytes.hex()}"
        pattern = bytes(0x5A for _ in range(room))
        init += f",m{room}:{DST:x}={pattern.hex()}"
        t2 = cbn + used
        gr1_out = (gr1 & ~7) | (t2 & 7)
        exp_s = f"cc={cc},r1={gr1_out:x},r2={DST + len(out):x},r3={room - len(out):x},r4={SRC + t2 // 8:x},r5={nbytes - t2 // 8:x}"
        if out:
            exp_s += f",m{len(out)}:{DST:x}={out.hex()}"
        T(name, "cmpsc %r2,%r4", init, exp_s)
    # the manual's example (programming note 5): three index symbols 103, 3FC, 3FF expand to 14 bytes; CBN 7 -> 5
    ex = [bytes(8)] * 1024
    ex[0x103] = bytes([0x30 | 0, ]) + b"" if False else bytes([0]) + bytes([0x31]) if False else None
    # entry 103: unpreceded, 4 bytes; 3FC: 5 bytes; 3FF: 5 bytes
    ex = [bytes(8)] * 1024
    ex[0x103] = bytes([4]) + b"ABCD" + bytes(3)
    ex[0x3FC] = bytes([5]) + b"EFGHI" + bytes(2)
    ex[0x3FF] = bytes([5]) + b"JKLMN" + bytes(2)
    T("cmpsc_manual_example", "cmpsc %r2,%r4",
      f"r0={(2 << 12) | 0x100:x},r1={DICT | 7:x},r2=5000,r3=40,r4=6000,r5=5,m{8192}:{DICT:x}={hexs(ex)},m5:6000=0081ff9ff8",
      f"cc=0,r1={DICT | 5:x},r2=500e,r3=32,r4=6004,r5=1,m14:5000={(b'ABCD' + b'EFGHI' + b'JKLMN').hex()}")
    rnd = random.Random(99)
    cases = 0
    for seed in range(24):
        rng = random.Random(1000 + seed)
        cdss = rng.choice([1, 2, 3])
        entries = 512 << (cdss - 1)
        f1 = seed & 1
        chars = rng.choice([[65, 66], [65, 66, 67, 68], [65, 66, 67, 68, 69, 70]])
        trie = CM2.random_trie(rng, chars, depth=rng.choice([2, 3]), fan=(0, rng.choice([4, 9, 15])))
        try:
            comp, exp, nodes = CM2.build(trie, fmt1=bool(f1), entries=entries)
        except AssertionError:
            continue
        data = bytes(rng.choice(chars) for _ in range(rng.randrange(1, 40)))
        cbn = rng.randrange(0, 8)
        res = ctest(f"cmpsc_c{seed}", comp, exp, data, cdss, f1, cbn)
        if seed % 3 == 0:
            ctest(f"cmpsc_c{seed}_room", comp, exp, data, cdss, f1, cbn, room=max(1, len(res["bits"]) // 16))
        etest(f"cmpsc_e{seed}", exp, res["bits"], cdss, cbn)
        etest(f"cmpsc_e{seed}_room", exp, res["bits"], cdss, cbn, room=max(1, len(data) // 2))
        cases += 1
        if cases >= 14:
            break
    # symbol translation, order preservation, entropy encoding
    for seed in range(12):
        rng = random.Random(2000 + seed)
        cdss = rng.choice([1, 2, 3])
        entries = 512 << (cdss - 1)
        chars = rng.choice([[65, 66, 67], [65, 66, 67, 68, 69]])
        trie = CM2.random_trie(rng, chars, depth=rng.choice([2, 3]), fan=(0, rng.choice([4, 9, 15])), allow_dup=(seed % 3 == 2))
        mode = ("st", "op", "ee")[seed % 3]
        try:
            comp, exp, nodes = CM2.build(trie, fmt1=False, entries=entries, order_sort=(mode == "op"))
        except AssertionError:
            continue
        data = bytes(rng.choice(chars) for _ in range(rng.randrange(1, 40)))
        cbn = rng.randrange(0, 8)
        if mode == "ee":
            ed = CM2.ee_tables(rng, entries)
            cws = CM2.ee_codewords(ed)
            res = ctest(f"cmpsc_ee{seed}", comp, exp, data, cdss, 0, cbn, ee=(ed, cws[:entries]))
            exp_ee = [bytes([1, c]) + bytes(6) for c in range(256)] + list(exp[256:])
            etest(f"cmpsc_ee{seed}_x", exp_ee, res["bits"], cdss, cbn, ee=True, ed=ed)
            ctest(f"cmpsc_ee{seed}_room", comp, exp, data, cdss, 0, cbn, room=max(1, len(res["bits"]) // 16), ee=(ed, cws[:entries]))
        else:
            w = cdss + 8
            stt = rng.sample(range(1 << w), entries)
            ctest(f"cmpsc_{mode}{seed}", comp, exp, data, cdss, 0, cbn, op=(mode == "op"), st=stt)
    # the manual's "Set 2" dictionary for runs of one character: two children with the same child character
    def setn(d):
        if d == 0:
            return []
        return [CM2.Node([65, 65], setn(d - 1)), CM2.Node([65], [])]
    comp, exp, nodes = CM2.build(CM2.alphabet({65: setn(4)}), entries=512)
    for n in (1, 2, 3, 5, 9, 14, 20, 31):
        res = ctest(f"cmpsc_arun{n}", comp, exp, b"A" * n, 1, 0, n % 8)
        etest(f"cmpsc_arun{n}_x", exp, res["bits"], 1, n % 8)
    # fixed-format-1 sibling descriptors with many children
    kids = [CM2.Node([66 + (i % 20)], [CM2.Node([67])] if i % 3 == 0 else []) for i in range(18)]
    for f1 in (0, 1):
        comp, exp, nodes = CM2.build(CM2.alphabet({65: list(kids)}), fmt1=bool(f1), entries=512)
        data = bytes([65, 66 + 17 % 20, 67, 65, 66 + 14, 65, 66 + 2, 67, 65, 66 + 5])
        res = ctest(f"cmpsc_sd{f1}", comp, exp, data, 1, f1, 2)
        etest(f"cmpsc_sd{f1}_x", exp, res["bits"], 1, 2)
    # empty operands
    comp, exp, nodes = CM2.build(CM2.alphabet({65: [CM2.Node([66])]}), entries=512)
    ctest("cmpsc_empty_src", comp, exp, b"", 1, 0, 3)
    ctest("cmpsc_empty_dst", comp, exp, b"AB", 1, 0, 0, room=0)
_cmpsc_tests()

def _pcc_ecc_tests():
    import random, ecc_model as EM
    from cryptography.hazmat.primitives.asymmetric import x25519, x448
    from cryptography.hazmat.primitives import serialization as _S
    rnd = random.Random(77)
    layout = {64: ("P256", 32, 32, 256), 65: ("P384", 48, 48, 384), 66: ("P521", 66, 80, 521), 72: ("Ed25519", 32, 32, 255), 73: ("Ed448", 56, 64, 448)}
    def blk(fs, nb, xr, yr, xs, ys, d, fill=0x00):
        b = bytearray([fill]) * (5 * fs)
        for i, v in enumerate((xr, yr, xs, ys, d)):
            b[i * fs + fs - nb: (i + 1) * fs] = v.to_bytes(nb, "big")
        return bytes(b)
    for fc, (name, nb, fs, bits) in layout.items():
        c = EM.CURVES[name]
        G0 = (c["gx"], c["gy"])
        n = c["n"]
        def case(label, P, d, expect_cc, junk=0x5a):
            init = blk(fs, nb, 0, 0, P[0], P[1], d, junk)
            if expect_cc == 0:
                R = EM.mul(c, d, P)
                exp = f"cc=0,m{nb}:{DATA + fs - nb:x}={R[0].to_bytes(nb, 'big').hex()},m{nb}:{DATA + 2 * fs - nb:x}={R[1].to_bytes(nb, 'big').hex()}"
            else:
                exp = f"cc={expect_cc},m{nb}:{DATA + fs - nb:x}={bytes([junk]) .hex() * 0 or (init[fs - nb:fs]).hex()}"
            T(f"pcc_sm_{name}_{label}", "pcc", f"r0={fc:x},r1={DATA:x},m{len(init)}:{DATA:x}={init.hex()}", exp)
        dmax = (1 << bits) - 1 if name in ("Ed25519",) else n
        case("base", G0, rnd.randrange(1, min(n, 1 << 200)), 0)
        P2 = EM.mul(c, rnd.randrange(2, 1 << 60), G0)
        case("point", P2, rnd.randrange(1, (n if c["kind"] == 0 else 1 << (bits - 1))), 0)
        case("d1", P2, 1, 0)
        case("zero", P2, 0, 2)
        case("offcurve", (P2[0], (P2[1] + 1) % c["p"]), 5, 1)
        if c["kind"] == 0:
            case("dn", P2, n, 1)
            case("dbig", P2, n + 3, 1)
        if name == "Ed25519":
            case("msb", P2, (1 << 255) | 5, 1)
    # Montgomery
    for fc, nm, nb, fs, cls, bits in ((80, "X25519", 32, 32, x25519, 255), (81, "X448", 56, 64, x448, 448)):
        pcls = cls.X25519PrivateKey if nm == "X25519" else cls.X448PrivateKey
        pubcls = cls.X25519PublicKey if nm == "X25519" else cls.X448PublicKey
        for t in range(2):
            kb = bytearray(rnd.randrange(256) for _ in range(nb))
            if nm == "X25519":
                kb[0] &= 248; kb[31] &= 127; kb[31] |= 64
            else:
                kb[0] &= 252; kb[55] |= 128
            peer = pcls.generate().public_key().public_bytes(_S.Encoding.Raw, _S.PublicFormat.Raw)
            out = pcls.from_private_bytes(bytes(kb)).exchange(pubcls.from_public_bytes(peer))
            d = int.from_bytes(kb, "little")
            u = int.from_bytes(peer, "little")
            b = bytearray([0x5a]) * (3 * fs)
            b[2 * fs - nb + fs: 3 * fs] = b""
            b[fs + fs - nb: 2 * fs] = u.to_bytes(nb, "big")
            b[2 * fs + fs - nb: 3 * fs] = d.to_bytes(nb, "big")
            ur = int.from_bytes(out, "little")
            T(f"pcc_sm_{nm}_{t}", "pcc", f"r0={fc:x},r1={DATA:x},m{len(b)}:{DATA:x}={bytes(b).hex()}",
              f"cc=0,m{nb}:{DATA + fs - nb:x}={ur.to_bytes(nb, 'big').hex()}")
        T(f"pcc_sm_{nm}_u0", "pcc", f"r0={fc:x},r1={DATA:x},m{3 * fs}:{DATA:x}={bytes(3 * fs).hex()}", "cc=1")
_pcc_ecc_tests()
T("pcc_query2", "pcc", f"r0=0,r1={DATA:x}", f"m16:{DATA:x}=" + "%032x" % sum(1 << (127 - c) for c in (0, 1, 2, 3, 18, 19, 20, 50, 52, 64, 65, 66, 72, 73, 80, 81)))

def _kdsa_tests():
    import random, hashlib as _hl, ecc_model as EM
    from cryptography.hazmat.primitives.asymmetric import ec as _ec, ed25519 as _e25, ed448 as _e448, utils as _u
    from cryptography.hazmat.primitives import hashes as _h, serialization as _S
    rnd = random.Random(4242)
    def fields(fs, nb, values):
        b = bytearray([0x33]) * (len(values) * fs)
        for i, v in enumerate(values):
            if v is not None:
                b[i * fs: (i + 1) * fs] = bytes(fs - nb) + v.to_bytes(nb, "big")
        return bytes(b)
    nist = {"P256": (1, 9, 32, 32, _h.SHA256, _hl.sha256), "P384": (2, 10, 48, 48, _h.SHA384, _hl.sha384), "P521": (3, 11, 66, 80, _h.SHA512, _hl.sha512)}
    for name, (fcv, fcs, nb, fs, H, hf) in nist.items():
        c = EM.CURVES[name]
        n = c["n"]
        d = rnd.randrange(1, n)
        priv = _ec.derive_private_key(d, c["curve"])
        pub = priv.public_key().public_numbers()
        for t in range(2):
            digest = hf(bytes([t]) * 10).digest()
            e = int.from_bytes(digest, "big")
            k0 = rnd.randrange(1, n)
            r = EM.mul(c, k0, (c["gx"], c["gy"]))[0] % n
            s_ = pow(k0, -1, n) * (e + r * d) % n
            priv.public_key().verify(_u.encode_dss_signature(r, s_), digest, _ec.ECDSA(_u.Prehashed(H())))
            blk = fields(fs, nb, [r, s_, e, pub.x, pub.y])
            T(f"kdsa_ver_{name}_{t}", "kdsa %r0,%r4", f"r0={fcv:x},r1={DATA:x},m{len(blk)}:{DATA:x}={blk.hex()}", "cc=0")
        blk = fields(fs, nb, [r, (s_ + 1) % n or 1, e, pub.x, pub.y])
        T(f"kdsa_ver_{name}_badsig", "kdsa %r0,%r4", f"r0={fcv:x},r1={DATA:x},m{len(blk)}:{DATA:x}={blk.hex()}", "cc=2")
        blk = fields(fs, nb, [0, s_, e, pub.x, pub.y])
        T(f"kdsa_ver_{name}_r0", "kdsa %r0,%r4", f"r0={fcv:x},r1={DATA:x},m{len(blk)}:{DATA:x}={blk.hex()}", "cc=2")
        blk = fields(fs, nb, [r, n, e, pub.x, pub.y])
        T(f"kdsa_ver_{name}_sn", "kdsa %r0,%r4", f"r0={fcv:x},r1={DATA:x},m{len(blk)}:{DATA:x}={blk.hex()}", "cc=2")
        blk = fields(fs, nb, [r, s_, e, pub.x, (pub.y + 1) % c["p"]])
        T(f"kdsa_ver_{name}_offcurve", "kdsa %r0,%r4", f"r0={fcv:x},r1={DATA:x},m{len(blk)}:{DATA:x}={blk.hex()}", "cc=1")
        # signing with the deterministic bit: the random number is used as given
        digest = hf(b"sign me").digest()
        e = int.from_bytes(digest, "big")
        k = rnd.randrange(1, n)
        Rp = EM.mul(c, k, (c["gx"], c["gy"]))
        r = Rp[0] % n
        s_ = pow(k, -1, n) * (e + r * d) % n
        priv.public_key().verify(_u.encode_dss_signature(r, s_), digest, _ec.ECDSA(_u.Prehashed(H())))
        blk = fields(fs, nb, [0, 0, e, d, k])
        T(f"kdsa_sign_{name}", "kdsa %r0,%r4", f"r0={fcs | 0x80:x},r1={DATA:x},m{len(blk)}:{DATA:x}={blk.hex()}",
          f"cc=0,m{nb}:{DATA + fs - nb:x}={r.to_bytes(nb, 'big').hex()},m{nb}:{DATA + 2 * fs - nb:x}={s_.to_bytes(nb, 'big').hex()}")
        blk = fields(fs, nb, [0, 0, e, d, 0])
        T(f"kdsa_sign_{name}_k0", "kdsa %r0,%r4", f"r0={fcs | 0x80:x},r1={DATA:x},m{len(blk)}:{DATA:x}={blk.hex()}", "cc=2")
        blk = fields(fs, nb, [0, 0, e, 0, k])
        T(f"kdsa_sign_{name}_d0", "kdsa %r0,%r4", f"r0={fcs | 0x80:x},r1={DATA:x},m{len(blk)}:{DATA:x}={blk.hex()}", "cc=1")
        blk = fields(fs, nb, [0, 0, e, n, k])
        T(f"kdsa_sign_{name}_dn", "kdsa %r0,%r4", f"r0={fcs | 0x80:x},r1={DATA:x},m{len(blk)}:{DATA:x}={blk.hex()}", "cc=1")
    # EdDSA
    MSG = DATA + 0x1000
    def rev(b):
        return bytes(reversed(b))
    for name, fcv, fcs, el, fs, mod, hashf in (("Ed25519", 32, 40, 32, 32, _e25, None), ("Ed448", 36, 44, 57, 64, _e448, None)):
        keycls = mod.Ed25519PrivateKey if name == "Ed25519" else mod.Ed448PrivateKey
        pubcls = mod.Ed25519PublicKey if name == "Ed25519" else mod.Ed448PublicKey
        for t, mlen in enumerate((0, 5, 70)):
            seed = bytes(rnd.randrange(256) for _ in range(el))
            msg = bytes(rnd.randrange(256) for _ in range(mlen))
            sk = keycls.from_private_bytes(seed)
            sig = sk.sign(msg)
            pk = sk.public_key().public_bytes(_S.Encoding.Raw, _S.PublicFormat.Raw)
            Renc, Senc = sig[:el], sig[el:]
            pad = bytes(fs - el)
            Rf, Sf, Kf = pad + rev(Renc), pad + rev(Senc), pad + rev(pk)
            S0 = int.from_bytes(Senc, "little")
            base = f"r0={fcv:x},r1={DATA:x},r2={MSG:x},r3={mlen:x}"
            mem = lambda R, S, K: f"m{3 * fs}:{DATA:x}={(R + S + K).hex()}" + (f",m{mlen}:{MSG:x}={msg.hex()}" if mlen else "")
            T(f"kdsa_{name}_ver{t}", "kdsa %r0,%r2", base + "," + mem(Rf, Sf, Kf), f"cc=0,r2={MSG:x},r3={mlen:x}")
            Sbad = pad + rev(((S0 + 1) % EM.CURVES[name]["n"]).to_bytes(el, "little"))
            T(f"kdsa_{name}_verbad{t}", "kdsa %r0,%r2", base + "," + mem(Rf, Sbad, Kf), "cc=2")
            if mlen:
                T(f"kdsa_{name}_vermsg{t}", "kdsa %r0,%r2", base.replace(f"r3={mlen:x}", f"r3={mlen - 1:x}") + "," + mem(Rf, Sf, Kf), "cc=2")
            # signing
            Kseed = pad + seed
            T(f"kdsa_{name}_sign{t}", "kdsa %r0,%r2", f"r0={fcs:x},r1={DATA:x},r2={MSG:x},r3={mlen:x}," + mem(bytes(fs), bytes(fs), Kseed),
              f"cc=0,m{fs}:{DATA:x}={Rf.hex()},m{fs}:{DATA + fs:x}={Sf.hex()}")
        # an undecompressable public key (cc 1) and an invalid S (cc 2)
        c = EM.CURVES[name]
        bad = None
        for yy in range(2, 100):
            u = (yy * yy - 1) % c["p"]
            v = (c["d"] * yy * yy - c["a"]) % c["p"]
            x2 = u * pow(v, -1, c["p"]) % c["p"]
            if pow(x2, (c["p"] - 1) // 2, c["p"]) != 1:
                bad = yy
                break
        Kbad = bytes(fs - el) + rev(bad.to_bytes(el, "little"))
        T(f"kdsa_{name}_badkey", "kdsa %r0,%r2", f"r0={fcv:x},r1={DATA:x},r2={MSG:x},r3=0,m{3 * fs}:{DATA:x}={(Rf + Sf + Kbad).hex()}", "cc=1")
        T(f"kdsa_{name}_S0", "kdsa %r0,%r2", f"r0={fcv:x},r1={DATA:x},r2={MSG:x},r3=0,m{3 * fs}:{DATA:x}={(Rf + bytes(fs) + Kf).hex()}", "cc=2")
_kdsa_tests()
T("kdsa_query", "kdsa %r0,%r2", f"r0=0,r1={DATA:x}", f"m16:{DATA:x}=" + "%032x" % sum(1 << (127 - c) for c in (0, 1, 2, 3, 9, 10, 11, 32, 36, 40, 44)))


def main():
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    mc = os.environ.get("LLVM_MC", "llvm-mc")
    only = os.environ.get("EMU_ONLY")
    if only:
        import re
        tests[:] = [t for t in tests if re.search(only, t[0])]
    src = []
    for i, (name, asm, _, _) in enumerate(tests):
        src.append(f".globl s{i}\n.globl e{i}\ns{i}:\n{asm}\ne{i}:\n  nopr\n")
    with tempfile.TemporaryDirectory() as td:
        s = os.path.join(td, "emu.s")
        o = os.path.join(td, "emu.o")
        open(s, "w").write("\n".join(src))
        subprocess.run([mc, "-triple=s390x", "-mcpu=arch15", "-filetype=obj", s, "-o", o], check=True)
        b = os.path.join(td, "emu.bin")
        subprocess.run([os.environ.get("LLVM_OBJCOPY", "llvm-objcopy"), "-O", "binary",
                        "--only-section=.text", o, b], check=True)
        syms = subprocess.run([os.environ.get("LLVM_NM", "llvm-nm"), o], check=True,
                              capture_output=True, text=True).stdout
        code = open(b, "rb").read()
    addr = {}
    for line in syms.splitlines():
        f = line.split()
        if len(f) == 3:
            addr[f[2]] = int(f[0], 16)
    assert len(code) < DATA
    open(os.path.join(out, "emu.bin"), "wb").write(code + bytes(0x10000 - len(code)))
    with open(os.path.join(out, "emu.txt"), "w") as fh:
        for i, (name, _, init, expect) in enumerate(tests):
            st, en = addr[f"s{i}"], addr[f"e{i}"]
            # "@+n": test start address plus n
            expect = ",".join(kv if "=@+" not in kv else
                              kv.split("=")[0] + "=" + format(st + int(kv.split("@+")[1], 16), "x")
                              for kv in expect.split(","))
            fh.write(f"{name} {st:x} {en:x} {init or '-'} {expect}\n")
    print(f"{len(tests)} tests")


if __name__ == "__main__":
    main()
