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
T("pcc_query", "pcc", f"r0=0,r1={DATA:x}", f"m16:{DATA:x}=f0003800000028000000000000000000")

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


def main():
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    mc = os.environ.get("LLVM_MC", "llvm-mc")
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
