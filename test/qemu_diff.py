#!/usr/bin/env python3
"""Differential p-code check against QEMU: random general-register, immediate and storage
instructions with random inputs, executed by qemu-s390x (user mode) and by Ghidra's p-code
emulator.

  qemu_diff.py probe <s390-opc.txt> <s390-operands.txt> <outdir> [per-entry] [seed]
      runs every candidate opcode-table entry's tests in qemu-s390x and writes ok-entries.txt
      (entries whose tests all execute without a signal)
  qemu_diff.py gen <s390-opc.txt> <s390-operands.txt> <ok-entries.txt> <outdir> [per-entry] [seed]
      writes qd.elf and qd.txt
  qemu_diff.py cmp <outdir> <qemu.bin> <ghidra.bin> [examples]

Each test block loads r1-r4 and a 256-byte storage window (at r12) from an input record, sets
the condition code from the record (SPM with the program mask 0), executes the instruction
under test, then stores r1-r4, the condition code (IPM), FPRs, v16-v23 and the window to an
output record. Register operands are r1-r4, storage operands address the window through r12
(index 0, displacement a multiple of 8). Instructions that need structured inputs (register
pairs holding addresses and lengths, valid packed decimal, Unicode text, divides that must not
trap) come from the hand-built generators in qemu_special.py. The program writes the output
area to stdout and exits; QemuDiff.java runs the same image in Ghidra up to the write.
"""
import os, random, re, struct, subprocess, sys

BASE = 0x10000000
REC = 496               # r1-r4, cc|ipm, marker r6, f0-f7, v16-v23, 256 bytes of storage
FOFF, VOFF = 48, 112
SCRATCH = 256          # storage operands stay inside this window, reset before every test
GPR, FPR, AR, CR, DISP, BASE_F, INDEX, PCREL, SIGNED, LENGTH, PAIR, VR = (
    0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80, 0x100, 0x200, 0x400, 0x800)

# not testable this way: flow, traps, privileged/system, I/O, decimal/HFP/BFP/DFP (FPRs),
# vector, crypto, long string/storage-to-storage loops, execute, monitor, transactional
EXCLUDE = re.compile(
    r"^(b|br|bc|bal|bas|bct|bx|crb|cgrb|clrb|clgrb|cib|cgib|clib|clgib"
    r"|crt|cgrt|clrt|clgrt|cit|cgit|clfit|clgit|clt|clgt|trap|svc|ex|exrl|tbegin|tend|tabort|etnd|ntstg"
    r"|mc|lpsw|ssm|stnsm|stosm|sigp|spx|stpx|sck|stck|stcke|stckf|stckc|sckc|spt|stpt|stap|stidp"
    r"|lra|lctl|stctl|lurag|lura|sturg|stura|ptlb|ipte|idte|iske|sske|rrbe|ivsk|tprot|pc|pt|pr|bsg|bsa|sac|sam|tam|lasp|tar|epar|esar|ssar|esair|ssair|epair"
    r"|csp|cspg|diag|diagnose|stfl|stfle|sie|siga|xsch|ssch|stsch|tsch|tpi|hsch|msch|rsch|rchp|schm|csch|stcrw|stcps|sal"
    r"|pfmf|pfd|pfdrl|stck|sckpf|pgin|pgout|trace|tracg|lpswe|lpswey|nopr|nop|cfc|upt|cu|cksm|cmpsc|kmac|km|kmc|kimd|klmd|kmctr|kmf|kmo|kma|kdsa|pcc|pckmo|prno|ppno|kmd|kmc"
    r"|mvcl|clcl|mvcle|clcle|mvclu|clclu|mvst|clst|srst|srstu|tre|trt|trtr|trte|trtre|tr|troo|trot|trto|trtt|tp|ed|edmk|pack|unpk|pka|pku|unpka|unpku|mvo|mvn|mvz|zap|ap|sp|mp|dp|cp|srp|cvb|cvbg|cvby|cvd|cvdg|cvdy"
    r"|mvcp|mvcs|mvcdk|mvcsk|mvck|mvcos|mvpg|mvcin|plo|lpd|lpdg|clm|stm|lm|ecag|ectg|lpp|lcctl|lpctl|lsctl|qctri|qsi|qpaci|bpp|bprp|niai|ppa|sortl|dfltcc|nnpa|rdp|mvcrl"
    r"|epsw|lat|lgat|lfhat|llgfat|llgtat|d|dr|dl|dlr|dlg|dlgr|dsg|dsgr|dsgf|dsgfr|m|mr|mfy|ml|mlr|mlg|mlgr|mg|mgrk"
    r"|lmh|lmg|lmy|stmh|stmg|stmy|lam|lamy|stam|stamy|ear|sar|cpya|cds|cdsg|cdsy|csst|lpq|stpq|lcbb|efpc|sfpc|sfasr|srnm|srnmb|srnmt|lfpc|lfas|stfpc|ipm|spm|ipk|spka|ssm|bakr|pr|tbeginc)$")

def fl(ops, i):
    return ops[i][2]

def candidates(opc, operands):
    OPS = {}
    for line in open(operands):
        i, b, sh, f = line.split()
        OPS[int(i)] = (int(b), int(sh), int(f, 16))
    out, seen = [], set()
    for line in open(opc):
        f = line.split()
        name, op, mask, ln = f[0], bytes.fromhex(f[1]), bytes.fromhex(f[2]), int(f[3])
        flags = int(f[6], 16)
        ids = [int(x) for x in f[7:]]
        if flags & 0x100 or (f[1], f[2]) in seen:
            continue
        if flags & 0x10 and not flags & 0x20:      # branch through a register/storage address
            continue
        seen.add((f[1], f[2]))
        base = re.sub(r"(o|h|p|nle|l|m|nhe|lh|ne|nz|e|z|nlh|he|nl|nm|le|nh|np|no)$", "", name)
        if EXCLUDE.match(name) or EXCLUDE.match(base) or name.startswith(("k", "cu")):
            continue
        kinds = [OPS[i][2] for i in ids]
        if any(k & (AR | CR | LENGTH) for k in kinds) or any(k & VR and k & INDEX for k in kinds):
            continue
        if any(k & PCREL for k in kinds) and not flags & 0x20:
            continue          # PC-relative data (LARL, LRL, EXRL, ...): needs real addresses
        out.append((name, op, mask, ln, [(i,) + OPS[i] for i in ids]))
    return out

def encode(rng, name, op, mask, ln, ops):
    w = bytearray(op)
    def put(bits, shift, val):
        for k in range(bits):
            pos = shift + k
            byte, bit = pos // 8, 7 - pos % 8
            if (mask[byte] >> bit) & 1:
                continue
            b = (val >> (bits - 1 - k)) & 1
            w[byte] = (w[byte] & ~(1 << bit)) | (b << bit)
    for oid, bits, shift, f in ops:
        if f & GPR and f & BASE_F:
            put(bits, shift, 12)
        elif f & GPR and f & INDEX:
            put(bits, shift, 0)
        elif f & GPR:
            r = rng.choice([1, 2, 3, 4]) if not f & PAIR else rng.choice([2, 4])
            put(bits, shift, r)
        elif f & FPR:
            put(bits, shift, rng.choice([0, 1, 4, 5]) if f & PAIR else rng.randrange(8))
        elif f & VR:
            v = rng.randrange(8)                       # v16-v23
            put(bits, shift, v)
            vr = 3 if shift == 32 else shift // 4 - 2
            w[4] |= 1 << (3 - vr)
        elif f & PCREL:
            put(bits, shift, 0)
        elif f & DISP:
            if bits == 20:
                d = rng.randrange(0, SCRATCH - 32, 8)
                put(12, 20, d & 0xfff)
                put(8, 32, d >> 12)
            else:
                put(bits, shift, rng.randrange(0, SCRATCH - 32, 8))
        else:
            put(bits, shift, rng.getrandbits(bits))
    out = bytes(w[:ln])
    for oid, bits, shift, f in ops:
        if f & PCREL:
            PCREL_FIELDS[out] = (bits, shift)
    return out

def lg(r, d, b):          # LG r,d(b)
    return bytes([0xe3, r << 4, (b << 4) | (d >> 8 & 0xf), d & 0xff, 0, 0x04])
def stg(r, d, b):
    return bytes([0xe3, r << 4, (b << 4) | (d >> 8 & 0xf), d & 0xff, 0, 0x24])
def la(r, d, b):
    return bytes([0x41, r << 4, (b << 4) | (d >> 8 & 0xf), d & 0xff])
def larl(r, addr, here):
    off = (addr - here) // 2
    return bytes([0xc0, r << 4]) + struct.pack(">i", off)
def ld(f, d, b):
    return bytes([0x68, f << 4, (b << 4) | (d >> 8 & 0xf), d & 0xff])
def std(f, d, b):
    return bytes([0x60, f << 4, (b << 4) | (d >> 8 & 0xf), d & 0xff])
def vl(v, d, b, op=0x06):
    return bytes([0xe7, (v & 15) << 4, (b << 4) | (d >> 8 & 0xf), d & 0xff, 0x08 if v >= 16 else 0, op])
def vst(v, d, b):
    return vl(v, d, b, 0x0e)
def MVC(d1, b1, d2, b2, ln=256):
    return bytes([0xd2, ln - 1, (b1 << 4) | (d1 >> 8 & 0xf), d1 & 0xff, (b2 << 4) | (d2 >> 8 & 0xf), d2 & 0xff])
SPM0 = lambda r: bytes([0x04, r << 4])
IPM = lambda r: bytes([0xb2, 0x22, 0, r << 4])
SVC = lambda n: bytes([0x0a, n])
LGHI = lambda r, i: bytes([0xa7, (r << 4) | 9]) + struct.pack(">h", i)

PCREL_FIELDS = {}     # test bytes -> (bits, shift) of its PC-relative operand

def patch_target(t):
    """Point a PC-relative operand just past the 4-byte marker that follows the test."""
    if t not in PCREL_FIELDS:
        return t
    bits, shift = PCREL_FIELDS[t]
    w = bytearray(t)
    val = (len(t) + 4) // 2
    for k in range(bits):
        pos = shift + k
        byte, bit = pos // 8, 7 - pos % 8
        b = (val >> (bits - 1 - k)) & 1
        w[byte] = (w[byte] & ~(1 << bit)) | (b << bit)
    return bytes(w)

def build(tests_bytes, data, count):
    hdr = 0x1000
    code = bytearray()
    def here():
        return BASE + hdr + len(code)
    # fixed layout: inputs, outputs, scratch after code
    est = 64 + sum(len(t) + 400 for t in tests_bytes) + 64
    inp = BASE + hdr + ((est + 0xfff) & ~0xfff)
    outp = inp + count * REC
    scratch = outp + count * REC
    for i, t in enumerate(tests_bytes):
        # absolute record addresses per test, so an instruction that corrupts a register used
        # by the harness only spoils its own result
        code += larl(10, inp + i * REC, here())
        code += larl(11, outp + i * REC, here())
        code += larl(12, scratch, here())
        code += larl(13, scratch + SCRATCH, here())
        code += MVC(0, 12, 240, 10)              # the storage window from the input record
        for k in range(4):
            code += lg(1 + k, 8 * k, 10)
        for k in range(8):
            code += ld(k, FOFF + 8 * k, 10)
            code += vl(16 + k, VOFF + 16 * k, 10)
        code += lg(5, 32, 10) + SPM0(5) + LGHI(6, 0)
        code += patch_target(t)
        code += LGHI(6, 0x77)                 # skipped when a branch is taken
        code += IPM(5)
        for k in range(4):
            code += stg(1 + k, 8 * k, 11)
        code += MVC(240, 11, 0, 12)              # storage after the test
        code += stg(5, 32, 11) + stg(6, 40, 11)
        for k in range(8):
            code += std(k, FOFF + 8 * k, 11)
            code += vst(16 + k, VOFF + 16 * k, 11)
    stop = here()
    # write(1, outp, count*REC + SCRATCH); exit(0)
    code += LGHI(2, 1)
    code += larl(3, outp, here())
    code += bytes([0xc0, 0x41]) + struct.pack(">I", count * REC + SCRATCH)    # lgfi r4
    code += SVC(4) + LGHI(2, 0) + SVC(1)
    assert BASE + hdr + len(code) <= inp
    image = bytearray(hdr) + code
    image += bytes(inp - BASE - len(image)) + data + bytes(count * REC)
    rng = random.Random(7)
    pristine = bytes(rng.getrandbits(8) for _ in range(SCRATCH))
    image += pristine + pristine
    eh = struct.pack(">4sBBBBB7xHHIQQQIHHHHHH", b"\x7fELF", 2, 2, 1, 0, 0, 2, 22, 1,
                     BASE + hdr, 64, 0, 0, 64, 56, 1, 64, 0, 0)
    ph = struct.pack(">IIQQQQQQ", 1, 7, 0, BASE, BASE, len(image), len(image), 0x1000)
    image[0:len(eh)] = eh
    image[64:64 + len(ph)] = ph
    return image, stop, outp, scratch

def make_per_entry(entries, per, seed):
    """per tests for every entry, each entry with its own deterministic generator"""
    tests, data, names = [], bytearray(), []
    for e in entries:
        r = random.Random(f"{seed}/{e[0]}/{e[1].hex()}")
        t, d, n = make([e], r, per)
        tests += t; data += d; names += n
    return tests, data, names

import qemu_special
SPECIAL = qemu_special.SPECIAL

def special_entries():
    return [(n, b"special", b"", 0, []) for n in sorted(SPECIAL)]

def entry_key(e):
    return f"special {e[0]}" if e[1] == b"special" else e[0] + " " + e[1].hex() + " " + e[2].hex()

def make(entries, rng, count, ok=None):
    tests, data = [], bytearray()
    specials = [0, 1, 2, 0x7fffffff, 0x80000000, 0xffffffff, 0x8000000000000000,
                0xffffffffffffffff, 0x7fffffffffffffff, 0x100000000]
    names = []
    for i in range(count):
        e = entries[i % len(entries)]
        regs = window = None
        if e[1] == b"special":
            w, regs, window = SPECIAL[e[0]](rng)
        else:
            w = encode(rng, *e)
        tests.append(w)
        names.append((e[0], w.hex()))
        for k in range(4):
            v = rng.choice(specials) if rng.random() < 0.3 else rng.getrandbits(64)
            if rng.random() < 0.2:
                v = rng.getrandbits(8)
            if regs is not None:
                v = regs[k]
            data += struct.pack(">Q", v)
        data += struct.pack(">Q", rng.randrange(4) << 28)
        data += bytes(8)
        data_pad = True
        for k in range(8):            # doubles: mostly normal values, some specials
            x = rng.choice([0.0, -0.0, 1.0, -1.5, 2.0, float("inf"), 3.0e-310]) if rng.random() < 0.15 \
                else rng.uniform(-1e6, 1e6) * (10 ** rng.randint(-5, 5))
            data += struct.pack(">d", x)
        for k in range(8):
            data += bytes(rng.getrandbits(8) for _ in range(16)) if rng.random() < 0.5 else \
                b"".join(struct.pack(">d", rng.uniform(-1e3, 1e3)) for _ in range(2))
        data += bytes(window) if window is not None else bytes(rng.getrandbits(8) for _ in range(256))
    return tests, data, names

def run(path):
    return subprocess.run(["qemu-s390x", path], capture_output=True)

def main():
    mode = sys.argv[1]
    if mode == "probe":
        ents = candidates(sys.argv[2], sys.argv[3]) + special_entries()
        out = sys.argv[4]
        rng = random.Random(1)
        ok = []
        per = int(sys.argv[5]) if len(sys.argv) > 5 else 24
        seed = sys.argv[6] if len(sys.argv) > 6 else "1"
        for e in ents:
            tests, data, names = make_per_entry([e], per, seed)
            img, stop, outp, scratch = build(tests, data, per)
            p = f"{out}/probe.elf"
            open(p, "wb").write(img); os.chmod(p, 0o755)
            r = run(p)
            if r.returncode == 0 and len(r.stdout) == per * REC + SCRATCH:
                ok.append(entry_key(e))
            elif e[1] == b"special":
                print(f"special {e[0]}: does not run cleanly in qemu (exit {r.returncode})")
        open(f"{out}/ok-entries.txt", "w").write("\n".join(ok) + "\n")
        print(f"{len(ok)} of {len(ents)} candidate entries run cleanly in qemu-s390x")
    elif mode == "gen":
        ents = candidates(sys.argv[2], sys.argv[3]) + special_entries()
        okset = set(l.strip() for l in open(sys.argv[4]))
        ents = [e for e in ents if entry_key(e) in okset]
        out = sys.argv[5]
        per = int(sys.argv[6]) if len(sys.argv) > 6 else 24
        seed = sys.argv[7] if len(sys.argv) > 7 else "1"
        tests, data, names = make_per_entry(ents, per, seed)
        count = len(tests)
        img, stop, outp, scratch = build(tests, data, count)
        open(f"{out}/qd.elf", "wb").write(img); os.chmod(f"{out}/qd.elf", 0o755)
        with open(f"{out}/qd.txt", "w") as fh:
            fh.write(f"# stop 0x{stop:x} out 0x{outp:x} len {count * REC + SCRATCH} entry 0x{BASE + 0x1000:x}\n")
            for i, (n, w) in enumerate(names):
                fh.write(f"{i} {n} {w}\n")
        print(f"{count} tests over {len(ents)} entries")
    else:
        out, qf, gf = sys.argv[2:5]
        nex = int(sys.argv[5]) if len(sys.argv) > 5 else 3
        tests = [l.split() for l in open(f"{out}/qd.txt") if not l.startswith("#")]
        q, g = open(qf, "rb").read(), open(gf, "rb").read()
        from collections import Counter, defaultdict
        bad, per = defaultdict(list), Counter()
        ok = 0
        nm = ["r1", "r2", "r3", "r4", "cc", "taken-marker r6"] + [f"f{k}" for k in range(8)] + \
            [f"v{16 + k // 2}{'hl'[k % 2]}" for k in range(16)] + [f"mem+{8 * k}" for k in range(32)]
        for i, n, w in tests:
            i = int(i)
            qv = struct.unpack_from(">62Q", q, i * REC)
            gv = struct.unpack_from(">62Q", g, i * REC)
            per[n] += 1
            qv = qv[:4] + ((qv[4] >> 28) & 3,) + qv[5:]
            gv = gv[:4] + ((gv[4] >> 28) & 3,) + gv[5:]
            if qv == gv:
                ok += 1
            else:
                bad[n].append((w, [f"{nm[k]}: qemu {qv[k]:x} ghidra {gv[k]:x}" for k in range(62) if qv[k] != gv[k]]))
        sq, sg = q[len(tests) * REC:], g[len(tests) * REC:]
        print(f"qemu vs ghidra: {ok}/{len(tests)} tests agree ({100 * ok / len(tests):.2f}%), "
              f"{len(per)} mnemonics, {len(bad)} with differences; scratch storage "
              f"{'identical' if sq == sg else 'DIFFERS'}")
        for n, v in sorted(bad.items(), key=lambda kv: -len(kv[1])):
            print(f"  [{len(v):4d}/{per[n]}] {n}")
            for w, d in v[:nex]:
                print(f"         {w}: {'; '.join(d)}")

if __name__ == "__main__":
    main()
