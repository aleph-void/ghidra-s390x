#!/usr/bin/env python3
"""Build the s390x decode corpora (8-byte slots, each instruction padded with 0x0700 = bcr 0,%r0).

  gen_corpus.py <s390-opc.txt> <outdir> [seed]

s390-opc.txt is GNU binutils' s390_opcodes[] dumped by dumpopc.c:
  name opcode(6 bytes hex) mask(6 bytes hex) length modes min_cpu flags operands...
Writes:
  table.bin / table.idx  every table entry, 8 slots each: the opcode with random operand bits
  fuzz.bin               60,000 slots: random first byte (so every opcode and length occurs),
                         random remaining bytes
Deterministic for a given seed.
"""
import random, sys

opc, out = sys.argv[1], sys.argv[2]
rng = random.Random(int(sys.argv[3]) if len(sys.argv) > 3 else 1)
PAD = bytes.fromhex("0700") * 4

def slot(b):
    return (b + PAD)[:8]

def length(first):
    return (2, 4, 4, 6)[first >> 6]

table = bytearray()
idx = []
for i, line in enumerate(open(opc)):
    f = line.split()
    op, mask, n = bytes.fromhex(f[1]), bytes.fromhex(f[2]), int(f[3])
    for k in range(8):
        r = rng.getrandbits(48).to_bytes(6, "big") if k else bytes(6)
        w = bytes((o & m) | (x & ~m & 0xff) for o, m, x in zip(op, mask, r))[:n]
        table += slot(w)
        idx.append(i)
open(f"{out}/table.bin", "wb").write(table)
open(f"{out}/table.idx", "w").write("\n".join(map(str, idx)) + "\n")
fuzz = bytearray()
for _ in range(60000):
    first = rng.getrandbits(8)
    fuzz += slot(bytes([first]) + rng.getrandbits(40).to_bytes(5, "big")[:length(first) - 1])
open(f"{out}/fuzz.bin", "wb").write(fuzz)
print(f"table.bin: {len(idx)} slots; fuzz.bin: 60000 slots")
