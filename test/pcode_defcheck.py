#!/usr/bin/env python3
"""Static check of generated p-code: every unique (temporary) varnode read must be written on
every path before the read. SLEIGH accepts a local read on a path that never assigned it; the
emulator then stops with "Attempted to read uninitialized word in unique space".

  pcode_defcheck.py <DumpDisasm.java pcode output>   (test/ghidra-dis.sh ... pcode)
Prints the instructions with a violation and the count; exit status 1 if any.
"""
import re, sys

def check(ops):
    n = len(ops)
    succ = []
    for i, (out, opc, ins) in enumerate(ops):
        if opc in ("BRANCH", "CBRANCH"):
            r = ins[0][1]
            r = r if r < 2 ** 31 else r - 2 ** 32
            succ.append([i + r] if opc == "BRANCH" else [i + 1, i + r])
        elif opc in ("RETURN", "BRANCHIND"):
            succ.append([])
        else:
            succ.append([i + 1])
    IN = [None] * n
    if not n:
        return set()
    IN[0] = frozenset()
    work = [0]
    bad = set()
    def by(v):
        return {v[1] + k for k in range(v[2])} if v[0] == "unique" else set()
    while work:
        i = work.pop()
        st = IN[i]
        out, opc, ins = ops[i]
        uses = [] if opc == "BRANCH" else ([ins[1]] if opc == "CBRANCH" else ins)
        for v in uses:
            if v[0] == "unique" and not by(v) <= st:
                bad.add(i)
        ns = st | frozenset(by(out)) if out and out[0] == "unique" else st
        for j in succ[i]:
            if 0 <= j < n:
                new = ns if IN[j] is None else IN[j] & ns
                if IN[j] is None or new != IN[j]:
                    IN[j] = new
                    work.append(j)
    return bad

def main():
    insns, cur = [], None
    for l in open(sys.argv[1]).read().splitlines():
        if re.match(r"^[0-9a-f]{8} ", l):
            cur = [l, []]
            insns.append(cur)
        elif l.startswith("    (") or l.startswith("     ---"):
            if l.startswith("    ("):
                m = re.match(r"\s+(\((\w+), (0x[0-9a-f]+), (\d+)\) )?(\w+) (.*)$", l)
                out = (m.group(2), int(m.group(3), 16), int(m.group(4))) if m.group(1) else None
                opc, rest = m.group(5), m.group(6)
            else:
                m = re.match(r"\s+---  (\w+) (.*)$", l)
                out, opc, rest = None, m.group(1), m.group(2)
            ins = [(a, int(b, 16), int(c)) for a, b, c in re.findall(r"\((\w+), (0x[0-9a-f]+), (\d+)\)", rest)]
            cur[1].append((out, opc, ins))
    nbad = 0
    for head, ops in insns:
        b = check(ops)
        if b:
            nbad += 1
            if nbad <= 20:
                print("uninitialized temporary read:", head)
    print(f"{len(insns)} instructions, {nbad} with a read of an unwritten temporary")
    sys.exit(1 if nbad else 0)

main()
