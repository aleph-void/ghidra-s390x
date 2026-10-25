#!/usr/bin/env python3
"""Remove the hand-written constructors of the given mnemonics so tools/gen_table.py generates
them (with the semantics of tools/gen_semantics.py, checked against qemu-s390x).

  tools/strip_constructors.py <data/languages> <mnemonic-list-file>

Each removed constructor is replaced by a one-line comment naming the generated replacement.
"""
import glob, os, re, sys

lang, lst = sys.argv[1], sys.argv[2]
names = set(l.split()[0].upper() for l in open(lst) if l.strip() and not l.startswith("#"))
total = 0
for f in sorted(glob.glob(os.path.join(lang, "s390x_*.sinc"))):
    if f.endswith("s390x_table_gen.sinc"):
        continue
    s = open(f).read()
    out, pos, n = [], 0, 0
    for m in re.finditer(r"(?m)^:([A-Z0-9]+)\b[^\n]*?\bis\b", s):
        if m.group(1) not in names or m.start() < pos:
            continue
        # body: from the first "{" after the header to its matching "}"
        b = s.index("{", m.end())
        depth, i = 0, b
        while True:
            if s[i] == "{":
                depth += 1
            elif s[i] == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        out.append(s[pos:m.start()])
        out.append(f"# {m.group(1)}: generated in s390x_table_gen.sinc (tools/gen_semantics.py)")
        pos = i + 1
        n += 1
    out.append(s[pos:])
    if n:
        open(f, "w").write("".join(out))
        total += n
print(f"removed {total} constructors")
