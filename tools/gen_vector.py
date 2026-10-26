"""P-code for z/Architecture vector-facility instructions (used by gen_semantics.py).

Vector registers are 16-byte big-endian varnodes: element i of size s bytes (i = 0 leftmost)
is bits [8*(16-(i+1)*s), +8*s) of the varnode. Element loops are unrolled. When the element
size comes from an M operand at run time (base mnemonics such as VA), one unrolled block per
legal size is emitted and selected with branches.
"""
import re

SIZES = {"b": 1, "h": 2, "f": 4, "g": 8, "q": 16}
_n = [0]

def uid():
    _n[0] += 1
    return _n[0]

class Block:
    """Accumulates p-code lines with unique local names."""
    def __init__(self):
        self.lines = []
        self.tag = uid()
        self.loop_sh = None     # inside an element loop: name of the run-time shift amount

    def local(self, size, expr, base="t"):
        name = f"{base}{self.tag}_{uid()}"
        self.lines.append(f"local {name}:{size} = {expr};")
        return name

    def elem(self, v, i, s):
        if s == 16:
            return self.local(16, v, "e")
        if self.loop_sh is not None and i == LOOP_ELEM:
            w = self.local(16, f"{v} >> {self.loop_sh}", "w")
            return self.local(s, f"{w}:{s}", "e")
        sh = 8 * (16 - (i + 1) * s)
        w = self.local(16, f"{v} >> {sh}" if sh else v, "w")
        return self.local(s, f"{w}:{s}", "e")

    def add(self, line):
        self.lines.append(line)

    def text(self):
        return "\n".join(self.lines)

# Element loops. A per-element body longer than LOOP_MIN lines is emitted once inside a p-code
# loop over the elements instead of once per element: unrolled, the vector facility alone
# would exceed the 16 MiB a .sla may decode to (SlaFormat.MAX_FILE_SIZE).
LOOP_MIN = 12
LOOP_ELEM = "loop"          # element index meaning "the current loop element"

class LoopResult(str):
    """Name of a 16-byte value already assembled by an element loop."""

def loop_elems(blk, s, fn):
    """Run fn(LOOP_ELEM) once per element in a loop; returns the assembled 16-byte value."""
    sh = blk.local(8, f"{128 - 8 * s}", "sh")
    acc = blk.local(16, "zext(0:8)", "r")
    top = f"lp{blk.tag}_{uid()}"
    blk.add(f"<{top}>")
    saved, blk.loop_sh = blk.loop_sh, sh
    r = fn(LOOP_ELEM)
    blk.loop_sh = saved
    blk.add(f"{acc} = {acc} | (zext({r}) << {sh});")
    blk.add(f"{sh} = {sh} - {8 * s};")
    blk.add(f"if ({sh} s>= 0) goto <{top}>;")
    return LoopResult(acc)

def parts_or_loop(blk, s, fn, n=None):
    """Element results fn(i) for i in range(n): unrolled when short, else an element loop."""
    n = 16 // s if n is None else n
    if n == 1 or n != 16 // s:
        return [fn(i) for i in range(n)]
    mark = len(blk.lines)
    first = fn(0)
    if len(blk.lines) - mark <= LOOP_MIN:
        return [first] + [fn(i) for i in range(1, n)]
    del blk.lines[mark:]
    return loop_elems(blk, s, fn)

def assemble(blk, parts, s):
    """16-byte value from element values (list of names, leftmost first)."""
    if isinstance(parts, LoopResult):
        return parts
    acc = blk.local(16, "zext(0:8)", "r")
    for i, p in enumerate(parts):
        sh = 8 * (16 - (i + 1) * s)
        z = f"zext({p})" if s < 16 else p
        blk.add(f"{acc} = {acc} | ({z} << {sh});" if sh else f"{acc} = {acc} | {z};")
    return acc

# element operations: f(blk, a, b, s) -> name of the s-byte result
def _bin(op):
    return lambda blk, a, b, s: blk.local(s, f"{a} {op} {b}")

def _avg(signed):
    def f(blk, a, b, s):
        ext = "sext" if signed else "zext"
        w = blk.local(2 * s if s < 16 else 16, f"{ext}({a}) + {ext}({b}) + 1" if s < 16 else f"{a} + {b} + 1")
        sh = blk.local(2 * s if s < 16 else 16, f"{w} {'s>>' if signed else '>>'} 1")
        return blk.local(s, f"{sh}:{s}")
    return f

def _minmax(op):
    def f(blk, a, b, s):
        c = blk.local(1, f"{a} {op} {b}")
        return blk.local(s, f"zext({c}) * {a} + zext(!{c}) * {b}")
    return f

def _mulhi(signed):
    def f(blk, a, b, s):
        ext = "sext" if signed else "zext"
        p = blk.local(2 * s, f"{ext}({a}) * {ext}({b})")
        h = blk.local(2 * s, f"{p} >> {8 * s}")
        return blk.local(s, f"{h}:{s}")
    return f

def _carry(blk, a, b, s):
    c = blk.local(1, f"carry({a}, {b})")
    return blk.local(s, f"zext({c})")

def _noborrow(blk, a, b, s):
    c = blk.local(1, f"{a} >= {b}")
    return blk.local(s, f"zext({c})")

def _cmp(op):
    def f(blk, a, b, s):
        c = blk.local(1, f"{a} {op} {b}")
        return blk.local(s, f"-zext({c})" if True else "")
    return f

def _shift(op, rot=False):
    def f(blk, a, b, s):
        bits = 8 * s
        amt = blk.local(s, f"{b} & {bits - 1}")
        if rot:
            l = blk.local(s, f"{a} << {amt}")
            r = blk.local(s, f"{a} >> (({bits} - {amt}) & {bits - 1})")
            z = blk.local(1, f"{amt} == 0")
            return blk.local(s, f"zext({z}) * {a} + zext(!{z}) * ({l} | {r})")
        return blk.local(s, f"{a} {op} {amt}")
    return f

BINARY = {
    "va": _bin("+"), "vs": _bin("-"), "vml": _bin("*"),
    "vmx": _minmax("s>"), "vmn": _minmax("s<"), "vmxl": _minmax(">"), "vmnl": _minmax("<"),
    "vavg": _avg(True), "vavgl": _avg(False), "vmh": _mulhi(True), "vmlh": _mulhi(False),
    "vacc": _carry, "vscbi": _noborrow,
    "vceq": _cmp("=="), "vch": _cmp("s>"), "vchl": _cmp(">"),
    "verllv": _shift(None, True), "veslv": _shift("<<"), "vesrav": _shift("s>>"), "vesrlv": _shift(">>"),
}

def unary_lc(blk, a, s):
    return blk.local(s, f"-{a}")

def unary_lp(blk, a, s):
    n = blk.local(1, f"{a} s< 0")
    return blk.local(s, f"zext({n}) * (-{a}) + zext(!{n}) * {a}")

def unary_popct(blk, a, s):
    return blk.local(s, f"popcount({a})")

def unary_clz(blk, a, s):
    return blk.local(s, f"lzcount({a})")

def unary_ctz(blk, a, s):
    m = blk.local(s, f"({a} & -{a}) - 1")
    return blk.local(s, f"popcount({m})")

UNARY = {"vlc": unary_lc, "vlp": unary_lp, "vpopct": unary_popct, "vclz": unary_clz, "vctz": unary_ctz}

def size_of(name, base, mexpr_avail):
    """Element size fixed by the mnemonic suffix, or None (runtime M operand)."""
    suf = name[len(base):]
    suf = suf[:-1] if suf.endswith("s") and suf[:-1] in SIZES else suf
    return SIZES.get(suf)

def dispatch(sizes, body_for, m_operand):
    """Runtime element-size selection: body_for(s) -> text. sizes: allowed code->size map."""
    tag = uid()
    out = [f"local es{tag}:8 = {m_operand};"]
    for code in sizes:
        out.append(f"if (es{tag} == {code}) goto <es{tag}_{code}>;")
    out.append(f"goto <es{tag}_end>;")
    for code, s in sizes.items():
        out.append(f"<es{tag}_{code}>")
        out.append(body_for(s))
        out.append(f"goto <es{tag}_end>;")
    out.append(f"<es{tag}_end>")
    return "\n".join(out)

def elementwise(o0, o1, o2, s, fn, cc=None):
    blk = Block()
    parts = parts_or_loop(blk, s, lambda i: fn(blk, blk.elem(o1, i, s), blk.elem(o2, i, s), s))
    r = assemble(blk, parts, s)
    if cc:     # compare with CS: 0 all true, 1 some, 3 none
        ones = blk.local(16, "~zext(0:8)")
        blk.add(f"cc = zext({r} == 0) * 3 + zext({r} != 0) * zext({r} != {ones});")
    blk.add(f"{o0} = {r};")
    return blk.text()

def unary(o0, o1, s, fn):
    blk = Block()
    parts = parts_or_loop(blk, s, lambda i: fn(blk, blk.elem(o1, i, s), s))
    r = assemble(blk, parts, s)
    blk.add(f"{o0} = {r};")
    return blk.text()

BITWISE = {"vn": "{a} & {b}", "vo": "{a} | {b}", "vx": "{a} ^ {b}", "vnc": "{a} & ~{b}",
           "vnn": "~({a} & {b})", "vno": "~({a} | {b})", "vnx": "~({a} ^ {b})", "voc": "{a} | ~{b}"}

def semantics(ctx):
    n, o, k = ctx["name"], ctx["ops"], ctx["kinds"]
    if n in BITWISE:
        return f"{o[0]} = {BITWISE[n].format(a=o[1], b=o[2])};"
    if n == "vsel":
        return f"{o[0]} = ({o[1]} & {o[3]}) | ({o[2]} & ~{o[3]});"
    if n in ("vzero", "vone"):
        return f"{o[0]} = {"zext(0:8)" if n == "vzero" else '~zext(0:8)'};"
    if n == "vlr":
        return f"{o[0]} = {o[1]};"
    if n == "vgbm":
        blk = Block()
        blk.add(f"local gi:8 = {o[1]};")
        acc = blk.local(16, "zext(0:8)", "g")
        for i in range(16):
            bt = blk.local(16, f"zext((gi >> {15 - i}) & 1) * 0xff")
            blk.add(f"{acc} = {acc} | ({bt} << {8 * (15 - i)});")
        blk.add(f"{o[0]} = {acc};")
        return blk.text()
    # element-wise binary families (mnemonic = base + size suffix [+ s for CS compares])
    for base in sorted(BINARY, key=len, reverse=True):
        if n.startswith(base):
            suf = n[len(base):]
            cs = suf.endswith("s") and suf[:-1] in SIZES
            if cs:
                suf = suf[:-1]
            if suf and suf not in SIZES:
                continue
            fn = BINARY[base]
            iscmp = base in ("vceq", "vch", "vchl")
            if suf:
                return elementwise(o[0], o[1], o[2], SIZES[suf], fn, cs)
            # base form: M4 element size (M5 bit 1: set cc for compares)
            m = o[3]
            if iscmp:
                ccflag = o[4] if len(o) > 4 else "0"
                return (f"local csf:8 = {ccflag};\n" +
                        dispatch({0: 1, 1: 2, 2: 4, 3: 8}, lambda s: elementwise(o[0], o[1], o[2], s, fn, False), m) +
                        f"\nif ((csf & 1) == 0) goto <nocc>;\nlocal ones:16 = ~zext(0:8);\n"
                        f"cc = zext({o[0]} == 0) * 3 + zext({o[0]} != 0) * zext({o[0]} != ones);\n<nocc>")
            allowed = {0: 1, 1: 2, 2: 4, 3: 8, 4: 16} if base in ("va", "vs", "vacc", "vscbi") else {0: 1, 1: 2, 2: 4, 3: 8}
            return dispatch(allowed, lambda s: elementwise(o[0], o[1], o[2], s, fn), m)
    r = batch2(ctx)
    if r is not None:
        return r
    r = batch3(ctx)
    if r is not None:
        return r
    r = batch4(ctx)
    if r is not None:
        return r
    for base, fn in UNARY.items():
        if n.startswith(base):
            suf = n[len(base):]
            if suf and suf not in SIZES:
                continue
            if suf:
                return unary(o[0], o[1], SIZES[suf], fn)
            m = o[2] if len(o) > 2 else "0"
            return dispatch({0: 1, 1: 2, 2: 4, 3: 8}, lambda s: unary(o[0], o[1], s, fn), m)
    return None

# ---------------------------------------------------------------------------------------------
# element access with a run-time index

def get_rt(blk, v, idx, s):
    sh = blk.local(16, f"zext((16 - ({idx} + 1) * {s}) * 8)")
    t = blk.local(16, f"{v} >> {sh}")
    return blk.local(s, f"{t}:{s}")

def set_rt(blk, v, idx, s, val):
    sh = blk.local(16, f"zext((16 - ({idx} + 1) * {s}) * 8)")
    ones = blk.local(16, "zext(0xffffffffffffffff:8)") if s == 8 else None
    m = blk.local(16, f"zext(0xffffffffffffffff:8) >> {64 - 8 * s}" if s < 8 else ones if s == 8 else "~zext(0:8)")
    blk.add(f"{v} = ({v} & ~({m} << {sh})) | (zext({val}) << {sh});" if s < 16 else f"{v} = {val};")

def sized(n, base, m_idx, o, body, allowed=(1, 2, 4, 8)):
    """Fixed size from suffix, else run-time M operand o[m_idx]."""
    suf = n[len(base):]
    if suf in SIZES:
        return body(SIZES[suf])
    if suf == "":
        codes = {0: 1, 1: 2, 2: 4, 3: 8, 4: 16}
        return dispatch({c: s for c, s in codes.items() if s in allowed}, body, o[m_idx])
    return None

def vrep(o, s):
    blk = Block()
    blk.add(f"local ix{blk.tag}:8 = {o[2]} & {16 // s - 1};")
    e = get_rt(blk, o[1], f"ix{blk.tag}", s)
    r = assemble(blk, [e] * (16 // s), s)
    blk.add(f"{o[0]} = {r};")
    return blk.text()

def vrepi(o, s):
    blk = Block()
    blk.add(f"local iv{blk.tag}:8 = {o[1]};")
    e = blk.local(s, f"sext(iv{blk.tag}:2)" if s > 2 else f"iv{blk.tag}:{s}")
    r = assemble(blk, [e] * (16 // s), s)
    blk.add(f"{o[0]} = {r};")
    return blk.text()

def vlei(o, s):
    blk = Block()
    blk.add(f"local iv{blk.tag}:8 = {o[1]}; local ix{blk.tag}:8 = {o[2]} & {16 // s - 1};")
    e = blk.local(s, f"sext(iv{blk.tag}:2)" if s > 2 else f"iv{blk.tag}:{s}")
    set_rt(blk, o[0], f"ix{blk.tag}", s, e)
    return blk.text()

def vle(o, s, store=False, rev=False):
    blk = Block()
    blk.add(f"local ix{blk.tag}:8 = {o[2]} & {16 // s - 1};")
    if store:
        e = get_rt(blk, o[0], f"ix{blk.tag}", s)
        if rev:
            e = byterev(blk, e, s)
        blk.add(f"*:{s} {o[1]} = {e};")
    else:
        e = blk.local(s, f"*:{s} {o[1]}")
        if rev:
            e = byterev(blk, e, s)
        set_rt(blk, o[0], f"ix{blk.tag}", s, e)
    return blk.text()

def byterev(blk, e, s):
    if s == 1:
        return e
    parts = " | ".join(f"(zext({e}[{8 * k},8]) << {8 * (s - 1 - k)})" for k in range(s))
    return blk.local(s, parts)

def vlrep(o, s, rev=False):
    blk = Block()
    e = blk.local(s, f"*:{s} {o[1]}")
    if rev:
        e = byterev(blk, e, s)
    r = assemble(blk, [e] * (16 // s), s)
    blk.add(f"{o[0]} = {r};")
    return blk.text()

def vllez(o, s, left=False, rev=False):
    blk = Block()
    e = blk.local(s, f"*:{s} {o[1]}")
    if rev:
        e = byterev(blk, e, s)
    idx = 0 if left else 8 // s - 1
    parts = [e if i == idx else blk.local(s, "0") for i in range(16 // s)]
    r = assemble(blk, parts, s)
    blk.add(f"{o[0]} = {r};")
    return blk.text()

def vlvg(o, s):
    blk = Block()
    blk.add(f"local ix{blk.tag}:8 = {o[2]} & {16 // s - 1};")
    v = blk.local(s, f"{o[1]}:{s}" if s < 8 else o[1])
    set_rt(blk, o[0], f"ix{blk.tag}", s, v)
    return blk.text()

def vlgv(o, s):
    blk = Block()
    blk.add(f"local ix{blk.tag}:8 = {o[2]} & {16 // s - 1};")
    e = get_rt(blk, o[1], f"ix{blk.tag}", s)
    blk.add(f"{o[0]} = zext({e});" if s < 8 else f"{o[0]} = {e};")
    return blk.text()

def vgm(o, s):
    blk = Block()
    b = 8 * s
    blk.add(f"local st{blk.tag}:8 = {o[1]} & {b - 1}; local en{blk.tag}:8 = {o[2]} & {b - 1};")
    full = "0xffffffffffffffff" if s == 8 else hex((1 << b) - 1)
    m1 = blk.local(8, f"({full} >> st{blk.tag}) & {full}")
    m2 = blk.local(8, f"({full} << ({b - 1} - en{blk.tag})) & {full}")
    w = blk.local(1, f"st{blk.tag} > en{blk.tag}")
    m = blk.local(8, f"zext(!{w}) * ({m1} & {m2}) + zext({w}) * ({m1} | {m2})")
    e = blk.local(s, f"{m}:{s}")
    r = assemble(blk, [e] * (16 // s), s)
    blk.add(f"{o[0]} = {r};")
    return blk.text()

def vmr(o, s, high):
    blk = Block()
    n = 16 // s
    base = 0 if high else n // 2
    parts = []
    for i in range(n // 2):
        parts.append(blk.elem(o[1], base + i, s))
        parts.append(blk.elem(o[2], base + i, s))
    r = assemble(blk, parts, s)
    blk.add(f"{o[0]} = {r};")
    return blk.text()

def vpk(o, s, kind, cs=None):
    """s: source element size; result elements s/2: plain truncation, signed or unsigned
    saturation (cc: 0 none saturated, 1 some, 3 all - with the CS flag)."""
    blk = Block()
    h = s // 2
    parts = []
    sat = blk.local(1, "0")
    count = 0
    for v in (o[1], o[2]):
        for i in range(16 // s):
            e = blk.elem(v, i, s)
            if kind == "t":
                parts.append(blk.local(h, f"{e}:{h}"))
                continue
            if kind == "s":
                mx, mn = (1 << (8 * h - 1)) - 1, -(1 << (8 * h - 1))
                hi = blk.local(1, f"{e} s> {mx}")
                lo = blk.local(1, f"{e} s< {mn}")
                blk.add(f"{sat} = {sat} + {hi} + {lo};")
                tr = blk.local(h, f"{e}:{h}")
                parts.append(blk.local(h, f"zext({hi}) * {hex(mx)} + zext({lo}) * {hex(mn & ((1 << 8 * h) - 1))} + zext(!{hi} && !{lo}) * {tr}"))
            else:
                mx = (1 << (8 * h)) - 1
                hi = blk.local(1, f"{e} > {mx}")
                blk.add(f"{sat} = {sat} + {hi};")
                tr = blk.local(h, f"{e}:{h}")
                parts.append(blk.local(h, f"zext({hi}) * {hex(mx)} + zext(!{hi}) * {tr}"))
            count += 1
    r = assemble(blk, parts, h)
    blk.add(f"{o[0]} = {r};")
    if cs is not None:
        blk.add(f"local csf{blk.tag}:8 = {cs};")
        blk.add(f"if ((csf{blk.tag} & 1) == 0) goto <nocc{blk.tag}>;")
        blk.add(f"cc = zext({sat} != 0) * (1 + 2 * zext({sat} == {count}));")
        blk.add(f"<nocc{blk.tag}>")
    return blk.text()

def vup(o, s, signed, high):
    blk = Block()
    n = 16 // s
    base = 0 if high else n // 2
    ext = "sext" if signed else "zext"
    parts = [blk.local(2 * s, f"{ext}({blk.elem(o[1], base + i, s)})") for i in range(n // 2)]
    r = assemble(blk, parts, 2 * s)
    blk.add(f"{o[0]} = {r};")
    return blk.text()

def vperm(o):
    blk = Block()
    parts = []
    for i in range(16):
        sel = blk.elem(o[3], i, 1)
        ix = blk.local(1, f"{sel} & 0x1f")
        hi = blk.local(1, f"{ix} >= 16")
        i2 = blk.local(8, f"zext({ix} & 15)")
        a = get_rt(blk, o[1], i2, 1)
        b = get_rt(blk, o[2], i2, 1)
        parts.append(blk.local(1, f"zext({hi}) * {b} + zext(!{hi}) * {a}"))
    r = assemble(blk, parts, 1)
    blk.add(f"{o[0]} = {r};")
    return blk.text()

def vpdi(o):
    blk = Block()
    blk.add(f"local mm{blk.tag}:8 = {o[3]};")
    a0, a1 = blk.elem(o[1], 0, 8), blk.elem(o[1], 1, 8)
    b0, b1 = blk.elem(o[2], 0, 8), blk.elem(o[2], 1, 8)
    l = blk.local(8, f"zext((mm{blk.tag} & 4) != 0) * {a1} + zext((mm{blk.tag} & 4) == 0) * {a0}")
    r = blk.local(8, f"zext((mm{blk.tag} & 1) != 0) * {b1} + zext((mm{blk.tag} & 1) == 0) * {b0}")
    blk.add(f"{o[0]} = {assemble(blk, [l, r], 8)};")
    return blk.text()

def vseg(o, s):
    blk = Block()
    parts = []
    for d in range(2):
        e = blk.elem(o[1], (d + 1) * (8 // s) - 1, s)
        parts.append(blk.local(8, f"sext({e})"))
    blk.add(f"{o[0]} = {assemble(blk, parts, 8)};")
    return blk.text()

def vmul_eo(o, s, signed, odd, add=None):
    """Widening multiply of even/odd elements [+ double-width addend vector]."""
    blk = Block()
    ext = "sext" if signed else "zext"
    parts = []
    for i in range(8 // s):
        j = 2 * i + (1 if odd else 0)
        a, b = blk.elem(o[1], j, s), blk.elem(o[2], j, s)
        p = blk.local(2 * s, f"{ext}({a}) * {ext}({b})")
        if add:
            p = blk.local(2 * s, f"{p} + {blk.elem(add, i, 2 * s)}")
        parts.append(p)
    blk.add(f"{o[0]} = {assemble(blk, parts, 2 * s)};")
    return blk.text()

def vma(o, s, kind):
    """VMAL: low(a*b+c); VMAH/VMALH: high half of the double-width a*b+c (signed/unsigned)."""
    blk = Block()
    parts = []
    signed = kind == "h"
    ext = "sext" if signed else "zext"
    for i in range(16 // s):
        a, b, c = blk.elem(o[1], i, s), blk.elem(o[2], i, s), blk.elem(o[3], i, s)
        if kind == "l":
            parts.append(blk.local(s, f"{a} * {b} + {c}"))
        else:
            p = blk.local(2 * s, f"{ext}({a}) * {ext}({b}) + {ext}({c})")
            q = blk.local(2 * s, f"{p} >> {8 * s}")
            parts.append(blk.local(s, f"{q}:{s}"))
    blk.add(f"{o[0]} = {assemble(blk, parts, s)};")
    return blk.text()

def vsum(o, s, ts):
    """Sum elements of size s of V2 within each target element of size ts, plus the rightmost
    element (size s) of the corresponding target element of V3."""
    blk = Block()
    parts = []
    per = ts // s
    for t in range(16 // ts):
        acc = blk.local(ts, "0" if ts <= 8 else "zext(0:8)")
        for j in range(per):
            e = blk.elem(o[1], t * per + j, s)
            blk.add(f"{acc} = {acc} + zext({e});")
        e3 = blk.elem(o[2], t * per + per - 1, s)
        blk.add(f"{acc} = {acc} + zext({e3});")
        parts.append(acc)
    blk.add(f"{o[0]} = {assemble(blk, parts, ts)};")
    return blk.text()

def vshift_scalar(o, s, op):
    blk = Block()
    bits = 8 * s
    blk.add(f"local am{blk.tag}:8 = {o[2]} & {bits - 1};")
    amt = blk.local(s, f"am{blk.tag}:{s}" if s < 8 else f"am{blk.tag}")
    fn = _shift(op, op == "rot")
    parts = [fn(blk, blk.elem(o[1], i, s), amt, s) for i in range(16 // s)]
    blk.add(f"{o[0]} = {assemble(blk, parts, s)};")
    return blk.text()

def vshift_whole(o, op, unit):
    """VSL/VSRL/VSRA shift each byte by the bit count (0-7) in the corresponding byte of V3,
    taking bits from the neighbouring byte (z15 definition; earlier models required all
    counts equal). VSLB/VSRLB/VSRAB shift the whole vector by bytes (byte 7 of V3, bits 1-4)."""
    blk = Block()
    if unit == "byte":
        b7 = blk.elem(o[2], 7, 1)
        cnt = blk.local(16, f"zext(({b7} >> 3) & 15) * 8")
        blk.add(f"{o[0]} = {o[1]} {op} {cnt};")
        return blk.text()
    a = [blk.elem(o[1], i, 1) for i in range(16)]
    sign = blk.local(1, f"zext({a[0]} s< 0) * 0xff") if op == "s>>" else blk.local(1, "0")
    zero = blk.local(1, "0")
    parts = []
    for i in range(16):
        c = blk.local(1, f"{blk.elem(o[2], i, 1)} & 7")
        if op == "<<":
            nxt = a[i + 1] if i < 15 else zero
            w = blk.local(2, f"((zext({a[i]}) << 8) | zext({nxt})) << {c}")
            hi = blk.local(2, f"{w} >> 8")
            parts.append(blk.local(1, f"{hi}:1"))
        else:
            prv = a[i - 1] if i > 0 else sign
            w = blk.local(2, f"((zext({prv}) << 8) | zext({a[i]})) >> {c}")
            parts.append(blk.local(1, f"{w}:1"))
    blk.add(f"{o[0]} = {assemble(blk, parts, 1)};")
    return blk.text()

def vsldb(o, kind):
    blk = Block()
    blk.add(f"local sh{blk.tag}:8 = {o[3]};")
    hi = blk.local(32, f"(zext({o[1]}) << 128) | zext({o[2]})")
    if kind == "byte":
        r = blk.local(32, f"{hi} << ((sh{blk.tag} & 15) * 8)")
        blk.add(f"local rr{blk.tag}:32 = {r} >> 128; {o[0]} = rr{blk.tag}:16;")
    elif kind == "left":
        r = blk.local(32, f"{hi} << (sh{blk.tag} & 7)")
        blk.add(f"local rr{blk.tag}:32 = {r} >> 128; {o[0]} = rr{blk.tag}:16;")
    else:
        r = blk.local(32, f"{hi} >> (sh{blk.tag} & 7)")
        blk.add(f"{o[0]} = {r}:16;")
    return blk.text()

def vtm(o):
    return (f"local sel:16 = {o[0]} & {o[1]};\n"
            f"cc = zext(sel != 0) * (1 + 2 * zext(sel == {o[1]}));")

def vcksm(o):
    blk = Block()
    acc = blk.local(8, f"zext({blk.elem(o[2], 1, 4)})")
    for i in range(4):
        e = blk.elem(o[1], i, 4)
        blk.add(f"{acc} = {acc} + zext({e}); {acc} = ({acc} & 0xffffffff) + ({acc} >> 32);")
    r = blk.local(4, f"{acc}:4")
    z = blk.local(4, "0")
    blk.add(f"{o[0]} = {assemble(blk, [z, r, z, z], 4)};")
    return blk.text()

def vll(o, store, right=False, lenexpr=None):
    """VLL/VSTL: min(len+1,16) bytes at the left; VLRL/VSTRL: at the right."""
    blk = Block()
    ln = lenexpr if lenexpr else f"zext({o[1]}:4)"      # the length is bits 32-63 of R3
    blk.add(f"local ln{blk.tag}:8 = {ln};")
    ea = o[2] if not right else o[1]
    blk.add(f"local p{blk.tag}:8 = {ea};")
    v = o[0]
    if not store:
        blk.add(f"local acc{blk.tag}:16 = zext(0:8);")
    for i in range(16):
        pos = i if not right else 15 - i
        blk.add(f"if ({i} > ln{blk.tag}) goto <x{blk.tag}_{i}>;")
        if not right:
            src_byte = i
        if store:
            e = blk.elem(v, pos, 1)
            addr = f"p{blk.tag} + {i}" if not right else f"p{blk.tag} + (ln{blk.tag} - {i})"
            blk.add(f"*:1 ({addr}) = {e};")
        else:
            addr = f"p{blk.tag} + {i}" if not right else f"p{blk.tag} + (ln{blk.tag} - {i})"
            bt = blk.local(1, f"*:1 ({addr})")
            blk.add(f"acc{blk.tag} = acc{blk.tag} | (zext({bt}) << {8 * (15 - pos)});")
        blk.add(f"<x{blk.tag}_{i}>")
    if not store:
        blk.add(f"{v} = acc{blk.tag};")
    return blk.text()

def vgfm(o, s, acc=None):
    """Galois-field (carry-less) multiply-sum: XOR of the two double-width carry-less products of
    each element pair [XOR the double-width addend]."""
    blk = Block()
    parts = []
    for i in range(8 // s):
        res = blk.local(2 * s, "0" if 2 * s <= 8 else "zext(0:8)")
        for j in (2 * i, 2 * i + 1):
            a, b = blk.elem(o[1], j, s), blk.elem(o[2], j, s)
            wa = blk.local(2 * s, f"zext({a})")
            bt = f"bt{blk.tag}_{uid()}"
            close = loop(blk, bt, 0, 8 * s)
            blk.add(f"{res} = {res} ^ ({wa} << {bt}) * zext((({b} >> {bt}) & 1) != 0);")
            blk.add(close)
        if acc:
            blk.add(f"{res} = {res} ^ {blk.elem(acc, i, 2 * s)};")
        parts.append(res)
    blk.add(f"{o[0]} = {assemble(blk, parts, 2 * s)};")
    return blk.text()

def vreverse(o, s, mode, store=False):
    """vlbr/vstbr: byte-reverse each element; vler/vster: reverse the element order."""
    blk = Block()
    if store:
        src = o[0]
    else:
        src = blk.local(16, f"*:16 {o[1]}")
    n = 16 // s
    if mode == "br":
        parts = [byterev(blk, blk.elem(src, i, s), s) for i in range(n)]
    else:
        parts = [blk.elem(src, n - 1 - i, s) for i in range(n)]
    r = assemble(blk, parts, s)
    blk.add(f"*:16 {o[1]} = {r};" if store else f"{o[0]} = {r};")
    return blk.text()

def vec(o, s, signed):
    """VECTOR ELEMENT COMPARE (LOGICAL): the rightmost element of the leftmost doubleword."""
    blk = Block()
    idx = max(0, 8 // s - 1)
    a, b = blk.elem(o[0], idx, s), blk.elem(o[1], idx, s)
    blk.add(f"cc = zext({a} {'s<' if signed else '<'} {b}) + zext({a} {'s>' if signed else '>'} {b}) * 2;")
    return blk.text()

def batch2(ctx):
    n, o = ctx["name"], ctx["ops"]
    # halfword forms whose plain name would collide with another mnemonic
    hw = {"vuplhw": lambda: vup(o, 2, True, False), "vmlhw": lambda: elementwise(o[0], o[1], o[2], 2, _bin("*")),
          "vmalhw": lambda: vma(o, 2, "l")}
    if n in hw:
        return hw[n]()
    # VLLEBRZ/VSTEBR extended mnemonics: byte-reversed element 0 (doubleword) / leftmost word
    if n in ("ldrv", "lerv"):
        return vllez(o, 8 if n == "ldrv" else 4, n == "lerv", True)
    if n in ("stdrv", "sterv"):
        blk = Block()
        s_ = 8 if n == "stdrv" else 4
        e = byterev(blk, blk.elem(o[0], 0, s_), s_)
        blk.add(f"*:{s_} {o[1]} = {e};")
        return blk.text()
    m = re.fullmatch(r"vec(l?)([bhfg]?)", n)
    if m:
        return sized(n, "vec" + m.group(1), 2, o, lambda s: vec(o, s, not m.group(1)))
    m = re.fullmatch(r"vrep([bhfg]?)", n)
    if m:
        return sized(n, "vrep", 3, o, lambda s: vrep(o, s))
    m = re.fullmatch(r"vrepi([bhfg]?)", n)
    if m:
        return sized(n, "vrepi", 2, o, lambda s: vrepi(o, s))
    m = re.fullmatch(r"vlei([bhfg])", n)
    if m:
        return vlei(o, SIZES[m.group(1)])
    m = re.fullmatch(r"v(l|st)e(br)?([bhfg])", n)
    if m:
        return vle(o, SIZES[m.group(3)], m.group(1) == "st", m.group(2) == "br")
    m = re.fullmatch(r"vl(br)?rep([bhfg]?)", n)
    if m:
        return sized(n, "vlbrrep" if m.group(1) else "vlrep", 2, o, lambda s: vlrep(o, s, bool(m.group(1))))
    m = re.fullmatch(r"vll(e|ebr)z(lf|[bhfg]?)", n)
    if m:
        rev = m.group(1) == "ebr"
        if m.group(2) == "lf":
            return vllez(o, 4, True, rev)
        base = "vllebrz" if rev else "vllez"
        return sized(n, base, 2, o, lambda s: vllez(o, s, False, rev))
    m = re.fullmatch(r"vlvg([bhfg]?)", n)
    if m:
        return sized(n, "vlvg", 3, o, lambda s: vlvg(o, s))
    m = re.fullmatch(r"vlgv([bhfg]?)", n)
    if m:
        return sized(n, "vlgv", 3, o, lambda s: vlgv(o, s))
    if n == "vlvgp":
        return f"{o[0]} = (zext({o[1]}) << 64) | zext({o[2]});"
    m = re.fullmatch(r"vgm([bhfg]?)", n)
    if m:
        return sized(n, "vgm", 3, o, lambda s: vgm(o, s))
    m = re.fullmatch(r"vmr(h|l)([bhfg]?)", n)
    if m:
        return sized(n, "vmr" + m.group(1), 3, o, lambda s: vmr(o, s, m.group(1) == "h"))
    m = re.fullmatch(r"vpk([hfg]?)", n)
    if m:
        return sized(n, "vpk", 3, o, lambda s: vpk(o, s, "t"), (2, 4, 8))
    m = re.fullmatch(r"vpk(s|ls)([hfg]?)(s?)", n)
    if m:
        kind = "s" if m.group(1) == "s" else "u"
        if m.group(2):
            return vpk(o, SIZES[m.group(2)], kind, "1" if m.group(3) else None)
        return dispatch({1: 2, 2: 4, 3: 8}, lambda s: vpk(o, s, kind, o[4] if len(o) > 4 else "0"), o[3])
    m = re.fullmatch(r"vup(l?)(h|l|lh|ll)?([bhf]?)", n)
    if m and n.startswith(("vuph", "vupl")):
        base = re.match(r"vup(lh|ll|h|l)", n).group(0)
        kind = base[3:]
        signed = kind in ("h", "l")
        high = kind in ("h", "lh")
        return sized(n, base, 2, o, lambda s: vup(o, s, signed, high), (1, 2, 4))
    if n == "vperm":
        return vperm(o)
    if n == "vpdi":
        return vpdi(o)
    m = re.fullmatch(r"vseg([bhf]?)", n)
    if m:
        return sized(n, "vseg", 2, o, lambda s: vseg(o, s), (1, 2, 4))
    m = re.fullmatch(r"vm(l?)(e|o)([bhf]?)", n)
    if m:
        base = n[:4] if not m.group(1) else n[:4]
        base = re.match(r"vml?[eo]", n).group(0)
        return sized(n, base, 3, o, lambda s: vmul_eo(o, s, not m.group(1), m.group(2) == "o"), (1, 2, 4))
    m = re.fullmatch(r"vma(l?)(e|o)([bhf]?)", n)
    if m:
        base = re.match(r"vmal?[eo]", n).group(0)
        return sized(n, base, 4, o, lambda s: vmul_eo(o, s, not m.group(1), m.group(2) == "o", o[3]), (1, 2, 4))
    m = re.fullmatch(r"vma(l|h|lh)([bhf]?)", n)
    if m:
        kind = {"l": "l", "h": "h", "lh": "lh"}[m.group(1)]
        return sized(n, "vma" + m.group(1), 4, o, lambda s: vma(o, s, kind), (1, 2, 4))
    m = re.fullmatch(r"vsum(g|q)?([bhfg]?)", n)
    if m:
        ts = {None: 4, "g": 8, "q": 16}[m.group(1)]
        base = "vsum" + (m.group(1) or "")
        return sized(n, base, 3, o, lambda s: vsum(o, s, ts), (1, 2) if ts == 4 else (2, 4) if ts == 8 else (4, 8))
    m = re.fullmatch(r"v(esl|esra|esrl|erll)([bhfg]?)", n)
    if m:
        op = {"esl": "<<", "esra": "s>>", "esrl": ">>", "erll": "rot"}[m.group(1)]
        return sized(n, "v" + m.group(1), 3, o, lambda s: vshift_scalar(o, s, op))
    m = re.fullmatch(r"vs(l|ra|rl)(b?)", n)
    if m:
        op = {"l": "<<", "ra": "s>>", "rl": ">>"}[m.group(1)]
        return vshift_whole(o, op, "byte" if m.group(2) else "bit")
    if n == "vsldb":
        return vsldb(o, "byte")
    if n in ("vsld", "vsrd"):
        return vsldb(o, "left" if n == "vsld" else "right")
    if n == "vtm":
        return vtm(o)
    if n == "vcksm":
        return vcksm(o)
    if n in ("vll", "vstl"):
        return vll(o, n == "vstl")
    if n in ("vlrl", "vstrl"):
        return vll(o, n == "vstrl", True, o[2])
    if n in ("vlrlr", "vstrlr"):
        return vll(o, n == "vstrlr", True, f"zext({o[1]}:4)")
    m = re.fullmatch(r"vgfm(a?)([bhfg]?)", n)
    if m:
        base = "vgfm" + m.group(1)
        return sized(n, base, 4 if m.group(1) else 3, o, lambda s: vgfm(o, s, o[3] if m.group(1) else None))
    m = re.fullmatch(r"v(l|st)(br|er)([hfgq]?)", n)
    if m:
        base = "v" + m.group(1) + m.group(2)
        return sized(n, base, 2, o, lambda s: vreverse(o, s, m.group(2), m.group(1) == "st"), (2, 4, 8, 16))
    return None

# ---------------------------------------------------------------------------------------------
# quadword carry arithmetic, multiply-sum, element rotate-and-insert, bit permute, strings

def vquad(o, kind):
    """VAC/VACCC/VSBI/VSBCBI (quadword): V2 + V3 (or + ~V3) + carry-in (V4 bit 127)."""
    blk = Block()
    b = o[2] if kind in ("ac", "accc") else f"~{o[2]}"
    c = blk.local(16, f"{o[3]} & zext(1:8)")
    a = blk.local(16, o[1])
    bb = blk.local(16, b)
    s1 = blk.local(16, f"{a} + {bb}")
    if kind in ("ac", "sbi"):
        blk.add(f"{o[0]} = {s1} + {c};")
    else:
        co = blk.local(1, f"carry({a}, {bb}) || carry({s1}, {c})")
        blk.add(f"{o[0]} = zext({co});")
    return blk.text()

def vmsl(o, m6):
    blk = Block()
    blk.add(f"local sf{blk.tag}:8 = {m6};")
    p = []
    for i, bit in ((0, 8), (1, 4)):
        a = blk.local(16, f"zext({blk.elem(o[1], i, 8)})")
        b = blk.local(16, f"zext({blk.elem(o[2], i, 8)})")
        p.append(blk.local(16, f"({a} * {b}) << zext((sf{blk.tag} & {bit}) != 0)"))
    blk.add(f"{o[0]} = {p[0]} + {p[1]} + {o[3]};")
    return blk.text()

def verim(o, s):
    blk = Block()
    bits = 8 * s
    blk.add(f"local am{blk.tag}:8 = {o[3]} & {bits - 1};")
    amt = blk.local(s, f"am{blk.tag}:{s}" if s < 8 else f"am{blk.tag}")
    parts = []
    for i in range(16 // s):
        b, m, a = blk.elem(o[1], i, s), blk.elem(o[2], i, s), blk.elem(o[0], i, s)
        r = blk.local(s, f"({b} << {amt}) | ({b} >> (({bits} - {amt}) & {bits - 1}))")
        parts.append(blk.local(s, f"({a} & ~{m}) | ({r} & {m})"))
    blk.add(f"{o[0]} = {assemble(blk, parts, s)};")
    return blk.text()

def vbperm(o):
    blk = Block()
    acc = blk.local(2, "0")
    for i in range(16):
        ix = blk.elem(o[2], i, 1)
        sh = blk.local(16, f"zext(127 - {ix})")
        t = blk.local(16, f"({o[1]} >> {sh}) & zext(1:8)")
        bit = blk.local(2, f"{t}:2 * zext({ix} < 128)")
        blk.add(f"{acc} = {acc} | ({bit} << {15 - i});")
    blk.add(f"{o[0]} = zext({acc}) << 64;")
    return blk.text()

def first_index(blk, conds, s):
    """Byte index of the first true condition, 16 if none."""
    idx = blk.local(8, "16")
    for i in reversed(range(len(conds))):
        blk.add(f"{idx} = zext({conds[i]}) * {i * s} + zext(!{conds[i]}) * {idx};")
    return idx

def string_cc(blk, fm, fz):
    """0: zero found first (or only); 1: matches but no zero; 2: match before zero; 3: neither."""
    return (f"cc = zext({fz} == 16) * (zext({fm} == 16) * 3 + zext({fm} != 16)) + "
            f"zext({fz} != 16) * zext({fm} < {fz}) * 2;")

def elem_at(blk, v, idx, s):
    """Element of size s at run-time element index idx (8-byte local) of vector v."""
    sh = blk.local(8, f"{128 - 8 * s} - {idx} * {8 * s}", "sh")
    w = blk.local(16, f"{v} >> {sh}", "w")
    return blk.local(s, f"{w}:{s}", "e"), sh

def loop(blk, var, start, stop, step=1):
    """Open a counted loop: var runs start, start+step, ... while var < stop (all 8-byte).
    Returns the closing text to add after the body."""
    top = f"lp{blk.tag}_{uid()}"
    blk.add(f"local {var}:8 = {start};")
    blk.add(f"<{top}>")
    return f"{var} = {var} + {step};\nif ({var} < {stop}) goto <{top}>;"

def vstring(kind, o, s, flags):
    """VFAE/VFEE/VFENE/VISTR/VSTRC/VSTRS for element size s. flags: M flag value expression
    (IN 8, RT 4, ZS 2, CS 1). Element loops (the unrolled form is quadratic in the number of
    elements)."""
    blk = Block()
    t = blk.tag
    n = 16 // s
    blk.add(f"local fl{t}:8 = {flags};")
    zs = blk.local(1, f"(fl{t} & 2) != 0")
    inv = blk.local(1, f"(fl{t} & 8) != 0")
    rt = blk.local(1, f"(fl{t} & 4) != 0")
    fm = blk.local(8, "16")             # byte index of the first match, 16 if none
    fz = blk.local(8, "16")             # byte index of the first zero element (with ZS), 16 if none
    msk = blk.local(16, "zext(0:8)")
    sm = blk.local(1, "0")              # VFENE: first mismatch has a(i) < b(i)
    seen = blk.local(1, "0")            # VISTR: zero element seen
    i, j, d = f"i{t}", f"j{t}", f"d{t}"
    if kind == "strs":
        b7 = blk.elem(o[3], 7, 1)
        el = blk.local(8, f"zext({b7}) >> {s.bit_length() - 1}")
        bz = blk.local(8, "16")         # element index of the first zero element of V3
        close = loop(blk, j, 0, n)
        bj, _ = elem_at(blk, o[2], j, s)
        blk.add(f"{bz} = zext({bj} == 0 && {bz} == 16) * {j} + zext(!({bj} == 0 && {bz} == 16)) * {bz};")
        blk.add(close)
        blk.add(f"if (!{zs}) goto <nz{t}>;")
        blk.add(f"{el} = zext({el} < {n}) * {el} + zext({el} >= {n}) * {n};")
        blk.add(f"{el} = zext({el} < {bz}) * {el} + zext({el} >= {bz}) * {bz};")
        blk.add(f"<nz{t}>")
        k = blk.local(8, "16")          # element index of the first full or partial match
    close_i = loop(blk, i, 0, n)
    ai, shi = elem_at(blk, o[1], i, s)
    pos = blk.local(8, f"{i} * {s}")
    z = blk.local(1, f"{zs} && ({ai} == 0)")
    blk.add(f"{fz} = zext({z} && {fz} == 16) * {pos} + zext(!({z} && {fz} == 16)) * {fz};")
    if kind in ("fae", "strc", "fee", "fene"):
        if kind == "fae":
            r = blk.local(1, "0")
            cj = loop(blk, j, 0, n)
            bj, _ = elem_at(blk, o[2], j, s)
            blk.add(f"{r} = {r} || ({ai} == {bj});")
            blk.add(cj)
            blk.add(f"{r} = {r} != {inv};")
        elif kind == "strc":
            r = blk.local(1, "0")
            cj = loop(blk, j, 0, n, 2)
            tt = []
            for off in (0, 1):
                jj = blk.local(8, f"{j} + {off}")
                bj, _ = elem_at(blk, o[2], jj, s)
                c, _ = elem_at(blk, o[3], blk.local(8, f"{jj} * {s}"), 1)
                tt.append(blk.local(1, f"(({ai} == {bj}) && (({c} & 0x80) != 0)) || (({ai} < {bj}) && (({c} & 0x40) != 0)) || "
                                       f"(({ai} > {bj}) && (({c} & 0x20) != 0))"))
            blk.add(f"{r} = {r} || ({tt[0]} && {tt[1]});")
            blk.add(cj)
            blk.add(f"{r} = {r} != {inv};")
        else:
            bi, _ = elem_at(blk, o[2], i, s)
            r = blk.local(1, f"{ai} {'==' if kind == 'fee' else '!='} {bi}")
            if kind == "fene":
                first = blk.local(1, f"{r} && ({fm} == 16)")
                blk.add(f"{sm} = ({first} && ({ai} < {bi})) || (!{first} && {sm});")
        blk.add(f"{fm} = zext({r} && {fm} == 16) * {pos} + zext(!({r} && {fm} == 16)) * {fm};")
        if kind in ("fae", "strc"):
            me = blk.local(s, f"-zext({r})")
            blk.add(f"{msk} = {msk} | (zext({me}) << {shi});")
    elif kind == "istr":
        blk.add(f"{seen} = {seen} || ({ai} == 0);")
        part = blk.local(s, f"{ai} * zext(!{seen})" if s > 1 else f"{ai} * {seen} ^ {ai}")
        blk.add(f"{msk} = {msk} | (zext({part}) << {shi});")
    else:   # strs: does the substring V3[0:el) match (fully, or partially at the end) at i?
        mt = blk.local(1, "1")
        cd = loop(blk, d, 0, f"{n} - {i}")
        ad, _ = elem_at(blk, o[1], blk.local(8, f"{i} + {d}"), s)
        bd, _ = elem_at(blk, o[2], d, s)
        blk.add(f"{mt} = {mt} && (({d} >= {el}) || ({ad} == {bd}));")
        blk.add(cd)
        blk.add(f"{k} = zext({mt} && {k} == 16) * {i} + zext(!({mt} && {k} == 16)) * {k};")
    blk.add(close_i)
    if kind in ("fae", "strc"):
        mn = blk.local(8, f"zext({fm} < {fz}) * {fm} + zext({fm} >= {fz}) * {fz}")
        blk.add(f"{o[0]} = zext({rt}) * {msk} + zext(!{rt}) * (zext({mn}) << 64);")
        blk.add(f"if ((fl{t} & 1) == 0) goto <ns{t}>;")
        blk.add(string_cc(blk, fm, fz))
        blk.add(f"<ns{t}>")
    elif kind in ("fee", "fene"):
        mn = blk.local(8, f"zext({fm} < {fz}) * {fm} + zext({fm} >= {fz}) * {fz}")
        blk.add(f"{o[0]} = zext({mn}) << 64;")
        blk.add(f"if ((fl{t} & 1) == 0) goto <ns{t}>;")
        if kind == "fee":
            blk.add(string_cc(blk, fm, fz))
        else:
            blk.add(f"cc = zext({fz} == 16 && {fm} == 16) * 3 + zext(!({fz} == 16 && {fm} == 16)) * "
                    f"zext({fz} >= {fm}) * (2 - zext({sm}));")
        blk.add(f"<ns{t}>")
    elif kind == "istr":
        blk.add(f"{o[0]} = {msk};")
        blk.add(f"if ((fl{t} & 1) == 0) goto <ns{t}>;")
        blk.add(f"cc = 3 * zext(!{seen});")
        blk.add(f"<ns{t}>")
    else:
        sl0 = blk.local(8, f"{fz} >> {s.bit_length() - 1}")     # element index; 16 >> .. if none
        blk.add(f"{sl0} = zext({fz} == 16) * 16 + zext({fz} != 16) * {sl0};")
        blk.add(f"{sl0} = zext({sl0} > {n}) * {n} + zext({sl0} <= {n}) * {sl0};")
        res = blk.local(8, f"{k}")
        blk.add(f"cc = zext({k} == 16) * zext({sl0} != {n}) + zext({k} != 16) * "
                f"(zext({k} > {sl0}) + zext({k} <= {sl0}) * (2 + zext({n} - {k} < {el})));")
        blk.add(f"{res} = zext({k} == 16 || {k} > {sl0}) * {n} + zext({k} != 16 && {k} <= {sl0}) * {k};")
        blk.add(f"{res} = zext({el} != 0) * {res};")
        blk.add(f"cc = zext({el} != 0) * cc + zext({el} == 0) * 2;")
        blk.add(f"{o[0]} = zext({res} << {s.bit_length() - 1}) << 64;")
    return blk.text()

STRING_ARGS = {      # kind: (index of the M element-size operand in base form, number of vector operands)
    "fae": 3, "fee": 3, "fene": 3, "istr": 2, "strc": 4, "strs": 4}

def batch3(ctx):
    n, o = ctx["name"], ctx["ops"]
    m = re.fullmatch(r"v(ac|accc|sbi|sbcbi)(q?)", n)
    if m:
        return vquad(o, m.group(1))
    m = re.fullmatch(r"vmsl(g?)", n)
    if m:
        return vmsl(o, o[4] if m.group(1) else (o[5] if len(o) > 5 else "0"))
    m = re.fullmatch(r"verim([bhfg]?)", n)
    if m:
        return sized(n, "verim", 4, o, lambda s: verim(o, s))
    if n == "vbperm":
        return vbperm(o)
    m = re.fullmatch(r"v(fae|fee|fene|istr|strc|strs)(z?)([bhf]?)(s?)", n)
    if m:
        kind, z, suf, cs = m.groups()
        nv = STRING_ARGS[kind]
        fixed = (2 if z else 0) | (1 if cs else 0)
        if kind == "strs":
            fixed |= 1                          # VSTRS always sets the condition code
        if suf:
            fl = o[nv] if len(o) > nv else "0"
            flags = f"({fl}) | {fixed}"
            return vstring(kind, o, SIZES[suf], flags)
        fl = o[nv + 1] if len(o) > nv + 1 else "0"
        return dispatch({0: 1, 1: 2, 2: 4}, lambda s: vstring(kind, o, s, f"({fl}) | {fixed}"), o[nv])
    return None

# ---------------------------------------------------------------------------------------------
# z17 (vector-enhancements facility 3) and the remaining vector loads/stores

def vgather(o, vx, s, store):
    """VGEF/VGEG/VSCEF/VSCEG: element M3 addressed by D2 + B2 + element M3 of the index vector."""
    blk = Block()
    blk.add(f"local ix{blk.tag}:8 = {o[2]} & {16 // s - 1};")
    off = get_rt(blk, vx, f"ix{blk.tag}", s)
    ea = blk.local(8, f"{o[1]} + zext({off})" if s < 8 else f"{o[1]} + {off}")
    if store:
        e = get_rt(blk, o[0], f"ix{blk.tag}", s)
        blk.add(f"*:{s} {ea} = {e};")
    else:
        v = blk.local(s, f"*:{s} {ea}")
        set_rt(blk, o[0], f"ix{blk.tag}", s, v)
    return blk.text()

def vlbb(o):
    """VECTOR LOAD TO BLOCK BOUNDARY: bytes up to the next 64 << M3 byte boundary (at most 16);
    the remaining bytes of V1 are left unchanged (architecturally unpredictable)."""
    blk = Block()
    t = blk.tag
    blk.add(f"local bs{t}:8 = 64 << ({o[2]} & 7);")
    n = blk.local(8, f"bs{t} - ({o[1]} & (bs{t} - 1))")
    acc = blk.local(16, o[0])
    for i in range(16):
        blk.add(f"if ({n} <= {i}) goto <lb{t}>;")
        b = blk.local(1, f"*:1 ({o[1]} + {i})")
        sh = 8 * (15 - i)
        blk.add(f"{acc} = ({acc} & ~(zext(0xff:1) << {sh})) | (zext({b}) << {sh});")
    blk.add(f"<lb{t}>")
    blk.add(f"{o[0]} = {acc};")
    return blk.text()

def vblend(o, s):
    blk = Block()
    parts = []
    for i in range(16 // s):
        a, b, c = blk.elem(o[1], i, s), blk.elem(o[2], i, s), blk.elem(o[3], i, s)
        m = blk.local(1, f"{c} s< 0")
        parts.append(blk.local(s, f"zext({m}) * {a} + zext(!{m}) * {b}" if s < 16 else
                               f"(zext({m}) * {a}) + (zext(!{m}) * {b})"))
    blk.add(f"{o[0]} = {assemble(blk, parts, s)};")
    return blk.text()

def vdiv(o, s, signed, rem, idc):
    """VD/VDL/VR/VRL: a zero divisor (or, signed, the most negative value divided by -1) gives
    0 when the IDC bit of M5 is set and an integer-divide exception otherwise; p-code cannot
    raise the exception, so 0 is produced either way."""
    blk = Block()
    parts = []
    op = ("s%" if rem else "s/") if signed else ("%" if rem else "/")
    for i in range(16 // s):
        a, b = blk.elem(o[1], i, s), blk.elem(o[2], i, s)
        z = ZEROS(s)
        bad = blk.local(1, f"{b} == {z}")
        if signed:
            mn = f"{1 << (8 * s - 1)}:{s}" if s < 16 else "zext(1:8) << 127"
            ones = f"{(1 << 8 * s) - 1}:{s}" if s < 16 else "~zext(0:8)"
            blk.add(f"{bad} = {bad} || (({a} == {mn}) && ({b} == {ones}));")
        d = blk.local(s, f"{b} + zext({bad})")
        q = blk.local(s, f"{a} {op} {d}")
        parts.append(blk.local(s, f"{q} * zext(!{bad})"))
    blk.add(f"{o[0]} = {assemble(blk, parts, s)};")
    return blk.text()

def ZEROS(s):
    return f"0:{s}" if s < 16 else "zext(0:8)"

def veval(o):
    blk = Block()
    blk.add(f"local tt{blk.tag}:8 = {o[4]};")
    a, b, c = o[1], o[2], o[3]
    acc = blk.local(16, "zext(0:8)")
    for k in range(8):
        terms = [(a if k & 4 else f"~{a}"), (b if k & 2 else f"~{b}"), (c if k & 1 else f"~{c}")]
        m = blk.local(16, f"-zext((tt{blk.tag} >> {7 - k}) & 1)")
        blk.add(f"{acc} = {acc} | ({m} & ({terms[0]}) & ({terms[1]}) & ({terms[2]}));")
    blk.add(f"{o[0]} = {acc};")
    return blk.text()

def vgem(o, s):
    """Element i of V1 is all ones when bit i (from the left) of word 0 of V2 is one."""
    blk = Block()
    w = blk.elem(o[1], 0, 4)
    parts = []
    for i in range(16 // s):
        bit = blk.local(1, f"(({w} >> {31 - i}) & 1) != 0")
        parts.append(blk.local(s, f"-zext({bit})" if s < 16 else f"~zext(0:8) * zext({bit})"))
    blk.add(f"{o[0]} = {assemble(blk, parts, s)};")
    return blk.text()

def batch4(ctx):
    n, o = ctx["name"], ctx["ops"]
    m = re.fullmatch(r"v(ge|sce)(f|g)", n)
    if m and ctx.get("vindex"):
        return vgather(o, ctx["vindex"], SIZES[m.group(2)], m.group(1) == "sce")
    if n == "vlbb":
        return vlbb(o)
    m = re.fullmatch(r"vblend([bhfgq]?)", n)
    if m:
        return sized(n, "vblend", 4, o, lambda s: vblend(o, s), (1, 2, 4, 8, 16))
    m = re.fullmatch(r"v(d|dl|r|rl)([fgq]?)", n)
    if m:
        base = "v" + m.group(1)
        idc = o[3] if m.group(2) else (o[4] if len(o) > 4 else "0")
        return sized(n, base, 3, o, lambda s: vdiv(o, s, m.group(1) in ("d", "r"), m.group(1) in ("r", "rl"), idc), (4, 8, 16))
    if n == "veval":
        return veval(o)
    m = re.fullmatch(r"vgem([bhfgq]?)", n)
    if m:
        return sized(n, "vgem", 2, o, lambda s: vgem(o, s), (1, 2, 4, 8, 16))
    # 64-bit element forms of the multiply family (z17)
    m = re.fullmatch(r"vm(l?)(e|o)g", n)
    if m:
        return vmul_eo(o, 8, not m.group(1), m.group(2) == "o")
    m = re.fullmatch(r"vma(l?)(e|o)g", n)
    if m:
        return vmul_eo(o, 8, not m.group(1), m.group(2) == "o", o[3])
    m = re.fullmatch(r"vma(l|h|lh)(g|q)", n)
    if m:
        return vma(o, SIZES[m.group(2)], m.group(1))
    m = re.fullmatch(r"vup(h|l|lh|ll)g", n)
    if m:
        k = m.group(1)
        return vup(o, 8, k in ("h", "l"), k in ("h", "lh"))
    m = re.fullmatch(r"vec(l?)q", n)
    if m:
        return vec(o, 16, not m.group(1))
    return None
