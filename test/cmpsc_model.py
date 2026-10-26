"""Reference model of COMPRESSION CALL (CMPSC) written from the Principles of Operation: the
dictionary formats of Appendix D and the compression / expansion flowcharts (figures 7-217 to
7-222). It also builds dictionaries for tests (a trie of character strings is laid out as a
compression dictionary with sibling descriptors and the matching expansion dictionary)."""
import random

# ---------------------------------------------------------------- dictionary construction

class Node:
    def __init__(self, label, children=None):
        self.label = list(label)          # first character is the child character in the parent
        self.children = children or []
        self.index = None


def alphabet(extra=None):
    """256 alphabet nodes; extra: {first char: [Node, ...]} children"""
    extra = extra or {}
    return [Node([c], extra.get(c, [])) for c in range(256)]


def _needs_exam(n):
    return len(n.label) > 1 or bool(n.children)


def build(alpha, fmt1=False, entries=512, order_sort=False):
    """returns (comp, exp, nodes): comp / exp are lists of 8-byte entries (bytes); nodes in index order"""
    comp = [bytes(8)] * entries
    exp = [bytes(8)] * entries
    nodes = {}
    nxt = [256]
    sdpos = {}
    # allocate indices breadth first
    queue = list(alpha)
    for i, n in enumerate(alpha):
        n.index = i
        nodes[i] = n
        n.parent = None
        n.depth_label = [i]
    layout = {}
    qi = 0
    while qi < len(queue):
        p = queue[qi]
        qi += 1
        ch = p.children
        if not ch:
            continue
        if order_sort:
            ch.sort(key=lambda c: c.label)
        d = 1 if (p.index >= 256 and len(p.label) == 2 and len(ch) >= 2) else 0
        n0 = 5 - d if len(ch) >= 2 else 1
        sdcap = 14 if fmt1 else 7
        pos = nxt[0]
        p.cptr = pos
        plan = []                   # sequence of ("c", node) / ("sd", [nodes])
        first = ch[:n0]
        rest = ch[n0:]
        for c in first:
            plan.append(("c", c))
        while rest:
            grp, rest = rest[:sdcap], rest[sdcap:]
            plan.append(("sd", grp, bool(rest)))
            for c in grp:
                plan.append(("c", c))
        for item in plan:
            if item[0] == "c":
                item[1].index = pos
                nodes[pos] = item[1]
                item[1].parent = p
                queue.append(item[1])
            else:
                sdpos[(p.index, id(item[1][0]))] = pos
                item[1][0]._sd = (pos, item)
            pos += 1
        nxt[0] = pos
        layout[p.index] = plan
    assert nxt[0] <= entries
    # compression entries
    for idx, n in list(nodes.items()):
        ch = n.children
        own = n.label[1:] if idx >= 256 else []
        e = bytearray(8)
        if len(ch) == 0:
            assert len(own) <= 4
            e[0] = 0
            e[1] = len(own) << 5
            e[3:3 + len(own)] = bytes(own)
        elif len(ch) == 1:
            assert len(own) <= 4
            c = ch[0]
            e[0] = (1 << 5) | (0x10 if _needs_exam(c) else 0)
            e[1] = (len(own) << 5) | (c.index >> 8)
            e[2] = c.index & 0xff
            e[3:3 + len(own)] = bytes(own)
            e[3 + len(own)] = c.label[0]
        else:
            assert len(own) <= 1
            d = len(own)
            n0 = 5 - d
            cct = len(ch) if len(ch) <= n0 else (6 - d)
            x = 0
            for j, c in enumerate(ch[:n0]):
                if _needs_exam(c):
                    x |= 0x10 >> j
            y = 0
            if len(ch) > n0:
                sib = ch[n0:]
                cap = 14 if fmt1 else 7
                first = sib[:cap]
                bits = [1 if _needs_exam(c) else 0 for c in first]
                lo = 12 if fmt1 else 5
                if len(bits) > lo:
                    y = (bits[lo] << 1) | (bits[lo + 1] if len(bits) > lo + 1 else 0)
            e[0] = (cct << 5) | x
            e[1] = ((y & 3) << 6) | (d << 5) | (ch[0].index >> 8)
            e[2] = ch[0].index & 0xff
            if d:
                e[3] = own[0]
            for j, c in enumerate(ch[:n0]):
                e[3 + d + j] = c.label[0]
        comp[idx] = bytes(e)
    # sibling descriptors
    for p_index, plan in layout.items():
        for item in plan:
            if item[0] != "sd":
                continue
            grp, more = item[1], item[2]
            pos = grp[0]._sd[0]
            n = len(grp)
            if fmt1:
                sct = 15 if more else n
                bits = [1 if _needs_exam(c) else 0 for c in grp[:12]]
                bits += [0] * (12 - len(bits))
                e = bytearray(8)
                e[0] = (sct << 4) | (bits[0] << 3) | (bits[1] << 2) | (bits[2] << 1) | bits[3]
                e[1] = sum(b << (7 - k) for k, b in enumerate(bits[4:12]))
                for k, c in enumerate(grp[:6]):
                    e[2 + k] = c.label[0]
                comp[pos] = bytes(e)
                e2 = bytearray(8)
                for k, c in enumerate(grp[6:14]):
                    e2[k] = c.label[0]
                exp[pos] = bytes(e2)
            else:
                sct = 0 if more else n
                bits = [1 if _needs_exam(c) else 0 for c in grp[:5]]
                bits += [0] * (5 - len(bits))
                e = bytearray(8)
                e[0] = (sct << 5) | sum(b << (4 - k) for k, b in enumerate(bits))
                for k, c in enumerate(grp):
                    e[1 + k] = c.label[0]
                comp[pos] = bytes(e)
    # expansion entries: node symbol = parent symbol + label
    def symbol(n):
        s = []
        while n is not None:
            s = (n.label if n.index >= 256 else [n.index]) + s
            n = n.parent
        return s
    for idx, n in nodes.items():
        if idx < 256:
            continue
        s = symbol(n)
        lab = n.label
        if len(s) <= 7 and (idx & 1):
            e = bytearray(8)
            e[0] = len(s)
            e[1:1 + len(s)] = bytes(s)
        else:
            assert len(lab) <= 5
            pp = n.parent.index
            e = bytearray(8)
            e[0] = (len(lab) << 5) | (pp >> 8)
            e[1] = pp & 0xff
            e[2:2 + len(lab)] = bytes(lab)
            e[7] = len(s) - len(lab)
        exp[idx] = bytes(e)
    return comp, exp, nodes


def random_trie(rng, alphabet_chars, depth=3, fan=(0, 9), allow_dup=True):
    def make(d, first):
        n = rng.choice(range(fan[0], fan[1]))
        if d >= depth:
            n = 0
        chars = []
        for _ in range(n):
            chars.append(rng.choice(alphabet_chars))
        if not allow_dup:
            chars = sorted(set(chars))
        kids = []
        for c in chars:
            nk = 0
            lab = [c]
            sub = make(d + 1, c)
            kids.append(Node(lab, sub))
        return kids
    extra = {}
    for c in alphabet_chars:
        kids = make(1, c)
        # additional extension characters: only when the node has fewer than two children
        def fix(nodes):
            for k in nodes:
                maxa = 1 if len(k.children) >= 2 else 4
                if rng.random() < 0.5:
                    k.label += [rng.choice(alphabet_chars) for _ in range(rng.randrange(0, maxa + 1))]
                fix(k.children)
        fix(kids)
        extra[c] = kids
    return alphabet(extra)


# ---------------------------------------------------------------- compression (figure 7-217 / 7-218)

def _parent(comp, idx, f1):
    e = comp[idx]
    cct = e[0] >> 5
    act = d = 0
    if cct == 0:
        ncc, ccoff, sd = 0, 3, 0
    elif cct == 1:
        act = min(e[1] >> 5, 4) if idx >= 256 else 0
        ncc, ccoff, sd = 1, 3 + act, 0
    else:
        d = ((e[1] >> 5) & 1) if idx >= 256 else 0
        ncc = cct
        sd = 0
        if d == 0:
            if cct >= 6:
                ncc, sd = 5, 1
        else:
            if cct >= 5:
                ncc, sd = 4, 1
        ccoff = 3 + d
    cptr = ((e[1] & 0x1f) << 8) | e[2]
    return dict(e=e, cct=cct, ncc=ncc, ccoff=ccoff, sd=sd, cptr=cptr)


def _aec(comp, idx):
    e = comp[idx]
    cct = e[0] >> 5
    if cct <= 1:
        n = min(e[1] >> 5, 4)
    else:
        n = (e[1] >> 5) & 1
    return list(e[3:3 + n])


def _xbit(p, j):
    e = p["e"]
    if p["cct"] == 1:
        return (e[0] >> 4) & 1
    return (e[0] >> (4 - j)) & 1 if j < 5 else 1


def _sd(comp, exp, sdi, f1):
    e = comp[sdi]
    if f1:
        n = e[0] >> 4
        more = False
        if n == 0 or n >= 15:
            n, more = (14, True)
        chars = list(e[2:8]) + list(exp[sdi][0:8])
        ybits = [(e[0] >> (3 - k)) & 1 for k in range(4)] + [(e[1] >> (7 - k)) & 1 for k in range(8)]
    else:
        n = e[0] >> 5
        more = False
        if n == 0:
            n, more = (7, True)
        chars = list(e[1:8])
        ybits = [(e[0] >> (4 - k)) & 1 for k in range(5)]
    return n, more, chars[:n], ybits


def compress_one(comp, exp, src, f1, op=False):
    """one index symbol: returns (index, consumed, adj) with adj 0 / +1 / -1 (order preservation)"""
    pi = src[0]
    p = 1
    while True:
        par = _parent(comp, pi, f1)
        if par["cct"] == 0:
            return pi, p, 0
        if p >= len(src):
            return pi, p, 0
        sc = src[p]
        e = par["e"]
        flag = 1
        matched = None
        j = 0
        restart = False
        while j < par["ncc"]:
            cc = e[par["ccoff"] + j]
            if op:
                if sc > cc:
                    j += 1
                    continue
                ci = par["cptr"] + j
                if sc != cc:
                    return ci, p, -1
                if not _xbit(par, j):
                    return ci, p + 1, 0
                aec = _aec(comp, ci)
                if not aec:
                    pi, p = ci, p + 1
                    restart = True
                    break
                for k, a in enumerate(aec):
                    if p + 1 + k >= len(src):
                        return ci, p, -1
                    s = src[p + 1 + k]
                    if s > a:
                        break
                    if s != a:
                        return ci, p, -1
                else:
                    pi, p = ci, p + 1 + len(aec)
                    restart = True
                    break
                j += 1
                continue
            if sc == cc:
                ci = par["cptr"] + j
                if not _xbit(par, j):
                    return ci, p + 1, 0
                aec = _aec(comp, ci)
                if not aec:
                    pi, p = ci, p + 1
                    restart = True
                    break
                if len(src) - p - 1 >= len(aec) and list(src[p + 1:p + 1 + len(aec)]) == aec:
                    pi, p = ci, p + 1 + len(aec)
                    restart = True
                    break
                if flag == 0:
                    return pi, p, 0
                j += 1
                if j >= par["ncc"]:
                    return pi, p, 0
                continue
            flag = 0
            j += 1
        if restart:
            continue
        if not par["sd"]:
            if op:
                return par["cptr"] + par["ncc"] - 1, p, 1
            return pi, p, 0
        sdi = par["cptr"] + par["ncc"]
        first = True
        while True:
            n, more, chars, ybits = _sd(comp, exp, sdi, f1)
            for k, sc2 in enumerate(chars):
                if op and sc > sc2:
                    continue
                if (not op) and sc != sc2:
                    continue
                ci = sdi + 1 + k
                if op and sc != sc2:
                    return ci, p, -1
                lo = 12 if f1 else 5
                if k < lo:
                    y = ybits[k]
                elif first:
                    y = (par["e"][1] >> (7 - (k - lo))) & 1
                else:
                    y = 1
                if not y:
                    return ci, p + 1, 0
                aec = _aec(comp, ci)
                if not aec:
                    pi, p = ci, p + 1
                    restart = True
                    break
                ok = True
                gt = False
                for kk, a in enumerate(aec):
                    if p + 1 + kk >= len(src):
                        ok = False
                        break
                    s = src[p + 1 + kk]
                    if op and s > a:
                        gt = True
                        break
                    if s != a:
                        ok = False
                        break
                if gt:
                    continue
                if not ok:
                    if op:
                        return ci, p, -1
                    return pi, p, 0
                pi, p = ci, p + 1 + len(aec)
                restart = True
                break
            if restart:
                break
            if not more:
                if op:
                    return sdi + n, p, 1
                return pi, p, 0
            sdi += n + 1
            first = False
        # continue with new parent


def compress(comp, exp, data, f1=False, w=9, stt=None, op=False, ee=None, room=1 << 30, cbn=0, out_init=None):
    """-> dict(out bits as list, consumed bytes, cc). stt: list of interchange symbols per index (ST/OP);
    ee: (ed, codewords) with ed the 16 counts and codewords a per-index (value, length)"""
    bits = []
    pos = 0
    avail = room * 8 - cbn
    cc = 0
    while True:
        if pos >= len(data):
            cc = 0
            break
        if ee is None and avail < w:
            cc = 1
            break
        if ee is not None and avail <= 0:
            cc = 1
            break
        idx, cons, adj = compress_one(comp, exp, data[pos:], f1, op)
        if ee is not None:
            val, ln = ee[1][idx]
        else:
            val, ln = idx, w
            if stt is not None:
                val = (stt[idx] + adj) & ((1 << w) - 1)
        if ln > avail:
            cc = 1
            break
        bits += [(val >> (ln - 1 - i)) & 1 for i in range(ln)]
        avail -= ln
        pos += cons
    return dict(bits=bits, consumed=pos, cc=cc)


# ---------------------------------------------------------------- expansion (figure 7-219)

def expand(exp, bits_in, w, room, ee=None, ee_desc=None):
    """bits_in: list of bits (after the compressed-data bit number); returns (output, bits used, cc)"""
    out = bytearray()
    pos = 0
    n = len(bits_in)
    while True:
        # another index symbol?
        if ee is None:
            if n - pos < w:
                return bytes(out), pos, 0
            if room - len(out) <= 0:
                return bytes(out), pos, 1
            idx = 0
            for i in range(w):
                idx = (idx << 1) | bits_in[pos + i]
            used = w
        else:
            ed = ee_desc
            if n - pos <= 0:
                return bytes(out), pos, 0
            if room - len(out) <= 0:
                return bytes(out), pos, 1
            lb, cix, bl, cw = 2, 0, 1, 0
            while True:
                if n - pos < bl:
                    return bytes(out), pos, 0
                lb -= ed[bl - 1]
                cw = (cw << 1) | bits_in[pos + bl - 1]
                cix += ed[bl - 1]
                if cw >= lb:
                    break
                bl += 1
                lb *= 2
            if cw == 0:
                return bytes(out), pos, 0
            idx = cix - (cw - (lb - 1))
            used = bl
        if ee is None and idx < 256:
            out.append(idx)
            pos += used
            if room - len(out) <= 0:
                return bytes(out), pos, (0 if n - pos < w else 1)
            continue
        e = exp[idx]
        psl = e[0] >> 5
        if psl == 0:
            csl = e[0] & 7
            if room - len(out) < csl:
                return bytes(out), pos, 1
            out += e[1:1 + csl]
        else:
            ofst = e[7]
            symlen = psl + ofst
            if room - len(out) < symlen:
                return bytes(out), pos, 1
            buf = bytearray(symlen + 8)
            ent = idx
            first = True
            for _ in range(300):
                e = exp[ent]
                psl = min(e[0] >> 5, 5)
                if psl == 0:
                    csl = e[0] & 7
                    buf[0:csl] = e[1:1 + csl]
                    break
                ofst = e[7]
                buf[ofst:ofst + psl] = e[2:2 + psl]
                pp = ((e[0] & 0x1f) << 8) | e[1]
                if pp < 256 and ee is None:
                    buf[ofst - 1] = pp
                    break
                ent = pp
            out += buf[:symlen]
        pos += used
        if room - len(out) <= 0:
            nleft = n - pos
            if ee is None:
                return bytes(out), pos, (0 if nleft < w else 1)
            return bytes(out), pos, (0 if nleft <= 0 else 1)


# ---------------------------------------------------------------- entropy encoding

def ee_tables(rng, entries):
    """a valid entropy descriptor (16 counts of codewords per bit length) for `entries` dictionary
    entries plus the terminating all-zero codeword: a full binary code tree with entries + 1 leaves"""
    total = entries + 1
    leaves = [1, 1]
    while len(leaves) < total:
        cand = [i for i, l in enumerate(leaves) if l < 16]
        i = rng.choice(cand)
        l = leaves.pop(i)
        leaves += [l + 1, l + 1]
    counts = [0] * 16
    for l in leaves:
        counts[l - 1] += 1
    return counts


def ee_codewords(ed):
    """codeword (value, length) per sequence number (figure 7-221 inverted); the last one is the
    terminating all-zero codeword"""
    cws = []
    lb = 2
    for bl in range(1, 17):
        c = ed[bl - 1]
        for k in range(c):
            cws.append((lb - 1 - k, bl))
        lb = (lb - c) * 2
    return cws
