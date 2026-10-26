"""Reference model of SORT LISTS (SORTL-SFLR / SORTL-SVLR) written from the Principles of Operation
(chapter 26): a k-way merge with output-list formation. Used by emu_tests.py; the two worked
examples of the manual (figures 26-108 and 26-109) are asserted in selftest()."""


def run(lists, keylen, paylen, asc=True, mm=0, svlr=False, eil=0, op1=1 << 30, op2=1 << 30,
        state=None, prev=None, base=0):
    """lists: list of bytes (active input lists, in order). Returns a dict with the output bytes,
    output-list delineations (offsets relative to the start of the output), the consumed byte
    count per list, condition code, and the state needed to resume."""
    pos = [0] * len(lists)
    out = bytearray()
    olds = []
    op = state["open"] if state else False
    fn = state["fn"] if state else False
    start = state["start"] if state else 0
    length = state["len"] if state else 0
    prevkey = prev
    cont = False
    cc = None
    eilf = eiln = iilf = iiln = 0
    pend_eil = None
    placed = 0

    def reclen(n):
        rest = len(lists[n]) - pos[n]
        if svlr:
            if rest < keylen + 8:
                return None
            pl = int.from_bytes(lists[n][pos[n] + keylen + 6: pos[n] + keylen + 8], "big")
            rl = keylen + 8 + pl
        else:
            rl = keylen + paylen
        return rl if rest >= rl else None

    def key(n):
        return lists[n][pos[n]: pos[n] + keylen]

    def close():
        nonlocal op, op2
        olds.append((start, length))
        op2 -= 16
        op = False

    if mm == 0 and op and fn:
        if op2 < 16:
            cc = 1
        else:
            close()
    cont = (mm == 0) and op and not fn
    while cc is None:
        cand, nonempty = [], 0
        incomplete = None
        for n in range(len(lists)):
            if pos[n] == len(lists[n]):
                continue
            rl = reclen(n)
            if rl is None:
                incomplete = n
                break
            nonempty += 1
            cand.append(n)
        if incomplete is not None:
            cc, iilf, iiln, fn = 2, 1, incomplete, False
            break
        if nonempty == 0:
            if mm == 0 and op:
                if op2 < 16:
                    fn = True
                    cc = 1
                    break
                close()
            cc = 0
            break
        if pend_eil is not None:
            cc, fn = 2, True
            if eil == 3:
                eilf, eiln, fn = 1, pend_eil, False
            break
        def pick(cs):
            best = None
            for n in cs:
                if best is None:
                    best = n
                    continue
                a, b = key(n), key(best)
                if (a <= b) if asc else (a >= b):
                    best = n
            return best
        best = None
        if cont:
            qual = [n for n in cand if ((key(n) >= prevkey) if asc else (key(n) <= prevkey))]
            best = pick(qual) if qual else None
        newlist = best is None
        if newlist:
            best = pick(cand)
        if mm == 0 and newlist and op:
            if op2 < 16:
                fn = True
                cc = 1
                break
            close()
        rl = reclen(best)
        if op1 < rl:
            fn = True
            cc = 1
            break
        rec = lists[best][pos[best]: pos[best] + rl]
        if mm == 0:
            if newlist:
                op, start, length = True, base + len(out), rl
            else:
                length += rl
            prevkey = key(best)
        out += rec
        op1 -= rl
        pos[best] += rl
        placed += 1
        cont = mm == 0
        if pos[best] == len(lists[best]):
            if (best == 0 and eil & 2) or (best != 0 and eil & 1):
                pend_eil = best
    return dict(out=bytes(out), olds=olds, used=pos, cc=cc, op=op, fn=fn, start=start, len=length,
                prev=prevkey, eilf=eilf, eiln=eiln, iilf=iilf, iiln=iiln, op1=op1, op2=op2, placed=placed)


def _recs(vals, keylen=8, payload=b""):
    return b"".join(v.to_bytes(keylen, "big") + payload for v in vals)


def selftest():
    r = run([_recs([5, 1, 17, 3]), _recs([10, 8, 2, 14]), _recs([99, 6, 88, 20])], 8, 0)
    assert r["cc"] == 0
    assert r["out"] == _recs([5, 10, 99, 1, 6, 8, 17, 88, 2, 3, 14, 20])
    assert r["olds"] == [(0, 0x18), (0x18, 0x28), (0x40, 0x20)], r["olds"]
    r = run([_recs([5, 1]), _recs([10, 8]), _recs([99, 6]), _recs([17, 3]), _recs([2, 14]), _recs([88, 20])], 8, 0)
    assert r["out"] == _recs([2, 5, 10, 14, 17, 88, 99, 1, 3, 6, 8, 20])
    assert r["olds"] == [(0, 0x38), (0x38, 0x28)], r["olds"]


selftest()
