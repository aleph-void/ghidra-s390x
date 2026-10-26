"""Reference for DFLTCC-XPND tests: a straight port of puff.c (the zlib distribution's small inflater) that
also reports the bit position where the final block ends."""
import struct

MAXBITS = 15
LBASE = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258]
LEXT = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0]
DBASE = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577]
DEXT = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13]


class Puff:
    def __init__(self, data, hist=b""):
        self.data = data
        self.pos = 0                      # bit position
        self.out = bytearray(hist)
        self.nhist = len(hist)

    def bits(self, n):
        v = 0
        for i in range(n):
            byte = self.data[self.pos >> 3]
            v |= ((byte >> (self.pos & 7)) & 1) << i
            self.pos += 1
        return v

    @staticmethod
    def construct(lengths):
        count = [0] * 16
        for l in lengths:
            count[l] += 1
        left = 1
        for l in range(1, 16):
            left = (left << 1) - count[l]
            if left < 0:
                raise ValueError("oversubscribed")
        offs = [0] * 16
        for l in range(1, 15):
            offs[l + 1] = offs[l] + count[l]
        symbol = [0] * len(lengths)
        for s, l in enumerate(lengths):
            if l:
                symbol[offs[l]] = s
                offs[l] += 1
        return count, symbol, left

    def decode(self, tab):
        count, symbol, _ = tab
        code = first = index = 0
        for l in range(1, 16):
            code |= self.bits(1)
            c = count[l]
            if code < first + c:
                return symbol[index + code - first]
            index += c
            first = (first + c) << 1
            code <<= 1
        raise ValueError("bad code")

    def codes(self, lt, dt):
        while True:
            sym = self.decode(lt)
            if sym < 256:
                self.out.append(sym)
            elif sym == 256:
                return
            else:
                sym -= 257
                if sym >= 29:
                    raise ValueError("bad length")
                ln = LBASE[sym] + self.bits(LEXT[sym])
                ds = self.decode(dt)
                if ds >= 30:
                    raise ValueError("bad dist")
                dist = DBASE[ds] + self.bits(DEXT[ds])
                if dist > len(self.out):
                    raise ValueError("too far")
                for _ in range(ln):
                    self.out.append(self.out[-dist])

    def run(self):
        while True:
            last = self.bits(1)
            t = self.bits(2)
            if t == 0:
                self.pos = (self.pos + 7) & ~7
                ln = self.bits(16)
                nl = self.bits(16)
                if ln != (~nl & 0xffff):
                    raise ValueError("stored length")
                for _ in range(ln):
                    self.out.append(self.bits(8))
            elif t == 1:
                lens = [8] * 144 + [9] * 112 + [7] * 24 + [8] * 8
                self.codes(self.construct(lens), self.construct([5] * 30))
            elif t == 2:
                nlen = self.bits(5) + 257
                ndist = self.bits(5) + 1
                ncode = self.bits(4) + 4
                order = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15]
                lens = [0] * 19
                for i in range(ncode):
                    lens[order[i]] = self.bits(3)
                cl = self.construct(lens)
                lengths = []
                while len(lengths) < nlen + ndist:
                    sym = self.decode(cl)
                    if sym < 16:
                        lengths.append(sym)
                    else:
                        prev = 0
                        if sym == 16:
                            prev = lengths[-1]
                            rep = 3 + self.bits(2)
                        elif sym == 17:
                            rep = 3 + self.bits(3)
                        else:
                            rep = 11 + self.bits(7)
                        lengths += [prev] * rep
                self.codes(self.construct(lengths[:nlen]), self.construct(lengths[nlen:nlen + ndist]))
            else:
                raise ValueError("bad type")
            if last:
                return bytes(self.out[self.nhist:]), self.pos


def inflate(data, hist=b""):
    return Puff(data, hist).run()
