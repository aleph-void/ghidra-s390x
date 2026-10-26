"""Reference implementations for the message-security-assist tests: the compression functions
of SHA-1/256/512 and Keccak-f[1600] (so that a KIMD chaining value can be checked, which hashlib
does not expose; the final digests are checked against hashlib itself), the GHASH
multiplication of GCM, and the framing of the chaining values."""
import struct, hashlib

M32, M64 = 0xffffffff, (1 << 64) - 1

def _rotr(x, n, w, m):
    return ((x >> n) | (x << (w - n))) & m

def sha256_compress(h, block):
    K = _K256
    w = list(struct.unpack(">16I", block))
    for t in range(16, 64):
        s0 = _rotr(w[t - 15], 7, 32, M32) ^ _rotr(w[t - 15], 18, 32, M32) ^ (w[t - 15] >> 3)
        s1 = _rotr(w[t - 2], 17, 32, M32) ^ _rotr(w[t - 2], 19, 32, M32) ^ (w[t - 2] >> 10)
        w.append((w[t - 16] + s0 + w[t - 7] + s1) & M32)
    a, b, c, d, e, f, g, hh = h
    for t in range(64):
        t1 = (hh + (_rotr(e, 6, 32, M32) ^ _rotr(e, 11, 32, M32) ^ _rotr(e, 25, 32, M32)) + ((e & f) ^ (~e & g & M32)) + K[t] + w[t]) & M32
        t2 = ((_rotr(a, 2, 32, M32) ^ _rotr(a, 13, 32, M32) ^ _rotr(a, 22, 32, M32)) + ((a & b) ^ (a & c) ^ (b & c))) & M32
        hh, g, f, e, d, c, b, a = g, f, e, (d + t1) & M32, c, b, a, (t1 + t2) & M32
    return [(x + y) & M32 for x, y in zip(h, (a, b, c, d, e, f, g, hh))]

def sha512_compress(h, block):
    K = _K512
    w = list(struct.unpack(">16Q", block))
    for t in range(16, 80):
        s0 = _rotr(w[t - 15], 1, 64, M64) ^ _rotr(w[t - 15], 8, 64, M64) ^ (w[t - 15] >> 7)
        s1 = _rotr(w[t - 2], 19, 64, M64) ^ _rotr(w[t - 2], 61, 64, M64) ^ (w[t - 2] >> 6)
        w.append((w[t - 16] + s0 + w[t - 7] + s1) & M64)
    a, b, c, d, e, f, g, hh = h
    for t in range(80):
        t1 = (hh + (_rotr(e, 14, 64, M64) ^ _rotr(e, 18, 64, M64) ^ _rotr(e, 41, 64, M64)) + ((e & f) ^ (~e & g & M64)) + K[t] + w[t]) & M64
        t2 = ((_rotr(a, 28, 64, M64) ^ _rotr(a, 34, 64, M64) ^ _rotr(a, 39, 64, M64)) + ((a & b) ^ (a & c) ^ (b & c))) & M64
        hh, g, f, e, d, c, b, a = g, f, e, (d + t1) & M64, c, b, a, (t1 + t2) & M64
    return [(x + y) & M64 for x, y in zip(h, (a, b, c, d, e, f, g, hh))]

def sha1_compress(h, block):
    w = list(struct.unpack(">16I", block))
    for t in range(16, 80):
        x = w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16]
        w.append(((x << 1) | (x >> 31)) & M32)
    a, b, c, d, e = h
    for t in range(80):
        if t < 20:
            f, k = (b & c) | (~b & d & M32), 0x5a827999
        elif t < 40:
            f, k = b ^ c ^ d, 0x6ed9eba1
        elif t < 60:
            f, k = (b & c) | (b & d) | (c & d), 0x8f1bbcdc
        else:
            f, k = b ^ c ^ d, 0xca62c1d6
        tmp = ((((a << 5) | (a >> 27)) & M32) + f + e + k + w[t]) & M32
        e, d, c, b, a = d, c, ((b << 30) | (b >> 2)) & M32, a, tmp
    return [(x + y) & M32 for x, y in zip(h, (a, b, c, d, e))]

def _primes(n):
    ps, c = [], 2
    while len(ps) < n:
        if all(c % p for p in ps):
            ps.append(c)
        c += 1
    return ps

def _icbrt(n):
    lo, hi = 0, 1 << (n.bit_length() // 3 + 2)
    while lo < hi:
        m = (lo + hi + 1) // 2
        lo, hi = (m, hi) if m ** 3 <= n else (lo, m - 1)
    return lo

_K256 = [_icbrt(p << 96) & M32 for p in _primes(64)]
_K512 = [_icbrt(p << 192) & M64 for p in _primes(80)]

_RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000, 0x000000000000808b,
       0x0000000080000001, 0x8000000080008081, 0x8000000000008009, 0x000000000000008a, 0x0000000000000088,
       0x0000000080008009, 0x000000008000000a, 0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
       0x8000000000008003, 0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
       0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
_ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]

def keccak_f(state):
    """state: 200 bytes -> 200 bytes"""
    A = [[struct.unpack_from("<Q", state, 8 * (x + 5 * y))[0] for y in range(5)] for x in range(5)]
    rl = lambda v, n: ((v << n) | (v >> (64 - n))) & M64 if n else v
    for rnd in range(24):
        C = [A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4] for x in range(5)]
        D = [C[(x - 1) % 5] ^ rl(C[(x + 1) % 5], 1) for x in range(5)]
        A = [[A[x][y] ^ D[x] for y in range(5)] for x in range(5)]
        B = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                B[y][(2 * x + 3 * y) % 5] = rl(A[x][y], _ROT[x][y])
        A = [[B[x][y] ^ (~B[(x + 1) % 5][y] & B[(x + 2) % 5][y] & M64) for y in range(5)] for x in range(5)]
        A[0][0] ^= _RC[rnd]
    out = bytearray(200)
    for x in range(5):
        for y in range(5):
            struct.pack_into("<Q", out, 8 * (x + 5 * y), A[x][y])
    return bytes(out)

def keccak_absorb(state, block):
    s = bytearray(state)
    for i, b in enumerate(block):
        s[i] ^= b
    return keccak_f(bytes(s))

def ghash_mul(x, y):
    """GF(2^128) multiplication of GCM (integers, bit 0 = most significant)"""
    z, v = 0, y
    for i in range(128):
        if (x >> (127 - i)) & 1:
            z ^= v
        v = (v >> 1) ^ (0xe1 << 120) if v & 1 else v >> 1
    return z

def selftest():
    for alg, comp, iv, bs in ((hashlib.sha256, sha256_compress, [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19], 64),):
        blk = b"\x61\x62\x63\x80" + bytes(52) + (24).to_bytes(8, "big")
        assert struct.pack(">8I", *comp(iv, blk)) == alg(b"abc").digest()
    blk = b"\x61\x62\x63\x80" + bytes(108) + (24).to_bytes(16, "big")
    iv512 = list(struct.unpack(">8Q", bytes.fromhex("6a09e667f3bcc908bb67ae8584caa73b3c6ef372fe94f82ba54ff53a5f1d36f1510e527fade682d19b05688c2b3e6c1f1f83d9abfb41bd6b5be0cd19137e2179")))
    assert struct.pack(">8Q", *sha512_compress(iv512, blk)) == hashlib.sha512(b"abc").digest()
    blk = b"\x61\x62\x63\x80" + bytes(52) + (24).to_bytes(8, "big")
    assert struct.pack(">5I", *sha1_compress([0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0], blk)) == hashlib.sha1(b"abc").digest()
    blk = bytearray(136); blk[0:3] = b"abc"; blk[3] ^= 0x06; blk[135] ^= 0x80
    assert keccak_absorb(bytes(200), bytes(blk))[:32] == hashlib.sha3_256(b"abc").digest()

if __name__ == "__main__":
    selftest()
    print("ok")

# ---- block ciphers (cryptography is the oracle for single blocks; the modes are done here) ---------
import warnings
warnings.simplefilter("ignore")
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
try:
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
except Exception:
    from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES

def ecb_block(alg, key):
    """-> (encrypt, decrypt, block size) for alg 'dea' (8-byte key), 'tdea128' (16), 'tdea192' (24), 'aes' (16/24/32)"""
    if alg == "aes":
        a = algorithms.AES(key); bs = 16
    else:
        k = {"dea": key * 3, "tdea128": key + key[:8], "tdea192": key}[alg]
        a = TripleDES(k); bs = 8
    def enc(b):
        return Cipher(a, modes.ECB()).encryptor().update(b)
    def dec(b):
        return Cipher(a, modes.ECB()).decryptor().update(b)
    return enc, dec, bs

def mode_ecb(alg, key, data, dec):
    e, d, bs = ecb_block(alg, key)
    f = d if dec else e
    return b"".join(f(data[i:i + bs]) for i in range(0, len(data), bs)), None

def mode_cbc(alg, key, cv, data, dec):
    e, d, bs = ecb_block(alg, key)
    out = b""
    for i in range(0, len(data), bs):
        blk = data[i:i + bs]
        if dec:
            o = bytes(x ^ y for x, y in zip(d(blk), cv))
            cv = blk
        else:
            o = e(bytes(x ^ y for x, y in zip(blk, cv)))
            cv = o
        out += o
    return out, cv

def mode_cfb(alg, key, cv, data, dec, s):
    e, d, bs = ecb_block(alg, key)
    out = b""
    for i in range(0, len(data), s):
        seg = data[i:i + s]
        ks = e(cv)[:s]
        o = bytes(x ^ y for x, y in zip(seg, ks))
        out += o
        cv = cv[s:] + (seg if dec else o)
    return out, cv

def mode_ofb(alg, key, cv, data):
    e, d, bs = ecb_block(alg, key)
    out = b""
    for i in range(0, len(data), bs):
        cv = e(cv)
        out += bytes(x ^ y for x, y in zip(data[i:i + bs], cv))
    return out, cv

def mode_ctr(alg, key, counters, data):
    e, d, bs = ecb_block(alg, key)
    return b"".join(bytes(x ^ y for x, y in zip(data[i:i + bs], e(counters[i:i + bs]))) for i in range(0, len(data), bs)), None
