"""Elliptic-curve reference for the CPACF tests: affine arithmetic in Python integers for the NIST
curves and the Edwards curves, with the curve constants re-derived from the cryptography library
(and checked against tools/gen_ecc.py)."""
import hashlib, os, sys
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, x25519, x448
from cryptography.hazmat.primitives import serialization as S

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
import gen_ecc as G


def nist(curve, bits):
    g = ec.derive_private_key(1, curve).public_key().public_numbers()
    lo, hi = 1, 1 << (bits + 1)
    def ok(v):
        try:
            ec.derive_private_key(v, curve)
            return True
        except ValueError:
            return False
    while lo < hi:
        m = (lo + hi) // 2
        if ok(m):
            lo = m + 1
        else:
            hi = m
    return g.x, g.y, lo


CURVES = {}
for name, c, bits, d in (("P256", ec.SECP256R1(), 256, G.P256), ("P384", ec.SECP384R1(), 384, G.P384), ("P521", ec.SECP521R1(), 521, G.P521)):
    gx, gy, n = nist(c, bits)
    assert (gx, gy, n) == (d["gx"], d["gy"], d["n"]), name
    assert (gy * gy - gx ** 3 - d["a"] * gx - d["b"]) % d["p"] == 0
    CURVES[name] = dict(d, curve=c, bits=bits)
CURVES["Ed25519"] = dict(G.ED25519)
CURVES["Ed448"] = dict(G.ED448)


def inv(a, m):
    return pow(a, -1, m)


def w_add(c, P, Q):
    p = c["p"]
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2:
        if (y1 + y2) % p == 0:
            return None
        lam = (3 * x1 * x1 + c["a"]) * inv(2 * y1, p) % p
    else:
        lam = (y2 - y1) * inv(x2 - x1, p) % p
    x3 = (lam * lam - x1 - x2) % p
    return x3, (lam * (x1 - x3) - y1) % p


def e_add(c, P, Q):
    p, a, d = c["p"], c["a"], c["d"]
    x1, y1 = P
    x2, y2 = Q
    t = d * x1 * x2 * y1 * y2 % p
    return ((x1 * y2 + y1 * x2) * inv(1 + t, p) % p, (y1 * y2 - a * x1 * x2) * inv(1 - t, p) % p)


def mul(c, k, P):
    add = w_add if c["kind"] == 0 else e_add
    R = None if c["kind"] == 0 else (0, 1)
    Q = P
    while k:
        if k & 1:
            R = add(c, R, Q) if R is not None else Q
        Q = add(c, Q, Q)
        k >>= 1
    return R


def on_curve(c, P):
    x, y = P
    p = c["p"]
    if c["kind"] == 0:
        return (y * y - x ** 3 - c["a"] * x - c["b"]) % p == 0
    return (c["a"] * x * x + y * y - 1 - c["d"] * x * x * y * y) % p == 0


def be(v, n):
    return v.to_bytes(n, "big")


def selftest():
    # the Edwards base points are re-derived from the library's public keys
    for name, hasher, mod, bits, nbytes in (("Ed25519", lambda s: hashlib.sha512(s).digest(), ed25519, 255, 32),
                                            ("Ed448", lambda s: hashlib.shake_256(s).digest(114), ed448, 447, 57)):
        c = CURVES[name]
        seed = bytes(range(nbytes))
        h = hasher(seed)
        s = int.from_bytes(h[:nbytes], "little")
        if name == "Ed25519":
            s = (s & ~7 & ((1 << 254) - 1)) | (1 << 254)
        else:
            s = (s & ~3 & ((1 << 447) - 1)) | (1 << 447)
        pub = mod.__dict__[("Ed25519PrivateKey" if name == "Ed25519" else "Ed448PrivateKey")].from_private_bytes(seed).public_key().public_bytes(S.Encoding.Raw, S.PublicFormat.Raw)
        mine = mul(c, s, (c["gx"], c["gy"]))
        y = mine[1] | ((mine[0] & 1) << (8 * nbytes - 1))
        assert y.to_bytes(nbytes, "little") == pub, name
        assert on_curve(c, (c["gx"], c["gy"]))
        assert mul(c, c["n"], (c["gx"], c["gy"])) == (0, 1)


selftest()
