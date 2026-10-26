"""P-code for the elliptic-curve functions of the message-security-assist extensions 9 and later:
PERFORM CRYPTOGRAPHIC COMPUTATION scalar multiplication (PCC-Scalar-Multiply P256, P384, P521, Ed25519,
Ed448, X25519, X448) and COMPUTE DIGITAL SIGNATURE AUTHENTICATION (KDSA-ECDSA-Verify / -Sign P256,
P384, P521; KDSA-EdDSA-Verify / -Sign Ed25519, Ed448).

The group arithmetic is one engine subtable, `cp_ecc` (code stored once in the .sla), with its values
in 72-byte scratch registers ep_* (s390x.slaspec) and 144-byte product registers: Weierstrass curves use
the complete projective addition formulas of Renes, Costello and Batina (Algorithm 1, any a, b), the
Edwards curves the unified formulas of add-2008-bbjlp, the Montgomery curves the RFC 7748 ladder. Modular
inverses and square roots are exponentiations; every field operation is one SLEIGH statement on big
varnodes. The instruction constructors (here) move the parameter-block fields in and out, check the
ranges the manual requires, and for EdDSA run the hashing between engine calls (SHA-512 or SHAKE256).

Operands are big-endian and right-aligned in the parameter block fields as the manual defines (the
EdDSA compressed points and the S value are byte-reversed relative to RFC 8032; the private key bytes
are hashed as given). ECDSA signing with the deterministic bit set uses the supplied random number; with
the bit clear (and for the encrypted-key function) the random number is mixed with s390_trng_byte() bytes.
Operations run to completion (never condition code 3).
"""

# ---------------------------------------------------------------- curve constants
P256 = dict(p=0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
            n=0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551,
            b=0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
            gx=0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
            gy=0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)
P384 = dict(p=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff,
            n=0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973,
            b=0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef,
            gx=0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7,
            gy=0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f)
P521 = dict(p=2 ** 521 - 1,
            n=0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409,
            b=0x51953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00,
            gx=0xc6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66,
            gy=0x11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650)
for _c in (P256, P384, P521):
    _c["a"] = _c["p"] - 3
    _c["kind"] = 0
_P25519 = 2 ** 255 - 19
ED25519 = dict(p=_P25519, a=_P25519 - 1, d=(-121665 * pow(121666, -1, _P25519)) % _P25519,
               n=2 ** 252 + 27742317777372353535851937790883648493,
               gx=15112221349535400772501151409588531511454012693041857206046113283949847762202,
               gy=46316835694926478169428394003475163141307993866256225615783033603165251855960, kind=1)
_P448 = 2 ** 448 - 2 ** 224 - 1
ED448 = dict(p=_P448, a=1, d=(-39081) % _P448,
             n=2 ** 446 - 13818066809895115352007386748515426880336692474882178609894547503885,
             gx=224580040295924300187604334099896036246789641632564134246125461686950415467406032909029192869357953282578032075146446173674602635247710,
             gy=298819210078481492676017930443930673437544040154080242095928241372331506189835876003536878655418784733982303233503462500531545062832660, kind=1)
ED25519["sqrtm1"] = pow(2, (_P25519 - 1) // 4, _P25519)
ED25519["sqe"] = (_P25519 + 3) // 8
ED448["sqe"] = (_P448 + 1) // 4
ED448["sqrtm1"] = 0
X25519 = dict(p=_P25519, a24=121665, bits=255)
X448 = dict(p=_P448, a24=39081, bits=448)

NREG = 72   # bytes per value register
REGS = ("p a b b3 d n gx gy x1 y1 z1 x2 y2 z2 x3 y3 z3 rx ry rz bx by bz t0 t1 t2 t3 t4 t5 t6 t7 t8 tm "
        "k e r s w u1 u2 dd kk ex v u m sq sq2 pp1 pp2 pp3 pp4 pp5 ax ay cx cy m1 m2").split()
BIG = ("pr", "pm")


def regs_decl(offset=0x20000):
    """the slaspec lines declaring the ECC scratch registers"""
    out = [f"define register offset={offset:#x} size={NREG} [ " + " ".join("ep_" + r for r in REGS) + " ];"]
    out.append(f"define register offset={offset + 0x2000:#x} size=144 [ ep_pr ep_pm ];")
    out.append(f"define register offset={offset + 0x3000:#x} size=1 [ ep_mode ep_kind ep_ok ep_st ep_rnd ep_ret ep_rm ep_rw ep_ri ep_sg ep_k25 ep_b1 ];")
    out.append(f"define register offset={offset + 0x3020:#x} size=4 [ ep_nb ep_pb ];")
    return out


class Emit:
    def __init__(self):
        self.t = []
        self.n = 0

    def u(self):
        self.n += 1
        return self.n

    def s(self, text):
        self.t.append(text)

    def mm(self, d, a, b, m="ep_p"):
        self.s(f"ep_pr = zext({a}); ep_pm = zext({b}); ep_pr = ep_pr * ep_pm; ep_pm = zext({m}); ep_pr = ep_pr % ep_pm; {d} = ep_pr:{NREG};")

    def ad(self, d, a, b, m="ep_p"):
        u = self.u()
        self.s(f"{d} = {a} + {b}; if ({d} < {m}) goto <L_ad{u}>; {d} = {d} - {m}; <L_ad{u}>")

    def sb(self, d, a, b, m="ep_p"):
        u = self.u()
        self.s(f"if ({a} < {b}) goto <L_sb{u}>; {d} = {a} - {b}; goto <L_se{u}>; <L_sb{u}> ep_tm = {a} + {m}; {d} = ep_tm - {b}; <L_se{u}>")


def const_stmts(reg, value):
    """assign a (up to 72-byte) constant to a register using 64-bit pieces"""
    chunks = []
    v = value
    while v:
        chunks.append(v & ((1 << 64) - 1))
        v >>= 64
    if not chunks:
        return f"{reg} = 0;"
    chunks.reverse()
    s = f"{reg} = {chunks[0]:#x};"
    for c in chunks[1:]:
        s += f" {reg} = ({reg} << 64) | {c:#x};"
    return s


def engine():
    """the cp_ecc subtable"""
    E = Emit()
    E.s("cp_ecc: is epsilon {")
    E.s("  local i4:4 = 0; local bt:8 = 0;")
    S = E.s
    # ================================================================= modes
    S("  if (ep_mode == 1) goto <L_mul>; if (ep_mode == 2) goto <L_mont>; if (ep_mode == 3) goto <L_ver>; if (ep_mode == 4) goto <L_sig>; "
      "if (ep_mode == 5) goto <L_edv>; if (ep_mode == 6) goto <L_dec>; if (ep_mode == 7) goto <L_red>; if (ep_mode == 9) goto <L_eds>; goto <L_exit>;")
    # ----------------------------------------------------------------- padd: (x1,y1,z1) + (x2,y2,z2) -> (x3,y3,z3)
    S("  <L_padd> if (ep_kind != 0) goto <L_eadd>;")
    mm, ad, sb = E.mm, E.ad, E.sb
    mm("ep_t0", "ep_x1", "ep_x2"); mm("ep_t1", "ep_y1", "ep_y2"); mm("ep_t2", "ep_z1", "ep_z2")
    ad("ep_t3", "ep_x1", "ep_y1"); ad("ep_t4", "ep_x2", "ep_y2"); mm("ep_t3", "ep_t3", "ep_t4")
    ad("ep_t4", "ep_t0", "ep_t1"); sb("ep_t3", "ep_t3", "ep_t4")
    ad("ep_t4", "ep_x1", "ep_z1"); ad("ep_t5", "ep_x2", "ep_z2"); mm("ep_t4", "ep_t4", "ep_t5")
    ad("ep_t5", "ep_t0", "ep_t2"); sb("ep_t4", "ep_t4", "ep_t5")
    ad("ep_t5", "ep_y1", "ep_z1"); ad("ep_x3", "ep_y2", "ep_z2"); mm("ep_t5", "ep_t5", "ep_x3")
    ad("ep_x3", "ep_t1", "ep_t2"); sb("ep_t5", "ep_t5", "ep_x3")
    mm("ep_z3", "ep_a", "ep_t4"); mm("ep_x3", "ep_b3", "ep_t2"); ad("ep_z3", "ep_x3", "ep_z3")
    sb("ep_x3", "ep_t1", "ep_z3"); ad("ep_z3", "ep_t1", "ep_z3"); mm("ep_y3", "ep_x3", "ep_z3")
    ad("ep_t1", "ep_t0", "ep_t0"); ad("ep_t1", "ep_t1", "ep_t0"); mm("ep_t2", "ep_a", "ep_t2"); mm("ep_t4", "ep_b3", "ep_t4")
    ad("ep_t1", "ep_t1", "ep_t2"); sb("ep_t2", "ep_t0", "ep_t2"); mm("ep_t2", "ep_a", "ep_t2"); ad("ep_t4", "ep_t4", "ep_t2")
    mm("ep_t0", "ep_t1", "ep_t4"); ad("ep_y3", "ep_y3", "ep_t0"); mm("ep_t0", "ep_t5", "ep_t4"); mm("ep_x3", "ep_t3", "ep_x3")
    sb("ep_x3", "ep_x3", "ep_t0"); mm("ep_t0", "ep_t3", "ep_t1"); mm("ep_z3", "ep_t5", "ep_z3"); ad("ep_z3", "ep_z3", "ep_t0")
    S("  goto <L_padd_ret>;")
    # Edwards (a, d): add-2008-bbjlp
    S("  <L_eadd>")
    mm("ep_t0", "ep_z1", "ep_z2"); mm("ep_t1", "ep_t0", "ep_t0"); mm("ep_t2", "ep_x1", "ep_x2"); mm("ep_t3", "ep_y1", "ep_y2")
    mm("ep_t4", "ep_t2", "ep_t3"); mm("ep_t4", "ep_d", "ep_t4"); sb("ep_t5", "ep_t1", "ep_t4"); ad("ep_t6", "ep_t1", "ep_t4")
    ad("ep_t7", "ep_x1", "ep_y1"); ad("ep_t8", "ep_x2", "ep_y2"); mm("ep_t7", "ep_t7", "ep_t8"); sb("ep_t7", "ep_t7", "ep_t2"); sb("ep_t7", "ep_t7", "ep_t3")
    mm("ep_x3", "ep_t0", "ep_t5"); mm("ep_x3", "ep_x3", "ep_t7")
    mm("ep_t7", "ep_a", "ep_t2"); sb("ep_t7", "ep_t3", "ep_t7"); mm("ep_y3", "ep_t0", "ep_t6"); mm("ep_y3", "ep_y3", "ep_t7")
    mm("ep_z3", "ep_t5", "ep_t6")
    S("  <L_padd_ret> if (ep_rw == 1) goto <L_pw1>; if (ep_rw == 2) goto <L_pw2>; if (ep_rw == 3) goto <L_pw3>; goto <L_pw4>;")
    # ----------------------------------------------------------------- scalar multiplication: (bx,by,bz) * k -> (rx,ry,rz), ep_nb bits
    S("  <L_smul> ep_rx = 0; ep_ry = 1; ep_rz = 0; if (ep_kind == 0) goto <L_sm0>; ep_rz = 1; <L_sm0> i4 = ep_nb;")
    S("  <L_sml> if (i4 == 0) goto <L_smd>; i4 = i4 - 1; ep_x1 = ep_rx; ep_y1 = ep_ry; ep_z1 = ep_rz; ep_x2 = ep_rx; ep_y2 = ep_ry; ep_z2 = ep_rz; ep_rw = 1; goto <L_padd>;")
    S("  <L_pw1> ep_rx = ep_x3; ep_ry = ep_y3; ep_rz = ep_z3; if (((ep_k >> i4) & 1) == 0) goto <L_sml>; ep_x1 = ep_rx; ep_y1 = ep_ry; ep_z1 = ep_rz; ep_x2 = ep_bx; ep_y2 = ep_by; ep_z2 = ep_bz; ep_rw = 2; goto <L_padd>;")
    S("  <L_pw2> ep_rx = ep_x3; ep_ry = ep_y3; ep_rz = ep_z3; goto <L_sml>;")
    S("  <L_smd> if (ep_rm == 1) goto <L_sm1>; if (ep_rm == 2) goto <L_sm2>; if (ep_rm == 3) goto <L_sm3>; if (ep_rm == 4) goto <L_sm4>; if (ep_rm == 5) goto <L_sm5>; goto <L_sm6>;")
    # ----------------------------------------------------------------- modular exponentiation: ep_v = ep_u ^ ep_ex mod ep_m ; inverse: exponent m - 2
    S("  <L_pow> ep_v = 1; i4 = 576;")
    S("  <L_pwl> if (i4 == 0) goto <L_pwd>; i4 = i4 - 1;")
    mm("ep_v", "ep_v", "ep_v", "ep_m")
    S("  if (((ep_ex >> i4) & 1) == 0) goto <L_pwl>;")
    mm("ep_v", "ep_v", "ep_u", "ep_m")
    S("  goto <L_pwl>;")
    S("  <L_pwd> if (ep_ri == 1) goto <L_pi1>; if (ep_ri == 2) goto <L_pi2>; if (ep_ri == 3) goto <L_pi3>; if (ep_ri == 4) goto <L_pi4>; if (ep_ri == 5) goto <L_pi5>; goto <L_pi6>;")
    S("  <L_inv> ep_ex = ep_m - 2; goto <L_pow>;")
    # ----------------------------------------------------------------- on-curve test of the affine point (x1, y1): ep_ok
    S("  <L_chk> ep_ok = 0; if (ep_x1 >= ep_p) goto <L_chkd>; if (ep_y1 >= ep_p) goto <L_chkd>; if (ep_kind != 0) goto <L_chke>;")
    mm("ep_t0", "ep_y1", "ep_y1"); mm("ep_t1", "ep_x1", "ep_x1"); mm("ep_t1", "ep_t1", "ep_x1"); mm("ep_t2", "ep_a", "ep_x1"); ad("ep_t1", "ep_t1", "ep_t2"); ad("ep_t1", "ep_t1", "ep_b")
    S("  if (ep_t0 != ep_t1) goto <L_chkd>; ep_ok = 1; goto <L_chkd>;")
    S("  <L_chke>")
    mm("ep_t0", "ep_x1", "ep_x1"); mm("ep_t1", "ep_y1", "ep_y1"); mm("ep_t2", "ep_a", "ep_t0"); ad("ep_t2", "ep_t2", "ep_t1")
    mm("ep_t3", "ep_t0", "ep_t1"); mm("ep_t3", "ep_d", "ep_t3")
    S("  ep_t4 = 1; ep_t3 = ep_t3 + ep_t4; if (ep_t3 < ep_p) goto <L_chkf>; ep_t3 = ep_t3 - ep_p; <L_chkf> if (ep_t2 != ep_t3) goto <L_chkd>; ep_ok = 1;")
    S("  <L_chkd> if (ep_ret == 1) goto <L_ck1>; goto <L_ck2>;")
    # ----------------------------------------------------------------- affine from projective: x3 = rx / rz, y3 = ry / rz (rz != 0)
    S("  <L_aff> ep_m = ep_p; ep_u = ep_rz; ep_ri = 1; goto <L_inv>;")
    S("  <L_pi1> ep_pr = zext(ep_rx); ep_pm = zext(ep_v); ep_pr = ep_pr * ep_pm; ep_pm = zext(ep_p); ep_pr = ep_pr % ep_pm; ep_x3 = ep_pr:72;")
    mm("ep_y3", "ep_ry", "ep_v")
    S("  if (ep_ret == 4) goto <L_af4>; if (ep_ret == 5) goto <L_af5>; goto <L_af6>;")
    # ================================================================= mode 1: affine scalar multiplication
    S("  <L_mul> ep_st = 0; ep_ret = 1; goto <L_chk>;")
    S("  <L_ck1> if (ep_ok != 0) goto <L_mul2>; ep_st = 1; goto <L_exit>;")
    S("  <L_mul2> if (ep_k != 0) goto <L_mul4>; ep_st = 2; goto <L_exit>;")
    S("  <L_mul4> ep_bx = ep_x1; ep_by = ep_y1; ep_bz = 1; ep_rm = 1; goto <L_smul>;")
    S("  <L_sm1> if (ep_rz != 0) goto <L_mul3>; ep_st = 2; goto <L_exit>;")
    S("  <L_mul3> ep_ret = 4; goto <L_aff>;")
    S("  <L_af4> goto <L_exit>;")
    # ================================================================= mode 2: Montgomery ladder (x only): ep_x3 = ep_k * ep_u (u coordinate)
    S("  <L_mont> ep_x1 = ep_u; ep_x2 = 1; ep_z2 = 0; ep_x3 = ep_u; ep_z3 = 1; ep_k25 = 0; i4 = ep_nb;")
    S("  <L_mtl> if (i4 == 0) goto <L_mtd>; i4 = i4 - 1; ep_t0 = (ep_k >> i4) & 1; ep_sg = ep_t0:1; ep_k25 = ep_k25 ^ ep_sg; if (ep_k25 == 0) goto <L_mts>;")
    S("  ep_t0 = ep_x2; ep_x2 = ep_x3; ep_x3 = ep_t0; ep_t0 = ep_z2; ep_z2 = ep_z3; ep_z3 = ep_t0; <L_mts> ep_k25 = ep_sg;")
    ad("ep_t0", "ep_x2", "ep_z2"); mm("ep_t1", "ep_t0", "ep_t0"); sb("ep_t2", "ep_x2", "ep_z2"); mm("ep_t3", "ep_t2", "ep_t2"); sb("ep_t4", "ep_t1", "ep_t3")
    ad("ep_t5", "ep_x3", "ep_z3"); sb("ep_t6", "ep_x3", "ep_z3"); mm("ep_t6", "ep_t6", "ep_t0"); mm("ep_t5", "ep_t5", "ep_t2")
    ad("ep_t7", "ep_t6", "ep_t5"); mm("ep_x3", "ep_t7", "ep_t7"); sb("ep_t7", "ep_t6", "ep_t5"); mm("ep_t7", "ep_t7", "ep_t7"); mm("ep_z3", "ep_x1", "ep_t7")
    mm("ep_x2", "ep_t1", "ep_t3"); mm("ep_t7", "ep_d", "ep_t4"); ad("ep_t7", "ep_t7", "ep_t1"); mm("ep_z2", "ep_t4", "ep_t7")
    S("  goto <L_mtl>;")
    S("  <L_mtd> if (ep_k25 == 0) goto <L_mtf>; ep_t0 = ep_x2; ep_x2 = ep_x3; ep_x3 = ep_t0; ep_t0 = ep_z2; ep_z2 = ep_z3; ep_z3 = ep_t0;")
    S("  <L_mtf> ep_m = ep_p; ep_u = ep_z2; ep_ri = 2; goto <L_inv>;")
    S("  <L_pi2> ep_pr = zext(ep_x2); ep_pm = zext(ep_v); ep_pr = ep_pr * ep_pm; ep_pm = zext(ep_p); ep_pr = ep_pr % ep_pm; ep_x3 = ep_pr:72; goto <L_exit>;")
    # ================================================================= mode 3: ECDSA verify; inputs e r s, public key x2 y2, curve; ep_st 0 valid, 1 bad key, 2 bad signature
    S("  <L_ver> ep_st = 0; ep_cx = ep_x2; ep_cy = ep_y2; ep_x1 = ep_x2; ep_y1 = ep_y2; ep_ret = 2; goto <L_chk>;")
    S("  <L_ck2> if (ep_ok != 0) goto <L_ver2>; ep_st = 1; goto <L_exit>;")
    S("  <L_ver2> ep_st = 2; if (ep_r == 0) goto <L_exit>; if (ep_s == 0) goto <L_exit>; if (ep_r >= ep_n) goto <L_exit>; if (ep_s >= ep_n) goto <L_exit>;")
    S("  ep_m = ep_n; ep_u = ep_s; ep_ri = 3; goto <L_inv>;")
    S("  <L_pi3> ep_w = ep_v; ep_e = ep_e % ep_n;")
    mm("ep_u1", "ep_e", "ep_w", "ep_n"); mm("ep_u2", "ep_r", "ep_w", "ep_n")
    S("  ep_bx = ep_gx; ep_by = ep_gy; ep_bz = 1; ep_k = ep_u1; ep_rm = 2; goto <L_smul>;")
    S("  <L_sm2> ep_pp1 = ep_rx; ep_pp2 = ep_ry; ep_pp3 = ep_rz; ep_bx = ep_cx; ep_by = ep_cy; ep_bz = 1; ep_k = ep_u2; ep_rm = 3; goto <L_smul>;")
    S("  <L_sm3> ep_x1 = ep_pp1; ep_y1 = ep_pp2; ep_z1 = ep_pp3; ep_x2 = ep_rx; ep_y2 = ep_ry; ep_z2 = ep_rz; ep_rw = 3; goto <L_padd>;")
    S("  <L_pw3> if (ep_z3 == 0) goto <L_exit>; ep_rx = ep_x3; ep_ry = ep_y3; ep_rz = ep_z3; ep_ret = 5; goto <L_aff>;")
    S("  <L_af5> ep_x3 = ep_x3 % ep_n; if (ep_x3 != ep_r) goto <L_exit>; ep_st = 0; goto <L_exit>;")
    # ================================================================= mode 4: ECDSA sign (k in ep_kk, e, d): r s
    S("  <L_sig> ep_st = 0; if (ep_rnd == 0) goto <L_sg0>; ep_t0 = ep_n - 1; ep_kk = ep_kk % ep_t0; ep_kk = ep_kk + 1; <L_sg0> ep_bx = ep_gx; ep_by = ep_gy; ep_bz = 1; ep_k = ep_kk; ep_rm = 4; goto <L_smul>;")
    S("  <L_sm4> ep_ret = 6; goto <L_aff>;")
    S("  <L_af6> ep_r = ep_x3 % ep_n; ep_m = ep_n; ep_u = ep_kk; ep_ri = 4; goto <L_inv>;")
    S("  <L_pi4> ep_w = ep_v; ep_e = ep_e % ep_n;")
    mm("ep_t0", "ep_r", "ep_dd", "ep_n"); ad("ep_t0", "ep_t0", "ep_e", "ep_n"); mm("ep_s", "ep_t0", "ep_w", "ep_n")
    S("  goto <L_exit>;")
    # ================================================================= mode 5: EdDSA verify: [S]B == R + [k]A  (A in x1,y1; R in x2,y2; S in ep_s; k in ep_e); ep_ok
    S("  <L_edv> ep_ok = 0; ep_bx = ep_x1; ep_by = ep_y1; ep_bz = 1; ep_pp4 = ep_x2; ep_pp5 = ep_y2; ep_k = ep_e; ep_rm = 5; goto <L_smul>;")
    S("  <L_sm5> ep_pp1 = ep_rx; ep_pp2 = ep_ry; ep_pp3 = ep_rz; ep_bx = ep_gx; ep_by = ep_gy; ep_bz = 1; ep_k = ep_s; ep_rm = 6; goto <L_smul>;")
    S("  <L_sm6> ep_x1 = ep_pp1; ep_y1 = ep_pp2; ep_z1 = ep_pp3; ep_x2 = ep_pp4; ep_y2 = ep_pp5; ep_z2 = 1; ep_rw = 4; goto <L_padd>;")
    S("  <L_pw4> ")
    mm("ep_t0", "ep_rx", "ep_z3"); mm("ep_t1", "ep_x3", "ep_rz"); mm("ep_t2", "ep_ry", "ep_z3"); mm("ep_t3", "ep_y3", "ep_rz")
    S("  if (ep_t0 != ep_t1) goto <L_exit>; if (ep_t2 != ep_t3) goto <L_exit>; ep_ok = 1; goto <L_exit>;")
    # ================================================================= mode 6: decompress a point: y in ep_y1, sign bit ep_sg; result x in ep_x1; ep_ok
    S("  <L_dec> ep_ok = 0; if (ep_y1 >= ep_p) goto <L_exit>;")
    mm("ep_t0", "ep_y1", "ep_y1")
    S("  ep_t4 = 1;")
    sb("ep_t5", "ep_t0", "ep_t4")                    # u = y^2 - 1
    mm("ep_t6", "ep_d", "ep_t0"); sb("ep_t6", "ep_t6", "ep_a")      # v = d y^2 - a
    S("  ep_m = ep_p; ep_u = ep_t6; ep_ri = 5; goto <L_inv>;")
    S("  <L_pi5> ")
    mm("ep_t7", "ep_t5", "ep_v")                      # x^2 = u / v
    S("  ep_u = ep_t7; ep_ex = ep_sq; ep_m = ep_p; ep_ri = 6; goto <L_pow>;")
    S("  <L_pi6> ep_x1 = ep_v;")
    mm("ep_t0", "ep_x1", "ep_x1")
    S("  if (ep_t0 == ep_t7) goto <L_dx>; if (ep_k25 == 0) goto <L_exit>; ep_t1 = ep_p - ep_t7; if (ep_t0 != ep_t1) goto <L_exit>; ep_t1 = ep_sq2;")
    mm("ep_x1", "ep_x1", "ep_t1")
    S("  <L_dx> if (ep_x1 != 0) goto <L_dy>; if (ep_sg != 0) goto <L_exit>; ep_ok = 1; goto <L_exit>;")
    S("  <L_dy> ep_t0 = ep_x1 & 1; ep_b1 = ep_t0:1; if (ep_b1 == ep_sg) goto <L_dz>; ep_x1 = ep_p - ep_x1; <L_dz> ep_ok = 1; goto <L_exit>;")
    # ================================================================= mode 7: reduce ep_pr (144 bytes) modulo ep_n into ep_r ; mode 8 handled above (use 9)
    S("  <L_red> ep_pm = zext(ep_n); ep_pr = ep_pr % ep_pm; ep_r = ep_pr:72; goto <L_exit>;")
    # ================================================================= mode 9: EdDSA S = (r + k * s) mod n   (k in ep_k, s in ep_dd, r in ep_r) -> ep_s
    S("  <L_eds>")
    mm("ep_t0", "ep_k", "ep_dd", "ep_n"); ad("ep_s", "ep_r", "ep_t0", "ep_n")
    S("  goto <L_exit>;")
    S("  <L_exit>")
    S("}")
    return "\n".join(E.t)


def engines():
    return engine()


# ================================================================= instruction wrappers
CPM_EDB, CPM_DIG = 0x100000, 0x4100
CPM_MOFF = CPM_EDB + 0x100

PCC_FC = {64: ("P256", P256, 32, 32, 256, 1), 65: ("P384", P384, 48, 48, 384, 1), 66: ("P521", P521, 66, 80, 521, 1),
          72: ("Ed25519", ED25519, 32, 32, 255, 1), 73: ("Ed448", ED448, 56, 64, 448, 1),
          80: ("X25519", X25519, 32, 32, 255, 2), 81: ("X448", X448, 56, 64, 448, 2)}


def curve_stmts(c):
    """set the engine's curve registers"""
    t = [f"ep_kind = {c.get('kind', 0)};", const_stmts("ep_p", c["p"])]
    if "a" in c:
        t.append(const_stmts("ep_a", c["a"]))
    if c.get("kind", 0) == 0 and "b" in c:
        t.append(const_stmts("ep_b", c["b"]))
        t.append(const_stmts("ep_b3", 3 * c["b"] % c["p"]))
    if "d" in c:
        t.append(const_stmts("ep_d", c["d"]))
    if "n" in c:
        t.append(const_stmts("ep_n", c["n"]))
        t.append(const_stmts("ep_gx", c["gx"]))
        t.append(const_stmts("ep_gy", c["gy"]))
    if "sqe" in c:
        t.append(const_stmts("ep_sq", c["sqe"]))
        t.append(const_stmts("ep_sq2", c["sqrtm1"]))
        t.append(f"ep_k25 = {1 if c['sqrtm1'] else 0};")
    return " ".join(t)


def load_be(reg, addr, n, tag):
    return (f"{reg} = 0; ec_j = 0; <L_ld{tag}> {reg} = ({reg} << 8) | zext(*:1 ({addr} + ec_j)); ec_j = ec_j + 1; "
            f"if (ec_j < {n}) goto <L_ld{tag}>;")


def store_be(reg, addr, n, tag):
    return (f"ec_j = 0; <L_st{tag}> ec_sh = ({n} - 1 - ec_j) * 8; ep_tm = {reg} >> ec_sh; ec_b = ep_tm:1; *:1 ({addr} + ec_j) = ec_b; "
            f"ec_j = ec_j + 1; if (ec_j < {n}) goto <L_st{tag}>;")


def pcc_ecc_code(fc_local="fc"):
    """the PCC scalar-multiply functions: returns the statements (to be placed after `if (fc < 64) goto <L_nec>;`)"""
    t = []
    A = t.append
    A("local ec_j:8 = 0; local ec_sh:8 = 0; local ec_b:1 = 0; local ec_n:8 = 0; local ec_fs:8 = 0; local ec_pad:8 = 0; local ec_m:1 = 0; local ec_ok:1 = 0;")
    for fc, (nm, c, nb, fs, bits, m) in sorted(PCC_FC.items()):
        A(f"if ({fc_local} != {fc}) goto <L_ec{fc}>; ec_n = {nb}; ec_fs = {fs}; ec_m = {m}; ec_ok = 1; ep_nb = {bits}; ")
        if m == 1:
            A(curve_stmts(c))
            if c["kind"] == 0:
                A(const_stmts("ep_w", c["n"]))
            elif fc == 72:
                A(f"ep_w = 1; ep_w = ep_w << 255;")
            else:
                A("ep_w = 0;")
        else:
            A(const_stmts("ep_p", c["p"]) + f" ep_d = {c['a24']}; ep_kind = 1;")
        A(f"<L_ec{fc}>")
    A("if (ec_ok != 0) goto <L_ecv>; trap_specification(); goto <L_done>;\n<L_ecv> ec_pad = ec_fs - ec_n; ep_st = 0;")
    A("if (ec_m == 2) goto <L_ecmont>;")
    A(load_be("ep_x1", "(r1 + (2 * ec_fs) + ec_pad)", "ec_n", "a"))
    A(load_be("ep_y1", "(r1 + (3 * ec_fs) + ec_pad)", "ec_n", "b"))
    A(load_be("ep_k", "(r1 + (4 * ec_fs) + ec_pad)", "ec_n", "c"))
    A("if (ep_w == 0) goto <L_ecl>; if (ep_k < ep_w) goto <L_ecl>; cc = 1; goto <L_done>;\n<L_ecl> ep_mode = 1; goto <L_eccrun>;")
    A("<L_ecmont> ")
    A(load_be("ep_u", "(r1 + ec_fs + ec_pad)", "ec_n", "d"))
    A(load_be("ep_k", "(r1 + (2 * ec_fs) + ec_pad)", "ec_n", "e"))
    A("if (ep_u == 0) goto <L_ecbad>; if (ep_u >= ep_p) goto <L_ecbad>; ep_mode = 2; goto <L_eccrun>;\n<L_ecbad> cc = 1; goto <L_done>;")
    A("<L_eccrun> build cp_ecc;")
    A("if (ec_m == 2) goto <L_ecmo>; if (ep_st == 0) goto <L_ecok>; cc = ep_st; goto <L_done>;")
    A("<L_ecok> ")
    A(store_be("ep_x3", "(r1 + ec_pad)", "ec_n", "f"))
    A(store_be("ep_y3", "(r1 + ec_fs + ec_pad)", "ec_n", "g"))
    A("cc = 0; goto <L_done>;")
    A("<L_ecmo> ")
    A(store_be("ep_x3", "(r1 + ec_pad)", "ec_n", "h"))
    A("cc = 0; goto <L_done>;")
    return "\n".join(t)


# ---------------------------------------------------------------- KDSA
import math
IV512 = [math.isqrt(q << 128) & 0xffffffffffffffff for q in (2, 3, 5, 7, 11, 13, 17, 19)]
KDSA_ENC = {17: ("S", "P256"), 18: ("S", "P384"), 19: ("S", "P521"), 48: ("ES", "Ed25519"), 52: ("ES", "Ed448")}
KDSA_FC = {1: ("V", "P256"), 2: ("V", "P384"), 3: ("V", "P521"), 9: ("S", "P256"), 10: ("S", "P384"), 11: ("S", "P521"),
           32: ("EV", "Ed25519"), 36: ("EV", "Ed448"), 40: ("ES", "Ed25519"), 44: ("ES", "Ed448")}
KDSA_CURVE = {"P256": (P256, 32, 32), "P384": (P384, 48, 48), "P521": (P521, 66, 80),
              "Ed25519": (ED25519, 32, 32), "Ed448": (ED448, 57, 64)}
CPM_AENC, CPM_RENC, CPM_PREF, CPM_DOM = 0x4200, 0x4240, 0x4280, 0x4300
WRAPB, KEYA = 0x1b00, 0x040
DOM4 = b"SigEd448" + b"\x00\x00"


class KD:
    def __init__(self):
        self.n = 0
        self.t = []

    def tag(self):
        self.n += 1
        return str(self.n)

    def s(self, text):
        self.t.append(text)

    def cp_cpm(self, dst, src, n):
        g = self.tag()
        self.s(f"kd_i = 0; <L_kc{g}> if (zext(kd_i) >= {n}) goto <L_kd{g}>; *[cpm]:1 (({dst}) + kd_i) = *[cpm]:1 (({src}) + kd_i); kd_i = kd_i + 1; goto <L_kc{g}>; <L_kd{g}>")

    def ram_to_cpm(self, dst, src, n, rev=False):
        g = self.tag()
        idx = f"({n} - 1 - kd_j)" if rev else "kd_j"
        self.s(f"kd_j = 0; <L_kr{g}> if (kd_j >= {n}) goto <L_ke{g}>; kd_i = kd_j:4; *[cpm]:1 (({dst}) + kd_i) = *:1 (({src}) + {idx}); kd_j = kd_j + 1; goto <L_kr{g}>; <L_ke{g}>")

    def cpm_to_ram(self, dst, src, n, rev=False):
        g = self.tag()
        if rev:
            self.s(f"kd_j = 0; <L_kw{g}> if (kd_j >= {n}) goto <L_kx{g}>; kd_t = {n} - 1 - kd_j; kd_i = kd_t:4; *:1 (({dst}) + kd_j) = *[cpm]:1 (({src}) + kd_i); kd_j = kd_j + 1; goto <L_kw{g}>; <L_kx{g}>")
        else:
            self.s(f"kd_j = 0; <L_kw{g}> if (kd_j >= {n}) goto <L_kx{g}>; kd_i = kd_j:4; *:1 (({dst}) + kd_j) = *[cpm]:1 (({src}) + kd_i); kd_j = kd_j + 1; goto <L_kw{g}>; <L_kx{g}>")

    def le_load(self, reg, src, n):
        """reg = little-endian integer of n bytes at cpm src (reg 72 bytes or ep_pr 144 bytes)"""
        g = self.tag()
        self.s(f"{reg} = 0; kd_j = 0; <L_kl{g}> if (kd_j >= {n}) goto <L_km{g}>; kd_i = kd_j:4; kd_b = *[cpm]:1 (({src}) + kd_i); kd_sh = kd_j * 8; "
               f"{'ep_pm' if reg == 'ep_pr' else 'ep_tm'} = zext(kd_b); {'ep_pm' if reg == 'ep_pr' else 'ep_tm'} = {'ep_pm' if reg == 'ep_pr' else 'ep_tm'} << kd_sh; "
               f"{reg} = {reg} | {'ep_pm' if reg == 'ep_pr' else 'ep_tm'}; kd_j = kd_j + 1; goto <L_kl{g}>; <L_km{g}>")

    def le_store(self, reg, dst, n):
        g = self.tag()
        self.s(f"kd_j = 0; <L_kn{g}> if (kd_j >= {n}) goto <L_ko{g}>; kd_sh = kd_j * 8; ep_tm = {reg} >> kd_sh; kd_b = ep_tm:1; kd_i = kd_j:4; *[cpm]:1 (({dst}) + kd_i) = kd_b; kd_j = kd_j + 1; goto <L_kn{g}>; <L_ko{g}>")

    def encode_point(self, dst):
        """compressed encoding of the affine point (ep_x3, ep_y3): y with the sign bit of x in the top bit, little-endian, kd_el bytes"""
        g = self.tag()
        self.s(f"ep_tm = ep_x3 & 1; kd_sh = (kd_el * 8) - 1; ep_tm = ep_tm << kd_sh; ep_t0 = ep_y3 | ep_tm; ")
        self.le_store("ep_t0", dst, "kd_el")

    def hash_input(self, hdr_parts, hdr_len_expr):
        """assemble [dom][parts...] ending at the message start (CPM_MOFF); sets kd_hs (start) and kd_hn (length)"""
        self.s(f"kd_hs = {CPM_MOFF:#x} - ({hdr_len_expr}); kd_hn = ({hdr_len_expr}) + kd_ml; kd_at = kd_hs:4;")
        self.s("if (kd_dl == 0) goto <L_hnd%s>;" % self.n)
        # dom4 bytes
        for i, b in enumerate(DOM4):
            self.s(f"*[cpm]:1 (kd_at + {i}) = {b:#x};")
        self.s("<L_hnd%s> kd_off = kd_dl;" % self.n)
        for src in hdr_parts:
            g = self.tag()
            self.s(f"kd_i = 0; <L_hp{g}> if (zext(kd_i) >= kd_el) goto <L_hq{g}>; *[cpm]:1 (kd_at + (kd_off:4 + kd_i)) = *[cpm]:1 ({src} + kd_i); kd_i = kd_i + 1; goto <L_hp{g}>; <L_hq{g}> kd_off = kd_off + kd_el;")
        self.n += 1


def kdsa_insn(o, x):
    """KDSA: x = R2 + 1, R2 number"""
    r2a, r2l = o[1], x[0]
    K = KD()
    S = K.s
    S(f"local r2num:4 = {x[1]};")
    S("local fc:1 = r0:1 & 0x7f; local kd_j:8 = 0; local kd_t:8 = 0; local kd_i:4 = 0; local kd_sh:8 = 0; local kd_b:1 = 0; local kd_n:8 = 0; local kd_fs:8 = 0; local kd_pad:8 = 0; "
      "local kd_op:1 = 0; local kd_ph:1 = 0; local kd_el:8 = 0; local kd_dl:8 = 0; local kd_hl:8 = 0; local kd_h:1 = 0; local kd_ml:8 = 0; local kd_hs:8 = 0; "
      "local kd_hn:8 = 0; local kd_at:4 = 0; local kd_off:8 = 0; local kd_ok:1 = 0; local kd_nb:4 = 0; local kd_cc:1 = 0; local kd_hph:1 = 0; local kd_enc:1 = 0; local kd_vo:8 = 0; local kd_ko:8 = 0; "
      "local wv:32 = 0; local wt:32 = 0; local wb:1 = 0; local wl:8 = 0; local wsh:8 = 0; local ci:4 = 0; local wk:1 = 0;")
    S("if (fc != 0) goto <L_fn>;")
    mask = 0
    for c in [0] + sorted(KDSA_FC) + sorted(KDSA_ENC):
        mask |= 1 << (127 - c)
    S(f"*:8 r1 = {mask >> 64:#x}:8; *:8 (r1 + 8) = {mask & ((1 << 64) - 1):#x}:8; cc = 0; goto <L_done>;")
    S("<L_fn> if (((r2num & 1) == 0) && (r2num != 0)) goto <L_rok>; trap_specification(); goto <L_done>;\n<L_rok>")
    allf = dict(KDSA_FC)
    allf.update(KDSA_ENC)
    for fc, (kind, cn) in sorted(allf.items()):
        c, n, fs = KDSA_CURVE[cn]
        opn = {"V": 1, "S": 2, "EV": 3, "ES": 4}[kind]
        S(f"if (fc != {fc}) goto <L_kf{fc}>; kd_op = {opn}; kd_n = {n}; kd_fs = {fs}; kd_ok = 1; kd_el = {n}; {'kd_enc = 1; ' if fc in KDSA_ENC else ''}ep_nb = {c['n'].bit_length() if kind in ('V', 'S') else (255 if cn == 'Ed25519' else 448)}; ")
        S(curve_stmts(c))
        if kind in ("EV", "ES"):
            ed448 = cn == "Ed448"
            S(f"kd_dl = {10 if ed448 else 0}; kd_hl = {114 if ed448 else 64}; kd_h = {1 if ed448 else 0}; kd_nb = {448 if ed448 else 255};")
            if ed448:
                S(const_stmts("ep_m1", (1 << 448) - 4) + " " + const_stmts("ep_m2", 1 << 447))
            else:
                S(const_stmts("ep_m1", (1 << 254) - 8) + " " + const_stmts("ep_m2", 1 << 254))
        S(f"<L_kf{fc}>")
    S("if (kd_ok != 0) goto <L_kv>; trap_specification(); goto <L_done>;\n<L_kv> kd_pad = kd_fs - kd_n; ep_st = 0;")
    S("if (kd_enc == 0) goto <L_kdnoenc>; wk = 1; kd_vo = kd_fs * 3; if (kd_op != 2) goto <L_kdv1>; kd_vo = kd_fs * 5;\n<L_kdv1>")
    S("wv = wkavp; wl = 31; ci = 0; <L_kdvl> wsh = (wl - zext(ci)) * 8; wt = wv >> wsh; wb = wt:1; if (*:1 (r1 + kd_vo + zext(ci)) != wb) goto <L_kdvb>; ci = ci + 1; if (zext(ci) <= wl) goto <L_kdvl>; goto <L_kdvd>;")
    S("<L_kdvb> kd_b = *:1 (r1 + kd_vo + 39); kd_b = (kd_b & 0xf0) | 1; *:1 (r1 + kd_vo + 39) = kd_b; cc = 1; goto <L_done>;\n<L_kdvd>")
    S(f"kd_ko = kd_fs * 2; if (kd_op != 2) goto <L_kdk1>; kd_ko = kd_fs * 3; <L_kdk1> ci = 0; <L_kdwc> *[cpm]:4 ({WRAPB:#x}:4 + ci) = *:4 (r1 + kd_ko + zext(ci)); ci = ci + 4; if (zext(ci) < kd_fs) goto <L_kdwc>;")
    S(f"cpmd = 13; cpwk = 1; cpwl = kd_fs; cpwa = 3; cpwn = 8; cpalg = 3; cpnk = 8; *[cpm]:32 ({KEYA:#x}:4) = wka; build cp_cipher; cpwk = 0;")
    S("<L_kdnoenc>")
    S("if (kd_op == 1) goto <L_kver>; if (kd_op == 2) goto <L_ksig>; if (kd_op == 3) goto <L_kev>; goto <L_kes>;")
    # ---- ECDSA verify
    S("<L_kver> ")
    S(load_be("ep_r", "(r1 + kd_pad)", "kd_n", "k1"))
    S(load_be("ep_s", "(r1 + kd_fs + kd_pad)", "kd_n", "k2"))
    S(load_be("ep_e", "(r1 + (2 * kd_fs) + kd_pad)", "kd_n", "k3"))
    S(load_be("ep_x2", "(r1 + (3 * kd_fs) + kd_pad)", "kd_n", "k4"))
    S(load_be("ep_y2", "(r1 + (4 * kd_fs) + kd_pad)", "kd_n", "k5"))
    S("ep_mode = 3; kd_ph = 1; goto <L_kdrun>;")
    S("<L_kp1> cc = ep_st; goto <L_done>;")
    # ---- ECDSA sign
    S("<L_ksig> ")
    S(load_be("ep_e", "(r1 + (2 * kd_fs) + kd_pad)", "kd_n", "k6"))
    S("if (kd_enc != 0) goto <L_kdd1>;")
    S(load_be("ep_dd", "(r1 + (3 * kd_fs) + kd_pad)", "kd_n", "k7"))
    S("goto <L_kdd2>; <L_kdd1> ep_dd = 0; kd_j = 0; <L_kdd3> kd_i = kd_j:4; kd_b = *[cpm]:1 (" + f"{WRAPB:#x}" + " + kd_i); ep_tm = zext(kd_b); ep_dd = (ep_dd << 8) | ep_tm; kd_j = kd_j + 1; if (kd_j < kd_fs) goto <L_kdd3>; <L_kdd2>")
    S(load_be("ep_kk", "(r1 + (4 * kd_fs) + kd_pad)", "kd_n", "k8"))
    S("if (ep_dd == 0) goto <L_ks1>; if (ep_dd < ep_n) goto <L_ks2>; <L_ks1> if (kd_enc == 0) goto <L_ks0>; kd_b = *:1 (r1 + kd_vo + 39); kd_b = kd_b & 0xf0; *:1 (r1 + kd_vo + 39) = kd_b; <L_ks0> cc = 1; goto <L_done>;\n<L_ks2> ep_rnd = 0; if (kd_enc != 0) goto <L_ks3>; if ((r0 & 0x80) == 0) goto <L_ks3>;")
    S("if (ep_kk == 0) goto <L_ks4>; if (ep_kk < ep_n) goto <L_ks5>; <L_ks4> cc = 2; goto <L_done>;\n<L_ks3> ep_rnd = 1; kd_j = 0; <L_ks6> if (kd_j >= kd_n) goto <L_ks5>; kd_b = s390_trng_byte(); kd_sh = kd_j * 8; ep_tm = zext(kd_b); ep_tm = ep_tm << kd_sh; ep_kk = ep_kk ^ ep_tm; kd_j = kd_j + 1; goto <L_ks6>;")
    S("<L_ks5> ep_mode = 4; kd_ph = 2; goto <L_kdrun>;")
    S("<L_kp2> ")
    S(store_be("ep_r", "(r1 + kd_pad)", "kd_n", "k9"))
    S(store_be("ep_s", "(r1 + kd_fs + kd_pad)", "kd_n", "ka"))
    S("cc = 0; goto <L_done>;")
    # ---- EdDSA verify
    S("<L_kev> kd_pad = kd_fs - kd_el; ")
    S(load_be("ep_s", "(r1 + kd_fs + kd_pad)", "kd_el", "kb"))
    K.ram_to_cpm(CPM_AENC, "r1 + (2 * kd_fs) + kd_pad", "kd_el", rev=True)
    K.ram_to_cpm(CPM_RENC, "r1 + kd_pad", "kd_el", rev=True)
    S(load_be("ep_t1", "(r1 + (2 * kd_fs) + kd_pad)", "kd_el", "kc"))
    S("kd_sh = (kd_el * 8) - 1; ep_t0 = ep_t1 >> kd_sh; ep_sg = ep_t0:1; ep_t0 = ep_t0 << kd_sh; ep_y1 = ep_t1 - ep_t0; ep_mode = 6; kd_ph = 10; goto <L_kdrun>;")
    S("<L_kp10> if (ep_ok != 0) goto <L_kv1>; cc = 1; goto <L_done>;\n<L_kv1> ep_ax = ep_x1; ep_ay = ep_y1; ")
    S(load_be("ep_t1", "(r1 + kd_pad)", "kd_el", "kd"))
    S("kd_sh = (kd_el * 8) - 1; ep_t0 = ep_t1 >> kd_sh; ep_sg = ep_t0:1; ep_t0 = ep_t0 << kd_sh; ep_y1 = ep_t1 - ep_t0; ep_mode = 6; kd_ph = 11; goto <L_kdrun>;")
    S("<L_kp11> if (ep_ok != 0) goto <L_kv2>; cc = 2; goto <L_done>;\n<L_kv2> ep_cx = ep_x1; ep_cy = ep_y1; if (ep_s == 0) goto <L_kv3>; if (ep_s < ep_n) goto <L_kv4>; <L_kv3> cc = 2; goto <L_done>;")
    S("<L_kv4> kd_ml = r2l_PLACEHOLDER;")
    S("kd_at = " + f"{CPM_MOFF:#x}; ")
    K.ram_to_cpm(f"{CPM_MOFF:#x}", f"{r2a}", "kd_ml")
    K.hash_input([CPM_RENC, CPM_AENC], "kd_dl + (2 * kd_el)")
    S("kd_hph = 12; goto <L_kdhash>;")
    S("<L_kp12> ")
    K.le_load("ep_pr", f"{CPM_DIG:#x}", "kd_hl")
    S("ep_mode = 7; kd_ph = 13; goto <L_kdrun>;")
    S("<L_kp13> ep_e = ep_r; ep_x1 = ep_ax; ep_y1 = ep_ay; ep_x2 = ep_cx; ep_y2 = ep_cy; ep_mode = 5; kd_ph = 14; goto <L_kdrun>;")
    S("<L_kp14> if (ep_ok != 0) goto <L_kv5>; cc = 2; goto <L_done>;\n<L_kv5> cc = 0; goto <L_done>;")
    # ---- EdDSA sign
    S("<L_kes> kd_pad = kd_fs - kd_el; kd_ml = r2l_PLACEHOLDER;")
    K.ram_to_cpm(f"{CPM_MOFF:#x}", f"{r2a}", "kd_ml")
    S("if (kd_enc != 0) goto <L_kde1>;")
    K.ram_to_cpm(f"{CPM_MOFF:#x} - kd_el:4", "r1 + (2 * kd_fs) + kd_pad", "kd_el")
    S("goto <L_kde2>; <L_kde1>")
    K.cp_cpm(f"{CPM_MOFF:#x} - kd_el:4", f"{WRAPB:#x} + kd_pad:4", "kd_el")
    S("<L_kde2>")
    S(f"kd_hs = {CPM_MOFF:#x} - kd_el; kd_hn = kd_el; kd_hph = 20; goto <L_kdhash>;")
    S("<L_kp20> ")
    K.le_load("ep_dd", f"{CPM_DIG:#x}", "kd_el")
    S("ep_dd = ep_dd & ep_m1; ep_dd = ep_dd | ep_m2; ")
    K.cp_cpm(CPM_PREF, f"{CPM_DIG:#x} + kd_el:4", "kd_el")
    S("ep_x1 = ep_gx; ep_y1 = ep_gy; ep_k = ep_dd; ep_nb = kd_nb; ep_mode = 1; kd_ph = 21; goto <L_kdrun>;")
    S("<L_kp21> ")
    K.encode_point(CPM_AENC)
    K.hash_input([CPM_PREF], "kd_dl + kd_el")
    S("kd_hph = 22; goto <L_kdhash>;")
    S("<L_kp22> ")
    K.le_load("ep_pr", f"{CPM_DIG:#x}", "kd_hl")
    S("ep_mode = 7; kd_ph = 23; goto <L_kdrun>;")
    S("<L_kp23> ep_u1 = ep_r; ep_x1 = ep_gx; ep_y1 = ep_gy; ep_k = ep_r; ep_nb = kd_nb; ep_mode = 1; kd_ph = 24; goto <L_kdrun>;")
    S("<L_kp24> ")
    K.encode_point(CPM_RENC)
    K.hash_input([CPM_RENC, CPM_AENC], "kd_dl + (2 * kd_el)")
    S("kd_hph = 25; goto <L_kdhash>;")
    S("<L_kp25> ")
    K.le_load("ep_pr", f"{CPM_DIG:#x}", "kd_hl")
    S("ep_mode = 7; kd_ph = 26; goto <L_kdrun>;")
    S("<L_kp26> ep_k = ep_r; ep_r = ep_u1; ep_mode = 9; kd_ph = 27; goto <L_kdrun>;")
    S("<L_kp27> ")
    K.cpm_to_ram("r1 + kd_pad", str(CPM_RENC), "kd_el", rev=True)
    S(store_be("ep_s", "(r1 + kd_fs + kd_pad)", "kd_el", "ke"))
    S("cc = 0; goto <L_done>;")
    # ---- the engines
    S("<L_kdrun> build cp_ecc;")
    S("if (kd_ph == 1) goto <L_kp1>; if (kd_ph == 2) goto <L_kp2>; if (kd_ph == 10) goto <L_kp10>; if (kd_ph == 11) goto <L_kp11>; if (kd_ph == 13) goto <L_kp13>; if (kd_ph == 14) goto <L_kp14>;")
    S("if (kd_ph == 21) goto <L_kp21>; if (kd_ph == 23) goto <L_kp23>; if (kd_ph == 24) goto <L_kp24>; if (kd_ph == 26) goto <L_kp26>; goto <L_kp27>;")
    iv = " ".join(f"*[cpm]:8 ({0 + 8 * i:#x}:4) = {w:#x};" for i, w in enumerate(IV512))
    S(f"<L_kdhash> cpa = kd_hs; cpl = kd_hn; cpfin = 1; cpsm = 1; cpbh = 0; cpbl = kd_hn * 8; if (kd_h != 0) goto <L_kdsh>; {iv} build cp_sha512; kd_i = 0; "
      f"<L_kdc> *[cpm]:8 ({CPM_DIG:#x}:4 + kd_i) = *[cpm]:8 (kd_i); kd_i = kd_i + 8; if (kd_i < 64) goto <L_kdc>; goto <L_kdhd>;")
    S(f"<L_kdsh> kd_i = 0; <L_kdz> *[cpm]:8 (kd_i) = 0; kd_i = kd_i + 8; if (kd_i < 200) goto <L_kdz>; cprt = 136; cpdm = 0x1f; cpps = 0; cpmd = 1; cpo = {CPM_DIG:#x}; cpn = 114; build cp_keccak;")
    S("<L_kdhd> cpsm = 0; kd_ph = kd_hph; if (kd_ph == 12) goto <L_kp12>; if (kd_ph == 20) goto <L_kp20>; if (kd_ph == 22) goto <L_kp22>; if (kd_ph == 25) goto <L_kp25>; goto <L_kp26>;")
    S("<L_done>")
    return "\n".join(K.t).replace("r2l_PLACEHOLDER", r2l)
