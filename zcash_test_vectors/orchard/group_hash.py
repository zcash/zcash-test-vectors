#!/usr/bin/env python3
import sys; assert sys.version_info[0] >= 3, "Python 3 required."

from hashlib import blake2b
import math

from . import iso_pallas

from .pallas import Fp, p, q, PALLAS_B, Point
from .iso_pallas import PALLAS_ISO_B, PALLAS_ISO_A, Point as IsoPoint

from ..utils import i2beosp, cldiv, beos2ip, i2leosp, lebs2ip, leos2ip
from ..output import render_args, render_tv
from ..rand import Rand


# https://stackoverflow.com/questions/2612720/how-to-do-bitwise-exclusive-or-of-two-strings-in-python
def sxor(s1,s2):
    return bytes([a ^ b for a,b in zip(s1,s2)])

def expand_message_xmd(msg: bytes, dst: bytes, len_in_bytes: int):
    assert isinstance(msg, bytes)
    assert isinstance(dst, bytes)
    assert len(dst) <= 255

    b_in_bytes = 64 # hash function output size
    r_in_bytes = 128

    ell = cldiv(len_in_bytes, b_in_bytes)

    assert ell <= 255

    dst_prime = dst + i2beosp(8, len(dst))
    z_pad = b"\x00" * r_in_bytes
    l_i_b_str = i2beosp(16, len_in_bytes)
    msg_prime = z_pad + msg + l_i_b_str + i2beosp(8, 0) + dst_prime

    b = []

    b0_ctx = blake2b(digest_size=b_in_bytes, person=i2beosp(128,0))
    b0_ctx.update(msg_prime)
    b.append(b0_ctx.digest())
    assert len(b[0]) == b_in_bytes

    b1_ctx = blake2b(digest_size=b_in_bytes, person=i2beosp(128,0))
    b1_ctx.update(b[0] + i2beosp(8, 1) + dst_prime)
    b.append(b1_ctx.digest())
    assert len(b[1]) == b_in_bytes

    for i in range(2, ell + 1):
        bi_input = sxor(b[0], b[i-1])

        assert len(bi_input) == b_in_bytes

        bi_input += i2beosp(8, i) + dst_prime

        bi_ctx = blake2b(digest_size=b_in_bytes, person=i2beosp(128,0))
        bi_ctx.update(bi_input)

        b.append(bi_ctx.digest())
        assert len(b[i]) == b_in_bytes

    return b''.join(b[1:])[0:len_in_bytes]

def hash_to_field(msg, dst):
    k = 256
    count = 2
    m = 1

    L = cldiv(math.ceil(math.log2(p)) + k, 8)
    assert L == 512/8

    len_in_bytes = count * m * L
    uniform_bytes = expand_message_xmd(msg, dst, len_in_bytes)

    elements = []
    for i in range(0, count):
        for j in range(0, m):
            elm_offset = L * (j + i * m)
            tv = uniform_bytes[elm_offset:elm_offset+L]
            elements.append(Fp(beos2ip(tv), False))

    assert len(elements) == count

    return elements

def map_to_curve_simple_swu(u):
    # The notation below follows Appendix F.2 of the Internet Draft
    zero = Fp(0)
    assert zero.inv() == Fp(0)

    A = PALLAS_ISO_A
    B = PALLAS_ISO_B
    Z = Fp(-13, False)
    c1 = -B / A
    c2 = Fp(-1) / Z

    tv1 = Z * u.exp(2)
    tv2 = tv1.exp(2)
    x1 = tv1 + tv2

    x1 = x1.inv()
    e1 = x1 == Fp(0)
    x1 = x1 + Fp(1)

    x1 = c2 if e1 else x1    # If (tv1 + tv2) == 0, set x1 = -1 / Z

    x1 = x1 * c1      # x1 = (-B / A) * (1 + (1 / (Z^2 * u^4 + Z * u^2)))
    gx1 = x1.exp(2)
    gx1 = gx1 + A
    gx1 = gx1 * x1
    gx1 = gx1 + B             # gx1 = g(x1) = x1^3 + A * x1 + B
    x2 = tv1 * x1            # x2 = Z * u^2 * x1
    tv2 = tv1 * tv2
    gx2 = gx1 * tv2           # gx2 = (Z * u^2)^3 * gx1

    e2 = (gx1.sqrt() is not None)

    x = x1 if e2 else x2    # If is_square(gx1), x = x1, else x = x2
    yy = gx1 if e2 else gx2  # If is_square(gx1), yy = gx1, else yy = gx2
    y = yy.sqrt()

    e3 = u.sgn0() == y.sgn0()

    y = y if e3 else -y  #y = CMOV(-y, y, e3)

    return iso_pallas.Point(x, y)

def group_hash(d, m):
    dst = d + b"-" + b"pallas" + b"_XMD:BLAKE2b_SSWU_RO_"

    elems = hash_to_field(m, dst)
    assert len(elems) == 2

    q = [map_to_curve_simple_swu(elems[0]).iso_map(), map_to_curve_simple_swu(elems[1]).iso_map()]

    return q[0] + q[1]


def main():
    fixed_test_vectors = [
        # This is the Pallas test vector from the Sage and Rust code (in affine coordinates).
        (b"z.cash:test", b"Trans rights now!", Point(Fp(10899331951394555178876036573383466686793225972744812919361819919497009261523),
                                                     Fp(851679174277466283220362715537906858808436854303373129825287392516025427980))),
    ]

    for (domain, msg, point) in fixed_test_vectors:
        gh = group_hash(domain, msg)
        assert gh == point

    test_vectors = [(domain, msg) for (domain, msg, _) in fixed_test_vectors]

    from random import Random
    rng = Random(0xabad533d)
    def randbytes(l):
        ret = []
        while len(ret) < l:
            ret.append(rng.randrange(0, 256))
        return bytes(ret)
    rand = Rand(randbytes)

    # Generate test vectors with the following properties:
    # - One of two domains.
    # - Random message lengths between 0 and 255 bytes.
    # - Random message contents.
    for _ in range(10):
        domain = b"z.cash:test-longer" if rand.bool() else b"z.cash:test"
        msg_len = rand.u8()
        msg = bytes([rand.u8() for _ in range(msg_len)])
        test_vectors.append((domain, msg))

    render_tv(
        render_args(),
        'orchard_group_hash',
        (
            ('domain', 'Vec<u8>'),
            ('msg', 'Vec<u8>'),
            ('point', '[u8; 32]'),
        ),
        [{
            'domain': domain,
            'msg': msg,
            'point': bytes(group_hash(domain, msg)),
        } for (domain, msg) in test_vectors],
    )

def map_to_curve_test_vectors():
    fixed_test_vectors = [
        (Fp(0), IsoPoint(Fp(19938918781445865934736160264407396416050199005817793816893455093350997047296),
                         Fp(1448774895934493446148762800986014913165975534940595774801697325542407056356))),
        (Fp(1), IsoPoint(Fp(5290181550357368025040301950220623271393946308300025648720253222947454165280),
                         Fp(24520995241805476578231005891941079870703368870355132644748659103632565232759))),
        (Fp(0x123456789abcdef123456789abcdef123456789abcdef123456789abcdef0123),
                IsoPoint(Fp(16711718778908753690082328243251803703269853000652055785581237369882690082595),
                         Fp(1764705856161931038824461929646873031992914829456409784642560948827969833589))),
    ]

    for (u, point) in fixed_test_vectors:
        P = map_to_curve_simple_swu(u)
        assert P == point

    test_vectors = [u for (u, _) in fixed_test_vectors]

    from random import Random
    rng = Random(0xabad533d)
    def randbytes(l):
        ret = []
        while len(ret) < l:
            ret.append(rng.randrange(0, 256))
        return bytes(ret)
    rand = Rand(randbytes)

    # Generate random test vectors
    for _ in range(10):
        test_vectors.append(Fp(leos2ip(rand.b(32))))

    render_tv(
        render_args(),
        'orchard_map_to_curve',
        (
            ('u', '[u8; 32]'),
            ('point', '[u8; 32]'),
        ),
        [{
            'u': bytes(u),
            'point': bytes(map_to_curve_simple_swu(u)),
        } for u in test_vectors],
    )


if __name__ == "__main__":
    main()
