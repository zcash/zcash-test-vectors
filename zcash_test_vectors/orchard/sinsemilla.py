#!/usr/bin/env python3
import sys; assert sys.version_info[0] >= 3, "Python 3 required."

import math

from .pallas import Fp, Point
from ..utils import cldiv, lebs2ip, i2leosp
from .group_hash import group_hash
from ..output import render_args, render_tv
from ..rand import Rand

SINSEMILLA_K = 10

# Interprets a string or a list as a sequence of bits.
def str_to_bits(s):
    for c in s:
        assert c in ['0', '1', 0, 1, False, True]
    # Regular Python truthiness is fine here except for bool('0') == True.
    return [c != '0' and bool(c) for c in s]

def pad(n, m):
    padding_needed = n * SINSEMILLA_K - len(m)
    zeros = [0] * padding_needed
    m = list(m) + zeros

    return [lebs2ip(str_to_bits(m[i*SINSEMILLA_K : (i+1)*SINSEMILLA_K])) for i in range(n)]

def sinsemilla_hash_to_point(d, m):
    n = cldiv(len(m), SINSEMILLA_K)
    m = pad(n, m)
    acc = group_hash(b"z.cash:SinsemillaQ", d)

    for m_i in m:
        acc = acc.checked_incomplete_add(
            group_hash(b"z.cash:SinsemillaS", i2leosp(32, m_i))
        ).checked_incomplete_add(acc)

    return acc

def sinsemilla_hash(d, m):
    return sinsemilla_hash_to_point(d, m).extract()


def main():
    test_vectors = [
        # 40 bits, so no padding
        (b"z.cash:test-Sinsemilla", [0,0,0,1,0,1,1,0,1,0,1,0,0,1,1,0,0,0,1,1,0,1,1,0,0,0,1,1,0,1,1,0,1,1,1,1,0,1,1,0]),
    ]

    sh = sinsemilla_hash_to_point(test_vectors[0][0], test_vectors[0][1])
    assert sh == Point(Fp(19681977528872088480295086998934490146368213853811658798708435106473481753752),
                       Fp(14670850419772526047574141291705097968771694788047376346841674072293161339903))

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
    # - Random message bits.
    for _ in range(10):
        domain = b"z.cash:test-Sinsemilla-longer" if rand.bool() else b"z.cash:test-Sinsemilla"
        msg_len = rand.u8()
        msg = bytes([rand.bool() for _ in range(msg_len)])
        test_vectors.append((domain, msg))

    test_vectors = [{
        'domain': domain,
        'msg': msg,
        'point': bytes(sinsemilla_hash_to_point(domain, msg)),
        'hash': bytes(sinsemilla_hash(domain, msg)),
    } for (domain, msg) in test_vectors]

    render_tv(
        render_args(),
        'orchard_sinsemilla',
        (
            ('domain', {'rust_type': 'Vec<u8>', 'bitcoin_flavoured': False}),
            ('msg', {
                'rust_type': 'Vec<bool>',
                'rust_fmt': lambda x: str_to_bits(x),
            }),
            ('point', '[u8; 32]'),
            ('hash', '[u8; 32]'),
        ),
        test_vectors,
    )


if __name__ == "__main__":
    main()
