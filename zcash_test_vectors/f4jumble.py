#!/usr/bin/env python3
import sys; assert sys.version_info[0] >= 3, "Python 3 required."

from hashlib import blake2b
import math
import struct

from .output import render_args, render_tv
from .rand import Rand
from .utils import i2leosp


# Maximum output length of BLAKE2b
l_H = 64
assert 8*l_H == 512

MIN_l_M = 48
MAX_l_M = 4194368
assert MAX_l_M == 65537*l_H

def instantiate(l_L, l_R):
    def H(i, u):
        digest = blake2b(
            digest_size=l_L,
            person=b'UA_F4Jumble_H' + bytes([i, 0, 0]),
        )
        digest.update(u)
        return digest.digest()

    def G(i, u):
        def inner(j):
            digest = blake2b(
                digest_size=l_H,
                person=b'UA_F4Jumble_G' + bytes([i]) + i2leosp(16, j),
            )
            digest.update(u)
            return digest.digest()

        return b''.join([inner(j) for j in range(0, math.ceil(l_R/l_H))])[:l_R]

    return (H, G)

def xor(x, y):
    return bytes([a ^ b for (a, b) in zip(x, y)])

def f4jumble(M):
    l_M = len(M)
    assert MIN_l_M <= l_M and l_M <= MAX_l_M

    l_L = min([l_H, l_M//2])
    l_R = l_M - l_L
    (H, G) = instantiate(l_L, l_R)
    a = M[:l_L]
    b = M[l_L:]

    x = xor(b, G(0, a))
    y = xor(a, H(0, x))
    d = xor(x, G(1, y))
    c = xor(y, H(1, d))

    return c + d

def f4jumble_inv(M):
    l_M = len(M)
    assert MIN_l_M <= l_M and l_M <= MAX_l_M

    l_L = min([l_H, l_M//2])
    l_R = l_M - l_L
    (H, G) = instantiate(l_L, l_R)
    c = M[:l_L]
    d = M[l_L:]

    y = xor(c, H(1, d))
    x = xor(d, G(1, y))
    a = xor(y, H(0, x))
    b = xor(x, G(0, a))

    return a + b


def main():
    args = render_args()

    from random import Random
    rng = Random(0xabad533d)
    def randbytes(l):
        ret = []
        while len(ret) < l:
            ret.append(rng.randrange(0, 256))
        return bytes(ret)
    rand = Rand(randbytes)

    plain_test_vectors = []

    # Generate test vectors with various lengths:
    for l_M in [
        MIN_l_M,
        l_H,
        2*l_H,
        2*l_H + 1,
        3*l_H,
        3*l_H + 1,
        257*l_H,
        257*l_H + 1,
    ]:
        M = rand.b(l_M)
        jumbled = f4jumble(M)
        assert len(jumbled) == len(M)
        assert f4jumble_inv(jumbled) == M

        plain_test_vectors.append({
            'normal': M,
            'jumbled': jumbled,
        })

    render_tv(
        args,
        'f4jumble',
        (
            ('normal', 'Vec<u8>'),
            ('jumbled', 'Vec<u8>'),
        ),
        plain_test_vectors,
    )

def long_test_vectors():
    args = render_args()

    hashed_test_vectors = []

    for l_M in [
        3246395,
        MAX_l_M,
    ]:
        M = bytes([i & 0xFF for i in range(l_M)])
        jumbled = f4jumble(M)
        assert len(jumbled) == len(M)
        assert f4jumble_inv(jumbled) == M

        hashed_test_vectors.append({
            'length': l_M,
            'jumbled_hash': blake2b(jumbled).digest()
        })

    render_tv(
        args,
        'f4jumble_long',
        (
            ('length', 'usize'),
            ('jumbled_hash', '[u8; 64]'),
        ),
        hashed_test_vectors,
    )


if __name__ == "__main__":
    main()
