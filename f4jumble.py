#!/usr/bin/env python3
import sys; assert sys.version_info[0] >= 3, "Python 3 required."

import math
import struct

from pyblake2 import blake2b

from tv_output import render_args, render_tv
from tv_rand import Rand


# Maximum output length of BLAKE2b
l_H = 64
assert 8*l_H == 512

def instantiate(l_L, l_R):
    def H(i, u):
        digest = blake2b(
            digest_size=l_L,
            person=b'UA_F4Jumble_H_' + bytes([i, 0]),
        )
        digest.update(u)
        return digest.digest()

    def G(i, u):
        def inner(j):
            digest = blake2b(
                digest_size=l_H,
                person=b'UA_F4Jumble_G_' + bytes([i, j]),
            )
            digest.update(u)
            return digest.digest()
        
        return b''.join([inner(j) for j in range(0, math.ceil(l_R/l_H))])[:l_R]

    return (H, G)

def xor(x, y):
    return bytes([a ^ b for (a, b) in zip(x, y)])

def f4jumble(M):
    l_M = len(M)
    assert 48 <= l_M and l_M <= 16448

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
    assert 48 <= l_M and l_M <= 16448

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

    test_vectors = []
    # Generate test vectors with various lengths:
    for l_M in [
        48,
        l_H,
        2*l_H,
        2*l_H + 1,
        3*l_H,
        3*l_H + 1,
        (rand.u32() % 16400) + 48,
        16448,
    ]:
        M = rand.b(l_M)
        assert f4jumble_inv(f4jumble(M)) == M
        test_vectors.append(M)

    test_vectors = [{
        'normal': M,
        'jumbled': f4jumble(M),
    } for M in test_vectors]

    render_tv(
        args,
        'f4jumble',
        (
            ('normal', 'Vec<u8>'),
            ('jumbled', 'Vec<u8>'),
        ),
        test_vectors,
    )


if __name__ == "__main__":
    main()
