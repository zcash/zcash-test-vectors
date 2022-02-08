#!/usr/bin/env python3
import sys; assert sys.version_info[0] >= 3, "Python 3 required."

from .pallas import Fp
from . import poseidon

from ..utils import leos2ip
from ..output import render_args, render_tv
from ..rand import Rand

def main():
    test_vectors = [[Fp.ZERO, Fp(1)]]

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
        test_vectors.append([
            Fp(leos2ip(rand.b(32))),
            Fp(leos2ip(rand.b(32))),
        ])

    render_tv(
        render_args(),
        'orchard_poseidon_hash',
        (
            ('input', '[[u8; 32]; 2]'),
            ('output', '[u8; 32]'),
        ),
        [{
            'input': list(map(bytes, input)),
            'output': bytes(poseidon.hash(input[0], input[1])),
        } for input in test_vectors],
    )

if __name__ == "__main__":
    main()
