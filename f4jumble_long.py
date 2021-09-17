#!/usr/bin/env python3
import sys; assert sys.version_info[0] >= 3, "Python 3 required."

from pyblake2 import blake2b

from tv_output import render_args, render_tv
from f4jumble import f4jumble, f4jumble_inv, MAX_l_M


def main():
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
