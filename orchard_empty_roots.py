#!/usr/bin/env python3
import sys; assert sys.version_info[0] >= 3, "Python 3 required."

from zcash_test_vectors.orchard.merkle_tree import empty_roots
from zcash_test_vectors.orchard.pallas import Fp
from zcash_test_vectors.output import render_args, render_tv
from zcash_test_vectors.utils import i2lebsp


def main():
    args = render_args()

    render_tv(
        args,
        'orchard_empty_roots',
        (
            ('empty_roots', '[[u8; 32]; 33]'),
        ),
        {
            'empty_roots': list(map(bytes, empty_roots())),
        },
    )


if __name__ == '__main__':
    main()
