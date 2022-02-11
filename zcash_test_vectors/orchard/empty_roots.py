#!/usr/bin/env python3
import sys; assert sys.version_info[0] >= 3, "Python 3 required."

from .merkle_tree import empty_roots
from .pallas import Fp

from ..output import render_args, render_tv
from ..utils import i2lebsp


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
