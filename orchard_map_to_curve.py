#!/usr/bin/env python3
import sys; assert sys.version_info[0] >= 3, "Python 3 required."

from zcash_test_vectors.orchard.group_hash import map_to_curve_simple_swu
from zcash_test_vectors.orchard.iso_pallas import Point as IsoPoint
from zcash_test_vectors.orchard.pallas import Fp
from zcash_test_vectors.utils import leos2ip
from zcash_test_vectors.output import render_args, render_tv
from zcash_test_vectors.rand import Rand


def main():
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
