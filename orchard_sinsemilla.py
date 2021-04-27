#!/usr/bin/env python3
import sys; assert sys.version_info[0] >= 3, "Python 3 required."

import math

import orchard_iso_pallas

from orchard_pallas import Fp, Point
from sapling_utils import cldiv, lebs2ip, i2leosp
from orchard_group_hash import group_hash

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

if __name__ == "__main__":
    # This is the Pallas test vector from the Sage and Rust code (in affine coordinates).
    gh = group_hash(b"z.cash:test", b"Trans rights now!")
    assert gh == Point(Fp(10899331951394555178876036573383466686793225972744812919361819919497009261523),
                       Fp(851679174277466283220362715537906858808436854303373129825287392516025427980))

    # 40 bits, so no padding
    sh = sinsemilla_hash_to_point(b"z.cash:test-Sinsemilla", '0001011010100110001101100011011011110110')
    assert sh == Point(Fp(19681977528872088480295086998934490146368213853811658798708435106473481753752),
                       Fp(14670850419772526047574141291705097968771694788047376346841674072293161339903))
