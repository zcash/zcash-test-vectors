#!/usr/bin/env python3
import sys; assert sys.version_info[0] >= 3, "Python 3 required."

from binascii import unhexlify

from .pedersen import pedersen_hash
from ..utils import i2lebsp, leos2bsp

MERKLE_DEPTH = 32

def merkle_crh(layer, left, right):
    assert layer < MERKLE_DEPTH
    assert len(left) == 255
    assert len(right) == 255
    l = i2lebsp(6, MERKLE_DEPTH - 1 - layer)
    return pedersen_hash(b'Zcash_PH', l + left + right)


a = unhexlify('87a086ae7d2252d58729b30263fb7b66308bf94ef59a76c9c86e7ea016536505')[::-1]
b = unhexlify('a75b84a125b2353da7e8d96ee2a15efe4de23df9601b9d9564ba59de57130406')[::-1]
c = unhexlify('5bf43b5736c19b714d1f462c9d22ba3492c36e3d9bbd7ca24d94b440550aa561')[::-1]
a = leos2bsp(a)[:255]
b = leos2bsp(b)[:255]
c = leos2bsp(c)[:255]
assert merkle_crh(MERKLE_DEPTH - 1 - 25, a, b) == c
assert merkle_crh(MERKLE_DEPTH - 1 - 26, a, b) != c
