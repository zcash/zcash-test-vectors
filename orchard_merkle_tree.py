#!/usr/bin/env python3
import sys; assert sys.version_info[0] >= 3, "Python 3 required."

from binascii import unhexlify

from orchard_pallas import Fp
from orchard_sinsemilla import sinsemilla_hash

from sapling_utils import i2lebsp, leos2bsp

# https://zips.z.cash/protocol/nu5.pdf#constants
MERKLE_DEPTH = 32
L_MERKLE = 255

# https://zips.z.cash/protocol/nu5.pdf#orchardmerklecrh
def merkle_crh(layer, left, right):
    assert layer < MERKLE_DEPTH
    assert len(left) == L_MERKLE
    assert len(right) == L_MERKLE
    l = i2lebsp(6, MERKLE_DEPTH - 1 - layer)
    return sinsemilla_hash(b"z.cash:Orchard-MerkleCRH", l + left + right)

left = unhexlify("87a086ae7d2252d58729b30263fb7b66308bf94ef59a76c9c86e7ea016536505")[::-1]
right = unhexlify("a75b84a125b2353da7e8d96ee2a15efe4de23df9601b9d9564ba59de57130406")[::-1]

left = leos2bsp(left)[:L_MERKLE]
right = leos2bsp(right)[:L_MERKLE]

# parent = merkle_crh(MERKLE_DEPTH - 1 - 25, left, right)
parent = Fp(17261766847362299889572407272882432634088514578301422827180452043349931590033)
assert merkle_crh(MERKLE_DEPTH - 1 - 25, left, right) == parent
assert merkle_crh(MERKLE_DEPTH - 1 - 26, left, right) != parent
