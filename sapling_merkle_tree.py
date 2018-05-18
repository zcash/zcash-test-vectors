#!/usr/bin/env python3
from sapling_pedersen import pedersen_hash
from sapling_utils import i2lebsp

MERKLE_DEPTH = 32

def merkle_crh(layer, left, right):
    l = i2lebsp(6, MERKLE_DEPTH - 1 - layer)
    return pedersen_hash(b'Zcash_PH', l + left + right)
