#!/usr/bin/env python3
from pyblake2 import blake2s

from sapling_jubjub import Point, JUBJUB_COFACTOR

# First 64 bytes of the BLAKE2s input during group hash.
# This is chosen to be some random string that we couldn't have
# anticipated when we designed the algorithm, for rigidity purposes.
# We deliberately use an ASCII hex string of 32 bytes here.
CRS = b'096b36a5804bfacef1691e173c366a47ff5ba84a44f26ddd7e8d9f79d5b42df0'


#
# Group hash
#

def group_hash(D, M):
    digest = blake2s(person=D)
    digest.update(CRS)
    digest.update(M)
    p = Point.from_bytes(digest.digest())
    if not p:
        return None
    q = p * JUBJUB_COFACTOR
    if q == Point.ZERO:
        return None
    return q

def find_group_hash(D, M):
    i = 0
    while True:
        p = group_hash(D, M + bytes([i]))
        if p:
            return p
        i += 1
        assert(i < 256)


#
# Sapling generators
#

SPENDING_KEY_BASE = find_group_hash(b'Zcash_G_', b'')
PROVING_KEY_BASE = find_group_hash(b'Zcash_H_', b'')
