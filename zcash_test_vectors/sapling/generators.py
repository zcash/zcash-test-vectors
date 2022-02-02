#!/usr/bin/env python3
import sys; assert sys.version_info[0] >= 3, "Python 3 required."

from hashlib import blake2s

from .jubjub import Point, JUBJUB_COFACTOR
from ..output import render_args, render_tv
from ..utils import i2leosp

# First 64 bytes of the BLAKE2s input during group hash.
# This is chosen to be some random string that we couldn't have
# anticipated when we designed the algorithm, for rigidity purposes.
# We deliberately use an ASCII hex string of 32 bytes here.
URS = b'096b36a5804bfacef1691e173c366a47ff5ba84a44f26ddd7e8d9f79d5b42df0'


#
# Group hash
#

def group_hash(D, M):
    digest = blake2s(person=D)
    digest.update(URS)
    digest.update(M)
    p = Point.from_bytes(digest.digest())
    if p is None:
        return None
    q = p * JUBJUB_COFACTOR
    if q == Point.ZERO:
        return None
    return q

def find_group_hash(D, M):
    i = 0
    while True:
        p = group_hash(D, M + bytes([i]))
        if p is not None:
            return p
        i += 1
        assert i < 256


#
# Sapling generators
#

SPENDING_KEY_BASE = find_group_hash(b'Zcash_G_', b'')
PROVING_KEY_BASE = find_group_hash(b'Zcash_H_', b'')
NOTE_POSITION_BASE = find_group_hash(b'Zcash_J_', b'')
WINDOWED_PEDERSEN_RANDOMNESS_BASE = find_group_hash(b'Zcash_PH', b'r')
VALUE_COMMITMENT_VALUE_BASE = find_group_hash(b'Zcash_cv', b'v')
VALUE_COMMITMENT_RANDOMNESS_BASE = find_group_hash(b'Zcash_cv', b'r')

required_bases = 4
PEDERSEN_BASES = [find_group_hash(b'Zcash_PH', i2leosp(32, iminus1))
                  for iminus1 in range(0, required_bases)]

def main():
    render_tv(
        render_args(),
        'sapling_generators',
        (
            ('skb', '[u8; 32]'),
            ('pkb', '[u8; 32]'),
            ('npb', '[u8; 32]'),
            ('wprb', '[u8; 32]'),
            ('vcvb', '[u8; 32]'),
            ('vcrb', '[u8; 32]'),
            ('pb0', '[u8; 32]'),
            ('pb1', '[u8; 32]'),
            ('pb2', '[u8; 32]'),
            ('pb3', '[u8; 32]'),
        ),
        {
            'skb': bytes(SPENDING_KEY_BASE),
            'pkb': bytes(PROVING_KEY_BASE),
            'npb': bytes(NOTE_POSITION_BASE),
            'wprb': bytes(WINDOWED_PEDERSEN_RANDOMNESS_BASE),
            'vcvb': bytes(VALUE_COMMITMENT_VALUE_BASE),
            'vcrb': bytes(VALUE_COMMITMENT_RANDOMNESS_BASE),
            'pb0': bytes(PEDERSEN_BASES[0]),
            'pb1': bytes(PEDERSEN_BASES[1]),
            'pb2': bytes(PEDERSEN_BASES[2]),
            'pb3': bytes(PEDERSEN_BASES[3]),
        },
    )


if __name__ == '__main__':
    main()
