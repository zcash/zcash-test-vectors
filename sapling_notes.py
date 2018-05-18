#!/usr/bin/env python3
from sapling_pedersen import windowed_pedersen_commitment
from sapling_utils import i2lebsp

def note_commit(rcm, g_d, pk_d, v):
    return windowed_pedersen_commitment(rcm, [1] * 6 + i2lebsp(64, v) + g_d + pk_d)
