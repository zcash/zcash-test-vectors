#!/usr/bin/env python3
import sys; assert sys.version_info[0] >= 3, "Python 3 required."

from hashlib import blake2s

from ..output import render_args, render_tv
from .group_hash import group_hash
from .sinsemilla import sinsemilla_hash_to_point

# https://zips.z.cash/protocol/nu5.pdf#concretespendauthsig
SPENDING_KEY_BASE = group_hash(b'z.cash:Orchard', b'G')

# https://zips.z.cash/protocol/nu5.pdf#commitmentsandnullifiers
NULLIFIER_K_BASE = group_hash(b'z.cash:Orchard', b'K')

# https://zips.z.cash/protocol/nu5.pdf#concretehomomorphiccommit
VALUE_COMMITMENT_VALUE_BASE = group_hash(b'z.cash:Orchard-cv', b'v')
VALUE_COMMITMENT_RANDOMNESS_BASE = group_hash(b'z.cash:Orchard-cv', b'r')

# Used in SinsemillaCommit (https://zips.z.cash/protocol/nu5.pdf#concretesinsemillacommit)
NOTE_COMMITMENT_BASE = group_hash(b'z.cash:Orchard-NoteCommit-r', b'')
NOTE_COMMITMENT_Q = group_hash(b'z.cash:SinsemillaQ', b'z.cash:Orchard-NoteCommit-M')

# Used in SinsemillaShortCommit (https://zips.z.cash/protocol/nu5.pdf#concretesinsemillacommit)
IVK_COMMITMENT_BASE = group_hash(b'z.cash:Orchard-CommitIvk-r', b'')
IVK_COMMITMENT_Q = group_hash(b'z.cash:SinsemillaQ', b'z.cash:Orchard-CommitIvk-M')

# Used in SinsemillaHash (https://zips.z.cash/protocol/nu5.pdf#orchardmerklecrh)
MERKLE_CRH_Q = group_hash(b'z.cash:SinsemillaQ', b'z.cash:Orchard-MerkleCRH')

def main():
    render_tv(
        render_args(),
        'orchard_generators',
        (
            ('skb', '[u8; 32]'),
            ('nkb', '[u8; 32]'),
            ('vcvb', '[u8; 32]'),
            ('vcrb', '[u8; 32]'),
            ('cmb', '[u8; 32]'),
            ('cmq', '[u8; 32]'),
            ('ivkb', '[u8; 32]'),
            ('ivkq', '[u8; 32]'),
            ('mcq', '[u8; 32]'),
        ),
        {
            'skb': bytes(SPENDING_KEY_BASE),
            'nkb': bytes(NULLIFIER_K_BASE),
            'vcvb': bytes(VALUE_COMMITMENT_VALUE_BASE),
            'vcrb': bytes(VALUE_COMMITMENT_RANDOMNESS_BASE),
            'cmb': bytes(NOTE_COMMITMENT_BASE),
            'cmq': bytes(NOTE_COMMITMENT_Q),
            'ivkb': bytes(IVK_COMMITMENT_BASE),
            'ivkq': bytes(IVK_COMMITMENT_Q),
            'mcq': bytes(MERKLE_CRH_Q),
        },
    )


if __name__ == '__main__':
    main()
