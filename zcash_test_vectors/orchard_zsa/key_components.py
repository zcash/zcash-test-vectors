#!/usr/bin/env python3
import sys;

assert sys.version_info[0] >= 3, "Python 3 required."

from ..orchard.pallas import Fp, Point
from ..orchard.key_components import derive_nullifier, SpendingKey, FullViewingKey
from ..output import render_args, render_tv

from zcash_test_vectors.bip340_reference import pubkey_gen
from zcash_test_vectors.orchard_zsa.asset_base import native_asset


#
# Key components
#

# The IssuanceKeys class contains the two issuance keys, isk and ik.
# The instantiation is done using the byte representation of isk, and it generates ik appropriately.
class IssuanceKeys(object):
    def __init__(self, data):
        self.isk = data

        if len(self.isk) != 32 or self.isk == b'\0' * 32:
            raise ValueError("invalid issuer key")

        self.ik = pubkey_gen(self.isk)


def main():
    args = render_args()

    from .note import OrchardZSANote
    from random import Random
    from ..rand import Rand

    rng = Random(0xabad533d)

    def randbytes(l):
        ret = []
        while len(ret) < l:
            ret.append(rng.randrange(0, 256))
        return bytes(ret)

    rand = Rand(randbytes)

    test_vectors = []
    for i in range(0, 10):
        sk = SpendingKey(rand.b(32))
        isk = IssuanceKeys(rand.b(32))
        fvk = FullViewingKey.from_spending_key(sk)
        default_d = fvk.default_d()
        default_pk_d = fvk.default_pkd()

        note_v = rand.u64()
        is_native = i < 5
        asset_base = native_asset() if is_native else Point.rand(rand)
        note_rho = Fp.random(rand)
        note_rseed = rand.b(32)
        note = OrchardZSANote(
            default_d,
            default_pk_d,
            note_v,
            asset_base,
            note_rho,
            note_rseed,
        )
        note_cm = note.note_commitment()
        note_nf = derive_nullifier(fvk.nk, note_rho, note.psi, note_cm)

        internal = fvk.internal()
        test_vectors.append({
            'sk': sk.data,
            'ask': bytes(sk.ask),
            'ak': bytes(fvk.ak),
            'isk': bytes(isk.isk),
            'ik': bytes(isk.ik),
            'nk': bytes(fvk.nk),
            'rivk': bytes(fvk.rivk),
            'ivk': bytes(fvk.ivk()),
            'ovk': fvk.ovk,
            'dk': fvk.dk,
            'default_d': default_d,
            'default_pk_d': bytes(default_pk_d),
            'internal_rivk': bytes(internal.rivk),
            'internal_ivk': bytes(internal.ivk()),
            'internal_ovk': internal.ovk,
            'internal_dk': internal.dk,
            'asset': bytes(asset_base),
            'note_v': note_v,
            'note_rho': bytes(note_rho),
            'note_rseed': bytes(note_rseed),
            'note_cmx': bytes(note_cm.extract()),
            'note_nf': bytes(note_nf),
        })

    render_tv(
        args,
        'orchard_zsa_key_components',
        (
            ('sk', '[u8; 32]'),
            ('ask', '[u8; 32]'),
            ('ak', '[u8; 32]'),
            ('isk', '[u8; 32]'),
            ('ik', '[u8; 32]'),
            ('nk', '[u8; 32]'),
            ('rivk', '[u8; 32]'),
            ('ivk', '[u8; 32]'),
            ('ovk', '[u8; 32]'),
            ('dk', '[u8; 32]'),
            ('default_d', '[u8; 11]'),
            ('default_pk_d', '[u8; 32]'),
            ('internal_rivk', '[u8; 32]'),
            ('internal_ivk', '[u8; 32]'),
            ('internal_ovk', '[u8; 32]'),
            ('internal_dk', '[u8; 32]'),
            ('asset', '[u8; 32]'),
            ('note_v', 'u64'),
            ('note_rho', '[u8; 32]'),
            ('note_rseed', '[u8; 32]'),
            ('note_cmx', '[u8; 32]'),
            ('note_nf', '[u8; 32]'),
        ),
        test_vectors,
    )


if __name__ == '__main__':
    main()
