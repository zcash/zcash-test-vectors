#!/usr/bin/env python3
import sys;

from zcash_test_vectors.bip340_reference import schnorr_sign
from zcash_test_vectors.orchard_zsa.key_components import IssuanceKeys

from ..output import render_args, render_tv

assert sys.version_info[0] >= 3, "Python 3 required."

def main():
    args = render_args()

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

    # Start with the test vector from the BIP 340 repository. Specifically, the index 0 from https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
    test_vectors.append({
        'isk': bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000003"),
        'ik': bytes.fromhex("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"),
        'msg': bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000"),
        'sig': bytes.fromhex("E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0"),
    })

    # Now generate some more vectors using the BIP 340 reference implementation.
    for i in range(0, 10):
        issuance_keys = IssuanceKeys(rand.b(32))
        isk = issuance_keys.isk
        ik = issuance_keys.ik
        msg = rand.b(32)
        aux_rand = b'\0' * 32
        sig = schnorr_sign(msg, bytes(isk), aux_rand)

        test_vectors.append({
            'isk': bytes(isk),
            'ik': bytes(ik),
            'msg': msg,
            'sig': sig,
        })

    render_tv(
        args,
        'orchard_zsa_issuance_auth_sig',
        (
            ('isk', '[u8; 32]'),
            ('ik', '[u8; 32]'),
            ('msg', '[u8; 32]'),
            ('sig', '[u8; 64]'),
        ),
        test_vectors,
    )

if __name__ == '__main__':
    main()
