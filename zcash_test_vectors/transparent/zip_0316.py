#!/usr/bin/env python3
import sys; assert sys.version_info[0] >= 3, "Python 3 required."

from ..output import render_args, render_tv
from ..rand import Rand
from ..sapling.key_components import prf_expand
from secp256k1 import PrivateKey


def derive_ovks(chaincode, pk):
    assert len(pk) == 33 and pk[0] in (0x02, 0x03)
    I_ovk = prf_expand(chaincode, b'\xD0' + pk)
    ovk_external = I_ovk[:32]
    ovk_internal = I_ovk[32:]
    return (ovk_external, ovk_internal)


def main():
    args = render_args()

    from random import Random
    rng = Random(0xabad533d)
    def randbytes(l):
        ret = []
        while len(ret) < l:
            ret.append(rng.randrange(0, 256))
        return bytes(ret)
    rand = Rand(randbytes)

    test_vectors = []
    for i in range(10):
        chaincode = rand.b(32)
        pk = PrivateKey(rand.b(32), True).pubkey.serialize(compressed=True)
        (external_ovk, internal_ovk) = derive_ovks(chaincode, pk)
        test_vectors.append({
            'c' : chaincode,
            'pk': pk,
            'external_ovk': external_ovk,
            'internal_ovk': internal_ovk,
        })

    render_tv(
        args,
        'zip_0316',
        (
            ('c',            '[u8; 32]'),
            ('pk',           '[u8; 33]'),
            ('external_ovk', '[u8; 32]'),
            ('internal_ovk', '[u8; 32]'),
        ),
        test_vectors,
    )

if __file__ == '__main__':
    main()
