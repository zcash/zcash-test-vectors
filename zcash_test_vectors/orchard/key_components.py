#!/usr/bin/env python3
import sys;

from zcash_test_vectors.bip340_reference import pubkey_gen
from zcash_test_vectors.orchard.asset_base import native_asset

assert sys.version_info[0] >= 3, "Python 3 required."

from hashlib import blake2b

from ..ff1 import ff1_aes256_encrypt
from ..sapling.key_components import prf_expand

from .generators import NULLIFIER_K_BASE, SPENDING_KEY_BASE, group_hash
from .pallas import Fp, Scalar, Point
from . import poseidon
from .commitments import commit_ivk
from ..utils import i2leosp, i2lebsp, lebs2osp
from .utils import to_base, to_scalar
from ..output import render_args, render_tv


#
# PRFs and hashes
#

def diversify_hash(d):
    P = group_hash(b'z.cash:Orchard-gd', d)
    if P == Point.identity():
        P = group_hash(b'z.cash:Orchard-gd', b'')
    return P


def prf_nf_orchard(nk, rho):
    return poseidon.hash(nk, rho)


def derive_nullifier(nk, rho: Fp, psi: Fp, cm):
    scalar = prf_nf_orchard(nk, rho) + psi  # addition mod p
    point = NULLIFIER_K_BASE * Scalar(scalar.s) + cm
    return point.extract()


#
# Key components
#

class SpendingKey(object):
    def __init__(self, data):
        self.data = data

        self.ask = to_scalar(prf_expand(self.data, b'\x06'))
        self.nk = to_base(prf_expand(self.data, b'\x07'))
        self.rivk = to_scalar(prf_expand(self.data, b'\x08'))
        if self.ask == Scalar.ZERO:
            raise ValueError("invalid spending key")

        self.akP = SPENDING_KEY_BASE * self.ask
        if bytes(self.akP)[-1] & 0x80 != 0:
            self.ask = -self.ask

        self.ak = self.akP.extract()
        assert commit_ivk(self.rivk, self.ak, self.nk) is not None


class ExtendedSpendingKey(SpendingKey):
    def __init__(self, chaincode, data):
        SpendingKey.__init__(self, data)
        self.chaincode = chaincode

    @classmethod
    def master(cls, S):
        digest = blake2b(person=b'ZcashIP32Orchard')
        digest.update(S)
        I = digest.digest()
        I_L = I[:32]
        I_R = I[32:]
        return cls(I_R, I_L)

    def child(self, i):
        assert 0x80000000 <= i and i <= 0xFFFFFFFF

        I = prf_expand(self.chaincode, b'\x81' + self.data + i2leosp(32, i))
        I_L = I[:32]
        I_R = I[32:]
        return self.__class__(I_R, I_L)


# The IssuanceKeys class contains the two issuance keys, isk and ik.
# It is initialized with data that is the byte representation of isk, and it generates ik appropriately.
class IssuanceKeys(object):
    def __init__(self, data):
        self.isk = data

        if self.isk == b'\0' * 32:
            raise ValueError("invalid issuer key")

        self.ik = pubkey_gen(self.isk)


class FullViewingKey(object):
    def __init__(self, rivk, ak, nk):
        (self.rivk, self.ak, self.nk) = (rivk, ak, nk)
        K = i2leosp(256, self.rivk.s)
        R = prf_expand(K, b'\x82' + i2leosp(256, self.ak.s) + i2leosp(256, self.nk.s))
        self.dk = R[:32]
        self.ovk = R[32:]

    @classmethod
    def from_spending_key(cls, sk):
        return cls(sk.rivk, sk.ak, sk.nk)

    def ivk(self):
        return commit_ivk(self.rivk, self.ak, self.nk)

    def diversifier(self, j):
        return lebs2osp(ff1_aes256_encrypt(self.dk, b'', i2lebsp(88, j)))

    def default_d(self):
        return self.diversifier(0)

    def g_d(self, j):
        return diversify_hash(self.diversifier(j))

    def pk_d(self, j):
        return self.g_d(j) * Scalar(self.ivk().s)

    def default_pkd(self):
        return self.pk_d(0)

    def internal(self):
        K = i2leosp(256, self.rivk.s)
        rivk_internal = to_scalar(prf_expand(K, b'\x83' + i2leosp(256, self.ak.s) + i2leosp(256, self.nk.s)))
        return self.__class__(rivk_internal, self.ak, self.nk)


def main():
    args = render_args()

    from .note import OrchardNote
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
        isk = IssuanceAuthorizingKey(rand.b(32))
        fvk = FullViewingKey.from_spending_key(sk)
        default_d = fvk.default_d()
        default_pk_d = fvk.default_pkd()

        note_v = rand.u64()
        is_native = i < 5
        asset_base = native_asset() if is_native else Point.rand(rand)
        note_rho = Fp.random(rand)
        note_rseed = rand.b(32)
        note = OrchardNote(
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
        'orchard_key_components',
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
