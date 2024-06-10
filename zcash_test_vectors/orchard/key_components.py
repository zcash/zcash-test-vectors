#!/usr/bin/env python3
import sys; assert sys.version_info[0] >= 3, "Python 3 required."

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

        self.ask  = to_scalar(prf_expand(self.data, b'\x06'))
        self.nk   = to_base(prf_expand(self.data, b'\x07'))
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
        I   = digest.digest()
        I_L = I[:32]
        I_R = I[32:]
        return cls(I_R, I_L)

    def child(self, i):
        assert 0x80000000 <= i and i <= 0xFFFFFFFF

        I   = prf_expand(self.chaincode, b'\x81' + self.data + i2leosp(32, i))
        I_L = I[:32]
        I_R = I[32:]
        return self.__class__(I_R, I_L)


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

class KeyInit(object):
    def __init__(self, rand):
        self.sk = SpendingKey(rand.b(32))
        self.fvk = FullViewingKey.from_spending_key(self.sk)
        self.default_d = self.fvk.default_d()
        self.default_pk_d = self.fvk.default_pkd()

        self.note_v = rand.u64()
        self.note_rho = Fp.random(rand)
        self.note_rseed = rand.b(32)

        self.internal = self.fvk.internal()

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
    for _ in range(0, 10):
        k = KeyInit(rand)
        note = OrchardNote(
            k.default_d,
            k.default_pk_d,
            k.note_v,
            k.note_rho,
            k.note_rseed,
        )
        note_cm = note.note_commitment()
        note_nf = derive_nullifier(k.fvk.nk, k.note_rho, note.psi, note_cm)
        test_vectors.append({
            'sk': k.sk.data,
            'ask': bytes(k.sk.ask),
            'ak': bytes(k.fvk.ak),
            'nk': bytes(k.fvk.nk),
            'rivk': bytes(k.fvk.rivk),
            'ivk': bytes(k.fvk.ivk()),
            'ovk': k.fvk.ovk,
            'dk': k.fvk.dk,
            'default_d': k.default_d,
            'default_pk_d': bytes(k.default_pk_d),
            'internal_rivk': bytes(k.internal.rivk),
            'internal_ivk': bytes(k.internal.ivk()),
            'internal_ovk': k.internal.ovk,
            'internal_dk': k.internal.dk,
            'note_v': k.note_v,
            'note_rho': bytes(k.note_rho),
            'note_rseed': bytes(k.note_rseed),
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
