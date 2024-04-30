#!/usr/bin/env python3
import sys;

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

# Removed the main() function from here in favour of the test vectors generated in orchard_zsa/key_components.py.
# Please use the orchard_zsa_key_components test vectors as they are a superset of the original orchard_key_components
# vectors.
