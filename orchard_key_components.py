#!/usr/bin/env python3
import sys; assert sys.version_info[0] >= 3, "Python 3 required."

from ff1 import ff1_aes256_encrypt
from sapling_key_components import prf_expand

from orchard_generators import NULLIFIER_K_BASE, SPENDING_KEY_BASE, group_hash
from orchard_pallas import Fp, Scalar, Point
from orchard_poseidon_hash import poseidon_hash
from orchard_commitments import commit_ivk, note_commit
from utils import leos2bsp, leos2ip, i2leosp, i2lebsp, lebs2osp
from tv_output import render_args, render_tv

#
# Utilities
#

def to_scalar(buf):
    return Scalar(leos2ip(buf))

def to_base(buf):
    return Fp(leos2ip(buf))


#
# PRFs and hashes
#

def diversify_hash(d):
    P = group_hash(b'z.cash:Orchard-gd', d)
    if P == Point.identity():
        P = group_hash(b'z.cash:Orchard-gd', b'')
    return P

def prf_nf_orchard(nk, rho):
    return poseidon_hash(nk, rho)

def derive_nullifier(nk, rho: Fp, psi: Fp, cm):
    scalar = prf_nf_orchard(nk, rho) + psi  # addition mod p
    point = NULLIFIER_K_BASE * Scalar(scalar.s) + cm
    return point.extract()

#
# Key components
#

class SpendingKey:
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


class FullViewingKey(object):
    def __init__(self, sk):
        (self.rivk, self.ak, self.nk) = (sk.rivk, sk.ak, sk.nk)
        K = i2leosp(256, self.rivk.s)
        R = prf_expand(K, b'\x82' + i2leosp(256, self.ak.s) + i2leosp(256, self.nk.s))
        self.dk = R[:32]
        self.ovk = R[32:]

    def ivk(self):
        return commit_ivk(self.rivk, self.ak, self.nk)

    def default_d(self):
        index = i2lebsp(88, 0)
        return lebs2osp(ff1_aes256_encrypt(self.dk, b'', index))

    def default_gd(self):
        return diversify_hash(self.default_d())

    def default_pkd(self):
        return self.default_gd() * Scalar(self.ivk().s)


def main():
    args = render_args()

    from random import Random
    from tv_rand import Rand

    rng = Random(0xabad533d)
    def randbytes(l):
        ret = []
        while len(ret) < l:
            ret.append(rng.randrange(0, 256))
        return bytes(ret)
    rand = Rand(randbytes)

    test_vectors = []
    for _ in range(0, 10):
        sk = SpendingKey(rand.b(32))
        fvk = FullViewingKey(sk)
        note_v = rand.u64()
        note_r = Scalar.random(rand)
        note_rho = Fp.random(rand)
        note_psi = Fp.random(rand)
        note_cm = note_commit(
            note_r,
            leos2bsp(bytes(fvk.default_gd())),
            leos2bsp(bytes(fvk.default_pkd())),
            note_v,
            note_rho,
            note_psi)
        note_nf = derive_nullifier(fvk.nk, note_rho, note_psi, note_cm)
        test_vectors.append({
            'sk': sk.data,
            'ask': bytes(sk.ask),
            'ovk': fvk.ovk,
            'rivk': bytes(fvk.rivk),
            'ak': bytes(fvk.ak),
            'nk': bytes(fvk.nk),
            'ivk': bytes(fvk.ivk()),
            'default_d': fvk.default_d(),
            'default_pk_d': bytes(fvk.default_pkd()),
            'note_v': note_v,
            'note_r': bytes(note_r),
            'note_cmx': bytes(note_cm.extract()),
            'note_nf': bytes(note_nf),
        })

    render_tv(
        args,
        'orchard_key_components',
        (
            ('sk', '[u8; 32]'),
            ('ask', '[u8; 32]'),
            ('ovk', '[u8; 32]'),
            ('rivk', '[u8; 32]'),
            ('ak', '[u8; 32]'),
            ('nk', '[u8; 32]'),
            ('ivk', '[u8; 32]'),
            ('default_d', '[u8; 11]'),
            ('default_pk_d', '[u8; 32]'),
            ('note_v', 'u64'),
            ('note_r', '[u8; 32]'),
            ('note_cmx', '[u8; 32]'),
            ('note_nf', '[u8; 32]'),
        ),
        test_vectors,
    )


if __name__ == '__main__':
    main()
