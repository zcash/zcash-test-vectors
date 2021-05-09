#!/usr/bin/env python3
import sys; assert sys.version_info[0] >= 3, "Python 3 required."

from pyblake2 import blake2b, blake2s

from orchard_generators import NULLIFIER_K_BASE, SPENDING_KEY_BASE, group_hash
from orchard_pallas import Fp, Scalar, Point
from orchard_poseidon_hash import poseidon_hash
from orchard_merkle_tree import MERKLE_DEPTH
from orchard_commitments import commit_ivk, note_commit
from utils import leos2bsp, leos2ip, i2leosp
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

def prf_expand(sk: bytes, t: bytes):
    digest = blake2b(person=b'Zcash_ExpandSeed')
    digest.update(sk)
    digest.update(t)
    return digest.digest()

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
        if commit_ivk(self.rivk, self.ak, self.nk) is None:
            raise ValueError("invalid spending key")


class FullViewingKey(object):
    def __init__(self, sk):
        (self.rivk, self.ak, self.nk) = (sk.rivk, sk.ak, sk.nk)
        K = i2leosp(256, self.rivk.s)
        R = prf_expand(K, b'\x82' + i2leosp(256, self.ak.s) + i2leosp(256, self.nk.s))
        self.dk = R[:32]
        self.ovk = R[32:]

    def ivk(self):
        return commit_ivk(self.rivk, self.ak, self.nk)

    def ovk(self):
        return prf_expand(self.data, b'\x02')[:32]

    def default_d(self):
        return i2leosp(88, 1337)

    def default_pkd(self):
        return diversify_hash(self.default_d()) * self.ivk()


def main():
    args = render_args()

    test_vectors = []
    for i in range(0, 10):
        sys.stdout.write(".")
        sys.stdout.flush()
        sk = SpendingKey(bytes([i] * 32))
        fvk = FullViewingKey(sk)
        note_v = (2548793025584392057432895043257984320*i) % 2**64
        note_r = Scalar(8890123457840276890326754358439057438290574382905).exp(i+1)
        note_rho = Fp(342358729643275392567239275209835729829*i)
        note_psi = Fp(432592604358294371936572103719358723958*i)
        note_cm = note_commit(
            note_r,
            leos2bsp(bytes(diversify_hash(fvk.default_d()))),
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
