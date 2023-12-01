#!/usr/bin/env python3
import sys; assert sys.version_info[0] >= 3, "Python 3 required."

from hashlib import blake2b
import os

from .generators import SPENDING_KEY_BASE
from .jubjub import Fr, Point, r_j
from .key_components import to_scalar
from ..utils import cldiv, leos2ip
from ..output import render_args, render_tv


def H(x):
    digest = blake2b(person=b'Zcash_RedJubjubH')
    digest.update(x)
    return digest.digest()

def h_star(B):
    return Fr(leos2ip(H(B)))


class RedJubjub(object):
    l_G = 256 # l_J
    l_H = 512
    Public = Point
    Private = Fr
    Random = Fr

    def __init__(self, P_g, random=os.urandom):
        self.P_g = P_g
        self._random = random

    def gen_private(self):
        return to_scalar(self._random(64))

    def derive_public(self, sk):
        return self.P_g * sk

    def gen_random(self):
        T = self._random((self.l_H + 128) // 8)
        return h_star(T)

    @staticmethod
    def randomize_private(sk, alpha):
        return sk + alpha

    def randomize_public(self, vk, alpha):
        return vk + self.P_g * alpha

    def sign(self, sk, M):
        T = self._random((self.l_H + 128) // 8)
        vk_bar = bytes(self.derive_public(sk))
        r = h_star(T + vk_bar + M)
        R = self.P_g * r
        Rbar = bytes(R)
        S = r + h_star(Rbar + vk_bar + M) * sk
        Sbar = bytes(S) # TODO: bitlength(r_j)
        return Rbar + Sbar

    def verify(self, vk, M, sig):
        mid = cldiv(self.l_G, 8)
        (Rbar, Sbar) = (sig[:mid], sig[mid:]) # TODO: bitlength(r_j)
        R = Point.from_bytes(Rbar)
        S = leos2ip(Sbar)
        vk_bar = bytes(vk)
        c = h_star(Rbar + vk_bar + M)
        return R and S < r_j and self.P_g * Fr(S) == R + vk * c


def main():
    args = render_args()

    from random import Random
    rng = Random(0xabad533d)
    def randbytes(l):
        ret = []
        while len(ret) < l:
            ret.append(rng.randrange(0, 256))
        return bytes(ret)
    rj = RedJubjub(SPENDING_KEY_BASE, randbytes)

    test_vectors = []
    for i in range(0, 10):
        sk = rj.gen_private()
        vk = rj.derive_public(sk)
        alpha = rj.gen_random()
        rsk = rj.randomize_private(sk, alpha)
        rvk = rj.randomize_public(vk, alpha)

        M = bytes([i] * 32)
        sig = rj.sign(sk, M)
        rsig = rj.sign(rsk, M)
        assert rj.verify(vk, M, sig)
        assert rj.verify(rvk, M, rsig)
        assert not rj.verify(vk, M, rsig)
        assert not rj.verify(rvk, M, sig)

        test_vectors.append({
            'sk': bytes(sk),
            'vk': bytes(vk),
            'alpha': bytes(alpha),
            'rsk': bytes(rsk),
            'rvk': bytes(rvk),
            'm': M,
            'sig': sig,
            'rsig': rsig,
        })

    render_tv(
        args,
        'sapling_signatures',
        (
            ('sk', '[u8; 32]'),
            ('vk', '[u8; 32]'),
            ('alpha', '[u8; 32]'),
            ('rsk', '[u8; 32]'),
            ('rvk', '[u8; 32]'),
            ('m', '[u8; 32]'),
            ('sig', '[u8; 64]'),
            ('rsig', '[u8; 64]'),
        ),
        test_vectors,
    )


if __name__ == '__main__':
    main()
