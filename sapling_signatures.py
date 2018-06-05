#!/usr/bin/env python3
from binascii import hexlify
import os
from pyblake2 import blake2b

from sapling_generators import SPENDING_KEY_BASE
from sapling_jubjub import Fr, Point, r_j
from sapling_key_components import to_scalar
from sapling_utils import cldiv, leos2ip
from tv_output import chunk


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
        r = h_star(T + M)
        R = self.P_g * r
        Rbar = bytes(R)
        S = r + h_star(Rbar + M) * sk
        Sbar = bytes(S) # TODO: bitlength(r_j)
        return Rbar + Sbar

    def verify(self, vk, M, sig):
        mid = cldiv(self.l_G, 8)
        (Rbar, Sbar) = (sig[:mid], sig[mid:]) # TODO: bitlength(r_j)
        R = Point.from_bytes(Rbar)
        S = leos2ip(Sbar)
        c = h_star(Rbar + M)
        return R and S < r_j and self.P_g * Fr(S) == R + vk * c


def main():
    from random import Random
    rng = Random(0xabad533d)
    def randbytes(l):
        ret = []
        while len(ret) < l:
            ret.append(rng.randrange(0, 256))
        return bytes(ret)
    rj = RedJubjub(SPENDING_KEY_BASE, randbytes)

    print('''
        struct TestVector {
            sk: [u8; 32],
            vk: [u8; 32],
            alpha: [u8; 32],
            rsk: [u8; 32],
            rvk: [u8; 32],
            m: [u8; 32],
            sig: [u8; 64],
            rsig: [u8; 64],
        };

        // From https://github.com/zcash-hackworks/zcash-test-vectors/blob/master/sapling_signatures.py
        let test_vectors = vec![''')
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

        print('''            TestVector {
                sk: [
                    %s
                ],
                vk: [
                    %s
                ],
                alpha: [
                    %s
                ],
                rsk: [
                    %s
                ],
                rvk: [
                    %s
                ],
                m: [
                    %s
                ],
                sig: [
                    %s
                ],
                rsig: [
                    %s
                ],
            },''' % (
                chunk(hexlify(bytes(sk))),
                chunk(hexlify(bytes(vk))),
                chunk(hexlify(bytes(alpha))),
                chunk(hexlify(bytes(rsk))),
                chunk(hexlify(bytes(rvk))),
                chunk(hexlify(M)),
                chunk(hexlify(sig)),
                chunk(hexlify(rsig)),
            ))
    print('        ];')


if __name__ == '__main__':
    main()
