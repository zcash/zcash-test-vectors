#!/usr/bin/env python3
from binascii import hexlify
from pyblake2 import blake2b, blake2s

from sapling_generators import PROVING_KEY_BASE, SPENDING_KEY_BASE, group_hash
from sapling_jubjub import Fr
from sapling_merkle_tree import MERKLE_DEPTH
from sapling_notes import note_commit, note_nullifier
from sapling_utils import chunk, leos2bsp

#
# PRFs and hashes
#

def prf_expand(sk, t):
    digest = blake2b(person=b'Zcash_ExpandSeed')
    digest.update(sk)
    digest.update(t)
    return digest.digest()

def crh_ivk(ak, nk):
    digest = blake2s(person=b'Zcashivk')
    digest.update(ak)
    digest.update(nk)
    ivk = digest.digest()
    ivk = ivk[:31] + bytes([ivk[31] & 0b00000111])
    return ivk


#
# Key components
#

def cached(f):
    def wrapper(self):
        if not hasattr(self, '_cached'):
            self._cached = {}
        if not self._cached.get(f):
            self._cached[f] = f(self)
        return self._cached[f]
    return wrapper

class SpendingKey(object):
    def __init__(self, data):
        self.data = data

    @cached
    def ask(self):
        return Fr.from_bytes(prf_expand(self.data, b'\0'))

    @cached
    def nsk(self):
        return Fr.from_bytes(prf_expand(self.data, b'\1'))

    @cached
    def ovk(self):
        return prf_expand(self.data, b'\2')[:32]

    @cached
    def ak(self):
        return SPENDING_KEY_BASE * self.ask()

    @cached
    def nk(self):
        return PROVING_KEY_BASE * self.nsk()

    @cached
    def ivk(self):
        return Fr.from_bytes(crh_ivk(bytes(self.ak()), bytes(self.nk())))

    @cached
    def default_d(self):
        i = 0
        while True:
            d = prf_expand(self.data, bytes([3, i]))[:11]
            if group_hash(b'Zcash_gd', d):
                return d
            i += 1
            assert i < 256

    @cached
    def default_pkd(self):
        return group_hash(b'Zcash_gd', self.default_d()) * self.ivk()


def main():
    print('''
        struct TestVector {
            sk: [u8; 32],
            ask: [u8; 32],
            nsk: [u8; 32],
            ovk: [u8; 32],
            ak: [u8; 32],
            nk: [u8; 32],
            ivk: [u8; 32],
            default_d: [u8; 11],
            default_pk_d: [u8; 32],
            note_v: u64,
            note_r: [u8; 32],
            note_cm: [u8; 32],
            note_pos: u64,
            note_nf: [u8; 32],
        };

        // From https://github.com/zcash-hackworks/zcash-test-vectors/blob/master/sapling_key_components.py
        let test_vectors = vec![''')
    for i in range(0, 10):
        sk = SpendingKey(bytes([i] * 32))
        note_v = (2548793025584392057432895043257984320*i) % 2**64
        note_r = Fr(8890123457840276890326754358439057438290574382905).exp(i+1)
        note_cm = note_commit(
            note_r,
            leos2bsp(bytes(group_hash(b'Zcash_gd', sk.default_d()))),
            leos2bsp(bytes(sk.default_pkd())),
            note_v)
        note_pos = (980705743285409327583205473820957432*i) % 2**MERKLE_DEPTH
        note_nf = note_nullifier(sk.nk(), note_cm, Fr(note_pos))
        print('''            TestVector {
                sk: [
                    %s
                ],
                ask: [
                    %s
                ],
                nsk: [
                    %s
                ],
                ovk: [
                    %s
                ],
                ak: [
                    %s
                ],
                nk: [
                    %s
                ],
                ivk: [
                    %s
                ],
                default_d: [
                    %s
                ],
                default_pk_d: [
                    %s
                ],
                note_v: %s,
                note_r: [
                    %s
                ],
                note_cm: [
                    %s
                ],
                note_pos: %s,
                note_nf: [
                    %s
                ],
            },''' % (
                chunk(hexlify(sk.data)),
                chunk(hexlify(bytes(sk.ask()))),
                chunk(hexlify(bytes(sk.nsk()))),
                chunk(hexlify(sk.ovk())),
                chunk(hexlify(bytes(sk.ak()))),
                chunk(hexlify(bytes(sk.nk()))),
                chunk(hexlify(bytes(sk.ivk()))),
                chunk(hexlify(sk.default_d())),
                chunk(hexlify(bytes(sk.default_pkd()))),
                note_v,
                chunk(hexlify(bytes(note_r))),
                chunk(hexlify(bytes(note_cm.u))),
                note_pos,
                chunk(hexlify(note_nf)),
            ))
    print('        ];')


if __name__ == '__main__':
    main()
