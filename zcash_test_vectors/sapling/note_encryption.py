#!/usr/bin/env python3
import sys; assert sys.version_info[0] >= 3, "Python 3 required."

from chacha20poly1305 import ChaCha20Poly1305
from hashlib import blake2b
import os
import struct

from .generators import VALUE_COMMITMENT_VALUE_BASE, VALUE_COMMITMENT_RANDOMNESS_BASE
from .jubjub import Fr, JUBJUB_COFACTOR
from .key_components import SpendingKey, diversify_hash
from .notes import note_commit
from ..utils import leos2bsp, leos2ip
from ..output import render_args, render_tv


def kdf_sapling(shared_secret, epk):
    digest = blake2b(digest_size=32, person=b'Zcash_SaplingKDF')
    digest.update(bytes(shared_secret))
    digest.update(bytes(epk))
    return digest.digest()

def prf_ock(ovk, cv, cmu, ephemeral_key):
    digest = blake2b(digest_size=32, person=b'Zcash_Derive_ock')
    digest.update(ovk)
    digest.update(cv)
    digest.update(cmu)
    digest.update(ephemeral_key)
    return digest.digest()

class SaplingKeyAgreement(object):
    @staticmethod
    def private(random):
        return Fr(leos2ip(random(32)))

    @staticmethod
    def derive_public(esk, g_d):
        return g_d * esk

    @staticmethod
    def agree(esk, pk_d):
        return pk_d * esk * JUBJUB_COFACTOR

class SaplingSym(object):
    @staticmethod
    def k(random):
        return random(32)

    @staticmethod
    def encrypt(key, plaintext):
        cip = ChaCha20Poly1305(key)
        return bytes(cip.encrypt(b'\x00' * 12, plaintext))


class SaplingNotePlaintext(object):
    def __init__(self, d, v, rcm, memo):
        self.d = d
        self.v = v
        self.rcm = rcm
        self.memo = memo

    def __bytes__(self):
        return (
            b'\x01' +
            self.d +
            struct.pack('<Q', self.v) +
            bytes(self.rcm) +
            self.memo
        )

class SaplingNoteEncryption(object):
    def __init__(self, random=os.urandom):
        self._random = random

    def encrypt(self, np, pk_d_new, g_d_new, cv_new, cm_new, ovk=None):
        esk = SaplingKeyAgreement.private(self._random)
        epk = SaplingKeyAgreement.derive_public(esk, g_d_new)
        p_enc = bytes(np)
        shared_secret = SaplingKeyAgreement.agree(esk, pk_d_new)
        k_enc = kdf_sapling(shared_secret, epk)
        c_enc = SaplingSym.encrypt(k_enc, p_enc)

        if not ovk:
            ock = SaplingSym.k(self._random)
            op = self._random(64)
        else:
            cv = bytes(cv_new)
            cmu = bytes(cm_new.u)
            ephemeral_key = bytes(epk)
            ock = prf_ock(ovk, cv, cmu, ephemeral_key)
            op = bytes(pk_d_new) + bytes(esk)

        c_out = SaplingSym.encrypt(ock, op)

        return (esk, epk, shared_secret, k_enc, p_enc, c_enc, ock, op, c_out)


def main():
    args = render_args()

    from random import Random
    rng = Random(0xabad533d)
    def randbytes(l):
        ret = []
        while len(ret) < l:
            ret.append(rng.randrange(0, 256))
        return bytes(ret)
    ne = SaplingNoteEncryption(randbytes)

    test_vectors = []
    for i in range(0, 10):
        sk = SpendingKey(bytes([i] * 32))
        pk_d = sk.default_pkd()
        g_d = diversify_hash(sk.default_d())

        np = SaplingNotePlaintext(
            sk.default_d(),
            100000000 * (i+1),
            Fr(8890123457840276890326754358439057438290574382905).exp(i+1),
            b'\xf6' + b'\x00'*511)
        cv = VALUE_COMMITMENT_VALUE_BASE * Fr(np.v) + VALUE_COMMITMENT_RANDOMNESS_BASE * np.rcm
        cm = note_commit(
            np.rcm,
            leos2bsp(bytes(g_d)),
            leos2bsp(bytes(pk_d)),
            np.v)

        (
            esk, epk,
            shared_secret,
            k_enc, p_enc, c_enc,
            ock, op, c_out,
        ) = ne.encrypt(np, pk_d, g_d, cv, cm, sk.ovk())

        test_vectors.append({
            'ovk': sk.ovk(),
            'ivk': bytes(sk.ivk()),
            'default_d': sk.default_d(),
            'default_pk_d': bytes(sk.default_pkd()),
            'v': np.v,
            'rcm': bytes(np.rcm),
            'memo': np.memo,
            'cv': bytes(cv),
            'cmu': bytes(cm.u),
            'esk': bytes(esk),
            'epk': bytes(epk),
            'shared_secret': bytes(shared_secret),
            'k_enc': k_enc,
            'p_enc': p_enc,
            'c_enc': c_enc,
            'ock': ock,
            'op': op,
            'c_out': c_out,
        })

    render_tv(
        args,
        'sapling_note_encryption',
        (
            ('ovk', '[u8; 32]'),
            ('ivk', '[u8; 32]'),
            ('default_d', '[u8; 11]'),
            ('default_pk_d', '[u8; 32]'),
            ('v', 'u64'),
            ('rcm', '[u8; 32]'),
            ('memo', '[u8; 512]'),
            ('cv', '[u8; 32]'),
            ('cmu', '[u8; 32]'),
            ('esk', '[u8; 32]'),
            ('epk', '[u8; 32]'),
            ('shared_secret', '[u8; 32]'),
            ('k_enc', '[u8; 32]'),
            ('p_enc', '[u8; 564]'),
            ('c_enc', '[u8; 580]'),
            ('ock', '[u8; 32]'),
            ('op', '[u8; 64]'),
            ('c_out', '[u8; 80]'),
        ),
        test_vectors,
    )


if __name__ == '__main__':
    main()
