#!/usr/bin/env python3
import sys; assert sys.version_info[0] >= 3, "Python 3 required."

from chacha20poly1305 import ChaCha20Poly1305
import os
from pyblake2 import blake2b
from transaction import MAX_MONEY
from tv_output import render_args, render_tv
from tv_rand import Rand

from orchard_generators import VALUE_COMMITMENT_VALUE_BASE, VALUE_COMMITMENT_RANDOMNESS_BASE
from orchard_pallas import Scalar
from orchard_commitments import note_commit, rcv_trapdoor
from orchard_key_components import diversify_hash, prf_expand, FullViewingKey, SpendingKey
from orchard_note import OrchardNote, OrchardNotePlaintext
from orchard_utils import to_scalar
from utils import leos2bsp

# https://zips.z.cash/protocol/nu5.pdf#concreteorchardkdf
def kdf_orchard(shared_secret, ephemeral_key):
    digest = blake2b(digest_size=32, person=b'Zcash_OrchardKDF')
    digest.update(bytes(shared_secret))
    digest.update(bytes(ephemeral_key))
    return digest.digest()

# https://zips.z.cash/protocol/nu5.pdf#concreteprfs
def prf_ock_orchard(ovk, cv, cmx, ephemeral_key):
    digest = blake2b(digest_size=32, person=b'Zcash_Orchardock')
    digest.update(ovk)
    digest.update(cv)
    digest.update(cmx)
    digest.update(ephemeral_key)
    return digest.digest()

# https://zips.z.cash/protocol/nu5.pdf#concreteorchardkeyagreement
class OrchardKeyAgreement(object):
    @staticmethod
    def esk(rseed, rho):
        return to_scalar(prf_expand(bytes(rseed), b'\x04' + bytes(rho)))

    @staticmethod
    def derive_public(esk, g_d):
        return g_d * esk

    @staticmethod
    def agree(esk, pk_d):
        return pk_d * esk

# https://zips.z.cash/protocol/nu5.pdf#concretesym
class OrchardSym(object):
    @staticmethod
    def k(random):
        return random(32)

    @staticmethod
    def encrypt(key, plaintext):
        cip = ChaCha20Poly1305(key)
        return bytes(cip.encrypt(b'\x00' * 12, plaintext))

    @staticmethod
    def decrypt(key, ciphertext):
        cip = ChaCha20Poly1305(key)
        return bytes(cip.decrypt(b'\x00' * 12, ciphertext))

# https://zips.z.cash/protocol/nu5.pdf#saplingandorchardencrypt
class OrchardNoteEncryption(object):
    def __init__(self, random=os.urandom):
        self._random = random

    def rseed(self):
        return self._random.b(32)

    def encrypt(self, note: OrchardNote, memo, pk_d_new, g_d_new, cv_new, cm_new, ovk=None):
        np = note.note_plaintext(memo)
        esk = OrchardKeyAgreement.esk(np.rseed, note.rho)
        p_enc = bytes(np)
        epk = OrchardKeyAgreement.derive_public(esk, g_d_new)
        shared_secret = OrchardKeyAgreement.agree(esk, pk_d_new)
        k_enc = kdf_orchard(shared_secret, epk)
        c_enc = OrchardSym.encrypt(k_enc, p_enc)

        if not ovk:
            ock = OrchardSym.k(self._random)
            op = self._random.b(64)
        else:
            cv = bytes(cv_new)
            cmx = bytes(cm_new.x)
            ephemeral_key = bytes(epk)
            ock = prf_ock_orchard(ovk, cv, cmx, ephemeral_key)
            op = bytes(pk_d_new) + bytes(esk)

        c_out = OrchardSym.encrypt(ock, op)

        self.epk = epk
        self.c_enc = c_enc
        self.c_out = c_out

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
    rand = Rand(randbytes)

    ne = OrchardNoteEncryption(rand)

    test_vectors = []
    for i in range(0, 10):
        sk = SpendingKey(bytes([i] * 32))
        fvk = FullViewingKey(sk)
        pk_d = fvk.default_pkd()
        g_d = diversify_hash(fvk.default_d())

        rseed = ne.rseed()
        memo = rand.b(512)
        np = OrchardNotePlaintext(
            fvk.default_d(),
            Scalar(rand.u64() % (MAX_MONEY + 1)),
            rseed,
            memo
        )

        rcv = rcv_trapdoor(rand)
        cv = VALUE_COMMITMENT_VALUE_BASE * np.v + VALUE_COMMITMENT_RANDOMNESS_BASE * rcv

        rho = np.dummy_nullifier(rand)
        note = OrchardNote(fvk.default_d(), pk_d, np.v, rho, rseed)
        cm = note_commit(
            note.rcm,
            leos2bsp(bytes(g_d)),
            leos2bsp(bytes(pk_d)),
            np.v.s,
            rho,
            note.psi
        )

        (
            esk, epk,
            shared_secret,
            k_enc, p_enc, c_enc,
            ock, op, c_out,
        ) = ne.encrypt(note, memo, pk_d, g_d, cv, cm, fvk.ovk)

        test_vectors.append({
            'ovk': fvk.ovk,
            'ivk': bytes(fvk.ivk()),
            'default_d': fvk.default_d(),
            'default_pk_d': bytes(pk_d),
            'v': np.v.s,
            'rcm': bytes(note.rcm),
            'memo': np.memo,
            'cv': bytes(cv),
            'cmx': bytes(cm.x),
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
        'orchard_note_encryption',
        (
            ('ovk', '[u8; 32]'),
            ('ivk', '[u8; 32]'),
            ('default_d', '[u8; 11]'),
            ('default_pk_d', '[u8; 32]'),
            ('v', 'u64'),
            ('rcm', '[u8; 32]'),
            ('memo', '[u8; 512]'),
            ('cv', '[u8; 32]'),
            ('cmx', '[u8; 32]'),
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
