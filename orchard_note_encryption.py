#!/usr/bin/env python3
import sys; assert sys.version_info[0] >= 3, "Python 3 required."

from chacha20poly1305 import ChaCha20Poly1305
import os
from pyblake2 import blake2b
from transaction import MAX_MONEY
from tv_output import render_args, render_tv
from tv_rand import Rand

from orchard_generators import VALUE_COMMITMENT_VALUE_BASE, VALUE_COMMITMENT_RANDOMNESS_BASE
from orchard_pallas import Point, Scalar
from orchard_commitments import rcv_trapdoor
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
        ephemeral_key = bytes(epk)
        shared_secret = OrchardKeyAgreement.agree(esk, pk_d_new)
        k_enc = kdf_orchard(shared_secret, epk)
        c_enc = OrchardSym.encrypt(k_enc, p_enc)

        if not ovk:
            ock = OrchardSym.k(self._random)
            op = self._random.b(64)
        else:
            cv = bytes(cv_new)
            cmx = bytes(cm_new.extract())
            ock = prf_ock_orchard(ovk, cv, cmx, ephemeral_key)
            op = bytes(pk_d_new) + bytes(esk)

        c_out = OrchardSym.encrypt(ock, op)

        self.esk = esk
        self.shared_secret = shared_secret
        self.k_enc = k_enc
        self.p_enc = p_enc
        self.ock = ock
        self.op = op

        return TransmittedNoteCipherText(
            epk, c_enc, c_out
        )

class TransmittedNoteCipherText(object):
    def __init__(self, epk, c_enc, c_out):
        self.epk = epk
        self.c_enc = c_enc
        self.c_out = c_out

    def decrypt_using_ivk(self, ivk: Scalar, rho, cm_star):
        epk = self.epk
        if not epk:
            return None

        shared_secret = OrchardKeyAgreement.agree(ivk, epk)
        k_enc = kdf_orchard(shared_secret, epk)
        p_enc = OrchardSym.decrypt(k_enc, self.c_enc)
        if not p_enc:
            return None

        leadbyte = p_enc[0]
        assert(leadbyte == 2)
        np = OrchardNotePlaintext(
            p_enc[1:12],   # d
            Scalar.from_bytes(p_enc[12:20]),  # v
            p_enc[20:52],  # rseed
            p_enc[52:564], # memo
        )

        g_d = diversify_hash(np.d)
        pk_d = OrchardKeyAgreement.derive_public(ivk, g_d)
        note = OrchardNote(np.d, pk_d, np.v, rho, np.rseed)

        esk = OrchardKeyAgreement.esk(np.rseed, rho)
        if OrchardKeyAgreement.derive_public(esk, g_d) != epk:
            return None

        cm = note.note_commitment()
        if not cm:
            return None
        if cm != cm_star:
            return None

        return (note, np.memo)

    def decrypt_using_fvk(self, fvk, rseed, rho, cv, cm_star):
        ock = prf_ock_orchard(fvk.ovk, bytes(cv), bytes(cm_star.extract()), bytes(self.epk))
        op = OrchardSym.decrypt(ock, self.c_out)
        if not op:
            return None

        (pk_d_star, esk) = (op[0:32], op[32:64])
        esk = Scalar.from_bytes(esk)
        pk_d = Point.from_bytes(pk_d_star)
        if bytes(pk_d) != pk_d_star:
            return None
        if OrchardKeyAgreement.esk(rseed, rho) != esk:
            return None

        shared_secret = OrchardKeyAgreement.agree(esk, pk_d)
        k_enc = kdf_orchard(shared_secret, self.epk)
        p_enc = OrchardSym.decrypt(k_enc, self.c_enc)
        if not p_enc:
            return None

        leadbyte = p_enc[0]
        assert(leadbyte == 2)
        np = OrchardNotePlaintext(
            p_enc[1:12],   # d
            Scalar.from_bytes(p_enc[12:20]),  # v
            p_enc[20:52],  # rseed
            p_enc[52:564], # memo
        )
        g_d = diversify_hash(np.d)
        note = OrchardNote(np.d, pk_d, np.v, rho, np.rseed)

        cm = note.note_commitment()
        if not cm:
            return None
        if cm != cm_star:
            return None

        if OrchardKeyAgreement.derive_public(esk, g_d) != self.epk:
            return None

        return (note, np.memo)

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
    for _ in range(0, 10):
        sender_sk = SpendingKey(rand.b(32))
        sender_fvk = FullViewingKey(sender_sk)

        receiver_sk = SpendingKey(rand.b(32))
        receiver_fvk = FullViewingKey(receiver_sk)
        ivk = receiver_fvk.ivk()
        d = receiver_fvk.default_d()
        pk_d = receiver_fvk.default_pkd()
        g_d = diversify_hash(d)

        rseed = ne.rseed()
        memo = rand.b(512)
        np = OrchardNotePlaintext(
            d,
            Scalar(rand.u64() % (MAX_MONEY + 1)),
            rseed,
            memo
        )

        rcv = rcv_trapdoor(rand)
        cv = VALUE_COMMITMENT_VALUE_BASE * np.v + VALUE_COMMITMENT_RANDOMNESS_BASE * rcv

        rho = np.dummy_nullifier(rand)
        note = OrchardNote(d, pk_d, np.v, rho, rseed)
        cm = note.note_commitment()

        transmitted_note_ciphertext = ne.encrypt(note, memo, pk_d, g_d, cv, cm, sender_fvk.ovk)

        (note_using_ivk, memo_using_ivk) = transmitted_note_ciphertext.decrypt_using_ivk(
            Scalar(ivk.s), rho, cm
        )
        (note_using_fvk, memo_using_fvk) = transmitted_note_ciphertext.decrypt_using_fvk(
            sender_fvk, rseed, rho, cv, cm
        )

        assert(bytes(note_using_ivk) == bytes(note_using_fvk))
        assert(memo_using_ivk == memo_using_fvk)
        assert(bytes(note_using_ivk) == bytes(note))
        assert(memo_using_ivk == memo)

        test_vectors.append({
            'ovk': sender_fvk.ovk,
            'ivk': bytes(ivk),
            'default_d': d,
            'default_pk_d': bytes(pk_d),
            'v': np.v.s,
            'rcm': bytes(note.rcm),
            'memo': np.memo,
            'cv': bytes(cv),
            'cmx': bytes(cm.extract()),
            'esk': bytes(ne.esk),
            'epk': bytes(transmitted_note_ciphertext.epk),
            'shared_secret': bytes(ne.shared_secret),
            'k_enc': ne.k_enc,
            'p_enc': ne.p_enc,
            'c_enc': transmitted_note_ciphertext.c_enc,
            'ock': ne.ock,
            'op': ne.op,
            'c_out': transmitted_note_ciphertext.c_out,
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
