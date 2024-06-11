#!/usr/bin/env python3
import sys;

from .asset_base import native_asset

assert sys.version_info[0] >= 3, "Python 3 required."

from ..output import render_args, render_tv
from ..rand import Rand

from ..orchard.pallas import Point, Scalar
from .commitments import value_commit
from ..orchard.commitments import rcv_trapdoor
from ..orchard.key_components import diversify_hash, FullViewingKey, SpendingKey
from..orchard.note_encryption import TransmittedNoteCipherText, OrchardNoteEncryption
from .note import OrchardZSANote, OrchardZSANotePlaintext


# https://zips.z.cash/zip-0226#note-structure-commitment
class OrchardZSANoteEncryption(OrchardNoteEncryption):
    def __init__(self, rand):
        super().__init__(rand)

    def encrypt(self, note: OrchardZSANote, memo, pk_d_new, g_d_new, cv_new, cm_new, ovk=None):
        tc = super().encrypt(note, memo, pk_d_new, g_d_new, cv_new, cm_new, ovk)

        return TransmittedZSANoteCipherText(
            tc.epk, tc.c_enc, tc.c_out
        )

class TransmittedZSANoteCipherText(TransmittedNoteCipherText):
    def __init__(self, epk, c_enc, c_out):
        super().__init__(epk, c_enc, c_out)

    @staticmethod
    def parse_bytes_as_note_plaintext(p_enc):
        return OrchardZSANotePlaintext.from_bytes(p_enc)

    @staticmethod
    def construct_note(np: OrchardZSANotePlaintext, pk_d, rho):
        return OrchardZSANote(np.d, pk_d, np.v, np.asset, rho, np.rseed)

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

    test_vectors = []
    for i in range(0, 20):
        sender_ovk = rand.b(32)

        receiver_sk = SpendingKey(rand.b(32))
        receiver_fvk = FullViewingKey.from_spending_key(receiver_sk)
        ivk = receiver_fvk.ivk()
        d = receiver_fvk.default_d()
        pk_d = receiver_fvk.default_pkd()
        g_d = diversify_hash(d)

        is_native = i < 10
        asset_point = native_asset() if is_native else Point.rand(rand)
        asset_bytes = bytes(asset_point)
        rseed = rand.b(32)
        memo = b'\xff' + rand.b(511)

        np = OrchardZSANotePlaintext(d, rand.u64(), rseed, asset_bytes, memo)

        rcv = rcv_trapdoor(rand)
        cv = value_commit(rcv, Scalar(np.v), asset_point)

        rho = np.dummy_nullifier(rand)
        note = OrchardZSANote(d, pk_d, np.v, asset_bytes, rho, rseed)
        cm = note.note_commitment()

        ne = OrchardZSANoteEncryption(rand)

        transmitted_note_ciphertext = ne.encrypt(note, memo, pk_d, g_d, cv, cm, sender_ovk)

        (note_using_ivk, memo_using_ivk) = transmitted_note_ciphertext.decrypt_using_ivk(
            Scalar(ivk.s), rho, cm.extract()
        )
        (note_using_ovk, memo_using_ovk) = transmitted_note_ciphertext.decrypt_using_ovk(
            sender_ovk, rho, cv, cm.extract()
        )

        assert(note_using_ivk == note_using_ovk)
        assert(memo_using_ivk == memo_using_ovk)
        assert(note_using_ivk == note)
        assert(memo_using_ivk == memo)

        test_vectors.append({
            'incoming_viewing_key': receiver_fvk.dk + bytes(ivk),
            'ovk': sender_ovk,
            'default_d': d,
            'default_pk_d': bytes(pk_d),
            'v': np.v,
            'rseed': note.rseed,
            'asset': asset_bytes,
            'memo': np.memo,
            'cv_net': bytes(cv),
            'rho': bytes(rho),
            'cmx': bytes(cm.extract()),
            'esk': bytes(ne.esk),
            'ephemeral_key': bytes(transmitted_note_ciphertext.epk),
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
        'orchard_zsa_note_encryption',
        (
            ('incoming_viewing_key', '[u8; 64]'),
            ('ovk', '[u8; 32]'),
            ('default_d', '[u8; 11]'),
            ('default_pk_d', '[u8; 32]'),
            ('v', 'u64'),
            ('rseed', '[u8; 32]'),
            ('asset', '[u8; 32]'),
            ('memo', '[u8; 512]'),
            ('cv_net', '[u8; 32]'),
            ('rho', '[u8; 32]'),
            ('cmx', '[u8; 32]'),
            ('esk', '[u8; 32]'),
            ('ephemeral_key', '[u8; 32]'),
            ('shared_secret', '[u8; 32]'),
            ('k_enc', '[u8; 32]'),
            ('p_enc', '[u8; 596]'),
            ('c_enc', '[u8; 612]'),
            ('ock', '[u8; 32]'),
            ('op', '[u8; 64]'),
            ('c_out', '[u8; 80]'),
        ),
        test_vectors,
    )


if __name__ == '__main__':
    main()
