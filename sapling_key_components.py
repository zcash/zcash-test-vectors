#!/usr/bin/env python3
import sys; assert sys.version_info[0] >= 3, "Python 3 required."

from pyblake2 import blake2b, blake2s

from sapling_generators import PROVING_KEY_BASE, SPENDING_KEY_BASE, group_hash
from sapling_jubjub import Fr
from sapling_merkle_tree import MERKLE_DEPTH
from sapling_notes import note_commit, note_nullifier
from sapling_utils import leos2bsp, leos2ip
from tv_output import render_args, render_tv

#
# Utilities
#

def to_scalar(buf):
    return Fr(leos2ip(buf))


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
    return leos2ip(ivk) % 2**251

def diversify_hash(d):
    return group_hash(b'Zcash_gd', d)


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


class DerivedAkNk(object):
    @cached
    def ak(self):
        return SPENDING_KEY_BASE * self.ask()

    @cached
    def nk(self):
        return PROVING_KEY_BASE * self.nsk()


class DerivedIvk(object):
    @cached
    def ivk(self):
        return Fr(crh_ivk(bytes(self.ak()), bytes(self.nk())))


class SpendingKey(DerivedAkNk, DerivedIvk):
    def __init__(self, data):
        self.data = data

    @cached
    def ask(self):
        return to_scalar(prf_expand(self.data, b'\x00'))

    @cached
    def nsk(self):
        return to_scalar(prf_expand(self.data, b'\x01'))

    @cached
    def ovk(self):
        return prf_expand(self.data, b'\x02')[:32]

    @cached
    def default_d(self):
        i = 0
        while True:
            d = prf_expand(self.data, bytes([3, i]))[:11]
            if diversify_hash(d):
                return d
            i += 1
            assert i < 256

    @cached
    def default_pkd(self):
        return diversify_hash(self.default_d()) * self.ivk()

    @cached
    def expanded_spending_key(self):
        return ExpandedSpendingKey(self.ask(), self.nsk(), self.ovk())

    @cached
    def full_viewing_key(self):
        return self.expanded_spending_key().full_viewing_key()

    @cached
    def default_address(self):
        return self.full_viewing_key().incoming_viewing_key().address(self.default_d())

    def __eq__(self, other):
        return self.data == other.data


class ExpandedSpendingKey(DerivedAkNk):
    def __init__(self, ask, nsk, ovk):
        self._ask = ask
        self._nsk = nsk
        self._ovk = ovk

    def ask(self):
        return self._ask

    def nsk(self):
        return self._nsk

    def ovk(self):
        return self._ovk

    def full_viewing_key(self):
        return FullViewingKey(self.ak(), self.nk(), self.ovk())

    def __eq__(self, other):
        return self.ask() == other.ask() and self.nsk() == other.nsk() and self.ovk() == other.ovk()


class FullViewingKey(DerivedIvk):
    def __init__(self, ak, nk, ovk):
        self._ak = ak
        self._nk = nk
        self._ovk = ovk

    def ak(self):
        return self._ak

    def nk(self):
        return self._nk

    def ovk(self):
        return self._ovk

    def incoming_viewing_key(self):
        return IncomingViewingKey(self.ivk())

    def __eq__(self, other):
        return self.ak() == other.ak() and self.nk() == other.nk() and self.ovk() == other.ovk()


class IncomingViewingKey(object):
    def __init__(self, ivk):
        self._ivk = ivk

    def ivk(self):
        return self._ivk

    def address(self, diversifier):
        pk_d = diversify_hash(diversifier) * self.ivk()
        return PaymentAddress(diversifier, pk_d)

    def __eq__(self, other):
        return self.ivk() == other.ivk()


class PaymentAddress(object):
    def __init__(self, d, pk_d):
        self._d = d
        self._pk_d = pk_d

    def d(self):
        return self._d

    def pk_d(self):
        return self._pk_d

    def __eq__(self, other):
        return self.d() == other.d() and self.pk_d() == other.pk_d()


def main():
    args = render_args()

    test_vectors = []
    for i in range(0, 10):
        sk = SpendingKey(bytes([i] * 32))
        note_v = (2548793025584392057432895043257984320*i) % 2**64
        note_r = Fr(8890123457840276890326754358439057438290574382905).exp(i+1)
        note_cm = note_commit(
            note_r,
            leos2bsp(bytes(diversify_hash(sk.default_d()))),
            leos2bsp(bytes(sk.default_pkd())),
            note_v)
        note_pos = (980705743285409327583205473820957432*i) % 2**MERKLE_DEPTH
        note_nf = note_nullifier(sk.nk(), note_cm, Fr(note_pos))

        full_viewing_key = sk.full_viewing_key()
        default_addr = sk.default_address()
        assert full_viewing_key == sk.expanded_spending_key().full_viewing_key()
        assert default_addr == full_viewing_key.incoming_viewing_key().address(sk.default_d())

        test_vectors.append({
            'sk': sk.data,
            'ask': bytes(sk.ask()),
            'nsk': bytes(sk.nsk()),
            'ovk': sk.ovk(),
            'ak': bytes(sk.ak()),
            'nk': bytes(sk.nk()),
            'ivk': bytes(sk.ivk()),
            'default_d': sk.default_d(),
            'default_pk_d': bytes(sk.default_pkd()),
            'note_v': note_v,
            'note_r': bytes(note_r),
            'note_cmu': bytes(note_cm.u),
            'note_pos': note_pos,
            'note_nf': note_nf,
        })

    render_tv(
        args,
        'sapling_key_components',
        (
            ('sk', '[u8; 32]'),
            ('ask', '[u8; 32]'),
            ('nsk', '[u8; 32]'),
            ('ovk', '[u8; 32]'),
            ('ak', '[u8; 32]'),
            ('nk', '[u8; 32]'),
            ('ivk', '[u8; 32]'),
            ('default_d', '[u8; 11]'),
            ('default_pk_d', '[u8; 32]'),
            ('note_v', 'u64'),
            ('note_r', '[u8; 32]'),
            ('note_cmu', '[u8; 32]'),
            ('note_pos', 'u64'),
            ('note_nf', '[u8; 32]'),
        ),
        test_vectors,
    )


if __name__ == '__main__':
    main()
