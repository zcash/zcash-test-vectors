#!/usr/bin/env python3
import sys; assert sys.version_info[0] >= 3, "Python 3 required."

from pyblake2 import blake2b

from sapling_key_components import to_scalar, prf_expand, diversify_hash, DerivedAkNk, DerivedIvk
from sapling_generators import SPENDING_KEY_BASE, PROVING_KEY_BASE
from utils import i2leosp, i2lebsp, lebs2osp
from ff1 import ff1_aes256_encrypt
from tv_output import render_args, render_tv, option, Some


def encode_xsk_parts(ask, nsk, ovk, dk):
    # bytes = i2leosp_256 for Fr
    return bytes(ask) + bytes(nsk) + ovk + dk

def encode_xfvk_parts(ak, nk, ovk, dk):
    return bytes(ak) + bytes(nk) + ovk + dk


class ExtendedBase(object):
    def ovk(self):
        return self._ovk

    def dk(self):
        return self._dk

    def c(self):
        return self._c

    def depth(self):
        return self._depth

    def parent_tag(self):
        return self._parent_tag

    def i(self):
        return self._i

    def diversifier(self, j):
        d = lebs2osp(ff1_aes256_encrypt(self.dk(), b'', i2lebsp(88, j)))
        return d if diversify_hash(d) else None

    def fingerprint(self):
        FVK = bytes(self.ak()) + bytes(self.nk()) + self.ovk()
        return blake2b(person=b'ZcashSaplingFVFP', digest_size=32, data=FVK).digest()

    def tag(self):
        return self.fingerprint()[:4]


class ExtendedSpendingKey(DerivedAkNk, DerivedIvk, ExtendedBase):
    def __init__(self, ask, nsk, ovk, dk, c, depth=0, parent_tag=i2leosp(32, 0), i=0):
        self._ask   = ask
        self._nsk   = nsk
        self._ovk   = ovk
        self._dk    = dk
        self._c     = c
        self._depth = depth
        self._parent_tag = parent_tag
        self._i     = i

    @classmethod
    def master(cls, S):
        I     = blake2b(person=b'ZcashIP32Sapling', data=S).digest()
        I_L   = I[:32]
        I_R   = I[32:]
        sk_m  = I_L
        ask_m = to_scalar(prf_expand(sk_m, b'\x00'))
        nsk_m = to_scalar(prf_expand(sk_m, b'\x01'))
        ovk_m = prf_expand(sk_m, b'\x02')[:32]
        dk_m  = prf_expand(sk_m, b'\x10')[:32]
        c_m   = I_R
        return cls(ask_m, nsk_m, ovk_m, dk_m, c_m)

    def ask(self):
        return self._ask

    def nsk(self):
        return self._nsk

    def is_xsk(self):
        return True

    def __bytes__(self):
        return (i2leosp(8, self.depth()) +
                self.parent_tag() +
                i2leosp(32, self.i()) +
                self.c() +
                encode_xsk_parts(self.ask(), self.nsk(), self.ovk(), self.dk()))

    def to_extended_fvk(self):
        return ExtendedFullViewingKey(self.ak(), self.nk(), self.ovk(), self.dk(), self.c(),
                                      self.depth(), self.parent_tag(), self.i())

    def child(self, i):
        if i >= 1<<31: # child is a hardened key
            prefix = b'\x11' + encode_xsk_parts(self.ask(), self.nsk(), self.ovk(), self.dk())
        else:
            prefix = b'\x12' + encode_xfvk_parts(self.ak(), self.nk(), self.ovk(), self.dk())

        I     = prf_expand(self.c(), prefix + i2leosp(32, i))
        I_L   = I[:32]
        I_R   = I[32:]
        I_ask = to_scalar(prf_expand(I_L, b'\x13'))
        I_nsk = to_scalar(prf_expand(I_L, b'\x14'))
        ask_i = I_ask + self.ask()
        nsk_i = I_nsk + self.nsk()
        ovk_i = prf_expand(I_L, b'\x15' + self.ovk())[:32]
        dk_i  = prf_expand(I_L, b'\x16' + self.dk())[:32]
        c_i   = I_R
        return self.__class__(ask_i, nsk_i, ovk_i, dk_i, c_i, self.depth()+1, self.tag(), i)


class ExtendedFullViewingKey(DerivedIvk, ExtendedBase):
    def __init__(self, ak, nk, ovk, dk, c, depth=0, parent_tag=i2leosp(32, 0), i=0):
        self._ak    = ak
        self._nk    = nk
        self._ovk   = ovk
        self._dk    = dk
        self._c     = c
        self._depth = depth
        self._parent_tag = parent_tag
        self._i     = i

    @classmethod
    def master(cls, S):
        return ExtendedSpendingKey.master(S).to_extended_fvk()

    def ak(self):
        return self._ak

    def nk(self):
        return self._nk

    def is_xsk(self):
        return False

    def __bytes__(self):
        return (i2leosp(8, self.depth()) +
                self.parent_tag() +
                i2leosp(32, self.i()) +
                self.c() +
                encode_xfvk_parts(self.ak(), self.nk(), self.ovk(), self.dk()))

    def to_extended_fvk(self):
        return self

    def child(self, i):
        if i >= 1<<31:
            raise ValueError("can't derive a child hardened key from an extended full viewing key")
        else:
            prefix = b'\x12' + encode_xfvk_parts(self.ak(), self.nk(), self.ovk(), self.dk())

        I     = prf_expand(self.c(), prefix + i2leosp(32, i))
        I_L   = I[:32]
        I_R   = I[32:]
        I_ask = to_scalar(prf_expand(I_L, b'\x13'))
        I_nsk = to_scalar(prf_expand(I_L, b'\x14'))
        ak_i  = SPENDING_KEY_BASE * I_ask + self.ak()
        nk_i  = PROVING_KEY_BASE  * I_nsk + self.nk()
        ovk_i = prf_expand(I_L, b'\x15' + self.ovk())[:32]
        dk_i  = prf_expand(I_L, b'\x16' + self.dk())[:32]
        c_i   = I_R
        return self.__class__(ak_i, nk_i, ovk_i, dk_i, c_i, self.depth()+1, self.tag(), i)


def main():
    args = render_args()

    def hardened(i): return i + (1<<31)

    seed = bytes(range(32))
    m = ExtendedSpendingKey.master(seed)
    m_1 = m.child(1)
    m_1_2h = m_1.child(hardened(2))
    m_1_2hv = m_1_2h.to_extended_fvk()
    m_1_2hv_3 = m_1_2hv.child(3)

    test_vectors = [
        {'ask' : Some(bytes(k.ask())) if k.is_xsk() else None,
         'nsk' : Some(bytes(k.nsk())) if k.is_xsk() else None,
         'ovk' : k.ovk(),
         'dk'  : k.dk(),
         'c'   : k.c(),
         'ak'  : bytes(k.ak()),
         'nk'  : bytes(k.nk()),
         'ivk' : bytes(k.ivk()),
         'xsk' : Some(bytes(k)) if k.is_xsk() else None,
         'xfvk': bytes(k.to_extended_fvk()),
         'fp'  : k.fingerprint(),
         'd0'  : option(k.diversifier(0)),
         'd1'  : option(k.diversifier(1)),
         'd2'  : option(k.diversifier(2)),
         'dmax': option(k.diversifier((1<<88)-1)),
        }
        for k in (m, m_1, m_1_2h, m_1_2hv, m_1_2hv_3)
    ]

    render_tv(
        args,
        'sapling_zip32',
        (
            ('ask', 'Option<[u8; 32]>'),
            ('nsk', 'Option<[u8; 32]>'),
            ('ovk', '[u8; 32]'),
            ('dk',  '[u8; 32]'),
            ('c',   '[u8; 32]'),
            ('ak',  '[u8; 32]'),
            ('nk',  '[u8; 32]'),
            ('ivk', '[u8; 32]'),
            ('xsk', 'Option<[u8; 169]>'),
            ('xfvk','[u8; 169]'),
            ('fp',  '[u8; 32]'),
            ('d0',  'Option<[u8; 11]>'),
            ('d1',  'Option<[u8; 11]>'),
            ('d2',  'Option<[u8; 11]>'),
            ('dmax','Option<[u8; 11]>'),
        ),
        test_vectors,
    )

if __name__ == '__main__':
    main()
