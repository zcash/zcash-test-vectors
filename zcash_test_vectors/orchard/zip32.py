#!/usr/bin/env python3
import sys; assert sys.version_info[0] >= 3, "Python 3 required."

from hashlib import blake2b

from .key_components import FullViewingKey, ExtendedSpendingKey

from ..hd_common import hardened
from ..utils import i2leosp
from ..output import render_args, render_tv


class DerivedSpendingKey(object):
    def __init__(self, extsk, depth=0, parent_tag=i2leosp(32, 0), i=0):
        self._extsk = extsk
        self._depth = depth
        self._parent_tag = parent_tag
        self._i     = i

    def __eq__(self, other):
        return (self._extsk == other._extsk  and
                self._depth == other._depth and
                self._parent_tag == other._parent_tag and
                self._i   == other._i)

    @classmethod
    def master(cls, S):
        return cls(ExtendedSpendingKey.master(S))

    def sk(self):
        return self._extsk.data

    def c(self):
        return self._extsk.chaincode

    def depth(self):
        return self._depth

    def parent_tag(self):
        return self._parent_tag

    def i(self):
        return self._i

    def fingerprint(self):
        fvk = FullViewingKey.from_spending_key(self._extsk)
        digest = blake2b(person=b'ZcashOrchardFVFP', digest_size=32)
        digest.update(bytes(fvk.ak) + bytes(fvk.nk) + bytes(fvk.rivk))
        return digest.digest()

    def tag(self):
        return self.fingerprint()[:4]

    def __bytes__(self):
        return (i2leosp(8, self.depth()) +
                self.parent_tag() +
                i2leosp(32, self.i()) +
                self.c() +
                self.sk())

    def child(self, i):
        return self.__class__(self._extsk.child(i), self.depth()+1, self.tag(), i)


def main():
    args = render_args()

    seed = bytes(range(32))
    m = DerivedSpendingKey.master(seed)
    m_1h = m.child(hardened(1))
    m_1h_2h = m_1h.child(hardened(2))
    m_1h_2h_3h = m_1h_2h.child(hardened(3))

    keys = [m, m_1h, m_1h_2h, m_1h_2h_3h]

    render_tvs(args, keys)

def render_tvs(args, keys):
    test_vectors = [
        {'sk'  : k.sk(),
         'c'   : k.c(),
         'xsk' : bytes(k),
         'fp'  : k.fingerprint(),
        }
        for k in keys
    ]

    render_tv(
        args,
        'orchard_zip32',
        (
            ('sk',  '[u8; 32]'),
            ('c',   '[u8; 32]'),
            ('xsk', '[u8; 73]'),
            ('fp',  '[u8; 32]'),
        ),
        test_vectors,
    )

if __name__ == '__main__':
    main()
