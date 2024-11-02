from hashlib import blake2b

from .sapling.key_components import prf_expand
from .utils import i2leosp

class HardenedOnlyContext(object):
    def __init__(self, MKGDomain, CKDDomain):
        assert type(MKGDomain) == bytes
        assert len(MKGDomain) == 16
        assert type(CKDDomain) == bytes
        assert len(CKDDomain) == 1

        self.MKGDomain = MKGDomain
        self.CKDDomain = CKDDomain

def MKGh(Context, IKM):
    assert type(Context) == HardenedOnlyContext

    digest = blake2b(person=Context.MKGDomain)
    digest.update(IKM)
    I   = digest.digest()
    I_L = I[:32]
    I_R = I[32:]
    return (I_L, I_R)

def CKDh(Context, sk_par, c_par, i):
    assert type(Context) == HardenedOnlyContext
    assert 0x80000000 <= i and i <= 0xFFFFFFFF

    I   = prf_expand(c_par, Context.CKDDomain + sk_par + i2leosp(32, i))
    I_L = I[:32]
    I_R = I[32:]
    return (I_L, I_R)
