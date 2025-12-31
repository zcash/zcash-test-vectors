from hashlib import blake2b

from .bech32m import bech32_encode, bech32_decode, convertbits, Encoding
from .sapling.key_components import prf_expand
from .utils import i2leosp

from .hd_common import hardened
from .output import render_args, render_tv

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

def CKDh(Context, sk_par, c_par, i, lead, tag):
    assert type(Context) == HardenedOnlyContext
    assert 0x80000000 <= i and i <= 0xFFFFFFFF
    assert 0x00 <= lead and lead <= 0xFF
    assert type(tag) == bytes

    lead_enc = bytes([] if lead == 0 and tag == b"" else [lead])
    I = prf_expand(c_par, Context.CKDDomain + sk_par + i2leosp(32, i) + lead_enc + tag)
    I_L = I[:32]
    I_R = I[32:]
    return (I_L, I_R)

def SeedFingerprint(seed):
    digest = blake2b(person=b'Zcash_HD_Seed_FP', digest_size=32)
    digest.update(i2leosp(8, len(seed)))
    digest.update(seed)
    seedfp = digest.digest()
    return bech32_encode('zip32seedfp', convertbits(seedfp, 8, 5), Encoding.BECH32M)


class RegisteredKey(object):
    Registered = HardenedOnlyContext(b'ZIPRegistered_KD', b'\xAC')

    def __init__(self, IKM, subpath, sk, chaincode, full_width=None):
        self.IKM = IKM
        self.subpath = subpath
        self.sk = sk
        self.chaincode = chaincode
        self.full_width = full_width  # the full-width cryptovalue at this path

    @classmethod
    def subtree_root(cls, ContextString, S, ZipNumber):
        length_ContextString = len(ContextString)
        length_S = len(S)

        assert length_ContextString <= 252
        assert 32 <= length_S <= 252

        IKM = bytes([length_ContextString]) + ContextString + bytes([length_S]) + S
        (sk_m, c_m) = MKGh(cls.Registered, IKM)
        (sk, chaincode) = CKDh(cls.Registered, sk_m, c_m, hardened(ZipNumber), 0, b"")
        return cls(IKM, [], sk, chaincode)

    def child(self, i, tag):
        (sk_child, c_child) = CKDh(self.Registered, self.sk, self.chaincode, i, 0, tag)
        (I_L, I_R) = CKDh(self.Registered, self.sk, self.chaincode, i, 1, tag)
        return self.__class__(None, self.subpath + [(i, tag)], sk_child, c_child, I_L + I_R)


def registered_key_derivation_tvs():
    args = render_args()

    context_string = b'Zcash test vectors'
    seed = bytes(range(32))
    m_1h = RegisteredKey.subtree_root(context_string, seed, 1)
    m_1h_2h = m_1h.child(hardened(2), b"trans rights are human rights")
    m_1h_2h_3h = m_1h_2h.child(hardened(3), b"")

    keys = [m_1h, m_1h_2h, m_1h_2h_3h]

    test_vectors = [
        {
            'context_string': context_string,
            'seed':       seed,
            'seedfp':     SeedFingerprint(seed),
            'zip_number': 1,
            'subpath':    k.subpath,
            'sk':         k.sk,
            'c':          k.chaincode,
            'full_width': k.full_width,
        }
        for k in keys
    ]

    render_tv(
        args,
        'zip_0032_registered',
        (
            ('context_string', '&\'static [u8]'),
            ('seed',       '[u8; 32]'),
            ('seedfp',     '&\'static str'),
            ('zip_number', 'u16'),
            ('subpath',    '&\'static [(u32, &\'static [u8])]'),
            ('sk',         '[u8; 32]'),
            ('c',          '[u8; 32]'),
            ('full_width', 'Option<[u8; 64]>'),
        ),
        test_vectors,
    )


class ArbitraryKey(object):
    Adhoc = HardenedOnlyContext(b'ZcashArbitraryKD', b'\xAB')

    def __init__(self, IKM, path, sk, chaincode):
        self.IKM = IKM
        self.path = path
        self.sk = sk
        self.chaincode = chaincode

    @classmethod
    def master(cls, ContextString, S):
        length_ContextString = len(ContextString)
        length_S = len(S)

        assert length_ContextString <= 252
        assert 32 <= length_S <= 252

        IKM = bytes([length_ContextString]) + ContextString + bytes([length_S]) + S
        (sk, chaincode) = MKGh(cls.Adhoc, IKM)
        return cls(IKM, [], sk, chaincode)

    def child(self, i):
        (sk_i, c_i) = CKDh(self.Adhoc, self.sk, self.chaincode, i, 0, b"")
        return self.__class__(None, self.path + [i], sk_i, c_i)


def arbitrary_key_derivation_tvs():
    args = render_args()

    context_string = b'Zcash test vectors'
    seed = bytes(range(32))
    m = ArbitraryKey.master(context_string, seed)
    m_1h = m.child(hardened(1))
    m_1h_2h = m_1h.child(hardened(2))
    m_1h_2h_3h = m_1h_2h.child(hardened(3))

    # Derive a path matching Zcash mainnet account index 0.
    m_32h = m.child(hardened(32))
    m_32h_133h = m_32h.child(hardened(133))
    m_32h_133h_0h = m_32h_133h.child(hardened(0))

    keys = [m, m_1h, m_1h_2h, m_1h_2h_3h, m_32h, m_32h_133h, m_32h_133h_0h]

    test_vectors = [
        {
            'context_string': context_string,
            'seed': seed,
            'seedfp': SeedFingerprint(seed),
            'ikm':  k.IKM,
            'path': k.path,
            'sk':   k.sk,
            'c':    k.chaincode,
        }
        for k in keys
    ]

    render_tv(
        args,
        'zip_0032_arbitrary',
        (
            ('context_string', '&\'static [u8]'),
            ('seed', '[u8; 32]'),
            ('seedfp', '&\'static str'),
            ('ikm',  'Option<&\'static [u8]>'),
            ('path', '&\'static [u32]'),
            ('sk',   '[u8; 32]'),
            ('c',    '[u8; 32]'),
        ),
        test_vectors,
    )
