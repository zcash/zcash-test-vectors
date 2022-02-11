#!/usr/bin/env python3
import sys; assert sys.version_info[0] >= 3, "Python 3 required."

import hashlib
import hmac
from secp256k1 import PrivateKey, PublicKey

from .zip_0316 import derive_ovks

from ..hd_common import ZCASH_MAIN_COINTYPE, hardened
from ..output import render_args, render_tv
from ..utils import i2leosp


class ExtendedSecretKey:
    def __init__(self, sk, chaincode):
        assert isinstance(sk, PrivateKey)
        assert len(chaincode) == 32
        self.sk = sk
        self.chaincode = chaincode

    @classmethod
    def master(cls, S):
        I = hmac.digest(b'Bitcoin seed', S, 'sha512')
        I_L = I[:32]
        I_R = I[32:]
        sk = PrivateKey(I_L, True)
        return cls(sk, I_R)

    def __bytes__(self):
        return self.chaincode + self.sk.private_key

    def public_key(self):
        return ExtendedPublicKey(self.sk.pubkey, self.chaincode)

    def child(self, i):
        assert 0 <= i and i <= 0xFFFFFFFF

        if i >= 0x80000000:
            I = hmac.digest(self.chaincode, b'\x00' + self.sk.private_key + i2leosp(32, i), 'sha512')
        else:
            I = hmac.digest(self.chaincode, self.sk.pubkey.serialize(compressed=True) + i2leosp(32, i), 'sha512')

        I_L = I[:32]
        I_R = I[32:]
        sk_i = PrivateKey(self.sk.tweak_add(I_L), True)
        return self.__class__(sk_i, I_R)


class ExtendedPublicKey:
    def __init__(self, pk, chaincode):
        assert isinstance(pk, PublicKey)
        assert len(chaincode) == 32

        self.pk = pk
        self.chaincode = chaincode

    def pubkey_bytes(self):
        pk_bytes = self.pk.serialize(compressed=True)
        assert len(pk_bytes) == 33
        assert pk_bytes[0] in (0x02, 0x03)
        return pk_bytes

    def __bytes__(self):
        return self.chaincode + self.pubkey_bytes()

    def address(self):
        ripemd160 = hashlib.new('ripemd160')
        ripemd160.update(hashlib.sha256(self.pubkey_bytes()).digest())
        return ripemd160.digest()

    def child(self, i):
        assert 0 <= i and i <= 0xFFFFFFFF

        assert i < 0x80000000, "cannot derive a hardened child from a public key"
        I = hmac.digest(self.chaincode, self.pk.serialize(compressed=True) + i2leosp(32, i), 'sha512')
        I_L = I[:32]
        I_R = I[32:]
        pk_i = self.pk.tweak_add(I_L)
        return self.__class__(pk_i, I_R)

    def derive_ovks(self):
        return derive_ovks(self.chaincode, self.pk.serialize(compressed=True))


def main():
    args = render_args()

    seed = bytes(range(32))
    root_key = ExtendedSecretKey.master(seed)
    purpose_key = root_key.child(hardened(44))
    coin_key = purpose_key.child(hardened(ZCASH_MAIN_COINTYPE))

    test_vectors = []
    for account in range(10):
        account_key = coin_key.child(hardened(account))
        pubkey = account_key.public_key()
        (external_ovk, internal_ovk) = pubkey.derive_ovks()
        test_vectors.append({
            'c' : pubkey.chaincode,
            'pk': pubkey.pk.serialize(compressed=True),
            'address': pubkey.address(),
            'external_ovk': external_ovk,
            'internal_ovk': internal_ovk,
            'account': account,
        })

    render_tv(
        args,
        'bip_0032',
        (
            ('c',            '[u8; 32]'),
            ('pk',           '[u8; 33]'),
            ('address',      '[u8; 20]'),
            ('external_ovk', '[u8; 32]'),
            ('internal_ovk', '[u8; 32]'),
            ('account',      'u32'),
        ),
        test_vectors,
    )

if __file__ == '__main__':
    main()
