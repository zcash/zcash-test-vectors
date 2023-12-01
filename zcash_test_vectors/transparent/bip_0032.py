#!/usr/bin/env python3
import sys; assert sys.version_info[0] >= 3, "Python 3 required."

from binascii import hexlify, unhexlify
import base58
import hashlib
import hmac
import re
from ripemd import ripemd160
from secp256k1 import PrivateKey, PublicKey

from .zip_0316 import derive_ovks

from ..hd_common import ZCASH_MAIN_COINTYPE, hardened
from ..output import render_args, render_tv
from ..utils import i2beosp


class ExtendedSecretKey:
    def __init__(self, chaincode, sk):
        assert len(chaincode) == 32
        assert isinstance(sk, PrivateKey)

        self.chaincode = chaincode
        self.sk = sk

    @classmethod
    def master(cls, S):
        I = hmac.digest(b'Bitcoin seed', S, 'sha512')
        I_L = I[:32]
        I_R = I[32:]
        sk = PrivateKey(I_L, True)
        return cls(I_R, sk)

    def __bytes__(self):
        # The extra zero byte is specified in
        # <https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#serialization-format>.
        return self.chaincode + b'\x00' + self.sk.private_key

    def public_key(self):
        return ExtendedPublicKey(self.chaincode, self.sk.pubkey)

    def child(self, i):
        assert 0 <= i and i <= 0xFFFFFFFF

        if i >= 0x80000000:
            I = hmac.digest(self.chaincode, b'\x00' + self.sk.private_key + i2beosp(32, i), 'sha512')
        else:
            I = hmac.digest(self.chaincode, self.sk.pubkey.serialize(compressed=True) + i2beosp(32, i), 'sha512')

        I_L = I[:32]
        I_R = I[32:]
        sk_i = PrivateKey(self.sk.tweak_add(I_L), True)
        child_i = self.__class__(I_R, sk_i)

        if i < 0x80000000:
            assert bytes(self.public_key().child(i)) == bytes(child_i.public_key())

        return child_i


class ExtendedPublicKey:
    def __init__(self, chaincode, pk):
        assert len(chaincode) == 32
        assert isinstance(pk, PublicKey)

        self.chaincode = chaincode
        self.pk = pk

    def pubkey_bytes(self):
        pk_bytes = self.pk.serialize(compressed=True)
        assert len(pk_bytes) == 33
        assert pk_bytes[0] in (0x02, 0x03)
        return pk_bytes

    def __bytes__(self):
        return self.chaincode + self.pubkey_bytes()

    def address(self):
        h = ripemd160.new()
        h.update(hashlib.sha256(self.pubkey_bytes()).digest())
        return h.digest()

    def child(self, i):
        assert 0 <= i and i <= 0xFFFFFFFF

        assert i < 0x80000000, "cannot derive a hardened child from a public key"
        I = hmac.digest(self.chaincode, self.pk.serialize(compressed=True) + i2beosp(32, i), 'sha512')
        I_L = I[:32]
        I_R = I[32:]
        pk_i = self.pk.tweak_add(I_L)
        return self.__class__(I_R, pk_i)

    def derive_ovks(self):
        return derive_ovks(self.chaincode, self.pk.serialize(compressed=True))


# Test vectors from <https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki>.
BIP32_TEST_VECTORS = [
    {
        'seed': unhexlify("000102030405060708090a0b0c0d0e0f"),
        'path': 'm/0H/1/2H/2/1000000000',
        'vectors': [
            {
                'path': 'm',
                'ext_pub': b'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8',
                'ext_prv': b'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi',
            },
            {
                'path': 'm/0H',
                'ext_pub': b'xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw',
                'ext_prv': b'xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7',
            },
            {
                'path': 'm/0H/1',
                'ext_pub': b'xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ',
                'ext_prv': b'xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs',
            },
            {
                'path': 'm/0H/1/2H',
                'ext_pub': b'xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5',
                'ext_prv': b'xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM',
            },
            {
                'path': 'm/0H/1/2H/2',
                'ext_pub': b'xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV',
                'ext_prv': b'xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334',
            },
            {
                'path': 'm/0H/1/2H/2/1000000000',
                'ext_pub': b'xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy',
                'ext_prv': b'xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76',
            }
        ]
    },
    {
        'seed': unhexlify("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"),
        'path': 'm/0/2147483647H/1/2147483646H/2',
        'vectors': [
            {
                'path': 'm',
                'ext_pub': b'xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB',
                'ext_prv': b'xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U',
            },
            {
                'path': 'm/0',
                'ext_pub': b'xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH',
                'ext_prv': b'xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt',
            },
            {
                'path': 'm/0/2147483647H',
                'ext_pub': b'xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a',
                'ext_prv': b'xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9',
            },
            {
                'path': 'm/0/2147483647H/1',
                'ext_pub': b'xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon',
                'ext_prv': b'xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef',
            },
            {
                'path': 'm/0/2147483647H/1/2147483646H',
                'ext_pub': b'xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL',
                'ext_prv': b'xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc',
            },
            {
                'path': 'm/0/2147483647H/1/2147483646H/2',
                'ext_pub': b'xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt',
                'ext_prv': b'xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j',
            },
        ]
    },
    # These vectors test for the retention of leading zeros. See bitpay/bitcore-lib#47 and iancoleman/bip39#58 for more information.
    {
        'seed': unhexlify("4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be"),
        'path': 'm/0H',
        'vectors': [
            {
                'path': 'm',
                'ext_pub': b'xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13',
                'ext_prv': b'xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6',
            },
            {
                'path': 'm/0H',
                'ext_pub': b'xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y',
                'ext_prv': b'xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L',
            },
        ]
    },
    # These vectors test for the retention of leading zeros. See btcsuite/btcutil#172 for more information.
    {
        'seed': unhexlify("3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678"),
        'path': 'm/0H/1H',
        'vectors': [
            {
                'path': 'm',
                'ext_pub': b'xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUKJyuyu5F1rzYGVxyL6tmgBUAEPrEz92mBXjByMRiJdba9wpnN37RLLAXa',
                'ext_prv': b'xprv9s21ZrQH143K48vGoLGRPxgo2JNkJ3J3fqkirQC2zVdk5Dgd5w14S7fRDyHH4dWNHUgkvsvNDCkvAwcSHNAQwhwgNMgZhLtQC63zxwhQmRv',
            },
            {
                'path': 'm/0H',
                'ext_pub': b'xpub69AUMk3qDBi3uW1sXgjCmVjJ2G6WQoYSnNHyzkmdCHEhSZ4tBok37xfFEqHd2AddP56Tqp4o56AePAgCjYdvpW2PU2jbUPFKsav5ut6Ch1m',
                'ext_prv': b'xprv9vB7xEWwNp9kh1wQRfCCQMnZUEG21LpbR9NPCNN1dwhiZkjjeGRnaALmPXCX7SgjFTiCTT6bXes17boXtjq3xLpcDjzEuGLQBM5ohqkao9G',
            },
            {
                'path': 'm/0H/1H',
                'ext_pub': b'xpub6BJA1jSqiukeaesWfxe6sNK9CCGaujFFSJLomWHprUL9DePQ4JDkM5d88n49sMGJxrhpjazuXYWdMf17C9T5XnxkopaeS7jGk1GyyVziaMt',
                'ext_prv': b'xprv9xJocDuwtYCMNAo3Zw76WENQeAS6WGXQ55RCy7tDJ8oALr4FWkuVoHJeHVAcAqiZLE7Je3vZJHxspZdFHfnBEjHqU5hG1Jaj32dVoS6XLT1',
            }
        ]
    }
]

def to_zip32_key_bytes(key_str):
    decoded = base58.b58decode_check(key_str)
    return decoded[13:]

def assert_keys_match(prv, pub, v):
    assert bytes(prv) == to_zip32_key_bytes(v['ext_prv']), (hexlify(bytes(prv)), hexlify(to_zip32_key_bytes(v['ext_prv'])))
    assert bytes(pub) == to_zip32_key_bytes(v['ext_pub']), (hexlify(bytes(pub)), hexlify(to_zip32_key_bytes(v['ext_pub'])))

def verify_test_vectors(obj):
    seed = obj['seed']
    prv = ExtendedSecretKey.master(seed)
    pub = prv.public_key()
    steps = obj['path'].split('/')
    step_pattern = re.compile(r'(\d+)(H?)')
    for step, v in zip(steps, obj['vectors']):
        if step == 'm':
            assert_keys_match(prv, pub, v)
        else:
            step_parts = step_pattern.match(step)
            i = int(step_parts.group(1))
            if len(step_parts.group(2)) > 0:
                i = hardened(i)
            prv = prv.child(i)
            pub = prv.public_key()
            assert_keys_match(prv, pub, v)

def main():
    args = render_args()

    for o in BIP32_TEST_VECTORS:
        verify_test_vectors(o)

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
