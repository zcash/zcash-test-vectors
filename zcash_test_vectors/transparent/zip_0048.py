#!/usr/bin/env python3
import sys; assert sys.version_info[0] >= 3, 'Python 3 required.'

from binascii import hexlify
import hashlib
from random import Random

from base58 import b58encode_check
from ripemd import ripemd160

from .bip_0032 import ExtendedPublicKey, ExtendedSecretKey

from ..hd_common import ADDRESS_CONSTANTS, hardened
from ..rand import Rand, randbytes
from ..transaction import Script
from ..output import render_args, render_tv


class AccountPrivateKey:
    def __init__(self, network, key_origin, sk):
        assert isinstance(sk, ExtendedSecretKey)
        self.network = network
        self.key_origin = key_origin
        self.sk = sk

    @classmethod
    def derive(cls, network, S, account):
        coin_type = ADDRESS_CONSTANTS[network]['coin_type']

        t_root_key = ExtendedSecretKey.master(S)
        t_purpose_key = t_root_key.child(hardened(48))
        t_coin_key = t_purpose_key.child(hardened(coin_type))
        t_account_key = t_coin_key.child(hardened(account))
        t_script_key = t_account_key.child(hardened(133000))

        key_origin = "[{fingerprint}/48'/{coin_type}'/{account}'/133000']".format(
            fingerprint=hexlify(t_root_key.key_fingerprint()).decode('utf-8'),
            coin_type=coin_type,
            account=account,
        )

        return cls(network, key_origin, t_script_key)

    def xprv(self):
        return b58encode_check(bytes(ADDRESS_CONSTANTS[self.network]['xprv_lead']) + bytes(self.sk)).decode('utf-8')

    def public_key(self):
        return AccountPublicKey(self.network, self.key_origin, self.sk.public_key())


class AccountPublicKey:
    def __init__(self, network, key_origin, pk):
        assert isinstance(pk, ExtendedPublicKey)
        self.network = network
        self.key_origin = key_origin
        self.pk = pk

    def xpub(self):
        return b58encode_check(bytes(ADDRESS_CONSTANTS[self.network]['xpub_lead']) + bytes(self.pk)).decode('utf-8')

    def key_info(self):
        return '{key_origin}{xpub}'.format(
            key_origin=self.key_origin,
            xpub=self.xpub(),
        )


class FullViewingKey:
    def __init__(self, network, required, key_info):
        assert 0 < len(key_info) # This is not in BIP 383 but we impose it.
        assert len(key_info) <= 15
        assert required <= len(key_info)
        for key in key_info:
            assert isinstance(key, AccountPublicKey)

        template = 'sh(sortedmulti({k}{keys}))'.format(
            k=required,
            keys=''.join([',@{0}/**'.format(i) for i in range(len(key_info))])
        )

        self.network = network
        self.wallet_descriptor_template = template
        self.key_info = key_info
        self.required = required

    @classmethod
    def standard(cls, required, keys):
        network = None
        for key in keys:
            if network is None:
                network = key.network
            else:
                assert network == key.network

        return cls(network, required, keys)

    def redeem_script(self, scope, address_index):
        assert self.wallet_descriptor_template.startswith('sh(sortedmulti(')

        pubkeys = sorted([
            key.pk.child(scope).child(address_index).pubkey_bytes()
            for key in self.key_info
        ])

        def small_num(n):
            assert 0 <= n
            assert n <= 16
            if n == 0:
                return 0x00 # OP_0
            else:
                return 0x50 + n # (OP_1 - 1) + n

        return Script.from_bytes(
            bytes([small_num(self.required)]) +
            b''.join([
                bytes([len(pubkey_bytes)]) + pubkey_bytes
                for pubkey_bytes in pubkeys
            ]) +
            bytes([
                small_num(len(self.key_info)),
                0xae, # OP_CHECKMULTISIG
            ])
        )

    def derive_address(self, scope, address_index):
        h = ripemd160.new()
        h.update(hashlib.sha256(self.redeem_script(scope, address_index).raw()).digest())
        p2sh_bytes = h.digest()

        return b58encode_check(bytes(ADDRESS_CONSTANTS[self.network]['p2sh_lead']) + p2sh_bytes).decode('utf-8')

    def external_address(self, address_index):
        return self.derive_address(0, address_index)

    def change_address(self, address_index):
        return self.derive_address(1, address_index)


def main():
    args = render_args()

    rng = Random(0xabad533d)

    # Seeds are fixed across all test vectors
    seeds = [
        bytes([i]+[0x48]*31)
        for i in range(15)
    ]

    test_vectors = []
    for network in ['mainnet', 'testnet']:
        # Separate randomness per network, so increasing the number of accounts doesn't
        # disturb the test vectors for later networks.
        rand = Rand(randbytes(rng))

        for account in range(10):
            num_keys = (rand.u8() % 15) + 1
            required = (rand.u8() % num_keys) + 1

            privkeys = [
                AccountPrivateKey.derive(network, seeds[i], account)
                for i in range(num_keys)
            ]
            pubkeys = [key.public_key() for key in privkeys]

            fvk = FullViewingKey.standard(required, pubkeys)

            test_vectors.append((account, fvk, privkeys))

    render_tvs(args, test_vectors)

def render_tvs(args, test_vectors):
    test_vectors = [
        {
            'network'   : fvk.network,
            'account'   : account,
            'wallet_descriptor_template': fvk.wallet_descriptor_template,
            'key_information_vector': [key.key_info() for key in fvk.key_info],
            'xprv_keys' : [key.xprv() for key in privkeys],
            'xpub_keys' : [key.xpub() for key in fvk.key_info],
            'required'  : fvk.required,
            'external_addresses' : [(i, fvk.external_address(i)) for i in range(3)],
            'change_addresses'   : [(i, fvk.change_address(i)) for i in range(3)],
        }
        for (account, fvk, privkeys) in test_vectors
    ]

    render_tv(
        args,
        'zcash_test_vectors/transparent/zip_0048',
        (
            ('network',            '&\'static str'),
            ('account',            'u32'),
            ('wallet_descriptor_template', '&\'static str'),
            ('key_information_vector',     '&\'static [&\'static str]'),
            ('xprv_keys',          '&\'static [&\'static str]'),
            ('xpub_keys',          '&\'static [&\'static str]'),
            ('required',           'u8'),
            ('external_addresses', '&\'static [(u32, &\'static str)]'),
            ('change_addresses',   '&\'static [(u32, &\'static str)]'),
        ),
        test_vectors,
    )

if __name__ == '__main__':
    main()
