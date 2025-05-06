#!/usr/bin/env python3
import sys; assert sys.version_info[0] >= 3, "Python 3 required."

import math
from random import Random
import struct
import base58

from ..bech32m import bech32_encode, bech32_decode, convertbits, Encoding
from ..output import render_args, render_tv, Some
from ..rand import Rand, randbytes
from ..hd_common import ZCASH_MAIN_COINTYPE, ZCASH_TEST_COINTYPE, hardened
from .bip_0032 import ExtendedSecretKey

class HrpMismatch(Exception):
    pass

class InvalidEncoding(Exception):
    pass

def encode(hrp, p2pkh_bytes):
    converted = convertbits(p2pkh_bytes, 8, 5)
    return bech32_encode(hrp, converted, Encoding.BECH32M)

def decode(hrp_expected, tex_addr):
    (hrp, data, encoding) = bech32_decode(tex_addr)
    if data is None or encoding != Encoding.BECH32M:
        raise InvalidEncoding("ZIP 320 addresses must be encoded using Bech32m")
    if hrp != hrp_expected:
        raise HrpMismatch("Expected: " + hrp_expected + "; got " + hrp)
    return bytes(convertbits(data, 5, 8, False))

ADDRESS_CONSTANTS = {
    "mainnet": { "coin_type": ZCASH_MAIN_COINTYPE, "p2pkh_lead": [0x1c, 0xb8], "tex_hrp": "tex" },
    "testnet": { "coin_type": ZCASH_TEST_COINTYPE, "p2pkh_lead": [0x1d, 0x25], "tex_hrp": "textest" },
    "regtest": { "coin_type": ZCASH_TEST_COINTYPE, "p2pkh_lead": [0x1d, 0x25], "tex_hrp": "texregtest" },
}

def main():
    args = render_args()

    network = "mainnet"
    constants = ADDRESS_CONSTANTS[network]

    rng = Random(0xabad533d)
    rand = Rand(randbytes(rng))
    seed = bytes(range(32))

    t_root_key = ExtendedSecretKey.master(seed)
    t_purpose_key = t_root_key.child(hardened(44))
    t_coin_key = t_purpose_key.child(hardened(constants["coin_type"]))

    test_vectors = []
    for account in range(0, 5):
        for j in range(0, 3):
            t_account_key = t_coin_key.child(hardened(account))
            t_external_key = t_account_key.child(0)
            t_index_key = t_external_key.child(j)
            t_index_pubkey = t_index_key.public_key()
            p2pkh_bytes = t_index_pubkey.address()
            t_addr = base58.b58encode_check(bytes(constants["p2pkh_lead"]) + p2pkh_bytes).decode('utf-8')

            tex_addr = encode(constants["tex_hrp"], p2pkh_bytes)

            p2pkh_bytes_decoded = decode(constants["tex_hrp"], tex_addr)
            assert p2pkh_bytes_decoded == p2pkh_bytes

            test_vectors.append({
                't_addr': t_addr,
                'p2pkh_bytes': p2pkh_bytes,
                'tex_addr': tex_addr,
                'account': account,
                'child_index': j,
            })

    render_tv(
        args,
        'zcash_test_vectors/transparent/zip_0320',
        (
            ('t_addr',            {'rust_type': '&\'static str'}),
            ('p2pkh_bytes',       '[u8; 20]'),
            ('tex_addr',          {'rust_type': '&\'static str'}),
            ('account',           'u32'),
            ('child_index',       'u32'),
        ),
        test_vectors,
    )


if __name__ == "__main__":
    main()
