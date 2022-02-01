#!/usr/bin/env python3
import sys; assert sys.version_info[0] >= 3, "Python 3 required."

import math
from random import Random
import struct

from zcash_test_vectors.bech32m import bech32_encode, bech32_decode, convertbits, Encoding

from zcash_test_vectors.output import render_args, render_tv, Some
from zcash_test_vectors.rand import Rand, randbytes
from zcash_test_vectors.zc_utils import write_compact_size, parse_compact_size
from zcash_test_vectors.f4jumble import f4jumble, f4jumble_inv
from zcash_test_vectors.sapling import key_components as sapling_key_components
from zcash_test_vectors.orchard import key_components as orchard_key_components
from zcash_test_vectors.unified_encoding import encode_unified, decode_unified
from zcash_test_vectors.unified_encoding import P2PKH_ITEM, P2SH_ITEM, SAPLING_ITEM, ORCHARD_ITEM

def main():
    args = render_args()

    rng = Random(0xabad533d)
    rand = Rand(randbytes(rng))

    test_vectors = []
    for _ in range(0, 10):
        has_t_addr = rand.bool()
        if has_t_addr:
            t_addr = b"".join([rand.b(20)])
        else:
            t_addr = None

        has_s_addr = rand.bool()
        if has_s_addr:
            sapling_sk = sapling_key_components.SpendingKey(rand.b(32))
            sapling_default_d = sapling_sk.default_d()
            sapling_default_pk_d = sapling_sk.default_pkd()
            sapling_raw_addr = b"".join([sapling_default_d[:11], bytes(sapling_default_pk_d)[:32]])
        else:
            sapling_raw_addr = None

        has_o_addr = (not has_s_addr) or rand.bool()
        if has_o_addr:
            orchard_sk = orchard_key_components.SpendingKey(rand.b(32))
            orchard_fvk = orchard_key_components.FullViewingKey.from_spending_key(orchard_sk)
            orchard_default_d = orchard_fvk.default_d()
            orchard_default_pk_d = orchard_fvk.default_pkd()
            orchard_raw_addr = b"".join([orchard_default_d[:11], bytes(orchard_default_pk_d)[:32]])
        else:
            orchard_raw_addr = None

        is_p2pkh = rand.bool()
        receivers = [
            (ORCHARD_ITEM, orchard_raw_addr),
            (SAPLING_ITEM, sapling_raw_addr),
            (P2PKH_ITEM, t_addr if is_p2pkh else None),
            (P2SH_ITEM, None if is_p2pkh else t_addr),
        ]
        ua = encode_unified(rng, receivers, "u")

        expected_lengths = {P2PKH_ITEM: 20, P2SH_ITEM: 20, SAPLING_ITEM: 43, ORCHARD_ITEM: 43}
        decoded = decode_unified(ua, "u", expected_lengths)
        assert decoded.get('orchard') == orchard_raw_addr
        assert decoded.get('sapling') == sapling_raw_addr
        assert decoded.get('transparent') == t_addr

        test_vectors.append({
            'p2pkh_bytes': t_addr if is_p2pkh else None,
            'p2sh_bytes': None if is_p2pkh else t_addr,
            'sapling_raw_addr': sapling_raw_addr,
            'orchard_raw_addr': orchard_raw_addr,
            'unified_addr': ua.encode()
        })

    render_tv(
        args,
        'unified_address',
        (
            ('p2pkh_bytes', {
                'rust_type': 'Option<[u8; 20]>',
                'rust_fmt': lambda x: None if x is None else Some(x),
            }),
            ('p2sh_bytes', {
                'rust_type': 'Option<[u8; 20]>',
                'rust_fmt': lambda x: None if x is None else Some(x),
            }),
            ('sapling_raw_addr', {
                'rust_type': 'Option<[u8; 43]>',
                'rust_fmt': lambda x: None if x is None else Some(x),
            }),
            ('orchard_raw_addr', {
                'rust_type': 'Option<[u8; 43]>',
                'rust_fmt': lambda x: None if x is None else Some(x),
            }),
            ('unified_addr', 'Vec<u8>')
        ),
        test_vectors,
    )


if __name__ == "__main__":
    main()
