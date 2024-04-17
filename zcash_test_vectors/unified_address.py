#!/usr/bin/env python3
import sys; assert sys.version_info[0] >= 3, "Python 3 required."

import math
from random import Random
import struct

from .bech32m import bech32_encode, bech32_decode, convertbits, Encoding

from .output import render_args, render_tv, Some
from .rand import Rand, randbytes
from .zc_utils import write_compact_size, parse_compact_size
from .f4jumble import f4jumble, f4jumble_inv
from .sapling import key_components as sapling_key_components, zip32 as sapling_zip32
from .orchard import key_components as orchard_key_components
from .transparent import bip_0032
from .hd_common import ZCASH_MAIN_COINTYPE, hardened
from .unified_encoding import encode_unified, decode_unified
from .unified_encoding import P2PKH_ITEM, P2SH_ITEM, SAPLING_ITEM, ORCHARD_ITEM

def main():
    args = render_args()

    rng = Random(0xabad533d)
    rand = Rand(randbytes(rng))
    seed = bytes(range(32))

    t_root_key = bip_0032.ExtendedSecretKey.master(seed)
    t_purpose_key = t_root_key.child(hardened(44))
    t_coin_key = t_purpose_key.child(hardened(ZCASH_MAIN_COINTYPE))

    s_root_key = sapling_zip32.ExtendedSpendingKey.master(seed)
    s_purpose_key = s_root_key.child(hardened(32))
    s_coin_key = s_purpose_key.child(hardened(ZCASH_MAIN_COINTYPE))

    o_root_key = orchard_key_components.ExtendedSpendingKey.master(seed)
    o_purpose_key = o_root_key.child(hardened(32))
    o_coin_key = o_purpose_key.child(hardened(ZCASH_MAIN_COINTYPE))

    test_vectors = []
    def gen_v(account, has_t_addr, is_p2pkh, has_s_addr, has_o_addr, has_unknown_item, unknown_tc, unknown_len):
        if has_t_addr:
            # This randomness is only used if this UA will have a P2SH key.
            # If it will have a P2PKH key, it gets overwritten below (after
            # we've decided on the diversifier index).
            t_addr = rand.b(20)
        else:
            t_addr = None

        # we will increment the diversifier index after generating each sample
        # within the current account
        j = 0
        for _ in range(0, 3):
            receivers = []
            if has_s_addr:
                s_account_key = s_coin_key.child(hardened(account))
                j = s_account_key.find_j(j)
                sapling_d = s_account_key.diversifier(j)
                sapling_pk_d = s_account_key.pk_d(j)
                sapling_raw_addr = sapling_d + bytes(sapling_pk_d)
                receivers.append((SAPLING_ITEM, sapling_raw_addr))
            else:
                sapling_raw_addr = None

            if has_o_addr:
                o_account_key = o_coin_key.child(hardened(account))
                orchard_fvk = orchard_key_components.FullViewingKey.from_spending_key(o_account_key)
                orchard_d = orchard_fvk.diversifier(j)
                orchard_pk_d = orchard_fvk.pk_d(j)
                orchard_raw_addr = orchard_d + bytes(orchard_pk_d)
                receivers.append((ORCHARD_ITEM, orchard_raw_addr))
            else:
                orchard_raw_addr = None

            if has_t_addr:
                if is_p2pkh:
                    t_account_key = t_coin_key.child(hardened(account))
                    t_external_key = t_account_key.child(0)
                    t_index_key = t_external_key.child(j)
                    t_index_pubkey = t_index_key.public_key()
                    t_addr = t_index_pubkey.address()
                    receivers.append((P2PKH_ITEM, t_addr))
                else:
                    receivers.append((P2SH_ITEM, t_addr))
            else:
                t_addr = None

            if has_unknown_item:
                unknown_bytes = b"".join([rand.b(unknown_len)])
                receivers.append((unknown_tc, unknown_bytes))
            else:
                unknown_bytes = None

            ua = encode_unified(receivers, "u")

            expected_lengths = {
                ORCHARD_ITEM: 43,
                SAPLING_ITEM: 43,
                P2PKH_ITEM: 20,
                P2SH_ITEM: 20,
                unknown_tc: unknown_len
            }
            decoded = decode_unified(ua, "u", expected_lengths)
            assert decoded.get('orchard') == orchard_raw_addr
            assert decoded.get('sapling') == sapling_raw_addr
            assert decoded.get('transparent') == t_addr
            if has_unknown_item:
                assert decoded.get('unknown') == (unknown_tc, unknown_bytes)
            else:
                assert decoded.get('unknown') == None

            test_vectors.append({
                'p2pkh_bytes': t_addr if is_p2pkh else None,
                'p2sh_bytes': None if is_p2pkh else t_addr,
                'sapling_raw_addr': sapling_raw_addr,
                'orchard_raw_addr': orchard_raw_addr,
                'unknown_typecode': unknown_tc if has_unknown_item else None,
                'unknown_bytes': unknown_bytes,
                'unified_addr': ua,
                'root_seed': seed,
                'account': account,
                'diversifier_index': j,
            })

            j += 1


    # Add a UA with just P2PKH & Sapling receivers
    gen_v(0, True,  True, True, False, False, None, None)
    # Add a UA with P2PKH, Sapling, and Orchard receivers
    gen_v(1, True,  True, True, True,  False, None, None)
    # Add a UA with just Sapling and Orchard receivers
    gen_v(2, False, None, True, True,  False, None, None)

    # Add random UAs for the remaining 17 accounts
    for account in range(3, 20):
        # Each set of sequential diversified addresses should have the same set
        # of typecodes, to simplify use in tests.
        has_t_addr = rand.bool()
        # use p2pkh 3/4 of the time
        is_p2pkh = any([rand.bool(), rand.bool()])

        has_s_addr = rand.bool()
        has_o_addr = (not has_s_addr) or rand.bool()
        # include an unknown item 1/4 of the time
        has_unknown_item = all([rand.bool(), rand.bool()])
        # use the range reserved for experimental typecodes for unknowns
        unknown_tc = rng.randrange(0xFFFA, 0xFFFF+1)
        unknown_len = rng.randrange(32, 256)

        gen_v(account, has_t_addr, is_p2pkh, has_s_addr, has_o_addr, has_unknown_item, unknown_tc, unknown_len)

    render_tv(
        args,
        'unified_address',
        (
            ('p2pkh_bytes',       'Option<[u8; 20]>'),
            ('p2sh_bytes',        'Option<[u8; 20]>'),
            ('sapling_raw_addr',  'Option<[u8; 43]>'),
            ('orchard_raw_addr',  'Option<[u8; 43]>'),
            ('unknown_typecode',  'Option<u32>'),
            ('unknown_bytes',     {'rust_type': 'Option<Vec<u8>>', 'bitcoin_flavoured': False}),
            ('unified_addr',      {'rust_type': '&\'static str'}),
            ('root_seed',         {'rust_type': 'Vec<u8>', 'bitcoin_flavoured': False}),
            ('account',           'u32'),
            ('diversifier_index', 'u32'),
        ),
        test_vectors,
    )


if __name__ == "__main__":
    main()
