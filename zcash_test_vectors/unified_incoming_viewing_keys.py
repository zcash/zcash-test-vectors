#!/usr/bin/env python3
import sys; assert sys.version_info[0] >= 3, "Python 3 required."

from random import Random

from .output import render_args, render_tv, Some
from .rand import Rand, randbytes
from .orchard import key_components as orchard_key_components
from .sapling import zip32 as sapling_zip32
from .transparent import bip_0032
from .hd_common import ZCASH_MAIN_COINTYPE, hardened
from .unified_encoding import encode_unified, decode_unified
from .unified_encoding import P2PKH_ITEM, SAPLING_ITEM, ORCHARD_ITEM


def main():
    args = render_args()

    rng = Random(0xabad533d)
    rand = Rand(randbytes(rng))
    seed = bytes(range(32))

    test_vectors = []
    for account in range(0, 20):
        has_t_key = rand.bool()
        if has_t_key:
            rand.b(20) # discard, to match UA generation

            # <https://zips.z.cash/zip-0316#encoding-of-unified-full-incoming-viewing-keys>
            # "However, the [Transparent P2PKH] FVK uses the key at the Account level, i.e.
            # at path m/44'/coin_type'/account', while the IVK uses the external (non-change)
            # child key at the Change level, i.e. at path m/44'/coin_type'/account'/0."
            root_key = bip_0032.ExtendedSecretKey.master(seed)
            purpose_key = root_key.child(hardened(44))
            coin_key = purpose_key.child(hardened(ZCASH_MAIN_COINTYPE))
            account_key = coin_key.child(hardened(account))
            external_key = account_key.child(0)
            t_key_bytes = bytes(external_key.public_key())
        else:
            t_key_bytes = None

        has_s_key = rand.bool()
        if has_s_key:
            root_key = sapling_zip32.ExtendedSpendingKey.master(seed)
            purpose_key = root_key.child(hardened(32))
            coin_key = purpose_key.child(hardened(ZCASH_MAIN_COINTYPE))
            account_key = coin_key.child(hardened(account))
            sapling_dk = account_key.to_extended_fvk().dk()
            sapling_ivk = account_key.ivk()
            sapling_ivk_bytes = bytes(sapling_dk) + bytes(sapling_ivk)
        else:
            sapling_ivk_bytes = None

        has_o_key = (not has_s_key) or rand.bool()
        if has_o_key:
            root_key = orchard_key_components.ExtendedSpendingKey.master(seed)
            purpose_key = root_key.child(hardened(32))
            coin_key = purpose_key.child(hardened(ZCASH_MAIN_COINTYPE))
            account_key = coin_key.child(hardened(account))
            orchard_fvk = orchard_key_components.FullViewingKey.from_spending_key(account_key)
            orchard_dk = orchard_fvk.dk
            orchard_ivk = orchard_fvk.ivk()
            orchard_ivk_bytes = bytes(orchard_dk) + bytes(orchard_ivk)
        else:
            orchard_ivk_bytes = None

        rand.bool() # discard, to match UA generation

        # include an unknown item 1/4 of the time
        has_unknown_item = rand.bool() and rand.bool()
        # use the range reserved for experimental typecodes for unknowns
        unknown_tc = rng.randrange(0xFFFA, 0xFFFF+1)
        unknown_len = rng.randrange(32, 256)
        if has_unknown_item:
            unknown_bytes = b"".join([rand.b(unknown_len)])
        else:
            unknown_bytes = None

        receivers = [
            (ORCHARD_ITEM, orchard_ivk_bytes),
            (SAPLING_ITEM, sapling_ivk_bytes),
            (P2PKH_ITEM, t_key_bytes),
            (unknown_tc, unknown_bytes),
        ]
        uivk = encode_unified(rng, receivers, "uivk")

        expected_lengths = {
            P2PKH_ITEM: 65,
            SAPLING_ITEM: 64,
            ORCHARD_ITEM: 64,
            unknown_tc: unknown_len
        }
        decoded = decode_unified(uivk, "uivk", expected_lengths)
        assert decoded.get('orchard') == orchard_ivk_bytes
        assert decoded.get('sapling') == sapling_ivk_bytes
        assert decoded.get('transparent') == t_key_bytes
        assert decoded.get('unknown') == ((unknown_tc, unknown_bytes) if unknown_bytes else None)

        test_vectors.append({
            't_key_bytes': t_key_bytes,
            'sapling_ivk_bytes': sapling_ivk_bytes,
            'orchard_ivk_bytes': orchard_ivk_bytes,
            'unknown_ivk_typecode': unknown_tc,
            'unknown_ivk_bytes': unknown_bytes,
            'unified_ivk': uivk.encode(),
            'account': account,
        })

    render_tv(
        args,
        'unified_incoming_viewing_keys',
        (
            ('t_key_bytes', {
                'rust_type': 'Option<[u8; 65]>',
                'rust_fmt': lambda x: None if x is None else Some(x),
            }),
            ('sapling_ivk_bytes', {
                'rust_type': 'Option<[u8; 64]>',
                'rust_fmt': lambda x: None if x is None else Some(x),
            }),
            ('orchard_ivk_bytes', {
                'rust_type': 'Option<[u8; 64]>',
                'rust_fmt': lambda x: None if x is None else Some(x),
            }),
            ('unknown_ivk_typecode', 'u32'),
            ('unknown_ivk_bytes', {
                'rust_type': 'Option<Vec<u8>>',
                'rust_fmt': lambda x: None if x is None else Some(x),
            }),
            ('unified_ivk', 'Vec<u8>'),
            ('account', 'u32'),
        ),
        test_vectors,
    )


if __name__ == "__main__":
    main()
