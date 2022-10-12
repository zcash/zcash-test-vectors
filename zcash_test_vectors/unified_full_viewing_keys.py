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
    for account in range(0, 20):
        has_t_key = rand.bool()
        if has_t_key:
            rand.b(20) # discard, to match UA generation

            # <https://zips.z.cash/zip-0316#encoding-of-unified-full-incoming-viewing-keys>
            # "However, the [Transparent P2PKH] FVK uses the key at the Account level, i.e.
            # at path m/44'/coin_type'/account', while the IVK uses the external (non-change)
            # child key at the Change level, i.e. at path m/44'/coin_type'/account'/0."
            t_account_key = t_coin_key.child(hardened(account))
            t_key_bytes = bytes(t_account_key.public_key())
        else:
            t_key_bytes = None

        has_s_key = rand.bool()
        if has_s_key:
            s_account_key = s_coin_key.child(hardened(account))
            sapling_fvk = s_account_key.to_extended_fvk()
            sapling_fvk_bytes = b"".join([
                bytes(sapling_fvk.ak()),
                bytes(sapling_fvk.nk()),
                sapling_fvk.ovk(),
                sapling_fvk.dk()
                ])
        else:
            sapling_fvk_bytes = None

        has_o_key = (not has_s_key) or rand.bool()
        if has_o_key:
            o_account_key = o_coin_key.child(hardened(account))
            orchard_fvk = orchard_key_components.FullViewingKey.from_spending_key(o_account_key)
            orchard_fvk_bytes = b"".join([
                bytes(orchard_fvk.ak),
                bytes(orchard_fvk.nk),
                bytes(orchard_fvk.rivk)
                ])
        else:
            orchard_fvk_bytes = None

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
            (ORCHARD_ITEM, orchard_fvk_bytes),
            (SAPLING_ITEM, sapling_fvk_bytes),
            (P2PKH_ITEM, t_key_bytes),
            (unknown_tc, unknown_bytes),
        ]
        ufvk = encode_unified(receivers, "uview")

        expected_lengths = {
            P2PKH_ITEM: 65,
            SAPLING_ITEM: 128,
            ORCHARD_ITEM: 96,
            unknown_tc: unknown_len
        }
        decoded = decode_unified(ufvk, "uview", expected_lengths)
        assert decoded.get('orchard') == orchard_fvk_bytes
        assert decoded.get('sapling') == sapling_fvk_bytes
        assert decoded.get('transparent') == t_key_bytes
        assert decoded.get('unknown') == ((unknown_tc, unknown_bytes) if unknown_bytes else None)

        test_vectors.append({
            't_key_bytes': t_key_bytes,
            'sapling_fvk_bytes': sapling_fvk_bytes,
            'orchard_fvk_bytes': orchard_fvk_bytes,
            'unknown_fvk_typecode': unknown_tc,
            'unknown_fvk_bytes': unknown_bytes,
            'unified_fvk': ufvk.encode(),
            'root_seed': seed,
            'account': account,
        })

    render_tv(
        args,
        'unified_full_viewing_keys',
        (
            ('t_key_bytes',          'Option<[u8; 65]>'),
            ('sapling_fvk_bytes',    'Option<[u8; 128]>'),
            ('orchard_fvk_bytes',    'Option<[u8; 96]>'),
            ('unknown_fvk_typecode', 'u32'),
            ('unknown_fvk_bytes',    {'rust_type': 'Option<Vec<u8>>', 'bitcoin_flavoured': False}),
            ('unified_fvk',          {'rust_type': 'Vec<u8>', 'bitcoin_flavoured': False}),
            ('root_seed',            {'rust_type': 'Vec<u8>', 'bitcoin_flavoured': False}),
            ('account',              'u32'),
        ),
        test_vectors,
    )


if __name__ == "__main__":
    main()
