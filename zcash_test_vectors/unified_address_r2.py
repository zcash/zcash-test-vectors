#!/usr/bin/env python3
import sys; assert sys.version_info[0] >= 3, "Python 3 required."

import struct
from random import Random

from .output import render_args, render_tv, Some
from .rand import Rand, randbytes
from .zc_utils import write_compact_size
from .sapling import key_components as sapling_key_components, zip32 as sapling_zip32
from .orchard import key_components as orchard_key_components
from .transparent import bip_0032
from .hd_common import ZCASH_MAIN_COINTYPE, hardened
from .unified_encoding import encode_unified, decode_unified
from .unified_encoding import P2PKH_ITEM, P2SH_ITEM, SAPLING_ITEM, ORCHARD_ITEM
from .unified_encoding import EXPIRY_HEIGHT_ITEM, EXPIRY_TIME_ITEM


def main():
    args = render_args()

    rng = Random(0x316_0002)
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

    def gen_ua(account, is_zu, has_t_addr, is_p2pkh, has_s_addr, has_o_addr,
               has_expiry_height, has_expiry_time):
        """Generate R2 unified addresses for a given account.

        is_zu: if True, encode as 'zu' (shielded-only); if False, encode as 'tu'.
        """
        hrp = "zu" if is_zu else "tu"

        if has_t_addr:
            assert not is_zu, "zu addresses must not contain transparent receivers"
            t_addr_random = rand.b(20)
        else:
            t_addr_random = None

        # Generate expiry metadata values
        if has_expiry_height:
            expiry_height = rng.randrange(1_000_000, 3_000_001)
            expiry_height_bytes = struct.pack('<I', expiry_height)
        else:
            expiry_height = None
            expiry_height_bytes = None

        if has_expiry_time:
            # Unix timestamp in a plausible future range
            expiry_time = rng.randrange(1_700_000_000, 2_000_000_001)
            expiry_time_bytes = struct.pack('<Q', expiry_time)
        else:
            expiry_time = None
            expiry_time_bytes = None

        j = 0
        for _ in range(3):
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

            t_addr = None
            if has_t_addr:
                if is_p2pkh:
                    t_account_key = t_coin_key.child(hardened(account))
                    t_external_key = t_account_key.child(0)
                    t_index_key = t_external_key.child(j)
                    t_index_pubkey = t_index_key.public_key()
                    t_addr = t_index_pubkey.address()
                    receivers.append((P2PKH_ITEM, t_addr))
                else:
                    t_addr = t_addr_random
                    receivers.append((P2SH_ITEM, t_addr))

            # Add metadata items
            if has_expiry_height:
                receivers.append((EXPIRY_HEIGHT_ITEM, expiry_height_bytes))
            if has_expiry_time:
                receivers.append((EXPIRY_TIME_ITEM, expiry_time_bytes))

            ua = encode_unified(receivers, hrp)

            # Verify round-trip
            expected_lengths = {
                ORCHARD_ITEM: 43,
                SAPLING_ITEM: 43,
                P2PKH_ITEM: 20,
                P2SH_ITEM: 20,
                EXPIRY_HEIGHT_ITEM: 4,
                EXPIRY_TIME_ITEM: 8,
            }
            decoded = decode_unified(ua, hrp, expected_lengths)
            assert decoded.get('orchard') == orchard_raw_addr
            assert decoded.get('sapling') == sapling_raw_addr
            assert decoded.get('transparent') == t_addr
            expected_unknown = []
            if has_expiry_height:
                expected_unknown.append((EXPIRY_HEIGHT_ITEM, expiry_height_bytes))
            if has_expiry_time:
                expected_unknown.append((EXPIRY_TIME_ITEM, expiry_time_bytes))
            assert decoded.get('unknown') == (expected_unknown if expected_unknown else None)

            test_vectors.append({
                'p2pkh_bytes': t_addr if (has_t_addr and is_p2pkh) else None,
                'p2sh_bytes': t_addr if (has_t_addr and not is_p2pkh) else None,
                'sapling_raw_addr': sapling_raw_addr,
                'orchard_raw_addr': orchard_raw_addr,
                'expiry_height': expiry_height,
                'expiry_time': expiry_time,
                'unified_addr': ua,
                'root_seed': seed,
                'account': account,
                'diversifier_index': j,
            })

            j += 1

    # --- Deterministic test vector set ---

    # zu addresses (shielded-only)
    # Sapling + Orchard, no expiry
    gen_ua(0, True, False, None, True, True, False, False)
    # Orchard only, with expiry height
    gen_ua(1, True, False, None, False, True, True, False)
    # Sapling only, with expiry time
    gen_ua(2, True, False, None, True, False, False, True)
    # Sapling + Orchard, with both expiry height and time
    gen_ua(3, True, False, None, True, True, True, True)

    # tu addresses (transparent-enabled)
    # P2PKH + Sapling + Orchard, no expiry
    gen_ua(4, False, True, True, True, True, False, False)
    # P2PKH + Orchard, with expiry height
    gen_ua(5, False, True, True, False, True, True, False)
    # P2SH + Sapling + Orchard, with expiry time
    gen_ua(6, False, True, False, True, True, False, True)
    # P2PKH + Sapling + Orchard, with both expiry height and time
    gen_ua(7, False, True, True, True, True, True, True)

    # Random additional vectors
    for account in range(8, 20):
        is_zu = rand.bool()
        has_t_addr = False if is_zu else rand.bool()
        is_p2pkh = any([rand.bool(), rand.bool()]) if has_t_addr else None
        has_s_addr = rand.bool()
        has_o_addr = (not has_s_addr) or rand.bool()
        has_expiry_height = rand.bool()
        has_expiry_time = rand.bool()

        gen_ua(account, is_zu, has_t_addr, is_p2pkh, has_s_addr, has_o_addr,
               has_expiry_height, has_expiry_time)

    render_tv(
        args,
        'unified_address_r2',
        (
            ('p2pkh_bytes',       'Option<[u8; 20]>'),
            ('p2sh_bytes',        'Option<[u8; 20]>'),
            ('sapling_raw_addr',  'Option<[u8; 43]>'),
            ('orchard_raw_addr',  'Option<[u8; 43]>'),
            ('expiry_height',     'Option<u32>'),
            ('expiry_time',       'Option<u64>'),
            ('unified_addr',      {'rust_type': '&\'static str'}),
            ('root_seed',         {'rust_type': 'Vec<u8>', 'bitcoin_flavoured': False}),
            ('account',           'u32'),
            ('diversifier_index', 'u32'),
        ),
        test_vectors,
    )


if __name__ == "__main__":
    main()
