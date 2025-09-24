#!/usr/bin/env python3
import sys; assert sys.version_info[0] >= 3, "Python 3 required."

import hashlib
import re
import struct
from random import Random
from ripemd import ripemd160

from .output import render_args, render_tv, Some
from .rand import Rand, randbytes
from .zc_utils import write_compact_size
from .orchard import key_components as orchard_key_components
from .sapling import zip32 as sapling_zip32
from .transparent import bip_0032
from .hd_common import ZCASH_MAIN_COINTYPE, hardened
from .unified_encoding import encode_unified, decode_unified
from .unified_encoding import P2PKH_ITEM, P2SH_ITEM, SAPLING_ITEM, ORCHARD_ITEM
from .unified_encoding import EXPIRY_HEIGHT_ITEM, EXPIRY_TIME_ITEM
from .viewing_key_derivation import (
    derive_sapling_fvk, derive_sapling_ivk,
    derive_orchard_fvk, derive_orchard_ivk,
)


def encode_p2sh_fvk(template, keys):
    """Encode a P2SH FVK item per ZIP 316.

    template: US-ASCII BIP 388 descriptor template string (with /**)
    keys: list of (chaincode, compressed_pubkey) tuples, each 32+33 bytes,
          in lexicographic order by (chaincode, pubkey)
    """
    template_bytes = template.encode('ascii')
    result = write_compact_size(len(template_bytes))
    result += template_bytes
    result += write_compact_size(len(keys))
    for (chaincode, pubkey) in keys:
        assert len(chaincode) == 32
        assert len(pubkey) == 33
        result += chaincode + pubkey
    return result


def derive_p2sh_ivk(fvk_template, fvk_keys):
    """Derive P2SH IVK encoding from a P2SH FVK.

    Transforms /** to /* in template, and derives each key at
    non-hardened child index 0 (external chain).

    Full P2SH derivation path (FVK level):
        m / 48' / coin_type' / account' / 133000'
    IVK level (this function derives):
        m / 48' / coin_type' / account' / 133000' / 0
    Address level (derive_p2sh_address derives):
        m / 48' / coin_type' / account' / 133000' / 0 / diversifier_index
    """
    from secp256k1 import PublicKey

    ivk_template = fvk_template.replace('/**', '/*')
    ivk_keys = []
    for (chaincode, pubkey_bytes) in fvk_keys:
        pk = PublicKey(pubkey_bytes, raw=True)
        ext_pk = bip_0032.ExtendedPublicKey(chaincode, pk)
        child = ext_pk.child(0)  # non-hardened external chain
        ivk_keys.append((child.chaincode, child.pubkey_bytes()))

    # Re-sort IVK keys after derivation: BIP 32 child derivation changes
    # both chaincode and pubkey, so the lexicographic order may differ from
    # the FVK-level order. The key information vector must be deterministic.
    ivk_keys.sort()

    return (ivk_template, ivk_keys, encode_p2sh_fvk(ivk_template, ivk_keys))


def derive_p2sh_address(ivk_template, ivk_keys, diversifier_index):
    """Derive a P2SH receiver from an IVK at a given diversifier index.

    1. Derive each key at diversifier_index using non-hardened BIP 32.
    2. Instantiate the sortedmulti descriptor template.
    3. Compute HASH160 of the serialized script.
    """
    from secp256k1 import PublicKey

    # Derive child keys at diversifier_index
    derived_pubkeys = []
    for (chaincode, pubkey_bytes) in ivk_keys:
        pk = PublicKey(pubkey_bytes, raw=True)
        ext_pk = bip_0032.ExtendedPublicKey(chaincode, pk)
        child = ext_pk.child(diversifier_index)
        derived_pubkeys.append(child.pubkey_bytes())

    # For sortedmulti, keys are sorted lexicographically per BIP 67
    sorted_pubkeys = sorted(derived_pubkeys)

    # Parse the threshold from the template: sh(sortedmulti(M,@0/*,...))
    m = re.match(r'sh\(sortedmulti\((\d+),', ivk_template)
    threshold = int(m.group(1))

    # Build the redeem script: OP_M <pubkey1> <pubkey2> ... OP_N OP_CHECKMULTISIG
    script = bytes([0x50 + threshold])  # OP_M
    for pk in sorted_pubkeys:
        script += bytes([len(pk)]) + pk  # push pubkey
    script += bytes([0x50 + len(sorted_pubkeys)])  # OP_N
    script += bytes([0xAE])  # OP_CHECKMULTISIG

    # HASH160(script) = RIPEMD160(SHA256(script))
    h = ripemd160.new()
    h.update(hashlib.sha256(script).digest())
    return h.digest()


# ZIP 48 derivation path constants
ZIP48_PURPOSE = 48
ZIP48_SCRIPT_TYPE = 133000  # Zcash P2SH

# Hardcoded 2-of-3 sortedmulti template
P2SH_FVK_TEMPLATE = "sh(sortedmulti(2,@0/**,@1/**,@2/**))"


def main():
    args = render_args()

    # Distinct seed from unified_address_r2 (0x316_0002) for independent RNG streams
    rng = Random(0x316_0003)
    rand = Rand(randbytes(rng))
    seed = bytes(range(32))

    # Use 3 deterministic seeds for the 3 cosigners
    cosigner_seeds = [
        bytes(range(32)),
        bytes(range(32, 64)),
        bytes(range(64, 96)),
    ]

    # Standard key derivation roots
    t_root_key = bip_0032.ExtendedSecretKey.master(seed)
    t_purpose_key = t_root_key.child(hardened(44))
    t_coin_key = t_purpose_key.child(hardened(ZCASH_MAIN_COINTYPE))

    s_root_key = sapling_zip32.ExtendedSpendingKey.master(seed)
    s_purpose_key = s_root_key.child(hardened(32))
    s_coin_key = s_purpose_key.child(hardened(ZCASH_MAIN_COINTYPE))

    o_root_key = orchard_key_components.ExtendedSpendingKey.master(seed)
    o_purpose_key = o_root_key.child(hardened(32))
    o_coin_key = o_purpose_key.child(hardened(ZCASH_MAIN_COINTYPE))

    # ZIP 48 multisig key roots for each cosigner
    cosigner_roots = []
    for cs_seed in cosigner_seeds:
        cs_root = bip_0032.ExtendedSecretKey.master(cs_seed)
        cs_purpose = cs_root.child(hardened(ZIP48_PURPOSE))
        cs_coin = cs_purpose.child(hardened(ZCASH_MAIN_COINTYPE))
        cosigner_roots.append(cs_coin)

    test_vectors = []
    for account in range(0, 20):
        # P2PKH and P2SH are mutually exclusive per ZIP 316 (both R0 and R2):
        # a UA/UVK cannot contain both a P2PKH and P2SH item.
        has_p2pkh_key = rand.bool()
        has_p2sh_key = rand.bool() and (not has_p2pkh_key)
        has_s_key = rand.bool()
        has_o_key = rand.bool() or (not has_s_key)
        has_expiry_height = rand.bool()
        has_expiry_time = rand.bool()

        # Decide if this will be a zu or tu address when derived
        has_transparent = has_p2pkh_key or has_p2sh_key
        is_zu = not has_transparent

        # --- Build UFVK ---
        fvk_items = []

        # P2PKH FVK: account-level extended public key (65 bytes = chaincode + compressed pubkey)
        if has_p2pkh_key:
            t_account_key = t_coin_key.child(hardened(account))
            t_fvk_bytes = bytes(t_account_key.public_key())[-65:]
            assert len(t_fvk_bytes) == 65
            fvk_items.append((P2PKH_ITEM, t_fvk_bytes))
        else:
            t_fvk_bytes = None

        # P2SH FVK: ZIP 48 2-of-3 sortedmulti
        if has_p2sh_key:
            p2sh_fvk_keys = []
            for cs_root in cosigner_roots:
                cs_account = cs_root.child(hardened(account))
                cs_script_type = cs_account.child(hardened(ZIP48_SCRIPT_TYPE))
                cs_pubkey = cs_script_type.public_key()
                p2sh_fvk_keys.append((cs_pubkey.chaincode, cs_pubkey.pubkey_bytes()))
            # Sort lexicographically by (chaincode, pubkey)
            p2sh_fvk_keys.sort()
            p2sh_fvk_bytes = encode_p2sh_fvk(P2SH_FVK_TEMPLATE, p2sh_fvk_keys)
            fvk_items.append((P2SH_ITEM, p2sh_fvk_bytes))
        else:
            p2sh_fvk_bytes = None
            p2sh_fvk_keys = None

        # Sapling FVK: ak || nk || ovk || dk (128 bytes)
        if has_s_key:
            (sapling_fvk_bytes, sapling_fvk, s_account_key) = derive_sapling_fvk(s_coin_key, account)
            fvk_items.append((SAPLING_ITEM, sapling_fvk_bytes))
        else:
            sapling_fvk_bytes = None
            sapling_fvk = None
            s_account_key = None

        # Orchard FVK: ak || nk || rivk (96 bytes)
        if has_o_key:
            (orchard_fvk_bytes, orchard_fvk) = derive_orchard_fvk(o_coin_key, account)
            fvk_items.append((ORCHARD_ITEM, orchard_fvk_bytes))
        else:
            orchard_fvk_bytes = None
            orchard_fvk = None

        # Expiry metadata
        if has_expiry_height:
            expiry_height = rng.randrange(1_000_000, 3_000_001)
            expiry_height_bytes = struct.pack('<I', expiry_height)
            fvk_items.append((EXPIRY_HEIGHT_ITEM, expiry_height_bytes))
        else:
            expiry_height = None
            expiry_height_bytes = None

        if has_expiry_time:
            expiry_time = rng.randrange(1_700_000_000, 2_000_000_001)
            expiry_time_bytes = struct.pack('<Q', expiry_time)
            fvk_items.append((EXPIRY_TIME_ITEM, expiry_time_bytes))
        else:
            expiry_time = None
            expiry_time_bytes = None

        ufvk = encode_unified(fvk_items, "uvf")

        # Verify UFVK round-trip
        fvk_expected_lengths = {
            P2PKH_ITEM: 65,
            SAPLING_ITEM: 128,
            ORCHARD_ITEM: 96,
        }
        fvk_decoded = decode_unified(ufvk, "uvf", fvk_expected_lengths)
        assert fvk_decoded.get('orchard') == orchard_fvk_bytes
        assert fvk_decoded.get('sapling') == sapling_fvk_bytes
        # decode_unified stores both P2PKH and P2SH as 'transparent'
        if has_p2pkh_key:
            assert fvk_decoded.get('transparent') == t_fvk_bytes
        elif has_p2sh_key:
            assert fvk_decoded.get('transparent') == p2sh_fvk_bytes
        else:
            assert fvk_decoded.get('transparent') is None
        expected_fvk_unknown = []
        if has_expiry_height:
            expected_fvk_unknown.append((EXPIRY_HEIGHT_ITEM, expiry_height_bytes))
        if has_expiry_time:
            expected_fvk_unknown.append((EXPIRY_TIME_ITEM, expiry_time_bytes))
        assert fvk_decoded.get('unknown') == (expected_fvk_unknown if expected_fvk_unknown else None)

        # --- Derive UIVK from UFVK ---
        ivk_items = []

        # P2PKH IVK: derive external child (index 0) from FVK
        if has_p2pkh_key:
            t_account_pubkey = t_account_key.public_key()
            t_ivk_pubkey = t_account_pubkey.child(0)  # external chain
            t_ivk_bytes = bytes(t_ivk_pubkey)[-65:]
            assert len(t_ivk_bytes) == 65
            ivk_items.append((P2PKH_ITEM, t_ivk_bytes))
        else:
            t_ivk_bytes = None
            t_ivk_pubkey = None

        # P2SH IVK: transform template and derive keys
        if has_p2sh_key:
            (p2sh_ivk_template, p2sh_ivk_keys, p2sh_ivk_bytes) = derive_p2sh_ivk(
                P2SH_FVK_TEMPLATE, p2sh_fvk_keys
            )
            ivk_items.append((P2SH_ITEM, p2sh_ivk_bytes))
        else:
            p2sh_ivk_bytes = None
            p2sh_ivk_keys = None
            p2sh_ivk_template = None

        # Sapling IVK: dk || ivk (64 bytes)
        if has_s_key:
            sapling_dk = sapling_fvk.dk()
            sapling_ivk_val = sapling_fvk.ivk()
            sapling_ivk_bytes = sapling_dk + bytes(sapling_ivk_val)
            ivk_items.append((SAPLING_ITEM, sapling_ivk_bytes))
        else:
            sapling_ivk_bytes = None

        # Orchard IVK: dk || ivk (64 bytes)
        if has_o_key:
            orchard_dk = orchard_fvk.dk
            orchard_ivk_val = orchard_fvk.ivk()
            orchard_ivk_bytes = orchard_dk + bytes(orchard_ivk_val)
            ivk_items.append((ORCHARD_ITEM, orchard_ivk_bytes))
        else:
            orchard_ivk_bytes = None

        # Metadata items retained unmodified from UFVK
        if has_expiry_height:
            ivk_items.append((EXPIRY_HEIGHT_ITEM, expiry_height_bytes))
        if has_expiry_time:
            ivk_items.append((EXPIRY_TIME_ITEM, expiry_time_bytes))

        uivk = encode_unified(ivk_items, "uvi")

        # Verify UIVK round-trip
        ivk_expected_lengths = {
            P2PKH_ITEM: 65,
            SAPLING_ITEM: 64,
            ORCHARD_ITEM: 64,
        }
        ivk_decoded = decode_unified(uivk, "uvi", ivk_expected_lengths)
        assert ivk_decoded.get('orchard') == orchard_ivk_bytes
        assert ivk_decoded.get('sapling') == sapling_ivk_bytes
        if has_p2pkh_key:
            assert ivk_decoded.get('transparent') == t_ivk_bytes
        elif has_p2sh_key:
            assert ivk_decoded.get('transparent') == p2sh_ivk_bytes
        else:
            assert ivk_decoded.get('transparent') is None
        expected_ivk_unknown = []
        if has_expiry_height:
            expected_ivk_unknown.append((EXPIRY_HEIGHT_ITEM, expiry_height_bytes))
        if has_expiry_time:
            expected_ivk_unknown.append((EXPIRY_TIME_ITEM, expiry_time_bytes))
        assert ivk_decoded.get('unknown') == (expected_ivk_unknown if expected_ivk_unknown else None)

        # --- Derive UA from UIVK ---
        ua_hrp = "zu" if is_zu else "tu"
        diversifier_index = 0

        ua_items = []

        if has_s_key:
            diversifier_index = s_account_key.find_j(diversifier_index)
            sapling_d = s_account_key.diversifier(diversifier_index)
            sapling_pk_d = s_account_key.pk_d(diversifier_index)
            sapling_raw_addr = sapling_d + bytes(sapling_pk_d)
            ua_items.append((SAPLING_ITEM, sapling_raw_addr))
        else:
            sapling_raw_addr = None

        if has_o_key:
            orchard_d = orchard_fvk.diversifier(diversifier_index)
            orchard_pk_d = orchard_fvk.pk_d(diversifier_index)
            orchard_raw_addr = orchard_d + bytes(orchard_pk_d)
            ua_items.append((ORCHARD_ITEM, orchard_raw_addr))
        else:
            orchard_raw_addr = None

        if has_p2pkh_key:
            t_p2pkh_addr = t_ivk_pubkey.child(diversifier_index).address()
            ua_items.append((P2PKH_ITEM, t_p2pkh_addr))
        else:
            t_p2pkh_addr = None

        if has_p2sh_key:
            t_p2sh_addr = derive_p2sh_address(
                p2sh_ivk_template, p2sh_ivk_keys, diversifier_index
            )
            ua_items.append((P2SH_ITEM, t_p2sh_addr))
        else:
            t_p2sh_addr = None

        # Expiry metadata propagated (use same values, per spec: value <= source)
        if has_expiry_height:
            ua_items.append((EXPIRY_HEIGHT_ITEM, expiry_height_bytes))
        if has_expiry_time:
            ua_items.append((EXPIRY_TIME_ITEM, expiry_time_bytes))

        derived_ua = encode_unified(ua_items, ua_hrp)

        test_vectors.append({
            # UFVK fields
            't_p2pkh_fvk_bytes': t_fvk_bytes,
            'p2sh_fvk_bytes': p2sh_fvk_bytes,
            'sapling_fvk_bytes': sapling_fvk_bytes,
            'orchard_fvk_bytes': orchard_fvk_bytes,
            'expiry_height': expiry_height,
            'expiry_time': expiry_time,
            'unified_fvk': ufvk,
            # UIVK fields
            't_p2pkh_ivk_bytes': t_ivk_bytes,
            'p2sh_ivk_bytes': p2sh_ivk_bytes,
            'sapling_ivk_bytes': sapling_ivk_bytes,
            'orchard_ivk_bytes': orchard_ivk_bytes,
            'unified_ivk': uivk,
            # Derived UA fields
            'p2pkh_addr': t_p2pkh_addr,
            'p2sh_addr': t_p2sh_addr,
            'sapling_raw_addr': sapling_raw_addr,
            'orchard_raw_addr': orchard_raw_addr,
            'derived_ua': derived_ua,
            # Derivation parameters
            'root_seed': seed,
            'cosigner_seed_1': cosigner_seeds[1],
            'cosigner_seed_2': cosigner_seeds[2],
            'account': account,
            'diversifier_index': diversifier_index,
        })

    render_tv(
        args,
        'zcash_test_vectors/unified_viewing_keys_r2',
        (
            # UFVK
            ('t_p2pkh_fvk_bytes',  'Option<[u8; 65]>'),
            ('p2sh_fvk_bytes',     {'rust_type': 'Option<&\'static [u8]>', 'bitcoin_flavoured': False}),
            ('sapling_fvk_bytes',  'Option<[u8; 128]>'),
            ('orchard_fvk_bytes',  'Option<[u8; 96]>'),
            ('expiry_height',      'Option<u32>'),
            ('expiry_time',        'Option<u64>'),
            ('unified_fvk',        {'rust_type': '&\'static str'}),
            # UIVK
            ('t_p2pkh_ivk_bytes',  'Option<[u8; 65]>'),
            ('p2sh_ivk_bytes',     {'rust_type': 'Option<&\'static [u8]>', 'bitcoin_flavoured': False}),
            ('sapling_ivk_bytes',  'Option<[u8; 64]>'),
            ('orchard_ivk_bytes',  'Option<[u8; 64]>'),
            ('unified_ivk',        {'rust_type': '&\'static str'}),
            # Derived UA
            ('p2pkh_addr',         'Option<[u8; 20]>'),
            ('p2sh_addr',          'Option<[u8; 20]>'),
            ('sapling_raw_addr',   'Option<[u8; 43]>'),
            ('orchard_raw_addr',   'Option<[u8; 43]>'),
            ('derived_ua',         {'rust_type': '&\'static str'}),
            # Derivation params (root_seed == cosigner_seed_0; cosigner_seed_1
            # and cosigner_seed_2 are the other two ZIP 48 cosigner seeds)
            ('root_seed',          {'rust_type': '[u8; 32]', 'bitcoin_flavoured': False}),
            ('cosigner_seed_1',    {'rust_type': '[u8; 32]', 'bitcoin_flavoured': False}),
            ('cosigner_seed_2',    {'rust_type': '[u8; 32]', 'bitcoin_flavoured': False}),
            ('account',            'u32'),
            ('diversifier_index',  'u32'),
        ),
        test_vectors,
    )


if __name__ == "__main__":
    main()
