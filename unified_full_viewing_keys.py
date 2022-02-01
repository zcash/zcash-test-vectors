#!/usr/bin/env python3
import sys; assert sys.version_info[0] >= 3, "Python 3 required."

import math
from random import Random
import struct

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding

from zcash_test_vectors.output import render_args, render_tv, Some
from zcash_test_vectors.rand import Rand, randbytes
from zcash_test_vectors.zc_utils import write_compact_size, parse_compact_size
from zcash_test_vectors.f4jumble import f4jumble, f4jumble_inv
from zcash_test_vectors.orchard import key_components as orchard_key_components
from zcash_test_vectors.sapling import zip32 as sapling_zip32
from zcash_test_vectors.unified_encoding import encode_unified, decode_unified
from zcash_test_vectors.unified_encoding import P2PKH_ITEM, P2SH_ITEM, SAPLING_ITEM, ORCHARD_ITEM

def main():
    args = render_args()

    rng = Random(0xabad533d)
    rand = Rand(randbytes(rng))
    seed = rand.b(32)

    test_vectors = []
    for i in range(0, 10):
        has_t_key = rand.bool()
        if has_t_key:
            c = rand.b(32)
            privkey = ec.derive_private_key(int.from_bytes(rand.b(32), 'little'), ec.SECP256K1())
            pubkey = privkey.public_key()
            pubkey_bytes = pubkey.public_bytes(Encoding.X962, PublicFormat.CompressedPoint)
            assert len(pubkey_bytes) == 33
            assert pubkey_bytes[0] in (0x02, 0x03)
            t_key_bytes = c + pubkey_bytes
        else:
            t_key_bytes = None

        has_s_key = rand.bool()
        if has_s_key:
            root_key = sapling_zip32.ExtendedSpendingKey.master(seed)
            purpose_key = root_key.child(sapling_zip32.hardened(32))
            coin_key = purpose_key.child(sapling_zip32.hardened(133))
            account_key = coin_key.child(sapling_zip32.hardened(i))
            sapling_fvk = account_key.to_extended_fvk()

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
            orchard_sk = orchard_key_components.SpendingKey(rand.b(32))
            orchard_fvk = orchard_key_components.FullViewingKey.from_spending_key(orchard_sk)
            orchard_fvk_bytes = b"".join([
                bytes(orchard_fvk.ak), 
                bytes(orchard_fvk.nk),
                bytes(orchard_fvk.rivk)
                ])
        else:
            orchard_fvk_bytes = None

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
        ufvk = encode_unified(rng, receivers, "uview")

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
        })

    render_tv(
        args,
        'unified_full_viewing_keys',
        (
            ('t_key_bytes', {
                'rust_type': 'Option<[u8; 65]>',
                'rust_fmt': lambda x: None if x is None else Some(x),
            }),
            ('sapling_fvk_bytes', {
                'rust_type': 'Option<[u8; 128]>',
                'rust_fmt': lambda x: None if x is None else Some(x),
            }),
            ('orchard_fvk_bytes', {
                'rust_type': 'Option<[u8; 96]>',
                'rust_fmt': lambda x: None if x is None else Some(x),
            }),
            ('unknown_fvk_typecode', 'u32'),
            ('unknown_fvk_bytes', {
                'rust_type': 'Option<Vec<u8>>',
                'rust_fmt': lambda x: None if x is None else Some(x),
            }),
            ('unified_fvk', 'Vec<u8>')
        ),
        test_vectors,
    )


if __name__ == "__main__":
    main()
