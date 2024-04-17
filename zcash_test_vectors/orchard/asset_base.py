#!/usr/bin/env python3
import sys;

assert sys.version_info[0] >= 3, "Python 3 required."

import random

from hashlib import blake2b
from ..orchard.group_hash import group_hash
from ..output import render_args, render_tv, option


def native_asset():
    return group_hash(b"z.cash:Orchard-cv", b"v")


def encode_asset_id(key, description):
    version_byte = b"\x00"
    return version_byte + key + description


def asset_digest(encoded_asset_id):
    h = blake2b(person=b"ZSA-Asset-Digest")
    h.update(encoded_asset_id)
    return h.digest()


def zsa_value_base(asset_digest_value):
    return group_hash(b"z.cash:OrchardZSA", asset_digest_value)


def get_random_unicode_bytes(length):
    try:
        get_char = unichr
    except NameError:
        get_char = chr

    # Update this to include code point ranges to be sampled
    include_ranges = [
        ( 0x0021, 0x0021 ),
        ( 0x0023, 0x0026 ),
        ( 0x0028, 0x007E ),
        ( 0x00A1, 0x00AC ),
        ( 0x00AE, 0x00FF ),
        ( 0x0100, 0x017F ),
        ( 0x0180, 0x024F ),
        ( 0x2C60, 0x2C7F ),
        ( 0x16A0, 0x16F0 ),
        ( 0x0370, 0x0377 ),
        ( 0x037A, 0x037E ),
        ( 0x0384, 0x038A ),
        ( 0x038C, 0x038C ),
    ]

    alphabet = [
        get_char(code_point) for current_range in include_ranges
        for code_point in range(current_range[0], current_range[1] + 1)
    ]
    description_bytes = ''.join(random.choice(alphabet) for i in range(length)).encode("UTF-8")[:length].decode('UTF-8', 'ignore').encode('UTF-8').ljust(length, b'Z')
    return description_bytes

def main():
    args = render_args()

    from zcash_test_vectors.rand import Rand
    from zcash_test_vectors.orchard.key_components import SpendingKey
    from zcash_test_vectors.orchard.key_components import FullViewingKey
    from zcash_test_vectors.orchard.key_components import IssuanceAuthorizingKey

    from random import Random

    rng = Random(0xabad533d)

    def randbytes(l):
        ret = []
        while len(ret) < l:
            ret.append(rng.randrange(0, 256))
        return bytes(ret)

    rand = Rand(randbytes)

    test_vectors = []
    for i in range(0, 20):
        sk = SpendingKey(rand.b(32))
        fvk = FullViewingKey.from_spending_key(sk)
        isk = IssuanceAuthorizingKey(rand.b(32))

        key_bytes = bytes(isk.ik)
        description_bytes = get_random_unicode_bytes(512)
        asset_base = zsa_value_base(asset_digest(encode_asset_id(key_bytes, description_bytes)))

        test_vectors.append({
            'key': key_bytes,
            'description': description_bytes,
            'asset_base': bytes(asset_base),
        })

    render_tv(
        args,
        'orchard_asset_id',
        (
            ('key', '[u8; 32]'),
            ('description', '[u8; 512]'),
            ('asset_base', '[u8; 32]'),
        ),
        test_vectors,
    )


if __name__ == '__main__':
    main()
