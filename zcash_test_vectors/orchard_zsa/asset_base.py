#!/usr/bin/env python3
import sys;

assert sys.version_info[0] >= 3, "Python 3 required."

import random

from hashlib import blake2b
from ..orchard.group_hash import group_hash
from ..output import render_args, render_tv

ZSA_ASSETID_VERSION_BYTE = b"\x00"

def native_asset():
    return group_hash(b"z.cash:Orchard-cv", b"v")


# https://zips.z.cash/zip-0227#zip-227-asset-identifiers
def asset_desc_digest(asset_desc):
    h = blake2b(digest_size=32, person=b"ZSA-AssetDescCRH")
    h.update(asset_desc)
    return h.digest()


# https://zips.z.cash/zip-0227#zip-227-asset-identifiers
def encode_asset_id(key, asset_desc_hash):
    if not (isinstance(key, (bytes, bytearray)) and len(key) == 33 and key[0] == 0x00):
        raise ValueError("issuer (ik_encoding) must be 33 bytes and start with 0x00")
    if len(asset_desc_hash) != 32:
        raise ValueError("assetDescHash must be 32 bytes")
    return ZSA_ASSETID_VERSION_BYTE + key + asset_desc_hash


# https://zips.z.cash/zip-0227#asset-digests
def asset_digest(encoded_asset_id):
    h = blake2b(person=b"ZSA-Asset-Digest")
    h.update(encoded_asset_id)
    return h.digest()


# https://zips.z.cash/zip-0227#orchardzsa-asset-bases
def zsa_value_base(asset_digest_value):
    return group_hash(b"z.cash:OrchardZSA", asset_digest_value)


def get_random_unicode_bytes(length, rand):

    random.seed(rand.u8())

    # TODO: Update this to include code point ranges to be sampled
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
        chr(code_point) for current_range in include_ranges
        for code_point in range(current_range[0], current_range[1] + 1)
    ]
    description_bytes = ''.join(random.choice(alphabet) for i in range(length)).encode("UTF-8")[:length].decode('UTF-8', 'ignore').encode('UTF-8').ljust(length, b'Z')
    return description_bytes


def main():
    args = render_args()

    from zcash_test_vectors.rand import Rand
    from zcash_test_vectors.orchard_zsa.key_components import IssuanceKeys

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
        isk = IssuanceKeys(rand.b(32))

        key_bytes = bytes(isk.ik_encoding)
        description_bytes = get_random_unicode_bytes(512, rand)
        asset_desc_hash = asset_desc_digest(description_bytes)
        asset_base = zsa_value_base(asset_digest(encode_asset_id(key_bytes, asset_desc_hash)))

        test_vectors.append({
            'key': key_bytes,
            'description': description_bytes,
            'asset_base': bytes(asset_base),
        })

    render_tv(
        args,
        'orchard_zsa_asset_base',
        (
            ('key', '[u8; 33]'),
            ('description', '[u8; 512]'),
            ('asset_base', '[u8; 32]'),
        ),
        test_vectors,
    )


if __name__ == '__main__':
    main()
