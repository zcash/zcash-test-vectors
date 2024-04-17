import sys; assert sys.version_info[0] >= 3, "Python 3 required."

from random import Random

from .zc_utils import write_compact_size, parse_compact_size
from .bech32m import bech32_encode, bech32_decode, convertbits, Encoding
from .f4jumble import f4jumble, f4jumble_inv

P2PKH_ITEM = 0x00
P2SH_ITEM = 0x01
SAPLING_ITEM = 0x02
ORCHARD_ITEM = 0x03

def tlv(typecode, value):
    return b"".join([write_compact_size(typecode), write_compact_size(len(value)), value])

def padding(hrp):
    assert(len(hrp) <= 16)
    return bytes(hrp, "utf8") + bytes(16 - len(hrp))

def encode_unified(items, hrp):
    encoded_items = []

    has_p2pkh = False
    has_p2sh = False
    for item in sorted(items):
        if item[1]:
            if item[0] == P2PKH_ITEM:
                has_p2pkh = True
            if item[0] == P2SH_ITEM:
                has_p2sh = True
            assert (not (has_p2pkh and has_p2sh))
            encoded_items.append(tlv(item[0], item[1]))

    encoded_items.append(padding(hrp))

    r_bytes = b"".join(encoded_items)
    converted = convertbits(f4jumble(r_bytes), 8, 5)
    return bech32_encode(hrp, converted, Encoding.BECH32M)

def decode_unified(encoded, expected_hrp, expected_lengths):
    (hrp, data, encoding) = bech32_decode(encoded)
    assert hrp == expected_hrp and encoding == Encoding.BECH32M
    assert(len(data) >= 48)

    decoded = f4jumble_inv(bytes(convertbits(data, 5, 8, False)))
    suffix = decoded[-16:]
    # check trailing padding bytes
    assert suffix == padding(hrp)
    rest = decoded[:-16]

    result = {}
    prev_type = -1
    while len(rest) > 0:
        (item_type, rest) = parse_compact_size(rest)
        (item_len, rest) = parse_compact_size(rest)

        expected_len = expected_lengths.get(item_type)
        if expected_len is not None:
            assert item_len == expected_len, "incorrect item length"

        assert len(rest) >= item_len
        (item, rest) = (rest[:item_len], rest[item_len:])

        if item_type == P2PKH_ITEM or item_type == P2SH_ITEM:
            assert not ('transparent' in result), "duplicate transparent item detected"
            result['transparent'] = item

        elif item_type == SAPLING_ITEM:
            assert not ('sapling' in result), "duplicate sapling item detected"
            result['sapling'] = item

        elif item_type == ORCHARD_ITEM:
            assert not ('orchard' in result), "duplicate orchard item detected"
            result['orchard'] = item

        else:
            assert not ('unknown' in result), "duplicate unknown item detected"
            result['unknown'] = (item_type, item)

        assert item_type > prev_type, "items out of order: typecodes %r and %r" % (prev_type, item_type)
        prev_type = item_type

    return result

