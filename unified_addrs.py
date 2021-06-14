#!/usr/bin/env python3
import sys; assert sys.version_info[0] >= 3, "Python 3 required."

import math
import struct

from pyblake2 import blake2b
from bech32m import bech32_encode, bech32_decode, convertbits, Encoding

from tv_output import render_args, render_tv, Some
from tv_rand import Rand
from f4jumble import f4jumble, f4jumble_inv
import sapling_key_components
import orchard_key_components

def encode_unified(receivers):
    orchard_receiver = b""
    if receivers['orchard']:
        orchard_receiver = b"".join([b"\x03", len(receivers['orchard']).to_bytes(1, byteorder='little'), receivers['orchard']])

    sapling_receiver = b""
    if receivers['sapling']:
        sapling_receiver = b"".join([b"\x02", len(receivers['sapling']).to_bytes(1, byteorder='little'), receivers['sapling']])

    t_receiver = b""
    if receivers['transparent']:
        t_receiver = b"".join([b"\x01", len(receivers['transparent']).to_bytes(1, byteorder='little'), receivers['transparent']])

    r_bytes = b"".join([orchard_receiver, sapling_receiver, t_receiver, bytes(16)])
    converted = convertbits(f4jumble(r_bytes), 8, 5)
    return bech32_encode("u", converted, Encoding.BECH32M)

def decode_unified(addr_str):
    (hrp, data, encoding) = bech32_decode(addr_str)
    assert hrp == "u" and encoding == Encoding.BECH32M

    decoded = f4jumble_inv(bytes(convertbits(data, 5, 8, False)))
    suffix = decoded[-16:]
    # check trailing zero bytes
    assert suffix == bytes(16)
    decoded = decoded[:-16]

    s = 0
    acc = []
    result = {}
    for b in decoded:
        if s == 0:
            receiver_type = b
            assert [1, 2, 3].count(b) > 0, "receiver type " + str(b) + " not recognized"
            s = 1
        elif s == 1:
          receiver_len = b
          expected_len == {1: 20, 2: 43, 3: 43}.get(receiver_type)
            if expected_len is not None:
                assert receiver_len == expected_len, "incorrect receiver length"
        elif s == 2:
            if len(acc) < receiver_len:
                acc.append(b)
            
            if len(acc) == receiver_len:
                if receiver_type == 1:
                    assert not ('transparent' in result), "duplicate transparent receiver detected"
                    assert len(acc) == 20
                    result['transparent'] = bytes(acc)
                    acc = []
                    s = 0

                elif receiver_type == 2:
                    assert not ('sapling' in result), "duplicate sapling receiver detected"
                    assert len(acc) == 43
                    result['sapling'] = bytes(acc)
                    acc = []
                    s = 0

                elif receiver_type == 3:
                    assert not ('orchard' in result), "duplicate orchard receiver detected"
                    assert len(acc) == 43
                    result['orchard'] = bytes(acc)
                    acc = []
                    s = 0
    return result


def main():
    args = render_args()

    from random import Random
    rng = Random(0xabad533d)
    def randbytes(l):
        ret = []
        while len(ret) < l:
            ret.append(rng.randrange(0, 256))
        return bytes(ret)
    rand = Rand(randbytes)

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
            orchard_fvk = orchard_key_components.FullViewingKey(orchard_sk)
            orchard_default_d = orchard_fvk.default_d()
            orchard_default_pk_d = orchard_fvk.default_pkd()
            orchard_raw_addr = b"".join([orchard_default_d[:11], bytes(orchard_default_pk_d)[:32]])
        else: 
            orchard_raw_addr = None

        receivers = {
            'orchard': orchard_raw_addr, 
            'sapling': sapling_raw_addr, 
            'transparent': t_addr
        }
        ua = encode_unified(receivers)

        decoded = decode_unified(ua)
        assert decoded.get('orchard') == receivers.get('orchard')
        assert decoded.get('sapling') == receivers.get('sapling')
        assert decoded.get('transparent') == receivers.get('transparent')

        test_vectors.append({
            't_addr_bytes': t_addr,
            'sapling_raw_addr': sapling_raw_addr,
            'orchard_raw_addr': orchard_raw_addr,
            'unified_addr': ua.encode()
        })

    render_tv(
        args,
        'unified_address',
        (
            ('t_addr_bytes', {
                'rust_type': 'Option<[u8; 22]>',
                'rust_fmt': lambda x: None if x is None else Some(x),
            }),
            ('sapling_raw_addr', {
                'rust_type': 'Option<[u8; 22]>',
                'rust_fmt': lambda x: None if x is None else Some(x),
            }),
            ('orchard_raw_addr', {
                'rust_type': 'Option<[u8; 22]>',
                'rust_fmt': lambda x: None if x is None else Some(x),
            }),
            ('unified_addr', 'Vec<u8>')
        ),
        test_vectors,
    )


if __name__ == "__main__":
    main()
