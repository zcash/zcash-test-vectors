#!/usr/bin/env python3
import sys; assert sys.version_info[0] >= 3, "Python 3 required."

import base58

from ..bech32m import bech32_encode, convertbits, Encoding
from ..output import render_args, render_tv
from .zip_0320 import ADDRESS_CONSTANTS, InvalidEncoding, HrpMismatch, decode

# Strings that a ZIP 320 Consumer configured for `network` MUST reject. Each case fails for exactly one reason.
#
# `direction` is "decode" for a TEX address that the Consumer parses, or "from_transparent" for a transparent address
# that the Consumer converts to a TEX address.

# The validating key hash of the ZIP 320 example (t1VmmGiyjVNeCjxDZzg7vZmd99WyzVby9yC).
PKH = bytes.fromhex("8286bf790866805397e3a947640b77a43f0b43a5")
EXAMPLE_TEX = "tex1s2rt77ggv6q989lr49rkgzmh5slsksa9khdgte"
EXAMPLE_T_ADDR = "t1VmmGiyjVNeCjxDZzg7vZmd99WyzVby9yC"
MAINNET_P2SH_LEAD = bytes([0x1c, 0xbd])
TESTNET_P2SH_LEAD = bytes([0x1c, 0xba])

class NotP2pkh(Exception):
    pass

def tex_from_t_addr(network, t_addr):
    constants = ADDRESS_CONSTANTS[network]
    decoded = base58.b58decode_check(t_addr)  # raises ValueError on a bad checksum
    if len(decoded) != 22 or list(decoded[:2]) != constants["p2pkh_lead"]:
        raise NotP2pkh("not a %s P2PKH address" % network)
    return bech32_encode(constants["tex_hrp"], convertbits(decoded[2:], 8, 5), Encoding.BECH32M)

def tex(hrp, payload, spec=Encoding.BECH32M):
    return bech32_encode(hrp, convertbits(payload, 8, 5), spec)

def main():
    args = render_args()

    decode_cases = [
        ("mainnet", tex("tex", PKH, Encoding.BECH32), "Bech32 checksum; ZIP 320 requires Bech32m"),
        ("mainnet", tex("tex", PKH[:19]), "19-byte payload"),
        ("mainnet", tex("tex", PKH + b"\x00"), "21-byte payload"),
        ("mainnet", tex("tex", bytes(ADDRESS_CONSTANTS["mainnet"]["p2pkh_lead"]) + PKH),
         "22-byte payload: the P2PKH lead bytes were encoded with the validating key hash"),
        ("mainnet", tex("tex", b""), "empty payload"),
        ("mainnet", bech32_encode("tex", convertbits(PKH, 8, 5) + [0], Encoding.BECH32M),
         "excess padding: one more 5-bit group than a 20-byte payload needs (ZIP 173 allows at most 4 padding bits)"),
        ("mainnet", "tex1S2rt77ggv6q989lr49rkgzmh5slsksa9khdgte", "mixed case"),
        ("mainnet", EXAMPLE_TEX[:-1] + "f", "checksum error (last character changed)"),
        ("mainnet", EXAMPLE_TEX[:-1] + "b", "character outside the Bech32 alphabet"),
        ("mainnet", EXAMPLE_TEX[:-1] + "\u0435", "non-ASCII character (Cyrillic small letter ie, which looks like 'e')"),
        ("mainnet", EXAMPLE_TEX.replace("1", "", 1), "no separator"),
        ("mainnet", "tex1qqqqq", "fewer than 6 characters after the separator"),
        ("mainnet", tex("textestnet", PKH), "unknown HRP"),
        ("mainnet", tex("textest", PKH), "Testnet TEX address given to a Mainnet Consumer"),
        ("testnet", EXAMPLE_TEX, "Mainnet TEX address given to a Testnet Consumer"),
        ("mainnet", tex("texregtest", PKH), "Regtest TEX address given to a Mainnet Consumer"),
    ]
    test_vectors = []
    for (network, addr, reason) in decode_cases:
        try:
            decode(ADDRESS_CONSTANTS[network]["tex_hrp"], addr)
            raise AssertionError("decode accepted an invalid case: " + reason)
        except (InvalidEncoding, HrpMismatch):
            pass
        test_vectors.append({'network': network, 'direction': 'decode', 'encoded': addr, 'reason': reason})

    t3 = base58.b58encode_check(MAINNET_P2SH_LEAD + PKH).decode('utf-8')
    tm = base58.b58encode_check(bytes(ADDRESS_CONSTANTS["testnet"]["p2pkh_lead"]) + PKH).decode('utf-8')
    t2 = base58.b58encode_check(TESTNET_P2SH_LEAD + PKH).decode('utf-8')
    unknown = base58.b58encode_check(bytes([0x1c, 0xb9]) + PKH).decode('utf-8')
    t1_bad = EXAMPLE_T_ADDR[:-1] + "D"
    conversion_cases = [
        ("mainnet", t3, "P2SH address: ZIP 320 defines TEX addresses for P2PKH only"),
        ("testnet", t2, "Testnet P2SH address: no TEX form either"),
        ("mainnet", tm, "Testnet P2PKH address given to a Mainnet Consumer"),
        ("mainnet", unknown, "t1-looking address whose prefix (0x1CB9) is not a Zcash transparent prefix"),
        ("mainnet", t1_bad, "Base58Check checksum error"),
    ]
    for (network, addr, reason) in conversion_cases:
        try:
            tex_from_t_addr(network, addr)
            raise AssertionError("conversion accepted an invalid case: " + reason)
        except (NotP2pkh, ValueError):
            pass
        test_vectors.append({'network': network, 'direction': 'from_transparent', 'encoded': addr, 'reason': reason})

    render_tv(
        args,
        'zcash_test_vectors/transparent/zip_0320_invalid',
        (
            ('network',   {'rust_type': '&\'static str'}),
            ('direction', {'rust_type': '&\'static str'}),
            ('encoded',   {'rust_type': '&\'static str'}),
            ('reason',    {'rust_type': '&\'static str'}),
        ),
        test_vectors,
    )


if __name__ == "__main__":
    main()
