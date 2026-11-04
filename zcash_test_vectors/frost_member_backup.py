#!/usr/bin/env python3
import sys; assert sys.version_info[0] >= 3, "Python 3 required."

# Test vectors for FROST member backup strings, as specified in the draft ZIP
# "FROST Member Backup Strings for Shielded Zcash"
# <https://github.com/zcash/zips/pull/1432>.
#
# Three generators share the groups built here:
# - main: one vector per member of each group, with the group's keys under
#   each derivation, the member's backup string and the group's viewing keys;
# - decoding: strings that decode to a payload, and strings that decoders
#   must reject;
# - restore: strings paired with a unified full viewing key, and the
#   derivation the restore finds, or none if it must reject the pair.

from itertools import combinations
from random import Random

from .bech32m import Encoding, bech32_decode, bech32_encode, convertbits
from .blake3 import blake3_derive_key
from .orchard.commitments import commit_ivk
from .orchard.generators import SPENDING_KEY_BASE
from .orchard.key_components import SpendingKey
from .orchard.pallas import Fp, Point, Scalar, q
from .orchard.utils import to_scalar
from .output import render_args, render_tv
from .rand import Rand, randbytes
from .sapling.key_components import prf_expand
from .unified_encoding import ORCHARD_ITEM, SAPLING_ITEM, decode_unified, encode_unified
from .utils import i2leosp

HRP = "zkfrost"
VERSION = 0x01
PAYLOAD_LEN = 68

ZIP_2005 = "zip2005"
LEGACY = "legacy"

#
# ZIP 2005 key derivation (use_qsk = true)
#

def h_qsk(sk):
    return prf_expand(sk, b'\x0C')[:32]

def h_qk(qsk):
    return blake3_derive_key("Zcash ZIP 2005 qk-derivation v1", qsk, 32)

def h_rivk_ext(qk, ak, nk):
    return to_scalar(prf_expand(qk, b'\x0D' + i2leosp(256, ak.s) + i2leosp(256, nk.s)))


class GroupKeys(object):
    """
    The key components of a group's Orchard full viewing key under one of the
    draft's derivations. ak is the group verifying key; it is not derived
    from sk.
    """
    def __init__(self, derivation, sk, ak):
        spending_key = SpendingKey(sk)
        self.derivation = derivation
        self.ak = ak
        self.nk = spending_key.nk
        if derivation == ZIP_2005:
            self.qsk = h_qsk(sk)
            self.qk = h_qk(self.qsk)
            self.rivk = h_rivk_ext(self.qk, ak, self.nk)
        elif derivation == LEGACY:
            self.qsk = None
            self.qk = None
            self.rivk = spending_key.rivk
        else:
            raise ValueError("unknown derivation")
        assert commit_ivk(self.rivk, self.ak, self.nk) is not None

    def fvk_bytes(self):
        return bytes(self.ak) + bytes(self.nk) + bytes(self.rivk)

    def ufvk(self, hrp):
        return encode_unified([(ORCHARD_ITEM, self.fvk_bytes())], hrp)

#
# Key generation with a trusted dealer, with identifiers 1 to n
#

class Group(object):
    def __init__(self, rand, t, n):
        assert 2 <= t <= n <= 255
        self.t = t
        self.n = n

        coefficients = [Scalar.random(rand) for _ in range(t)]
        assert coefficients[0] != Scalar.ZERO
        akP = SPENDING_KEY_BASE * coefficients[0]
        # The encoding of the group verifying key must have a sign bit of 0
        # (the ỹ bit of the protocol specification). When it does not,
        # negate the group key and therefore every share.
        if bytes(akP)[-1] & 0x80 != 0:
            coefficients = [-c for c in coefficients]
            akP = -akP
        assert bytes(akP)[-1] & 0x80 == 0
        self.akP = akP
        self.ak = akP.extract()

        def f(x):
            ret = Scalar.ZERO
            for c in reversed(coefficients):
                ret = ret * x + c
            return ret
        self.shares = {i: f(Scalar(i)) for i in range(1, n + 1)}
        self.verifying_shares = {i: SPENDING_KEY_BASE * s for (i, s) in self.shares.items()}

        # Every t-subset of verifying shares interpolates to the group key.
        for subset in combinations(range(1, n + 1), t):
            acc = Point.identity()
            for i in subset:
                lagrange = Scalar(1)
                for j in subset:
                    if j != i:
                        lagrange = lagrange * Scalar(j) / (Scalar(j) - Scalar(i))
                acc = acc + self.verifying_shares[i] * lagrange
            assert acc == akP

        while True:
            sk = rand.b(32)
            try:
                SpendingKey(sk)
                break
            except ValueError:
                pass
        self.sk = sk

    def payload(self, i):
        return bytes([VERSION, i, self.t, self.n]) + bytes(self.shares[i]) + self.sk

#
# Encoding and decoding
#

def encode_payload(payload, hrp=HRP, spec=Encoding.BECH32M):
    return bech32_encode(hrp, convertbits(payload, 8, 5), spec)

def encode_data(data, hrp=HRP):
    return bech32_encode(hrp, data, Encoding.BECH32M)

def decode(encoding):
    """
    Decodes a member backup string, following the rules in the draft. Returns
    (i, t, n, signing share, sk), or raises ValueError with the rule that
    rejected the string.
    """
    (hrp, data, spec) = bech32_decode(encoding)
    if hrp is None or spec != Encoding.BECH32M:
        raise ValueError("not Bech32m")
    if hrp != HRP:
        raise ValueError("wrong human-readable part")
    payload = convertbits(data, 5, 8, False)
    if payload is None:
        raise ValueError("invalid padding")
    payload = bytes(payload)
    if payload[:1] != bytes([VERSION]):
        raise ValueError("unsupported version")
    if len(payload) != PAYLOAD_LEN:
        raise ValueError("wrong payload length")
    (i, t, n) = (payload[1], payload[2], payload[3])
    if n == 0 or i == 0 or i > n or t < 2 or t > n:
        raise ValueError("invalid identifier, threshold or group size")
    return (i, t, n, payload[4:36], payload[36:68])

def restore_member(encoding, ufvk):
    """
    Restores a member from a backup string and a unified full viewing key, as
    the draft's Restore section does. Returns the derivation the group uses,
    or raises ValueError.
    """
    (_, _, _, share, sk) = decode(encoding)

    hrp = ufvk[:ufvk.rfind('1')]
    if hrp not in ("uview", "uviewtest"):
        raise ValueError("not a unified full viewing key")
    items = decode_unified(ufvk, hrp, {SAPLING_ITEM: 128, ORCHARD_ITEM: 96})
    if 'orchard' not in items:
        raise ValueError("no Orchard component")
    fvk = items['orchard']

    try:
        SpendingKey(sk)
    except ValueError:
        raise ValueError("invalid sk")
    try:
        Scalar.from_bytes(share)
    except ValueError:
        raise ValueError("non-canonical signing share")

    ak = Fp.from_bytes(fvk[:32])
    for derivation in (ZIP_2005, LEGACY):
        if GroupKeys(derivation, sk, ak).fvk_bytes() == fvk:
            return derivation
    raise ValueError("neither derivation matches the viewing key")

#
# The groups
#

def groups():
    rng = Random(0xF2057001)
    rand = Rand(randbytes(rng))
    a = Group(rand, 2, 3)
    b = Group(rand, 2, 3)
    c = Group(rand, 3, 5)
    # A: a ZIP 2005 group. B: a legacy group, and the ZIP 2005 viewing key
    # built from the same sk and ak, under which B's strings also restore.
    # C: a 3-of-5 ZIP 2005 group.
    return (a, b, c, [(a, ZIP_2005), (b, LEGACY), (b, ZIP_2005), (c, ZIP_2005)])

# The Sapling full viewing key of unified_viewing_keys_r2 vector 3, used for a
# viewing key with no Orchard component.
SAPLING_FVK = bytes.fromhex(
    "0fec4a4553bde5638ff97ac262635ddce4fd10e9b9eedb3bf2b60a4cb01730e1"
    "971db5d0921a68a3e4d78379076f47fb26388a874a16c14dd21cacfc0f14475e"
    "4381ed27a5002ea7a9c87339d66ba14675e7f806d9580b2e71c4d166c15243a5"
    "7b2ce29b1c441fb68534de0441e5d75c2da24667372d9ae6db6cf63693f44d86"
)


def main():
    args = render_args()
    (_, _, _, group_keys) = groups()

    test_vectors = []
    for (group, derivation) in group_keys:
        keys = GroupKeys(derivation, group.sk, group.ak)
        ufvk_mainnet = keys.ufvk("uview")
        ufvk_testnet = keys.ufvk("uviewtest")
        for i in range(1, group.n + 1):
            payload = group.payload(i)
            encoding = encode_payload(payload)
            assert decode(encoding) == (i, group.t, group.n, bytes(group.shares[i]), group.sk)
            assert restore_member(encoding, ufvk_mainnet) == derivation
            assert restore_member(encoding, ufvk_testnet) == derivation
            test_vectors.append({
                'derivation': derivation,
                't': group.t,
                'n': group.n,
                'identifier': i,
                'sk': group.sk,
                'ak': bytes(keys.ak),
                'nk': bytes(keys.nk),
                'qsk': keys.qsk,
                'qk': keys.qk,
                'rivk': bytes(keys.rivk),
                'signing_share': bytes(group.shares[i]),
                'verifying_share': bytes(group.verifying_shares[i]),
                'payload': payload,
                'encoding': encoding,
                'ufvk_mainnet': ufvk_mainnet,
                'ufvk_testnet': ufvk_testnet,
            })

    render_tv(
        args,
        'zcash_test_vectors/frost_member_backup',
        (
            ('derivation',      {'rust_type': '&\'static str'}),
            ('t',               'u8'),
            ('n',               'u8'),
            ('identifier',      'u8'),
            ('sk',              {'rust_type': '[u8; 32]', 'bitcoin_flavoured': False}),
            ('ak',              {'rust_type': '[u8; 32]', 'bitcoin_flavoured': False}),
            ('nk',              {'rust_type': '[u8; 32]', 'bitcoin_flavoured': False}),
            ('qsk',             {'rust_type': 'Option<[u8; 32]>', 'bitcoin_flavoured': False}),
            ('qk',              {'rust_type': 'Option<[u8; 32]>', 'bitcoin_flavoured': False}),
            ('rivk',            {'rust_type': '[u8; 32]', 'bitcoin_flavoured': False}),
            ('signing_share',   {'rust_type': '[u8; 32]', 'bitcoin_flavoured': False}),
            ('verifying_share', {'rust_type': '[u8; 32]', 'bitcoin_flavoured': False}),
            ('payload',         {'rust_type': '[u8; 68]', 'bitcoin_flavoured': False}),
            ('encoding',        {'rust_type': '&\'static str'}),
            ('ufvk_mainnet',    {'rust_type': '&\'static str'}),
            ('ufvk_testnet',    {'rust_type': '&\'static str'}),
        ),
        test_vectors,
    )


def decoding():
    args = render_args()
    (a, _, _, _) = groups()

    # Every case starts from member 1 of group A.
    payload = a.payload(1)
    encoding = encode_payload(payload)
    data_start = len(HRP) + 1

    def with_fields(version, i, t, n):
        return bytes([version, i, t, n]) + payload[4:]

    def flip_last_character(s):
        return s[:-1] + ('p' if s[-1] == 'q' else 'q')

    # The bits left over by the conversion to bytes must be at most 4 and all
    # zero (ZIP 173). A 68-byte payload leaves 1 bit, in the last character.
    data = convertbits(payload, 8, 5)
    nonzero_padding = data[:-1] + [data[-1] ^ 1]
    extra_padding = data + [0]

    mixed_case_data = (
        encoding[:data_start + 10]
        + encoding[data_start + 10].upper()
        + encoding[data_start + 11:]
    )
    assert mixed_case_data != encoding

    cases = [
        # (encoding, decoded payload or None, reason, rule that rejects it)
        (encoding, payload, "valid, lowercase", None),
        (encoding.upper(), payload, "valid, uppercase", None),
        (encode_payload(payload, hrp="zkfros"), None,
            "wrong human-readable part", "wrong human-readable part"),
        (flip_last_character(encoding), None, "invalid checksum", "not Bech32m"),
        (encode_payload(payload, spec=Encoding.BECH32), None,
            "Bech32 checksum instead of Bech32m", "not Bech32m"),
        (encoding[:len(HRP)].upper() + encoding[len(HRP):], None,
            "mixed case", "not Bech32m"),
        (mixed_case_data, None, "mixed case in the data part", "not Bech32m"),
        (encode_data(nonzero_padding), None, "non-zero padding bit", "invalid padding"),
        (encode_data(extra_padding), None, "more than 4 padding bits", "invalid padding"),
        (encode_payload(with_fields(0, 1, 2, 3)), None, "version 0", "unsupported version"),
        (encode_payload(with_fields(2, 1, 2, 3)), None, "version 2", "unsupported version"),
        (encode_payload(payload[:67]), None, "payload of 67 bytes", "wrong payload length"),
        (encode_payload(payload + b'\x00'), None, "payload of 69 bytes", "wrong payload length"),
        (encode_payload(with_fields(1, 0, 2, 3)), None,
            "identifier 0", "invalid identifier, threshold or group size"),
        (encode_payload(with_fields(1, 4, 2, 3)), None,
            "identifier greater than n", "invalid identifier, threshold or group size"),
        (encode_payload(with_fields(1, 1, 0, 3)), None,
            "threshold 0", "invalid identifier, threshold or group size"),
        (encode_payload(with_fields(1, 1, 1, 3)), None,
            "threshold 1", "invalid identifier, threshold or group size"),
        (encode_payload(with_fields(1, 1, 4, 3)), None,
            "threshold greater than n", "invalid identifier, threshold or group size"),
        (encode_payload(with_fields(1, 1, 1, 0)), None,
            "group size 0", "invalid identifier, threshold or group size"),
    ]

    test_vectors = []
    for (s, expected, reason, rule) in cases:
        if expected is None:
            try:
                decode(s)
                raise AssertionError("decoded: " + reason)
            except ValueError as e:
                assert str(e) == rule, (reason, str(e))
        else:
            assert decode(s) == (1, a.t, a.n, payload[4:36], payload[36:])
        test_vectors.append({
            'encoding': s,
            'payload': expected,
            'reason': reason,
        })

    render_tv(
        args,
        'zcash_test_vectors/frost_member_backup',
        (
            ('encoding', {'rust_type': '&\'static str'}),
            ('payload',  {'rust_type': 'Option<[u8; 68]>', 'bitcoin_flavoured': False}),
            ('reason',   {'rust_type': '&\'static str'}),
        ),
        test_vectors,
    )


def restore():
    args = render_args()
    (a, b, c, _) = groups()

    def ufvk(group, derivation):
        return GroupKeys(derivation, group.sk, group.ak).ufvk("uview")

    a1 = encode_payload(a.payload(1))
    b1 = encode_payload(b.payload(1))

    # The Pallas scalar modulus, which is not a canonical encoding of a
    # signing share.
    non_canonical = a.payload(1)[:4] + i2leosp(256, q) + a.sk
    sapling_only = encode_unified([(SAPLING_ITEM, SAPLING_FVK)], "uview")

    cases = [
        # (encoding, unified full viewing key, derivation or None, reason, rule)
        (a1, ufvk(a, ZIP_2005), ZIP_2005, "ZIP 2005 group", None),
        (b1, ufvk(b, LEGACY), LEGACY, "legacy group", None),
        (b1, ufvk(b, ZIP_2005), ZIP_2005,
            "legacy group's string with the ZIP 2005 viewing key from the same sk and ak", None),
        (a1, ufvk(c, ZIP_2005), None,
            "viewing key of another group", "neither derivation matches the viewing key"),
        (encode_payload(non_canonical), ufvk(a, ZIP_2005), None,
            "non-canonical signing share (the Pallas scalar modulus)", "non-canonical signing share"),
        (a1, sapling_only, None,
            "viewing key with no Orchard component", "no Orchard component"),
    ]

    test_vectors = []
    for (s, key, expected, reason, rule) in cases:
        if expected is None:
            try:
                restore_member(s, key)
                raise AssertionError("restored: " + reason)
            except ValueError as e:
                assert str(e) == rule, (reason, str(e))
        else:
            assert restore_member(s, key) == expected
        test_vectors.append({
            'encoding': s,
            'ufvk': key,
            'derivation': expected,
            'reason': reason,
        })

    render_tv(
        args,
        'zcash_test_vectors/frost_member_backup',
        (
            ('encoding',   {'rust_type': '&\'static str'}),
            ('ufvk',       {'rust_type': '&\'static str'}),
            ('derivation', {'rust_type': 'Option<&\'static str>'}),
            ('reason',     {'rust_type': '&\'static str'}),
        ),
        test_vectors,
    )


if __name__ == "__main__":
    main()
