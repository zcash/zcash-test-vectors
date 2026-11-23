#!/usr/bin/env python3
import sys; assert sys.version_info[0] >= 3, "Python 3 required."

# PROVISIONAL test vectors for key source 0x02 (viewing key only, no sk) of the FROST member
# backup string, version 2, as proposed in zcash/zips#1413 (Khadim's comment of 2026-11-18,
# revised in their comments of 2026-11-20 and 2026-11-21; this generator follows the 2026-11-21
# text). That payload is a proposal for discussion: it is not part of zcash/zips#1432.
# Regenerate these vectors if the payload changes.
#
# Every value comes from SYNTHETIC 2-of-3 groups made from a fixed, documented seed (see
# `SeededStream`). No real wallet's material is used.
#
# Payload (key source 0x02):
#   version (0x02) || key source (0x02) || network (0x00 Mainnet, 0x01 Testnet) || t || n ||
#   identifier form (0x00 short, 0x01 full) || identifier (1 or 32 bytes) || signing share (32) ||
#   birthday height (u32, little-endian) || ak || nk || rivk (96)
# encoded as Bech32m with the human-readable part "zkfrost" and no length limit: 139 bytes and 237
# characters in the short form, 170 bytes and 286 characters in the full form.
#
# Decoding rejects, in this order (the rule numbers are those of the 2026-11-21 text):
#  1. not valid Bech32m (including mixed case), or more than 4 leftover bits, or any not zero;
#  2. human-readable part, compared without regard to case, not "zkfrost";
#  3. format version not 0x02;
#  4. key source, network or identifier form not a known value;
#  5. payload not exactly the length its key source and identifier form give;
#  6. t < 2 or t > n;
#  7. identifier 0, or (full form) not a canonical Pallas scalar, or an integer from 1 to 255.
# Rules 3 and 4 read only the bytes the payload has: a payload that ends before the version, key
# source, network or identifier form fails rule 5.
#
# Restore (key source 0x02) rejects, in this order:
#  1. the string does not decode;
#  2. its network is not the wallet's;
#  3. the signing share is not a canonical Pallas scalar;
#  4. ak || nk || rivk is not a valid Orchard full viewing key (ak a non-identity point with sign
#     bit 0, nk and rivk canonical, the incoming viewing key non-zero in both scopes);
#  5. (SHOULD, when the group's verifying shares are known) the member's verifying share differs.

from hashlib import blake2b
import struct

from .bech32m import bech32_polymod, bech32_hrp_expand, convertbits
from .orchard.commitments import commit_ivk
from .orchard.generators import SPENDING_KEY_BASE
from .orchard.key_components import SpendingKey
from .orchard.pallas import Fp, Scalar, Point, p as P_MODULUS, q as Q_MODULUS
from .orchard.utils import to_scalar
from .output import render_args, render_tv
from .sapling.key_components import prf_expand
from .unified_encoding import encode_unified, ORCHARD_ITEM
from .utils import i2leosp, leos2ip

SOURCE_PATH = 'zcash_test_vectors/frost_member_backup_v2_ks02'

HRP = "zkfrost"
VERSION_2 = 0x02
KS_ZIP2005 = 0x00
KS_LEGACY = 0x01
KS_VIEWING_KEY_ONLY = 0x02
NET_MAINNET = 0x00
NET_TESTNET = 0x01
# Not a network value since the 2026-11-21 text (ZIPs do not specify regtest). Kept as a name only
# for the vectors that show 0x02 fails rule 4.
NET_FORMER_REGTEST = 0x02
ID_SHORT = 0x00
ID_FULL = 0x01
NETWORK_NAMES = ["mainnet", "testnet"]

# Documented birthday heights with four distinct bytes, so a byte-order mistake shows: the NU7
# activation heights of ZIP 259.
BIRTHDAY_MAINNET = 3543405
BIRTHDAY_TESTNET = 4465026

# Every random value below is derived from this tag. The date in it is that of the first payload
# text; it was deliberately not changed for the later revisions.
SEED_TAG = "zips#1413 v2 key source 0x02 synthetic 2-of-3 (payload of 2026-11-18)"

Q_LE = i2leosp(256, Q_MODULUS)  # not a canonical scalar encoding
P_LE = i2leosp(256, P_MODULUS)  # not a canonical base field encoding

BECH32M_CONST = 0x2bc830a3
BECH32_CONST = 1
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


#
# Deterministic randomness: the ChaCha20 keystream (64-bit block counter starting at 0, zero
# nonce; the stream of rand_chacha's ChaCha20Rng) keyed with
# BLAKE2b-256(personalization "KonclaveV2Vector", SEED_TAG || "/" || label), read in order.
#

def _chacha20_block(key_words, counter):
    def rotl(v, c):
        return ((v << c) & 0xffffffff) | (v >> (32 - c))

    def qr(s, a, b, c, d):
        s[a] = (s[a] + s[b]) & 0xffffffff; s[d] = rotl(s[d] ^ s[a], 16)
        s[c] = (s[c] + s[d]) & 0xffffffff; s[b] = rotl(s[b] ^ s[c], 12)
        s[a] = (s[a] + s[b]) & 0xffffffff; s[d] = rotl(s[d] ^ s[a], 8)
        s[c] = (s[c] + s[d]) & 0xffffffff; s[b] = rotl(s[b] ^ s[c], 7)

    init = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574] + key_words + [
        counter & 0xffffffff, counter >> 32, 0, 0]
    s = list(init)
    for _ in range(10):
        qr(s, 0, 4, 8, 12); qr(s, 1, 5, 9, 13); qr(s, 2, 6, 10, 14); qr(s, 3, 7, 11, 15)
        qr(s, 0, 5, 10, 15); qr(s, 1, 6, 11, 12); qr(s, 2, 7, 8, 13); qr(s, 3, 4, 9, 14)
    return struct.pack('<16I', *[(x + y) & 0xffffffff for (x, y) in zip(s, init)])


class SeededStream(object):
    def __init__(self, label):
        seed = blake2b(
            (SEED_TAG + "/" + label).encode(), digest_size=32, person=b'KonclaveV2Vector'
        ).digest()
        self.key_words = list(struct.unpack('<8I', seed))
        self.counter = 0
        self.buf = b''

    def b(self, n):
        while len(self.buf) < n:
            self.buf += _chacha20_block(self.key_words, self.counter)
            self.counter += 1
        (out, self.buf) = (self.buf[:n], self.buf[n:])
        return out

    def scalar(self):
        # LEOS2IP_512(64 bytes) mod q
        return to_scalar(self.b(64))


#
# Bech32m, with this payload's rules: no length limit, and ZIP 173's padding rule.
#

def encode_5bit(hrp, data5, constant):
    values = bech32_hrp_expand(hrp) + list(data5) + [0] * 6
    pm = bech32_polymod(values) ^ constant
    return hrp + '1' + ''.join(CHARSET[d] for d in data5) + \
        ''.join(CHARSET[(pm >> (5 * (5 - i))) & 31] for i in range(6))

def to_5bit(data):
    return convertbits(data, 8, 5, True)

def encode(payload, hrp=HRP):
    return encode_5bit(hrp, to_5bit(payload), BECH32M_CONST)

def bech32m_decode(s):
    if any(c.islower() for c in s) and any(c.isupper() for c in s):
        return None
    s = s.lower()
    pos = s.rfind('1')
    if pos < 1 or pos + 7 > len(s) or any(ord(c) < 33 or ord(c) > 126 for c in s):
        return None
    hrp = s[:pos]
    if any(c not in CHARSET for c in s[pos+1:]):
        return None
    data = [CHARSET.find(c) for c in s[pos+1:]]
    if bech32_polymod(bech32_hrp_expand(hrp) + data) != BECH32M_CONST:
        return None
    return (hrp, data[:-6])

def from_5bit_strict(data5):
    (acc, bits, out) = (0, 0, [])
    for v in data5:
        acc = ((acc << 5) | v) & 0xfff
        bits += 5
        if bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xff)
    if bits > 4 or (acc & ((1 << bits) - 1)) != 0:
        return None
    return bytes(out)

def leftover_bits(length):
    chars = (length * 8 + 4) // 5
    return chars * 5 - length * 8


#
# The payload
#

class Payload(object):
    def __init__(self, key_source, network, t, n, id_form, ident, share, birthday, sk, key):
        (self.key_source, self.network, self.t, self.n, self.id_form, self.ident, self.share,
         self.birthday, self.sk, self.key) = (
            key_source, network, t, n, id_form, ident, share, birthday, sk, key)

    def copy(self, **changes):
        fields = dict(self.__dict__)
        fields.update(changes)
        return Payload(**fields)

    def __bytes__(self):
        return b''.join([
            bytes([VERSION_2, self.key_source, self.network, self.t, self.n, self.id_form]),
            self.ident,
            self.share,
            struct.pack('<I', self.birthday),
            self.sk if self.sk is not None else b'',
            self.key,
        ])

def expected_len(key_source, id_form):
    id_len = {ID_SHORT: 1, ID_FULL: 32}.get(id_form)
    tail = {KS_ZIP2005: 64, KS_LEGACY: 64, KS_VIEWING_KEY_ONLY: 96}.get(key_source)
    if id_len is None or tail is None:
        return None
    return 6 + id_len + 32 + 4 + tail

def is_canonical_scalar(b):
    return leos2ip(b) < Q_MODULUS

def decode(s):
    """Returns (Payload, None), or (None, rule) for the first rule that rejects."""
    d = bech32m_decode(s)
    if d is None:
        return (None, 1)
    (hrp, data5) = d
    p = from_5bit_strict(data5)
    if p is None:
        return (None, 1)
    if hrp != HRP:
        return (None, 2)
    if len(p) > 0 and p[0] != VERSION_2:
        return (None, 3)
    if len(p) > 1 and p[1] not in (KS_ZIP2005, KS_LEGACY, KS_VIEWING_KEY_ONLY):
        return (None, 4)
    if len(p) > 2 and p[2] not in (NET_MAINNET, NET_TESTNET):
        return (None, 4)
    if len(p) > 5 and p[5] not in (ID_SHORT, ID_FULL):
        return (None, 4)
    if len(p) < 6 or len(p) != expected_len(p[1], p[5]):
        return (None, 5)
    (ks, net, t, n, form) = (p[1], p[2], p[3], p[4], p[5])
    if t < 2 or t > n:
        return (None, 6)
    id_len = 1 if form == ID_SHORT else 32
    ident = p[6:6+id_len]
    if form == ID_SHORT:
        if ident[0] == 0:
            return (None, 7)
    else:
        if not is_canonical_scalar(ident):
            return (None, 7)
        if leos2ip(ident) < 256:  # zero, or an integer the short form holds
            return (None, 7)
    o = 6 + id_len
    share = p[o:o+32]; o += 32
    birthday = struct.unpack('<I', p[o:o+4])[0]; o += 4
    sk = None
    if ks != KS_VIEWING_KEY_ONLY:
        sk = p[o:o+32]; o += 32
    return (Payload(ks, net, t, n, form, ident, share, birthday, sk, p[o:]), None)

def spend_validating_key(ak):
    """ak as Orchard accepts it: a non-identity Pallas point encoding with sign bit 0."""
    if ak[31] & 0x80 != 0:
        return None
    P = Point.from_bytes(ak)
    if P is None or P == Point.identity():
        return None
    return P

def full_viewing_key_valid(fvk):
    if spend_validating_key(fvk[:32]) is None:
        return False
    if leos2ip(fvk[32:64]) >= P_MODULUS or leos2ip(fvk[64:]) >= Q_MODULUS:
        return False
    (ak, nk) = (Fp(leos2ip(fvk[:32])), Fp(leos2ip(fvk[32:64])))
    # The incoming viewing key must be non-zero in both scopes, as orchard's
    # FullViewingKey::from_bytes requires: external (rivk) and internal (rivk_internal).
    rivk_internal = to_scalar(prf_expand(fvk[64:], b'\x83' + fvk[:64]))
    for rivk in (Scalar(leos2ip(fvk[64:])), rivk_internal):
        ivk = commit_ivk(rivk, ak, nk)
        if ivk is None or ivk == Fp.ZERO:
            return False
    return True

def public_of(x):
    return bytes(SPENDING_KEY_BASE * x)

def restore(s, wallet_net, known_vs):
    """Returns (Payload, fvk bytes, None), or (None, None, step) for the first step that rejects."""
    (p, _) = decode(s)
    if p is None:
        return (None, None, 1)
    if p.network != wallet_net:
        return (None, None, 2)
    if p.key_source != KS_VIEWING_KEY_ONLY or not is_canonical_scalar(p.share):
        return (None, None, 3)
    if not full_viewing_key_valid(p.key):
        return (None, None, 4)
    if known_vs is not None and public_of(Scalar(leos2ip(p.share))) != known_vs:
        return (None, None, 5)
    return (p, p.key, None)


#
# The synthetic groups: A (short identifiers 1, 2, 3) and B (identifiers derived as frost-core's
# Identifier::derive does for FROST(Pallas, BLAKE2b-512), from fixed labels). Both are 2-of-3.
# If the group key's encoding has its sign bit set, the group key and every share are negated
# (reddsa's EvenY rule). The viewing key is made as zcash-sign's `generate` makes it: a seeded
# sk, nk and rivk from it by the Orchard derivation, and the group key as ak; sk is then dropped.
#

def derive_identifier(label):
    # HID(m) = BLAKE2b-512(personalization "FROST_RedPallasI", m) mod q
    return to_scalar(blake2b(label, digest_size=64, person=b'FROST_RedPallasI').digest())

def draw_sk(label):
    stream = SeededStream(label)
    while True:
        b = stream.b(32)
        try:
            return SpendingKey(b)
        except ValueError:
            pass

class Member(object):
    pass

class Group(object):
    def __init__(self, name, full_ids):
        (self.name, self.t, self.n) = (name, 2, 3)
        stream = SeededStream(name + "/polynomial")
        a0 = stream.scalar()
        a1 = stream.scalar()
        assert a0 != Scalar.ZERO

        if public_of(a0)[31] & 0x80 != 0:
            (a0, a1) = (-a0, -a1)
        self.ak = public_of(a0)
        assert self.ak[31] & 0x80 == 0

        self.members = []
        for k in range(1, self.n + 1):
            m = Member()
            if full_ids:
                x = derive_identifier(("%s/%s/identifier/%d" % (SEED_TAG, name, k)).encode())
                m.id_form = ID_FULL
                m.id_payload = bytes(x)
            else:
                x = Scalar(k)
                m.id_form = ID_SHORT
                m.id_payload = bytes([k])
            m.id_scalar = bytes(x)
            s = a0 + a1 * x
            m.share = bytes(s)
            m.verifying_share = public_of(s)
            self.members.append(m)

        sk = draw_sk(name + "/sk")
        self.nk = bytes(sk.nk)
        self.rivk = bytes(sk.rivk)
        self.fvk = self.ak + self.nk + self.rivk
        assert full_viewing_key_valid(self.fvk)

        # Any two shares interpolate to the secret whose public key is ak.
        for i in range(self.n):
            for j in range(i + 1, self.n):
                (mi, mj) = (self.members[i], self.members[j])
                (xi, xj) = (Scalar(leos2ip(mi.id_scalar)), Scalar(leos2ip(mj.id_scalar)))
                secret = Scalar(leos2ip(mi.share)) * xj / (xj - xi) + \
                    Scalar(leos2ip(mj.share)) * xi / (xi - xj)
                assert public_of(secret) == self.ak

def member_payload(g, m, net, birthday):
    return Payload(KS_VIEWING_KEY_ONLY, net, g.t, g.n, m.id_form, m.id_payload, m.share,
                   birthday, None, g.fvk)

def ufvk(fvk, net):
    return encode_unified([(ORCHARD_ITEM, fvk)], "uview" if net == NET_MAINNET else "uviewtest")

def groups():
    return (Group("A", False), Group("B", True))


#
# Valid vectors
#

def main():
    args = render_args()
    (a, b) = groups()

    test_vectors = []
    for (g, net, birthday) in [
        (a, NET_TESTNET, BIRTHDAY_TESTNET),
        (a, NET_MAINNET, BIRTHDAY_MAINNET),
        (b, NET_TESTNET, BIRTHDAY_TESTNET),
    ]:
        for m in g.members:
            payload = bytes(member_payload(g, m, net, birthday))
            s = encode(payload)
            assert (len(payload), len(s)) == ((139, 237) if m.id_form == ID_SHORT else (170, 286))
            (d, _) = decode(s)
            assert d is not None and bytes(d) == payload
            (_, fvk, step) = restore(s, net, m.verifying_share)
            assert step is None and fvk == g.fvk
            test_vectors.append({
                'key_source': '0x%02x' % KS_VIEWING_KEY_ONLY,
                'network': NETWORK_NAMES[net],
                't': g.t,
                'n': g.n,
                'identifier_form': m.id_form,
                'identifier': m.id_payload,
                'identifier_scalar': m.id_scalar,
                'signing_share': m.share,
                'verifying_share': m.verifying_share,
                'ak': g.ak,
                'nk': g.nk,
                'rivk': g.rivk,
                'birthday_height': birthday,
                'payload': payload,
                'encoding': s,
                'payload_length': len(payload),
                'encoding_length': len(s),
                'leftover_bits': leftover_bits(len(payload)),
                'ufvk': ufvk(g.fvk, net),
            })

    render_tv(
        args,
        SOURCE_PATH,
        (
            ('key_source',        {'rust_type': '&\'static str'}),
            ('network',           {'rust_type': '&\'static str'}),
            ('t',                 {'rust_type': 'u8'}),
            ('n',                 {'rust_type': 'u8'}),
            ('identifier_form',   {'rust_type': 'u8'}),
            ('identifier',        {'rust_type': '&\'static [u8]', 'bitcoin_flavoured': False}),
            ('identifier_scalar', {'rust_type': '[u8; 32]', 'bitcoin_flavoured': False}),
            ('signing_share',     {'rust_type': '[u8; 32]', 'bitcoin_flavoured': False}),
            ('verifying_share',   {'rust_type': '[u8; 32]', 'bitcoin_flavoured': False}),
            ('ak',                {'rust_type': '[u8; 32]', 'bitcoin_flavoured': False}),
            ('nk',                {'rust_type': '[u8; 32]', 'bitcoin_flavoured': False}),
            ('rivk',              {'rust_type': '[u8; 32]', 'bitcoin_flavoured': False}),
            ('birthday_height',   {'rust_type': 'u32'}),
            ('payload',           {'rust_type': '&\'static [u8]', 'bitcoin_flavoured': False}),
            ('encoding',          {'rust_type': '&\'static str'}),
            ('payload_length',    {'rust_type': 'usize'}),
            ('encoding_length',   {'rust_type': 'usize'}),
            ('leftover_bits',     {'rust_type': 'usize'}),
            ('ufvk',              {'rust_type': '&\'static str'}),
        ),
        test_vectors,
    )


#
# Decoding vectors
#

def decoding():
    args = render_args()
    (a, b) = groups()

    base = member_payload(a, a.members[0], NET_TESTNET, BIRTHDAY_TESTNET)
    base_bytes = bytes(base)
    base_s = encode(base_bytes)
    b1 = member_payload(b, b.members[0], NET_TESTNET, BIRTHDAY_TESTNET)
    b1_bytes = bytes(b1)
    b1_s = encode(b1_bytes)

    def with_(**changes):
        return bytes(base.copy(**changes))

    def set_bytes(changes, data=base_bytes):
        d = bytearray(data)
        for (i, v) in changes:
            d[i] = v
        return bytes(d)

    def full_id(ident):
        return bytes(b1.copy(ident=ident))

    def int_id(v):
        return i2leosp(256, v)

    def flip_last(s):
        return s[:-1] + ('p' if s[-1] == 'q' else 'q')

    data5 = to_5bit(base_bytes)
    nonzero_pad = data5[:-1] + [data5[-1] | 1]  # the short form leaves 3 bits; set the lowest
    extra_char = to_5bit(b1_bytes) + [0]  # the full form leaves 0 bits; one more character leaves 5
    i = len(HRP) + 1 + 10
    mixed_data = base_s[:i] + base_s[i].upper() + base_s[i+1:]
    if mixed_data == base_s:
        mixed_data = base_s[:i+1] + base_s[i+1].upper() + base_s[i+2:]

    neg_one_scalar = bytes(Scalar.MINUS_ONE)  # q - 1, the largest canonical scalar
    ver3 = set_bytes([(0, 0x03)])
    v1_shaped = bytes([0x01]) + base_bytes[1:68]
    ks3 = set_bytes([(1, 0x03)])

    def rej(s, rule, why):
        return (s, None, rule, "rule %d: %s" % (rule, why))

    def ok(payload, why, s=None):
        return (encode(payload) if s is None else s, payload, None, why)

    cases = [
        # strings that decode
        ok(base_bytes, "valid, lowercase (group A member 1, Testnet)", base_s),
        ok(base_bytes, "valid, uppercase", base_s.upper()),
        ok(b1_bytes, "valid, full identifier (group B member 1, Testnet)", b1_s),
        ok(with_(birthday=0), "valid, birthday height 0 (unknown)"),
        ok(with_(ident=bytes([4])), "decodes: identifier 4 greater than n = 3 is not checked in version 2"),
        ok(with_(ident=bytes([255])), "decodes: short identifier 255, the largest the short form holds"),
        ok(full_id(int_id(256)), "decodes: full identifier 256, the smallest integer the short form cannot hold"),
        ok(full_id(neg_one_scalar), "decodes: full identifier q - 1, the largest canonical scalar"),
        # rule 1: Bech32m validity (case, checksum), leftover bits
        rej(flip_last(base_s), 1, "invalid checksum"),
        rej(encode_5bit(HRP, data5, BECH32_CONST), 1, "Bech32 checksum instead of Bech32m"),
        rej(HRP.upper() + base_s[len(HRP):], 1, "mixed case (upper-case prefix, lower-case rest)"),
        rej(mixed_data, 1, "mixed case in the data part"),
        rej(encode_5bit(HRP, nonzero_pad, BECH32M_CONST), 1, "non-zero padding bit (short form, 3 leftover bits)"),
        rej(encode_5bit(HRP, extra_char, BECH32M_CONST), 1, "more than 4 padding bits (full form plus one character, 5 leftover bits)"),
        rej(encode_5bit("zkfros", nonzero_pad, BECH32M_CONST), 1, "two rules: non-zero padding bit AND wrong prefix `zkfros`; the padding is first in order"),
        rej(flip_last(encode(base_bytes, "zkfros")), 1, "two rules: invalid checksum AND wrong prefix `zkfros`; the checksum is first in order"),
        # rule 2: human-readable part
        rej(encode(base_bytes, "zkfros"), 2, "prefix `zkfros` instead of `zkfrost`"),
        rej(encode(base_bytes, "zkfrostx"), 2, "prefix `zkfrostx`"),
        rej(encode(ver3, "zkfros"), 2, "two rules: wrong prefix AND version 3; the prefix is first in order"),
        # rule 3: format version
        rej(encode(set_bytes([(0, 0x01)])), 3, "version byte 0x01 on a version 2 payload; version 1's checks also reject it, for its length (139 bytes, not 68)"),
        rej(encode(v1_shaped), 3, "a 68-byte payload starting 0x01: the version is checked before the length; version 1's checks also reject it, for t < 2 (member 2, threshold 1 of 2)"),
        rej(encode(ver3), 3, "version 3"),
        rej(encode(set_bytes([(0, 0x03), (1, 0x03)])[:138]), 3, "three rules: version 3, key source 0x03 AND a 138-byte payload; the version is first in order"),
        # rule 4: key source, network or identifier form unknown
        rej(encode(ks3), 4, "key source 0x03"),
        rej(encode(with_(network=NET_FORMER_REGTEST)), 4, "network byte 0x02: only 0x00 Mainnet and 0x01 Testnet are values (no Regtest value)"),
        rej(encode(set_bytes([(2, 0x03)])), 4, "network 0x03"),
        rej(encode(set_bytes([(5, 0x02)])), 4, "identifier form 0x02"),
        rej(encode(ks3[:138]), 4, "two rules: key source 0x03 AND a 138-byte payload; the unknown value is first in order"),
        rej(encode(ks3 + b'\x00'), 4, "two rules: key source 0x03 AND a 140-byte payload (a length no layout has); the unknown value is first in order"),
        rej(encode(set_bytes([(2, 0x03), (3, 1)])), 4, "two rules: network 0x03 AND threshold 1; the unknown value is first in order"),
        rej(encode(set_bytes([(5, 0x02), (6, 0)])), 4, "two rules: identifier form 0x02 AND identifier byte 0; the unknown value is first in order"),
        rej(encode(set_bytes([(1, 0x03), (2, 0x03), (5, 0x02)])), 4, "key source 0x03, network 0x03 and identifier form 0x02 together"),
        rej(encode(bytes([0x02, 0x07])), 4, "payload `02 07`: key source 7 is present and unknown, and wins over the length"),
        # rule 5: exact length
        rej(encode(b''), 5, "empty payload: it ends before the version, so rule 3 has nothing to check"),
        rej(encode(bytes([0x02])), 5, "payload `02` alone: it ends before the key source, so rule 4 has nothing to check"),
        rej(encode(bytes([0x02, 0x02, 0x01])), 5, "payload `02 02 01`: known key source and network, but it ends before the identifier form"),
        rej(encode(with_(sk=bytes([0x5a] * 32))), 5, "key source 0x02 with a 32-byte sk field before the viewing key (171 bytes)"),
        rej(encode(with_(key=a.ak)), 5, "key source 0x02 with a 32-byte ak instead of the 96-byte viewing key (75 bytes)"),
        rej(encode(set_bytes([(1, KS_LEGACY)])), 5, "key source 0x01 on a 139-byte payload with no sk"),
        rej(encode(set_bytes([(1, KS_ZIP2005)])), 5, "key source 0x00 on a 139-byte payload with no sk"),
        rej(encode(base_bytes[:138]), 5, "payload of 138 bytes for key source 0x02, short form"),
        rej(encode(base_bytes + b'\x00'), 5, "payload of 140 bytes for key source 0x02, short form"),
        rej(encode(set_bytes([(3, 1)], base_bytes[:138])), 5, "two rules: 138 bytes AND threshold 1; the length is first in order"),
        rej(encode(set_bytes([(6, 0)], base_bytes[:138])), 5, "two rules: 138 bytes AND identifier 0; the length is first in order"),
        # rule 6: threshold and group size
        rej(encode(with_(t=1)), 6, "threshold 1"),
        rej(encode(with_(t=0)), 6, "threshold 0"),
        rej(encode(with_(t=4)), 6, "threshold 4 greater than n = 3"),
        rej(encode(with_(n=0)), 6, "group size 0"),
        rej(encode(set_bytes([(3, 1), (6, 0)])), 6, "two rules: threshold 1 AND short identifier 0; the threshold is first in order"),
        rej(encode(bytes(b1.copy(t=4, ident=Q_LE))), 6, "two rules: threshold 4 > n = 3 AND a non-canonical full identifier; the threshold is first in order"),
        # rule 7: identifier
        rej(encode(with_(ident=bytes([0]))), 7, "short identifier 0"),
        rej(encode(full_id(int_id(1))), 7, "full identifier 1, which the short form holds"),
        rej(encode(full_id(int_id(255))), 7, "full identifier 255, which the short form holds"),
        rej(encode(full_id(bytes(32))), 7, "full identifier 0"),
        rej(encode(full_id(Q_LE)), 7, "full identifier equal to the Pallas scalar modulus (non-canonical)"),
        rej(encode(full_id(bytes([0xff] * 32))), 7, "full identifier of 32 bytes 0xff (non-canonical)"),
    ]

    test_vectors = []
    for (s, payload, rule, reason) in cases:
        (d, got) = decode(s)
        if rule is None:
            assert d is not None and bytes(d) == payload, reason
        else:
            assert d is None and got == rule, reason
        test_vectors.append({
            'encoding': s,
            'payload': payload,
            'rule': rule,
            'reason': reason,
        })

    render_tv(
        args,
        SOURCE_PATH,
        (
            ('encoding', {'rust_type': '&\'static str'}),
            ('payload',  {'rust_type': 'Option<&\'static [u8]>', 'bitcoin_flavoured': False}),
            ('rule',     {'rust_type': 'Option<u8>'}),
            ('reason',   {'rust_type': '&\'static str'}),
        ),
        test_vectors,
    )


#
# Restore vectors
#

def find_x_not_on_curve():
    # The first x (counting 2, 3, ...) with no point (x, y) on Pallas, so ak = x fails to decompress.
    x = 2
    while True:
        xf = Fp(x)
        if (xf * xf * xf + Fp(5)).sqrt() is None:
            return bytes(xf)
        x += 1

def restore_vectors():
    args = render_args()
    (a, b) = groups()

    m1 = a.members[0]
    base = member_payload(a, m1, NET_TESTNET, BIRTHDAY_TESTNET)
    base_bytes = bytes(base)
    base_s = encode(base_bytes)
    b1_s = encode(bytes(member_payload(b, b.members[0], NET_TESTNET, BIRTHDAY_TESTNET)))
    mainnet_s = encode(bytes(member_payload(a, m1, NET_MAINNET, BIRTHDAY_MAINNET)))
    net2_s = encode(bytes(base.copy(network=NET_FORMER_REGTEST)))

    def with_(**changes):
        return encode(bytes(base.copy(**changes)))

    def fvk_with(start, value, **changes):
        k = a.fvk[:start] + value + a.fvk[start + len(value):]
        return with_(key=k, **changes)

    ak_odd = a.ak[:31] + bytes([a.ak[31] | 0x80])
    neg_share = bytes(-Scalar(leos2ip(m1.share)))
    vs1 = m1.verifying_share
    vs2 = a.members[1].verifying_share
    (main_net, test_net) = (NET_MAINNET, NET_TESTNET)

    def rok(s, net, vs, why):
        return (s, net, vs, None, why)

    def rrej(s, net, vs, step, why):
        return (s, net, vs, step, "step %d: %s" % (step, why))

    cases = [
        # strings the restore accepts
        rok(base_s, test_net, vs1, "valid, Testnet string on a Testnet wallet, the wallet knows the member's verifying share"),
        rok(base_s, test_net, None, "valid, verifying shares not known"),
        rok(b1_s, test_net, b.members[0].verifying_share, "valid, full identifier"),
        rok(mainnet_s, main_net, vs1, "valid, Mainnet string on a Mainnet wallet"),
        rok(with_(share=neg_share), test_net, None, "signing share with the wrong sign, verifying share not known: passes the restore, fails at first signing"),
        # step 1: decode
        rrej(encode(base_bytes[:138]), test_net, None, 1, "the string does not decode (138-byte payload, decoding rule 5)"),
        rrej(net2_s, test_net, None, 1, "the string does not decode (network byte 0x02, decoding rule 4): no wallet restores it"),
        # step 2: network mismatch
        rrej(mainnet_s, test_net, None, 2, "Mainnet string, Testnet wallet"),
        rrej(base_s, main_net, None, 2, "Testnet string, Mainnet wallet"),
        rrej(with_(network=NET_MAINNET, share=Q_LE), test_net, None, 2, "two steps: Mainnet string on a Testnet wallet AND a non-canonical signing share; the network is first"),
        rrej(fvk_with(0, bytes(32), network=NET_MAINNET), test_net, None, 2, "two steps: Mainnet string on a Testnet wallet AND a viewing key whose ak is all zero; the network is first"),
        # step 3: canonical signing share
        rrej(with_(share=Q_LE), test_net, None, 3, "non-canonical signing share (the Pallas scalar modulus)"),
        rrej(fvk_with(0, bytes(32), share=Q_LE), test_net, None, 3, "two steps: a non-canonical signing share AND a viewing key whose ak is all zero; the share is first"),
        # step 4: viewing key valid
        rrej(fvk_with(0, ak_odd), test_net, None, 4, "viewing key whose ak has the sign bit set (the raw odd-y group key)"),
        rrej(fvk_with(0, bytes(32)), test_net, None, 4, "viewing key whose ak is all zero (the identity)"),
        rrej(fvk_with(0, find_x_not_on_curve()), test_net, None, 4, "viewing key whose ak is not the x-coordinate of a Pallas point"),
        rrej(fvk_with(32, P_LE), test_net, None, 4, "viewing key whose nk is the Pallas base field modulus (non-canonical)"),
        rrej(fvk_with(64, Q_LE), test_net, None, 4, "viewing key whose rivk is the Pallas scalar modulus (non-canonical)"),
        # step 5: verifying share (a SHOULD, when the group's verifying shares are known)
        rrej(with_(share=neg_share), test_net, vs1, 5, "signing share with the wrong sign, verifying share known"),
        rrej(base_s, test_net, vs2, 5, "member 1's string checked against member 2's verifying share"),
    ]

    test_vectors = []
    for (s, net, vs, step, reason) in cases:
        (_, fvk, got) = restore(s, net, vs)
        assert got == step, reason
        test_vectors.append({
            'encoding': s,
            'wallet_network': NETWORK_NAMES[net],
            'verifying_share': vs,
            'fvk': fvk,
            'step': step,
            'reason': reason,
        })

    render_tv(
        args,
        SOURCE_PATH,
        (
            ('encoding',        {'rust_type': '&\'static str'}),
            ('wallet_network',  {'rust_type': '&\'static str'}),
            ('verifying_share', {'rust_type': 'Option<[u8; 32]>', 'bitcoin_flavoured': False}),
            ('fvk',             {'rust_type': 'Option<[u8; 96]>', 'bitcoin_flavoured': False}),
            ('step',            {'rust_type': 'Option<u8>'}),
            ('reason',          {'rust_type': '&\'static str'}),
        ),
        test_vectors,
    )


if __name__ == '__main__':
    main()
