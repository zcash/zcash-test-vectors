#!/usr/bin/env python3
import sys; assert sys.version_info[0] >= 3, "Python 3 required."

import struct

MAX_COMPACT_SIZE = 0x2000000

def write_compact_size(n, allow_u64=False):
    assert allow_u64 or n <= MAX_COMPACT_SIZE
    if n < 253:
        return struct.pack('B', n)
    elif n <= 0xFFFF:
        return struct.pack('B', 253) + struct.pack('<H', n)
    elif n <= 0xFFFFFFFF:
        return struct.pack('B', 254) + struct.pack('<I', n)
    else:
        return struct.pack('B', 255) + struct.pack('<Q', n)

def parse_compact_size(rest, allow_u64=False):
    (n, rest) = parse_compact_u64(rest)
    assert allow_u64 or n <= MAX_COMPACT_SIZE
    return (n, rest)

def parse_compact_u64(rest):
    assert len(rest) >= 1
    b = rest[0]
    if b < 253:
        return (b, rest[1:])
    elif b == 253:
        assert len(rest) >= 3
        n = struct.unpack('<H', rest[1:3])[0]
        assert n >= 253
        return (n, rest[3:])
    elif b == 254:
        assert len(rest) >= 5
        n = struct.unpack('<I', rest[1:5])[0]
        assert n >= 0x10000
        return (n, rest[5:])
    else:
        assert len(rest) >= 9
        n = struct.unpack('<Q', rest[1:9])[0]
        assert n >= 0x100000000
        return (n, rest[9:])


def assert_parse_fails(encoding, allow_u64):
    try:
        parse_compact_size(encoding, allow_u64)
    except AssertionError:
        pass
    else:
        raise AssertionError("parse_compact_size(%r) failed to raise AssertionError" % (encoding,))

def test_round_trip(n, encoding, allow_u64):
    assert write_compact_size(n, allow_u64) == encoding
    assert parse_compact_size(encoding, allow_u64) == (n, b'')
    assert parse_compact_size(encoding + b'*', allow_u64) == (n, b'*')
    assert_parse_fails(encoding[:-1], allow_u64)

for allow_u64 in (False, True):
    test_round_trip(0, b'\x00', allow_u64)
    test_round_trip(1, b'\x01', allow_u64)
    test_round_trip(252, b'\xFC', allow_u64)
    test_round_trip(253, b'\xFD\xFD\x00', allow_u64)
    test_round_trip(254, b'\xFD\xFE\x00', allow_u64)
    test_round_trip(255, b'\xFD\xFF\x00', allow_u64)
    test_round_trip(256, b'\xFD\x00\x01', allow_u64)
    test_round_trip(0xFFFE, b'\xFD\xFE\xFF', allow_u64)
    test_round_trip(0xFFFF, b'\xFD\xFF\xFF', allow_u64)
    test_round_trip(0x010000, b'\xFE\x00\x00\x01\x00', allow_u64)
    test_round_trip(0x010001, b'\xFE\x01\x00\x01\x00', allow_u64)
    test_round_trip(0x02000000, b'\xFE\x00\x00\x00\x02', allow_u64)

    assert_parse_fails(b'\xFD\xFC\x00', allow_u64)
    assert_parse_fails(b'\xFE\xFF\xFF\x00\x00', allow_u64)
    assert_parse_fails(b'\xFF\xFF\xFF\xFF\xFF\x00\x00\x00\x00', allow_u64)

assert_parse_fails(b'\xFE\x01\x00\x00\x02', False)
assert_parse_fails(b'\xFF\x00\x00\x00\x00\x01\x00\x00\x00', False)
assert_parse_fails(b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF', False)

test_round_trip(0xFFFFFFFE, b'\xFE\xFE\xFF\xFF\xFF', True)
test_round_trip(0xFFFFFFFF, b'\xFE\xFF\xFF\xFF\xFF', True)
test_round_trip(0x0100000000, b'\xFF\x00\x00\x00\x00\x01\x00\x00\x00', True)
test_round_trip(0xFFFFFFFFFFFFFFFF, b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF', True)
