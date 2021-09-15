#!/usr/bin/env python3
import sys; assert sys.version_info[0] >= 3, "Python 3 required."

import struct

def write_compact_size(n):
    if n < 253:
        return struct.pack('B', n)
    elif n <= 0xFFFF:
        return struct.pack('B', 253) + struct.pack('<H', n)
    elif n <= 0xFFFFFFFF:
        return struct.pack('B', 254) + struct.pack('<I', n)
    else:
        return struct.pack('B', 255) + struct.pack('<Q', n)

def parse_compact_size(rest):
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


def assert_parse_fails(encoding):
    try:
        parse_compact_size(encoding)
    except AssertionError:
        pass
    else:
        raise AssertionError("parse_compact_size(%r) failed to raise AssertionError" % (encoding,))

def test_round_trip(n, encoding):
    assert write_compact_size(n) == encoding
    assert parse_compact_size(encoding) == (n, b'')
    assert parse_compact_size(encoding + b'*') == (n, b'*')
    assert_parse_fails(encoding[:-1])

test_round_trip(0, b'\x00')
test_round_trip(1, b'\x01')
test_round_trip(252, b'\xFC')
test_round_trip(253, b'\xFD\xFD\x00')
test_round_trip(254, b'\xFD\xFE\x00')
test_round_trip(255, b'\xFD\xFF\x00')
test_round_trip(256, b'\xFD\x00\x01')
test_round_trip(0xFFFE, b'\xFD\xFE\xFF')
test_round_trip(0xFFFF, b'\xFD\xFF\xFF')
test_round_trip(0x010000, b'\xFE\x00\x00\x01\x00')
test_round_trip(0x010001, b'\xFE\x01\x00\x01\x00')
test_round_trip(0xFFFFFFFE, b'\xFE\xFE\xFF\xFF\xFF')
test_round_trip(0xFFFFFFFF, b'\xFE\xFF\xFF\xFF\xFF')
test_round_trip(0x0100000000, b'\xFF\x00\x00\x00\x00\x01\x00\x00\x00')
test_round_trip(0xFFFFFFFFFFFFFFFF, b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF')

assert_parse_fails(b'\xFD\xFC\x00')
assert_parse_fails(b'\xFE\xFF\xFF\x00\x00')
assert_parse_fails(b'\xFF\xFF\xFF\xFF\xFF\x00\x00\x00\x00')
