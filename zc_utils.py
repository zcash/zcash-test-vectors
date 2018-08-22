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

assert write_compact_size(0) == b'\x00'
assert write_compact_size(1) == b'\x01'
assert write_compact_size(252) == b'\xFC'
assert write_compact_size(253) == b'\xFD\xFD\x00'
assert write_compact_size(254) == b'\xFD\xFE\x00'
assert write_compact_size(255) == b'\xFD\xFF\x00'
assert write_compact_size(256) == b'\xFD\x00\x01'
assert write_compact_size(0xFFFE) == b'\xFD\xFE\xFF'
assert write_compact_size(0xFFFF) == b'\xFD\xFF\xFF'
assert write_compact_size(0x010000) == b'\xFE\x00\x00\x01\x00'
assert write_compact_size(0x010001) == b'\xFE\x01\x00\x01\x00'
assert write_compact_size(0xFFFFFFFE) == b'\xFE\xFE\xFF\xFF\xFF'
assert write_compact_size(0xFFFFFFFF) == b'\xFE\xFF\xFF\xFF\xFF'
assert write_compact_size(0x0100000000) == b'\xFF\x00\x00\x00\x00\x01\x00\x00\x00'
assert write_compact_size(0xFFFFFFFFFFFFFFFF) == b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF'
