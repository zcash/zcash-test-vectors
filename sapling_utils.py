#!/usr/bin/env python3
import sys; assert sys.version_info[0] >= 3, "Python 3 required."

def cldiv(n, divisor):
    return (n + (divisor - 1)) // divisor

def i2lebsp(l, x):
    return [int(c) for c in format(x, '0%sb' % l)[::-1]]

def leos2ip(S):
    return int.from_bytes(S, byteorder='little')

def beos2ip(S):
    return int.from_bytes(S, byteorder='big')

# This should be equivalent to LEBS2OSP(I2LEBSP(l, x))
def i2leosp(l, x):
    return x.to_bytes(cldiv(l, 8), byteorder='little')

# This should be equivalent to BEBS2OSP(I2BEBSP(l, x))
def i2beosp(l, x):
    return x.to_bytes(cldiv(l, 8), byteorder='big')

def bebs2ip(bits):
    ret = 0
    for b in bits:
        ret = ret * 2
        if b:
            ret += 1
    return ret

def lebs2ip(bits):
    return bebs2ip(bits[::-1])

def i2bebsp(m, x):
    assert 0 <= x and x < (1 << m)
    return [(x >> (m-1-i)) & 1 for i in range(m)]

def lebs2osp(bits):
    l = len(bits)
    bits = bits + [0] * (8 * cldiv(l, 8) - l)
    return bytes([lebs2ip(bits[i:i + 8]) for i in range(0, len(bits), 8)])

def leos2bsp(buf):
    return sum([[(c >> i) & 1 for i in range(8)] for c in buf], [])

def bebs2osp(bits, m=None):
    l = len(bits)
    bits = [0] * (8 * cldiv(l, 8) - l) + bits
    return bytes([bebs2ip(bits[i:i + 8]) for i in range(0, len(bits), 8)])

assert i2leosp(5, 7) == lebs2osp(i2lebsp(5, 7))
assert i2leosp(32, 1234567890) == lebs2osp(i2lebsp(32, 1234567890))

assert i2beosp(5, 7) == bebs2osp(i2bebsp(5, 7))
assert i2beosp(32, 1234567890) == bebs2osp(i2bebsp(32, 1234567890))

assert leos2ip(bytes(range(256))) == lebs2ip(leos2bsp(bytes(range(256))))

assert bebs2ip(i2bebsp(5, 7)) == 7
try:
    i2bebsp(3, 12)
except AssertionError:
    pass
else:
    raise AssertionError("invalid input not caught by i2bebsp")
