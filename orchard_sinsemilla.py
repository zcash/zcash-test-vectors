#!/usr/bin/env python3
import sys; assert sys.version_info[0] >= 3, "Python 3 required."

import math

import orchard_iso_pallas

from pyblake2 import blake2b, blake2s
from orchard_pallas import Fp, p, q, PALLAS_B
from orchard_iso_pallas import PALLAS_ISO_B, PALLAS_ISO_A
from sapling_utils import i2beosp, cldiv, beos2ip, i2leosp, lebs2ip
from binascii import hexlify
from bitstring import BitArray

# https://stackoverflow.com/questions/2612720/how-to-do-bitwise-exclusive-or-of-two-strings-in-python
def sxor(s1,s2):    
    # convert strings to a list of character pair tuples
    # go through each tuple, converting them to ASCII code (ord)
    # perform exclusive or on the ASCII code
    # then convert the result back to ASCII (chr)
    # merge the resulting array of characters as a string
    return bytes([a ^ b for a,b in zip(s1,s2)])

def expand_message_xmd(msg, dst, len_in_bytes):

    b_in_bytes = 64

    ell = cldiv(len_in_bytes, b_in_bytes)
    if ell > 255:
        raise
    dst_prime = dst + i2beosp(8, len(dst))  # check
    r_in_bytes = 64  # check
    z_pad = b"\x00" * r_in_bytes
    l_i_b_str = i2beosp(16, len_in_bytes)
    msg_prime = z_pad + msg + l_i_b_str + i2beosp(8, 0) + dst_prime

    b = []

    b0_ctx = blake2b(digest_size=64, person=i2beosp(128,0))
    b0_ctx.update(msg_prime)
    b.append(b0_ctx.digest())
    assert len(b[0]) == b_in_bytes

    b1_ctx = blake2b(digest_size=64, person=i2beosp(128,0))
    b1_ctx.update(b[0] + i2beosp(8, 1) + dst_prime)
    b.append(b1_ctx.digest())
    assert len(b[1]) == b_in_bytes

    for i in range(2, ell + 1):
        bi_input = b"\x00" * b_in_bytes

        for j in range(0, i):
            bi_input = sxor(bi_input, b[j])

        assert len(bi_input) == b_in_bytes

        bi_input += i2beosp(8, i) + dst_prime

        bi_ctx = blake2b(digest_size=64, person=i2beosp(128,0))
        bi_ctx.update(bi_input)

        b.append(bi_ctx.digest())
        assert len(b[i]) == b_in_bytes

    return b''.join(b)[0:len_in_bytes]


#1. ell = ceil(len_in_bytes / b_in_bytes)
#2. ABORT if ell > 255
#3. DST_prime = DST || I2OSP(len(DST), 1)
#4. Z_pad = I2OSP(0, r_in_bytes)
#5. l_i_b_str = I2OSP(len_in_bytes, 2)
#6. msg_prime = Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime
#7. b_0 = H(msg_prime)
#8. b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
#9. for i in (2, ..., ell):
#10.
#b_i = H(strxor(b_0, b_(i - 1)) || I2OSP(i, 1) || DST_prime)
#11. uniform_bytes = b_1 || ... || b_ell
#12. return substr(uniform_bytes, 0, len_in_bytes)


def hash_to_field(msg, dst):

    k = 256
    count = 2
    m = 1

    L = cldiv(math.ceil(math.log2(p)) + k, 8)
    assert L == 512/8

    len_in_bytes = count * 1 * L
    uniform_bytes = expand_message_xmd(msg, dst, len_in_bytes)


    elements = []

    for i in range(0, count):
        for j in range(0, m):
            elm_offset = L * (j + i * m)
            tv = uniform_bytes[elm_offset:elm_offset+L]
            elements.append(Fp(beos2ip(tv), False))
    
    assert len(elements) == 2

    return elements

#   hash_to_field(msg, count)   Parameters:
#
#   - DST, a domain separation tag (see discussion above).
#   - F, a finite field of characteristic p and order q = p^m.
#   - p, the characteristic of F (see immediately above).
#   - m, the extension degree of F, m >= 1 (see immediately above).
#   - L = ceil((ceil(log2(p)) + k) / 8), where k is the security
#     parameter of the suite (e.g., k = 128).
#   - expand_message, a function that expands a byte string and
#     domain separation tag into a uniformly random byte string
#     (see discussion above).   Inputs:
#   - msg, a byte string containing the message to hash.
#   - count, the number of elements of F to output.   Outputs:
#   - (u_0, ..., u_(count - 1)), a list of field elements.   Steps:
#   1. len_in_bytes = count * m * L
#   2. uniform_bytes = expand_message(msg, DST, len_in_bytes)
#   3. for i in (0, ..., count - 1):
#   4.   for j in (0, ..., m - 1):
#   5.     elm_offset = L * (j + i * m)
#   6.     tv = substr(uniform_bytes, elm_offset, L)
#   7.     e_j = OS2IP(tv) mod p
#   8.   u_i = (e_0, ..., e_(m - 1))
#   9. return (u_0, ..., u_(count - 1))

def map_to_curve_simple_swu(u):

    zero = Fp(0)
    assert zero.inv() == Fp(0)

    A = PALLAS_ISO_A
    B = PALLAS_ISO_B
    Z = Fp(-13, False)
    c1 = -B / A
    c2 = Fp(-1)

    tv1 = Z * u.exp(2)
    tv2 = tv1.exp(2)
    x1 = tv1 + tv2

    x1 = x1.inv()
    e1 = x1 == Fp(0)
    x1 = x1 + Fp(1)

    if e1:
        x1 = c2
    else:
        x1 = x1

    x1 = x1 * c1      # x1 = (-B / A) * (1 + (1 / (Z^2 * u^4 + Z * u^2)))
    gx1 = x1.exp(2)
    gx1 = gx1 + A
    gx1 = gx1 * x1
    gx1 = gx1 + B             # gx1 = g(x1) = x1^3 + A * x1 + B
    x2 = tv1 * x1            # x2 = Z * u^2 * x1
    tv2 = tv1 * tv2
    gx2 = gx1 * tv2           # gx2 = (Z * u^2)^3 * gx1

    e2 = (gx1.sqrt() is not None)

    x = x1 if e2 else x2    # If is_square(gx1), x = x1, else x = x2
    y2 = gx1 if e2 else gx2  # If is_square(gx1), y2 = gx1, else y2 = gx2
    y = y2.sqrt()

    e3 = u.sgn0() == y.sgn0()

    y = y if e3 else -y  #y = CMOV(-y, y, e3)

    return orchard_iso_pallas.Point(x, y)


def group_hash(d, m):
    dst = d + b"-" + b"pallas" + b"_XMD:BLAKE2b_SSWU_RO_"

    elems = hash_to_field(m, dst)
    assert len(elems) == 2

    q = [map_to_curve_simple_swu(elems[0]), map_to_curve_simple_swu(elems[1]) ]

    return (q[0] + q[1]).iso_map()

SINSEMILLA_K = 10

def pad(n, m):
    padding_needed = n * SINSEMILLA_K - m.len
    zeros = BitArray('0b' + ('0' * padding_needed))
    m = m + zeros

    pieces = []
    for i in range(0, n):
        pieces.append(
            lebs2ip(m[i*SINSEMILLA_K:i*(SINSEMILLA_K + 1)])
        )

    return pieces      


# note: m is a bitarray
def sinsemilla_hash_to_point(d, m):

    n = cldiv(m.len, SINSEMILLA_K)
    m = pad(n, m)
    acc = group_hash(b"z.cash:SinsemillaQ", d)

    for m_i in m:
        acc = acc + group_hash(b"z.cash:SinsemillaS", i2leosp(32, m_i)) + acc
    
    return acc

def sinsemilla_hash(d, m):
    return sinsemilla_hash_to_point(d, m).extract()

def sinsemilla_hash_bytes(d, m_bytes):
    # TODO: make sure it's not parsing it as hex
    return sinsemilla_hash(d, BitArray(m_bytes))

if __name__ == "__main__":
    gh = sinsemilla_hash_bytes(b"whatever", b"whatever2")
    print(gh)

    #x = expand_message_xmd(b"nothing", b"dst", 128)
    #y = hash_to_field(b"nothing", b"nothing")
    #print(hexlify(x))
    #print(str(y[0]), str(y[1]))