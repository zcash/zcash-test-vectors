#!/usr/bin/env python3
import sys; assert sys.version_info[0] >= 3, "Python 3 required."

from pyblake2 import blake2b, blake2s
from orchard_pallas import Fp
from sapling_utils import i2beosp, cldiv
from binascii import hexlify

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

    pass

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

if __name__ == "__main__":
    x = expand_message_xmd(b"nothing", b"dst", 128)
    print(hexlify(x))