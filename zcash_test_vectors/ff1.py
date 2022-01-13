#!/usr/bin/env python3
import sys; assert sys.version_info[0] >= 3, "Python 3 required."

import os
from binascii import unhexlify, hexlify

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from .utils import bebs2ip, i2bebsp, beos2ip, bebs2osp, cldiv

# Morris Dworkin
# NIST Special Publication 800-38G
# Recommendation for Block Cipher Modes of Operation: Methods for Format-Preserving Encryption
# <http://dx.doi.org/10.6028/NIST.SP.800-38G>
# specialized to the parameters below and a single-block PRF; unoptimized

radix = 2
minlen = maxlen = 88
maxTlen = 255
assert 2 <= radix and radix < 256
assert radix**minlen >= 100
assert 2 <= minlen and minlen <= maxlen and maxlen < 256

NUM_2 = bebs2ip
STR_2 = i2bebsp


def ff1_aes256_encrypt(key, tweak, x):
    n = len(x)
    t = len(tweak)
    assert minlen <= n and n <= maxlen
    assert t <= maxTlen

    u = n//2; v = n-u
    assert u == v
    A = x[:u]; B = x[u:]
    assert radix == 2
    b = cldiv(v, 8)
    d = 4*cldiv(b, 4) + 4
    assert d <= 16
    P = bytes([1, 2, 1, 0, 0, radix, 10, u % 256, 0, 0, 0, n, 0, 0, 0, t])
    for i in range(10):
        Q = tweak + b'\0'*((-t-b-1) % 16) + bytes([i]) + bebs2osp(B)
        y = beos2ip(aes_cbcmac(key, P + Q)[:d])
        c = (NUM_2(A)+y) % (1<<u)
        C = STR_2(u, c)
        A = B
        B = C
    return A + B

# This is not used except by tests.
def ff1_aes256_decrypt(key, tweak, x):
    n = len(x)
    t = len(tweak)
    assert minlen <= n and n <= maxlen
    assert t <= maxTlen

    u = n//2; v = n-u
    assert u == v
    A = x[:u]; B = x[u:]
    assert radix == 2
    b = cldiv(v, 8)
    d = 4*cldiv(b, 4) + 4
    assert d <= 16
    P = bytes([1, 2, 1, 0, 0, radix, 10, u % 256, 0, 0, 0, n, 0, 0, 0, t])
    for i in range(9, -1, -1):
        Q = tweak + b'\0'*((-t-b-1) % 16) + bytes([i]) + bebs2osp(A)
        y = beos2ip(aes_cbcmac(key, P + Q)[:d])
        c = (NUM_2(B)-y) % (1<<u)
        C = STR_2(u, c)
        B = A
        A = C
    return A + B

def test_ff1():
    # Test vectors consistent with the Java implementation at
    # <https://git.code.sf.net/p/format-preserving-encryption/code>.

    key = unhexlify("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94")

    tweak = b''
    x = [0]*88
    ct = ff1_aes256_encrypt(key, tweak, x)
    assert ''.join(map(str, ct)) == "0000100100110101011101111111110011000001101100111110011101110101011010100100010011001111", ct
    pt = ff1_aes256_decrypt(key, tweak, ct)
    assert pt == x, (ct, pt)

    x = list(map(int, "0000100100110101011101111111110011000001101100111110011101110101011010100100010011001111"))
    ct = ff1_aes256_encrypt(key, tweak, x)
    assert ''.join(map(str, ct)) == "1101101011010001100011110000010011001111110110011101010110100001111001000101011111011000", ct
    pt = ff1_aes256_decrypt(key, tweak, ct)
    assert pt == x, (ct, pt)

    x = [0, 1]*44
    ct = ff1_aes256_encrypt(key, tweak, x)
    assert ''.join(map(str, ct)) == "0000111101000001111011010111011111110001100101000000001101101110100010010111001100100110", ct
    pt = ff1_aes256_decrypt(key, tweak, ct)
    assert pt == x, (ct, pt)

    tweak = bytes(range(maxTlen))
    ct = ff1_aes256_encrypt(key, tweak, x)
    assert ''.join(map(str, ct)) == "0111110110001000000111010110000100010101101000000011100111100100100010101101111010100011", ct
    pt = ff1_aes256_decrypt(key, tweak, ct)
    assert pt == x, (ct, pt)

    key = os.urandom(32)
    tweak = b''
    ct = ff1_aes256_encrypt(key, tweak, x)
    pt = ff1_aes256_decrypt(key, tweak, ct)
    assert pt == x, (ct, pt)

    tweak = os.urandom(maxTlen)
    ct = ff1_aes256_encrypt(key, tweak, x)
    pt = ff1_aes256_decrypt(key, tweak, ct)
    assert pt == x, (ct, pt)


def aes_cbcmac(key, input):
    encryptor = Cipher(algorithms.AES(key), modes.CBC(b'\0'*16), backend=default_backend()).encryptor()
    return (encryptor.update(input) + encryptor.finalize())[-16:]

def test_aes():
    # Check we're actually using AES-256.

    # <https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Block-Ciphers>
    # <https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/aesmct.zip>

    # Simple test (this wouldn't catch a byte order error in the key):
    # ECBVarTxt256.rsp COUNT = 0
    KEY        = unhexlify("0000000000000000000000000000000000000000000000000000000000000000")
    PLAINTEXT  = unhexlify("80000000000000000000000000000000")
    CIPHERTEXT = unhexlify("ddc6bf790c15760d8d9aeb6f9a75fd4e")
    assert aes_cbcmac(KEY, PLAINTEXT) == CIPHERTEXT

    # Now something more rigorous:
    # ECBMCT256.rsp COUNT = 0
    key = unhexlify("f9e8389f5b80712e3886cc1fa2d28a3b8c9cd88a2d4a54c6aa86ce0fef944be0")
    acc = unhexlify("b379777f9050e2a818f2940cbbd9aba4")
    ct  = unhexlify("6893ebaf0a1fccc704326529fdfb60db")
    for i in range(1000):
        acc = aes_cbcmac(key, acc)
    assert acc == ct, hexlify(acc)


if __name__ == '__main__':
    test_aes()
    test_ff1()
