#!/usr/bin/env python3
from binascii import hexlify
from pyblake2 import blake2b, blake2s

ENDIANNESS = 'little'

# First 64 bytes of the BLAKE2s input during group hash.
# This is chosen to be some random string that we couldn't have
# anticipated when we designed the algorithm, for rigidity purposes.
# We deliberately use an ASCII hex string of 32 bytes here.
CRS = b'096b36a5804bfacef1691e173c366a47ff5ba84a44f26ddd7e8d9f79d5b42df0'

q_j = 52435875175126190479447740508185965837690552500527637822603658699938581184513
r_j = 6554484396890773809930967563523245729705921265872317281365359162392183254199

qm1d2 = 26217937587563095239723870254092982918845276250263818911301829349969290592256
assert((q_j - 1) // 2 == qm1d2)

#
# Field arithmetic
#

class FieldElement(object):
    def __init__(self, t, s, modulus):
        self.t = t
        self.s = s % modulus
        self.m = modulus

    def __add__(self, a):
        return self.t(self.s + a.s)

    def __sub__(self, a):
        return self.t(self.s - a.s)

    def __mul__(self, a):
        return self.t(self.s * a.s)

    def __truediv__(self, a):
        assert(a.s != 0)
        return self * a.inv()

    def exp(self, e):
        e = format(e, '0256b')
        ret = self.t(1)
        for c in e:
            ret = ret * ret
            if int(c):
                ret = ret * self
        return ret

    def inv(self):
        return self.exp(self.m - 2)

    def __bytes__(self):
        return self.s.to_bytes(32, byteorder=ENDIANNESS)

    def __eq__(self, a):
        return self.s == a.s



class Fq(FieldElement):
    def from_bytes(buf):
        s = int.from_bytes(buf, byteorder=ENDIANNESS)
        return Fq(s)

    def __init__(self, s):
        FieldElement.__init__(self, Fq, s, q_j)

    def __str__(self):
        return 'Fq(%s)' % self.s

    def sqrt(self):
        # Tonelli-Shank's algorithm for q mod 16 = 1
        # https://eprint.iacr.org/2012/685.pdf (page 12, algorithm 5)
        a = self.exp(qm1d2)
        if a == ONE:
            c = Fq(10238227357739495823651030575849232062558860180284477541189508159991286009131)
            r = self.exp(6104339283789297388802252303364915521546564123189034618274734669824)
            t = self.exp(12208678567578594777604504606729831043093128246378069236549469339647)
            m = 32

            # 7: while b != 1 do
            while t != ONE:
                # 8: Find least integer k >= 0 such that b^(2^k) == 1
                i = 1
                t2i = t * t
                while t2i != ONE:
                    t2i = t2i * t2i
                    i += 1
                assert(i < m)

                # 9:
                # w <- z^(2^(v-k-1))
                for j in range(0, m - i - 1):
                    c = c * c
                # b <- bz
                r = r * c
                # z <- w^2
                c = c * c
                # x <- xw
                t = t * c
                # v <- k
                m = i
            assert(r * r == self)
            return r
        elif a == MINUS_ONE:
            return None
        else:
            return ZERO


class Fr(FieldElement):
    def from_bytes(buf):
        s = int.from_bytes(buf, byteorder=ENDIANNESS)
        return Fr(s)

    def __init__(self, s):
        FieldElement.__init__(self, Fr, s, r_j)

    def __str__(self):
        return 'Fr(%s)' % self.s


#
# Point arithmetic
#

ZERO = Fq(0)
ONE = Fq(1)
MINUS_ONE = Fq(-1)
EIGHT = Fr(8)
JUBJUB_A = MINUS_ONE
JUBJUB_D = Fq(-10240) / Fq(10241)

class Point(object):
    def from_bytes(buf):
        u_sign = buf[31] >> 7
        buf = buf[:31] + bytes([buf[31] & 0b01111111])
        v = Fq.from_bytes(buf)

        vv = v * v
        u2 = (vv - ONE) / (vv * JUBJUB_D - JUBJUB_A)

        u = u2.sqrt()
        if not u:
            return None

        if u.s % 2 != u_sign:
            u = ZERO - u

        return Point(u, v)

    def __init__(self, u, v):
        self.u = u
        self.v = v

    def __add__(self, a):
        (u1, v1) = (self.u, self.v)
        (u2, v2) = (a.u, a.v)
        u3 = (u1*v2 + v1*u2) / (ONE + JUBJUB_D*u1*u2*v1*v2)
        v3 = (v1*v2 - JUBJUB_A*u1*u2) / (ONE - JUBJUB_D*u1*u2*v1*v2)
        return Point(u3, v3)

    def double(self):
        return self + self

    def __mul__(self, s):
        s = format(s.s, '0256b')
        ret = ZERO_POINT
        for c in s:
            ret = ret.double()
            if int(c):
                ret = ret + self
        return ret

    def __bytes__(self):
        buf = bytes(self.v)
        if self.u.s % 2 == 1:
            buf = buf[:31] + bytes([buf[31] | (1 << 7)])
        return buf

    def __eq__(self, a):
        return self.u == a.u and self.v == a.v

    def __str__(self):
        return 'Point(%s, %s)' % (self.u, self.v)


ZERO_POINT = Point(ZERO, ONE)

assert(ZERO_POINT + ZERO_POINT == ZERO_POINT)

#
# PRFs and hashes
#

def prf_expand(sk, t):
    digest = blake2b(person=b'Zcash_ExpandSeed')
    digest.update(sk)
    digest.update(t)
    return digest.digest()

def crh_ivk(ak, nk):
    digest = blake2s(person=b'Zcashivk')
    digest.update(ak)
    digest.update(nk)
    ivk = digest.digest()
    ivk = ivk[:31] + bytes([ivk[31] & 0b00000111])
    return ivk

def group_hash(d, m):
    digest = blake2s(person=d)
    digest.update(CRS)
    digest.update(m)
    p = Point.from_bytes(digest.digest())
    if not p:
        return None
    q = p * EIGHT
    if q == ZERO_POINT:
        return None
    return q

def find_group_hash(d, m):
    i = 0
    while True:
        p = group_hash(d, m + bytes([i]))
        if p:
            return p
        i += 1
        assert(i < 256)


#
# Sapling generators
#

SPENDING_KEY_BASE = find_group_hash(b'Zcash_G_', b'')
PROVING_KEY_BASE = find_group_hash(b'Zcash_H_', b'')


#
# Key components
#

def cached(f):
    def wrapper(self):
        if not hasattr(self, '_cached'):
            self._cached = {}
        if not self._cached.get(f):
            self._cached[f] = f(self)
        return self._cached[f]
    return wrapper

class SpendingKey(object):
    def __init__(self, data):
        self.data = data

    @cached
    def ask(self):
        return Fr.from_bytes(prf_expand(self.data, b'\0'))

    @cached
    def nsk(self):
        return Fr.from_bytes(prf_expand(self.data, b'\1'))

    @cached
    def ovk(self):
        return prf_expand(self.data, b'\2')[:32]

    @cached
    def ak(self):
        return SPENDING_KEY_BASE * self.ask()

    @cached
    def nk(self):
        return PROVING_KEY_BASE * self.nsk()

    @cached
    def ivk(self):
        return Fr.from_bytes(crh_ivk(bytes(self.ak()), bytes(self.nk())))

    @cached
    def default_d(self):
        i = 0
        while True:
            d = prf_expand(self.data, bytes([3, i]))[:11]
            if group_hash(b'Zcash_gd', d):
                return d
            i += 1
            assert(i < 256)

    @cached
    def default_pkd(self):
        return group_hash(b'Zcash_gd', self.default_d()) * self.ivk()


def chunk(h):
    h = str(h, 'utf-8')
    return '0x' + ', 0x'.join([h[i:i+2] for i in range(0, len(h), 2)])

def main():
    print('''
        struct TestVector {
            sk: [u8; 32],
            ask: [u8; 32],
            nsk: [u8; 32],
            ovk: [u8; 32],
            ak: [u8; 32],
            nk: [u8; 32],
            ivk: [u8; 32],
            default_d: [u8; 11],
            default_pk_d: [u8; 32],
        };

        let test_vectors = vec![''')
    for i in range(0, 10):
        sk = SpendingKey(bytes([i] * 32))
        print('''            TestVector {
                sk: [
                    %s
                ],
                ask: [
                    %s
                ],
                nsk: [
                    %s
                ],
                ovk: [
                    %s
                ],
                ak: [
                    %s
                ],
                nk: [
                    %s
                ],
                ivk: [
                    %s
                ],
                default_d: [
                    %s
                ],
                default_pk_d: [
                    %s
                ],
            },''' % (
    chunk(hexlify(sk.data)),
    chunk(hexlify(bytes(sk.ask()))),
    chunk(hexlify(bytes(sk.nsk()))),
    chunk(hexlify(sk.ovk())),
    chunk(hexlify(bytes(sk.ak()))),
    chunk(hexlify(bytes(sk.nk()))),
    chunk(hexlify(bytes(sk.ivk()))),
    chunk(hexlify(sk.default_d())),
    chunk(hexlify(bytes(sk.default_pkd()))),
))
    print('        ];')


if __name__ == '__main__':
    main()

