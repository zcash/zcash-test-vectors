#!/usr/bin/env python3
# -*- coding: utf8 -*-
import sys; assert sys.version_info[0] >= 3, "Python 3 required."

from ..sapling.jubjub import FieldElement
from ..utils import leos2ip

p = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001
q = 0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001

pm1d2 = 0x2000000000000000000000000000000011234c7e04a67c8dcc96987680000000
assert (p - 1) // 2 == pm1d2

S = 32
T = 0x40000000000000000000000000000000224698fc094cf91b992d30ed
assert (p - 1) == (1 << S) * T

tm1d2 = 0x2000000000000000000000000000000011234c7e04a67c8dcc969876
assert (T - 1) // 2 == tm1d2

# 5^T (mod p)
ROOT_OF_UNITY = 0x2bce74deac30ebda362120830561f81aea322bf2b7bb7584bdad6fabd87ea32f


#
# Field arithmetic
#

class Fp(FieldElement):
    @staticmethod
    def from_bytes(buf):
        return Fp(leos2ip(buf), strict=True)

    def random(rand):
        while True:
            try:
                return Fp(leos2ip(rand.b(32)), strict=True)
            except ValueError:
                pass

    def __init__(self, s, strict=False):
        FieldElement.__init__(self, Fp, s, p, strict=strict)

    def __str__(self):
        return 'Fp(%s)' % self.s

    def sgn0(self):
        # https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-10#section-4.1
        return (self.s % 2) == 1

    def sqrt(self):
        # Tonelli-Shank's algorithm for p mod 16 = 1
        # https://eprint.iacr.org/2012/685.pdf (page 12, algorithm 5)
        a = self.exp(pm1d2)
        if a == self.ONE:
            # z <- c^t
            c = Fp(ROOT_OF_UNITY)
            # x <- a \omega
            x = self.exp(tm1d2 + 1)
            # b <- x \omega = a \omega^2
            b = self.exp(T)
            y = S

            # 7: while b != 1 do
            while b != self.ONE:
                # 8: Find least integer k >= 0 such that b^(2^k) == 1
                k = 1
                b2k = b * b
                while b2k != self.ONE:
                    b2k = b2k * b2k
                    k += 1
                assert k < y

                # 9:
                # w <- z^(2^(y-k-1))
                for _ in range(0, y - k - 1):
                    c = c * c
                # x <- xw
                x = x * c
                # z <- w^2
                c = c * c
                # b <- bz
                b = b * c
                # y <- k
                y = k
            assert x * x == self
            return x
        elif a == self.MINUS_ONE:
            return None
        return self.ZERO


class Scalar(FieldElement):
    def __init__(self, s, strict=False):
        FieldElement.__init__(self, Scalar, s, q, strict=strict)

    def __str__(self):
        return 'Scalar(%s)' % self.s

    @staticmethod
    def from_bytes(buf):
        return Scalar(leos2ip(buf), strict=True)

    def random(rand):
        while True:
            try:
                return Scalar(leos2ip(rand.b(32)), strict=True)
            except ValueError:
                pass


for F in (Fp, Scalar):
    F.ZERO = F(0)
    F.ONE = F(1)
    F.MINUS_ONE = F(-1)

    assert F.ZERO + F.ZERO == F.ZERO
    assert F.ZERO + F.ONE == F.ONE
    assert F.ONE + F.ZERO == F.ONE
    assert F.ZERO - F.ONE == F.MINUS_ONE
    assert F.ZERO * F.ONE == F.ZERO
    assert F.ONE * F.ZERO == F.ZERO


#
# Point arithmetic
#

PALLAS_B = Fp(5)

class Point(object):
    @staticmethod
    def rand(rand):
        while True:
            data = rand.b(32)
            p = Point.from_bytes(data)
            if p is not None:
                return p

    @staticmethod
    def from_bytes(buf):
        assert len(buf) == 32
        if buf == bytes([0]*32):
            return Point.identity()

        y_sign = buf[31] >> 7
        buf = buf[:31] + bytes([buf[31] & 0b01111111])
        try:
            x = Fp.from_bytes(buf)
        except ValueError:
            return None

        x3 = x * x * x
        y2 = x3 + PALLAS_B

        y = y2.sqrt()
        if y is None:
            return None

        if y.s % 2 != y_sign:
            y = Fp.ZERO - y

        return Point(x, y)

    def __init__(self, x, y, is_identity=False):
        self.x = x
        self.y = y
        self.is_identity = is_identity

        if is_identity:
            assert self.x == Fp.ZERO
            assert self.y == Fp.ZERO
        else:
            assert self.y * self.y == self.x * self.x * self.x + PALLAS_B

    def identity():
        p = Point(Fp.ZERO, Fp.ZERO, True)
        return p

    def __neg__(self):
        if self.is_identity:
            return self
        else:
            return Point(Fp(self.x.s), -Fp(self.y.s))

    def __add__(self, a):
        if self.is_identity:
            return a
        elif a.is_identity:
            return self
        else:
            (x1, y1) = (self.x, self.y)
            (x2, y2) = (a.x, a.y)

            if x1 != x2:
                # <https://core.ac.uk/download/pdf/10898289.pdf> section 4.1
                λ = (y1 - y2) / (x1 - x2)
                x3 = λ*λ - x1 - x2
                y3 = λ*(x1 - x3) - y1
                return Point(x3, y3)
            elif y1 == -y2:
                return Point.identity()
            else:
                return self.double()

    def checked_incomplete_add(self, a):
        assert self != a
        assert self != -a
        assert self != Point.identity()
        assert a != Point.identity()
        return self + a

    def __sub__(self, a):
        return (-a) + self

    def double(self):
        if self.is_identity:
            return self

        # <https://core.ac.uk/download/pdf/10898289.pdf> section 4.1
        λ = (Fp(3) * self.x * self.x) / (self.y + self.y)
        x = λ*λ - self.x - self.x
        y = λ*(self.x - x) - self.y
        return Point(x, y)
    
    def extract(self):
        if self.is_identity:
            return Fp.ZERO
        return self.x

    def __mul__(self, s):
        assert isinstance(s, Scalar)
        s = format(s.s, '0256b')
        ret = self.ZERO
        for c in s:
            ret = ret.double()
            if int(c):
                ret = ret + self
        return ret

    def __bytes__(self):
        if self.is_identity:
            return bytes([0] * 32)

        buf = bytes(self.x)
        if self.y.s % 2 == 1:
            buf = buf[:31] + bytes([buf[31] | (1 << 7)])
        return buf

    def __eq__(self, a):
        if a is None:
            return False
        if not (self.is_identity or a.is_identity):
            return self.x == a.x and self.y == a.y
        else:
            return self.is_identity == a.is_identity

    def __str__(self):
        if self.is_identity:
            return 'Point(identity)'
        else:
            return 'Point(%s, %s)' % (self.x, self.y)


Point.ZERO = Point.identity()
Point.GENERATOR = Point(Fp.MINUS_ONE, Fp(2))

assert Point.ZERO + Point.ZERO == Point.ZERO
assert Point.GENERATOR - Point.GENERATOR == Point.ZERO
assert Point.GENERATOR + Point.GENERATOR + Point.GENERATOR == Point.GENERATOR * Scalar(3)
assert Point.GENERATOR + Point.GENERATOR - Point.GENERATOR == Point.GENERATOR

assert Point.from_bytes(bytes([0]*32)) == Point.ZERO
assert Point.from_bytes(bytes(Point.GENERATOR)) == Point.GENERATOR
