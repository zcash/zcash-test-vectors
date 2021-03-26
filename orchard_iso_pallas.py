#!/usr/bin/env python3
# -*- coding: utf8 -*-
import sys; assert sys.version_info[0] >= 3, "Python 3 required."

import orchard_pallas
from orchard_pallas import Fp, p, q, Scalar

#from sapling_jubjub import FieldElement
#from sapling_utils import leos2ip

#p = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001
#q = 0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001
#
#pm1d2 = 0x2000000000000000000000000000000011234c7e04a67c8dcc96987680000000
#assert (p - 1) // 2 == pm1d2
#
#S = 32
#T = 0x40000000000000000000000000000000224698fc094cf91b992d30ed
#assert (p - 1) == (1 << S) * T
#
#tm1d2 = 0x2000000000000000000000000000000011234c7e04a67c8dcc969876
#assert (T - 1) // 2 == tm1d2
#
#ROOT_OF_UNITY = 0x2bce74deac30ebda362120830561f81aea322bf2b7bb7584bdad6fabd87ea32f


#
# Field arithmetic
#

#@class Fp(FieldElement):
#@    @staticmethod
#@    def from_bytes(buf):
#@        return Fp(leos2ip(buf), strict=True)
#@
#@    def __init__(self, s, strict=False):
#@        FieldElement.__init__(self, Fp, s, p, strict=strict)
#@
#@    def __str__(self):
#@        return 'Fp(%s)' % self.s
#@
#@    def sqrt(self):
#@        # Tonelli-Shank's algorithm for p mod 16 = 1
#@        # https://eprint.iacr.org/2012/685.pdf (page 12, algorithm 5)
#@        a = self.exp(pm1d2)
#@        if a == self.ONE:
#@            # z <- c^t
#@            c = Fp(ROOT_OF_UNITY)
#@            # x <- a \omega
#@            x = self.exp(tm1d2 + 1)
#@            # b <- x \omega = a \omega^2
#@            b = self.exp(T)
#@            y = S
#@
#@            # 7: while b != 1 do
#@            while b != self.ONE:
#@                # 8: Find least integer k >= 0 such that b^(2^k) == 1
#@                k = 1
#@                b2k = b * b
#@                while b2k != self.ONE:
#@                    b2k = b2k * b2k
#@                    k += 1
#@                assert k < y
#@
#@                # 9:
#@                # w <- z^(2^(y-k-1))
#@                for _ in range(0, y - k - 1):
#@                    c = c * c
#@                # x <- xw
#@                x = x * c
#@                # z <- w^2
#@                c = c * c
#@                # b <- bz
#@                b = b * c
#@                # y <- k
#@                y = k
#@            assert x * x == self
#@            return x
#@        elif a == self.MINUS_ONE:
#@            return None
#@        return self.ZERO


#class Scalar(FieldElement):
#    def __init__(self, s, strict=False):
#        FieldElement.__init__(self, Scalar, s, q, strict=strict)
#
#    def __str__(self):
#        return 'Scalar(%s)' % self.s
#
#Fp.ZERO = Fp(0)
#Fp.ONE = Fp(1)
#Fp.MINUS_ONE = Fp(-1)
#
#assert Fp.ZERO + Fp.ZERO == Fp.ZERO
#assert Fp.ZERO + Fp.ONE == Fp.ONE
#assert Fp.ONE + Fp.ZERO == Fp.ONE
#assert Fp.ZERO - Fp.ONE == Fp.MINUS_ONE
#assert Fp.ZERO * Fp.ONE == Fp.ZERO
#assert Fp.ONE * Fp.ZERO == Fp.ZERO


#
# Point arithmetic
#

PALLAS_ISO_B = Fp(1265)
PALLAS_ISO_A = Fp(0x18354a2eb0ea8c9c49be2d7258370742b74134581a27a59f92bb4b0b657a014b)

class Point(object):
    #@staticmethod
    #def rand(rand):
    #    while True:
    #        data = rand.b(32)
    #        p = Point.from_bytes(data)
    #        if p is not None:
    #            return p

    #@staticmethod
    #def from_bytes(buf):
    #    assert len(buf) == 32
    #    if buf == bytes([0]*32):
    #        return Point.identity()

    #    y_sign = buf[31] >> 7
    #    buf = buf[:31] + bytes([buf[31] & 0b01111111])
    #    try:
    #        x = Fp.from_bytes(buf)
    #    except ValueError:
    #        return None

    #    x3 = x * x * x
    #    y2 = x3 + PALLAS_ISO_B

    #    y = y2.sqrt()
    #    if y is None:
    #        return None

    #    if y.s % 2 != y_sign:
    #        y = Fp.ZERO - y

    #    return Point(x, y)


    # Maps a point on iso-Pallas to a point on Pallas
    def iso_map(self):

        c = [
            None, # make the indices 1-based
            Fp(0x0e38e38e38e38e38e38e38e38e38e38e4081775473d8375b775f6034aaaaaaab),
            Fp(0x3509afd51872d88e267c7ffa51cf412a0f93b82ee4b994958cf863b02814fb76),
            Fp(0x17329b9ec525375398c7d7ac3d98fd13380af066cfeb6d690eb64faef37ea4f7),
            Fp(0x1c71c71c71c71c71c71c71c71c71c71c8102eea8e7b06eb6eebec06955555580),
            Fp(0x1d572e7ddc099cff5a607fcce0494a799c434ac1c96b6980c47f2ab668bcd71f),
            Fp(0x325669becaecd5d11d13bf2a7f22b105b4abf9fb9a1fc81c2aa3af1eae5b6604),
            Fp(0x1a12f684bda12f684bda12f684bda12f7642b01ad461bad25ad985b5e38e38e4),
            Fp(0x1a84d7ea8c396c47133e3ffd28e7a09507c9dc17725cca4ac67c31d8140a7dbb),
            Fp(0x3fb98ff0d2ddcadd303216cce1db9ff11765e924f745937802e2be87d225b234),
            Fp(0x025ed097b425ed097b425ed097b425ed0ac03e8e134eb3e493e53ab371c71c4f),
            Fp(0x0c02c5bcca0e6b7f0790bfb3506defb65941a3a4a97aa1b35a28279b1d1b42ae),
            Fp(0x17033d3c60c68173573b3d7f7d681310d976bbfabbc5661d4d90ab820b12320a),
            Fp(0x40000000000000000000000000000000224698fc094cf91b992d30ecfffffde5)
        ]

        if self == Point.identity():
            return orchard_pallas.identity()
        else:
            numerator_a = c[1] * self.x * self.x * self.x + c[2] * self.x * self.x + c[3] * self.x + c[4]
            denominator_a = self.x * self.x + c[5] * self.x + c[6]

            numerator_b = (c[7] * self.x * self.x * self.x + c[8] * self.x * self.x + c[9] * self.x + c[10]) * self.y
            denominator_b = self.x * self.x * self.x + c[11] * self.x * self.x + c[12] * self.x + c[13]

            return orchard_pallas.Point(numerator_a / denominator_a, numerator_b / denominator_b)

    def __init__(self, x, y):
        self.x = x
        self.y = y
        self.is_identity = False

    def identity():
        p = Point(Fp.ZERO, Fp.ZERO)
        p.is_identity = True
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

            if x1 == x2:
                if (y1 != y2) or (y1 == 0):
                    return Point.identity()
                else:
                    return self.double()
                #if y1 == -y2:
                #    return Point.identity()
                #else:
                #    return self.double()
            else:
                # <https://core.ac.uk/download/pdf/10898289.pdf> section 4.1
                λ = (y1 - y2) / (x1 - x2)
                x3 = λ*λ - x1 - x2
                y3 = λ*(x1 - x3) - y1
                return Point(x3, y3)

    def __sub__(self, a):
        return (-a) + self

    def double(self):
        if self.is_identity:
            return self

        # <https://core.ac.uk/download/pdf/10898289.pdf> section 4.1
        λ = (Fp(3) * self.x * self.x + PALLAS_ISO_A) / (self.y + self.y)
        x3 = λ*λ - self.x - self.x
        y3 = λ*(self.x - x3) - self.y
        return Point(x3, y3)

    def __mul__(self, s):
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

# Point.GENERATOR = Point(Fp.MINUS_ONE, Fp(2))

assert Point.ZERO + Point.ZERO == Point.ZERO
#assert Point.GENERATOR - Point.GENERATOR == Point.ZERO
#assert Point.GENERATOR + Point.GENERATOR + Point.GENERATOR == Point.GENERATOR * Scalar(3)
#assert Point.GENERATOR + Point.GENERATOR - Point.GENERATOR == Point.GENERATOR

#assert Point.from_bytes(bytes([0]*32)) == Point.ZERO
#assert Point.from_bytes(bytes(Point.GENERATOR)) == Point.GENERATOR
