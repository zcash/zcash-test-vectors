import os
import struct

def randbytes_inner(rng, l):
    ret = []
    while len(ret) < l:
        ret.append(rng.randrange(0, 256))
    return bytes(ret)

def randbytes(rng):
    return lambda l: randbytes_inner(rng, l)

class Rand(object):
    def __init__(self, random=os.urandom):
        self._random = random

    def b(self, l):
        return self._random(l)

    def v(self, l, f):
        return struct.unpack(f, self.b(l))[0]

    def i8(self):
        return self.v(1, 'b')

    def u8(self):
        return self.v(1, 'B')

    def u32(self):
        return self.v(4, '<I')

    def u64(self):
        return self.v(8, '<Q')

    def bool(self):
        return self.u8() % 2 > 0

    def a(self, vals):
        return vals[self.u8() % len(vals)]
