#!/usr/bin/env python3

def cldiv(n, divisor):
    return (n + (divisor - 1)) // divisor

def i2lebsp(l, x):
    return [int(c) for c in format(x, '0%sb' % l)[::-1]]

def leos2ip(S):
    return int.from_bytes(S, byteorder='little')

# This should be equivalent to LEBS2OSP(I2LEBSP(l, x))
def i2leosp(l, x):
    return x.to_bytes(cldiv(l, 8), byteorder='little')
