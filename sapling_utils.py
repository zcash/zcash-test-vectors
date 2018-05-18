#!/usr/bin/env python3

def i2lebsp(l, x):
    return [int(c) for c in format(x, '0%sb' % l)[::-1]]
