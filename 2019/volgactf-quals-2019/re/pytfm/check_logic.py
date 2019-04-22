#!/usr/bin/env python3
# coding=utf-8

from pytfm import transform
from struct import pack, unpack
from cmath import exp, pi

def mytransform(m):
    length = len(m)
    res = [0] * length
    for i in range(length):
        for j in range(length):
            res[i] += m[k] * exp(complex(0, -i*k*2*pi/length))
    return c2b(res)

def c2b(c):
    res = b''
    for i in c:
        res += pack('2d', i.real, i.imag)
    return res

test = b'abcd'
res1 = transform(test)
res2 = mytransform(test)
print(repr(res1))
print(repr(res2))
