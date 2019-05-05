#!/usr/bin/env python
# coding=utf-8

from struct import pack

mask = (1<<64) - 1
a = 0x3736353433323130
b = 0x6665646362613938
a = 0xA1E8895EB916B732
b = 0x50A2DCC51ED6C4A2
'''
for i in xrange(0x400):
    if a & 1:
        tmp = a
    else:
        tmp = ~a
    b ^= tmp
    a = ~a
    ha = (a & 0x8000000000000000) >> 63
    hb = (b & 0x8000000000000000) >> 63
    a = ((a*2) | hb) & mask
    b = ((b*2) | ha) & mask
    a, b = b, a
    b = (a+b) & mask
    ha = (a & 0x8000000000000000) >> 63
    hb = (b & 0x8000000000000000) >> 63
    a = ((a*2) | hb) & mask
    b = ((b*2) | ha) & mask

print hex(a), hex(b)
'''
for i in xrange(0x400):
    ha = b & 1
    hb = a & 1
    a = (a>>1) | (ha<<63)
    b = (b>>1) | (hb<<63)
    b = (b-a) & mask
    a, b = b, a
    ha = b & 1
    hb = a & 1
    a = (a>>1) | (ha<<63)
    b = (b>>1) | (hb<<63)
    a = (~a) & mask
    if a & 1:
        tmp = a
    else:
        tmp = (~a) & mask
    b ^= tmp
print repr(pack('2Q', a, b))
