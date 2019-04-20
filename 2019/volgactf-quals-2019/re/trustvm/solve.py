#!/usr/bin/env python
# coding=utf-8

from struct import unpack

def b2n(b):
    tmp = b[::-1].encode('hex')
    return int(tmp, 16)

def n2b(n):
    res = bytearray()
    for i in xrange(64):
        res.append(n&0xff)
        n >>= 8
    return str(res)

def shr(n, k):
    tmp = '{:0512b}'.format(n)
    tmp = tmp[512-k:]+tmp[:512-k]
    return int(tmp, 2)

f = open('./data.enc', 'rb')
c = f.read()
f.close()

key = 0x5d77702a1df93fd9274b2f9567c39a172c374053280f794474f6eaab10ec319d53046e70a80586f0f15fe2f95ee45c346e9c911af3dcdc089c44150b2ee1a9e1L
m = ''
for i in xrange(0, len(c), 64):
    tmp = b2n(c[i:i+64])
    tmp = shr(tmp, 0x4d)
    tmp ^= key
    m += n2b(tmp)
    key = shr(key, 512-0x6f)
    key ^= tmp

with open('flag.png', 'wb') as f:
    f.write(m)
