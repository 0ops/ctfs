#!/usr/bin/env python
# coding=utf-8
# author: seabreeze

from tea import TinyEncryptionAlgorithm as tea

def xor(a, b):
    return bytearray([i^j for i,j in zip(a,b)])

t = tea()
k = 'webasmintersting'
c = bytearray(b'5\x87l/\xbd\x02w\x99\x8c,H\xf6\x1dy"U\xe31\xd8\xcb\x93\x13\xd6\xb9')
# c = c[7::-1] + c[15:7:-1] + c[23:15:-1]

assert len(c) == 24

p1 = t.decrypt(c[:8], k)
p2 = t.decrypt(c[8:16], k)
p3 = t.decrypt(c[16:], k)
print p1+p2+p3
print repr(xor(p2, c[:8]))
print repr(xor(p3, c[8:16]))
