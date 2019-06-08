#!/usr/bin/env python
# coding=utf-8

from struct import unpack

with open('./JustRe.exe', 'rb') as f:
    c = f.read()
idx1 = 0x2f48
idx2 = 0x3c18
idx3 = 0xca0

'''
res = c[idx1:idx1+96]
c = bytearray(c)
c[idx3:idx3+96] = res
with open('retest.exe', 'wb') as f:
    f.write(str(c))
'''

res = unpack('24I', c[idx1:idx1+96])
ori = unpack('24I', c[idx2:idx2+96])

for i in range(256):
    k = 0
    tmp = ori[k] + i * 0x01010101
    tmp &= 0xffffffff
    tmp ^= res[k]
    test1 = tmp - k
    test1 &= 0xffffffff
    k = 2
    tmp = ori[k] + i * 0x01010101
    tmp &= 0xffffffff
    tmp ^= res[k]
    test2 = tmp - k
    test2 &= 0xffffffff
    if test1 == test2:
        print hex(test1), hex(i)
