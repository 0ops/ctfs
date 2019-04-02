#!/usr/bin/env python
# coding=utf-8

from struct import pack, unpack

def ror(n, k):
    tmp = '{:032b}'.format(n)
    tmp = tmp[32-k:] + tmp[:32-k]
    return int(tmp, 2)

def dec(block, key):
    left, right = unpack('2I', block)
    for i in range(12, 0, -1):
        right -= key[i*2+1]
        right &= 0xffffffff
        right = ror(right, left&0x1f) ^ left
        left -= key[i*2]
        left &= 0xffffffff
        left = ror(left, right&0x1f) ^ right
    right -= key[1]
    right &= 0xffffffff
    left -= key[0]
    left &= 0xffffffff
    return pack('2I', left, right)

with open('./data.jac2', 'rb') as f:
    c = f.read()

key = [1653718437, 3557604283, 3451515877, 3988607296, 712074628, 1118074590, 2043137705, 1216686862, 710130120, 696547595, 3668890423, 38109534, 20979886, 981772969, 2226257188, 661000287, 460742160, 3063000521, 3947939920, 642528651, 841038468, 947549048, 494570081, 2285758449, 742108731, 1843481506]
plain = ''
for i in range(0, len(c), 8):
    plain += dec(c[i:i+8], key)

with open('data', 'wb') as f:
    f.write(plain)
