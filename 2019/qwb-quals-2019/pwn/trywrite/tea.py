import os
import sys
import struct
import logging
import time

tea_num = 16
delta = 0x9e3779b9
op_32 = 0xffffffff

def tea_encrypt(v, k):
    v0, v1 = struct.unpack("<II", v)
    k0, k1, k2, k3 = struct.unpack("<IIII", k)
    tea_sum = 0
    for i in xrange(tea_num):
        tea_sum += delta
        tea_sum &= op_32
        v0 += ((((v1 << 4) & op_32) + k0) ^ (v1 + tea_sum) ^ (((v1 >> 5) & op_32) + k1))
        v0 &= op_32
        v1 += ((((v0 << 4) & op_32) + k2) ^ (v0 + tea_sum) ^ (((v0 >> 5) & op_32) + k3))
        v1 &= op_32
    return struct.pack('<II', v0, v1)

def tea_decrypt(v, k):
    v0, v1 = struct.unpack("<II", v)
    k0, k1, k2, k3 = struct.unpack("<IIII", k)
    tea_sum = (tea_num * delta) & op_32
    for i in xrange(tea_num):
        v1 -= (((v0 << 4) + k2) ^ (v0 + tea_sum) ^ ((v0 >> 5) + k3))
        v1 &= op_32
        v0 -= (((v1 << 4) + k0) ^ (v1 + tea_sum) ^ ((v1 >> 5) + k1))
        v0 &= op_32
        tea_sum -= delta
        tea_sum &= op_32
    return struct.pack('<II', v0, v1)

def str_encrypt(v, k):
    result = ""
    for i in xrange(0, len(v), 8):
        encrypt_text = tea_encrypt(v[i:i + 8], k)
        result += encrypt_text
    return result

def str_decrypt(v, k):
    result = ""
    for i in xrange(0, len(v), 8):
        result += tea_decrypt(v[i:i + 8], k)
    return result

if __name__ == '__main__':
    k = 'a'*16
    t = 'a'*80
    #t = t.encode('hex')
    a = str_encrypt(t, k)
    print a.encode('hex')
    b = str_decrypt(a, k)
    print b

