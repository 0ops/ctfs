#!/usr/bin/env python
# coding=utf-8

from Crypto.Cipher import AES

m = 'aaaaaaaaaaaaaaaa'
# iv = 'a208b2b4875dd0d3f00d84ef7edfea9e'.decode('hex')
iv = '0d18512b8241843f698ee00e6ed78938'.decode('hex')
# c = '258379d4897190e38de2cd68dfbe9f20'.decode('hex')
c = ('7939112a9ebb4edf17b18562d99e0bb9b86ca4f8213c290bc7fdc41fa8f23d60')[:32].decode('hex')

def mid(pre1, pre2):
    keymap = {}
    max_n = 0x3fffff

    for i in xrange(max_n):
        if i & 0xffff == 0:
            print hex(i)
        key2 = format(pre2+i, '032x').decode('hex')
        aes2 = AES.new(key2, AES.MODE_CBC, iv)
        tmp = aes2.encrypt(m)
        keymap[tmp] = key2
    print 'step1 ok'

    for i in xrange(max_n):
        if i & 0xffff == 0:
            print hex(i)
        key1 = format(pre1+i, '032x').decode('hex')
        aes1 = AES.new(key1, AES.MODE_CBC, iv)
        tmp = aes1.decrypt(c)
        if keymap.has_key(tmp):
            print 'key1', repr(key1)
            print 'key2', repr(keymap[tmp])
            return key1, key2

if __name__ == '__main__':
    # pre1 = 0xc2c82355515255bea700d1881f400000L
    # pre2 = 0x5dbbe248e1e5c50e1510f1e994c00000L
    pre1 = 11237954972221133508252466142586601472
    pre2 = 137653991910236467477613808499415842816
    print mid(pre1, pre2)
