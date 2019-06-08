#!/usr/bin/env python
# coding=utf-8

res = [3163, 3293, 3359, 6336, 6342, 3110, 3698, 3575, 6577, 3393, 3336, 6428, 3289, 3761, 3310, 6776, 3467, 3481, 3428, 3309, 6648, 3681, 6783, 6887, 3878, 6964, 6864, 3452, 4041, 3710, 7182, 7086]

pw = ''
for i in range(32):
    s = sum(range(i+1))
    s += 36 + (16<<8)
    s &= 0xffffffff
    for j in range(256):
        tmp = (j * s) & 0xffffffff
        tmp >>= 6
        if tmp == res[i]:
            pw += chr(j)
            break
print repr(pw)
