#!/usr/bin/env python
# coding=utf-8

from struct import unpack, pack
from itertools import combinations, permutations
from string import printable

p = set('0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_*{}')
data = unpack('54I', 'A10BFEFD5250919A27356FC9CD1F20F58FED32FEF93E8EDB54F91E051C7F21FEBBA8337BA103F99CCDE281C3E45BB322AEE650453C8F9EDCAF4EB4A96A487233589F32516E452F5F085A559B29851AEB8490009B067B0B9B11F36799AB13FB913622951815997B6FD1D6D9ED21FE67FBB011992574EEC43DF06F9398CE0275DF1610DFC3F92012BC0C814CF54C635A71A637163E8D7BF08091A49CFB2E4C25AD2F015AFB8155EF1A5113CCB96D533B9A0FAF7FBD83D89AF42453C5020532BC838162844348243819182BDBFA85D135935ABFC694AE851659'.decode('hex'))
coff = unpack('54I', '19CD49B81700E0556B964408EC81C1803C0B6C68920540558A1642CD819E03049F54DED97D673420BD4A1400000D1049E0A003E06D00F080D6AD07838107F64C432635A0DEC380C5244E8CEA08306068FFBF7F68F94BDE1979111A274D1C7999FCBF9C021E80822BFB07033CD61CE6DAF01B7B8F1DEF6CC5963A49D618808001B90180F41925710318F394928403E26D040B75F32A126A250B295702562058C4C08B4E20E7ADC7790302C2C47015965B564803663A9E3278007CD001E640C24ABEFB4C8504C4FEAB3700D85BD8BC4CE9010000000D28CAC4'.decode('hex'))
s = unpack('12I', '44DD81D4E0F06CE65D56866C6D2A6CEF0A2370D169B159913F0DCF3D761E33D9F01A6964CF84F3DB3A3E9E064DDE2271'.decode('hex'))

center = []
vertex = []
edge = []
for i in range(0, 54, 9):
    tmp = data[i:i+9]
    center.append(tmp[4])
    vertex.append(tmp[0])
    vertex.append(tmp[2])
    vertex.append(tmp[6])
    vertex.append(tmp[8])
    edge.append(tmp[1])
    edge.append(tmp[3])
    edge.append(tmp[5])
    edge.append(tmp[7])

def test(sv, se):
    for c in center:
        for i in combinations(vertex, 4):
            tv = sum(i, c) & 0xffffffff
            if tv == sv:
                print 'Find v', i
                for j in combinations(edge, 4):
                    te = sum(j, c) & 0xffffffff
                    if te == se:
                        print 'Find e', j
                        return i, j, c

print len(edge), len(vertex)
res = []
for i in range(6):
    v, e, c = test(s[i*2], s[i*2+1])
    print v, e
    tmp = coff[i*9:i*9+9]
    print tmp
    exit_flag = False
    for pv in permutations(v):
        flag1 = pv[0] * tmp[0] + pv[1] * tmp[2] + pv[2] * tmp[6] + pv[3] * tmp[8] + c * tmp[4]
        for pe in permutations(e):
            flag2 = flag1 + pe[0] * tmp[1] + pe[1] * tmp[3] + pe[2] * tmp[5] + pe[3] * tmp[7]
            flag2 = pack('I', flag2&0xffffffff)
            if set(flag2) < p:
                exit_flag = True
                # res.append(flag2)
                print repr(flag2),
    print
