__author__ = "polaris"

data = ""
from Crypto.Util.number import bytes_to_long

with open("ev3_scanner_record.pklg","rb") as f:
    data = f.read()
"""
flag1 = "\x0d\x00\x2a\x00\x00"
flag2 = "\x07\x00\x2a\x00\x02"
res = []
while True:
    if flag in data:
        i = data.index(flag)
        res.append(bytes_to_long(data[i+5:i+9]))
        print data[i+5:i+9].encode('hex')
        data = data[i+10:]
    else:
        break
print len(res)
for i in res:
    if i<0xa000:
        print 1,
    elif i<0xffff:
        print 0,
    else:
        raw_input()
"""

"""
flag = "\x0d\x00\x2a\x00\x00"
res = []
while True:
    if flag in data:
        i = data.index(flag)
        res.append(data[i+5:i+15])
        print data[i+5:i+15].encode('hex')
        data = data[i+16:]
    else:
        break
print len(res)
print set(res)
print res.count('\x04\x9a+\x01\x00\x00\x94\xf9\xc9[')
"""

def getres():
    data = ""
    with open("ev3_scanner_record.pklg","rb") as f:
        data = f.read()
    flag1 = "\x0d\x00\x2a\x00\x00"
    flag2 = "\x07\x00\x2a\x00\x02"
    d1 = '\x04\x00\x99\x1d\x00\x01\x00\x00\x01`'
    d2 = '\x04\x00\x99\x1d\x00\x02\x00\x02\x01`'
    res1 = []
    res2 = []
    for i in range(len(data)-5):
        if data[i:i+5] == flag1:
            res1.append(data[i+5:i+15]==d1)
        elif data[i:i+5] == flag2:
            res2.append(data[i+5:i+9])
    return res1, res2
