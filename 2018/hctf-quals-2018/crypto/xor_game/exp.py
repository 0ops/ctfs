__author__ = "polaris"

import base64
from Crypto.Util.strxor import strxor
import string 

data = ""
with open("cipher.txt","rb") as f:
    data = f.read().strip()


data = base64.b64decode(data)
print len(data)

lll = 11

"""
table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz,.? \n\r"

for lll in range(1,50):
    print lll
    data2 = [data[i:i+lll] for i in range(0,len(data),lll)]


    for i in range(256):
        flag = True
        for d in data2:
            c = chr(i^ord(d[0]))
            if c not in table:
                flag = False
                break
        if flag:
            raw_input(i)

"""
# xor_is_interesting!@#xor_is_interestin  @#
lll = 42
res = [ord(" ") for i in range(42)]
data2 = [data[i:i+lll] for i in range(0,len(data),lll)]
table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz,.? \n\r"
for index in range(len(data2[0])):
    for i in range(256):
        flag = True
        for dd in range(len(data2)-1):
            d = data2[dd]
            c = chr(i^ord(d[index]))

            if c not in string.printable:
                flag = False
                break
        if flag:
            raw_input((index,chr(i),c))
            res[index]=chr(i)

print len(res)
print bytearray(res)
