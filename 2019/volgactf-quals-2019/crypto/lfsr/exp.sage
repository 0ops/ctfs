__author__ = "polaris"

import sys
import binascii
#data = [int(i) for i in sys.argv[1]]
#n = int(sys.argv[2])

head = "VolgaCTF{"

data = "JKIzJOCdeCZhSlxv8OestLzPVKWCQ+wNtfk0LzwezSKjoe09EBB6QRyH8gYS9lrHLAk0DpSdBhwKE8ZgMclbDNXiHcG91V2+IA0bFmi+W2hDMYvThBVlkT6XkFb2s2lSzWL4+v0lKJRzfKrQksOBzBOMYF2RWrbxWIJWQuMWMzE0UCpq5tYnu7me06jDD/UFvpO+LfLmjwgYWTo4CPw1GqeGVVFt2klC2GE="
#data = "fJaL7q/WqoeadUTTHPJ1PSiTUxGlTO+0gz+1KOp2xXNS5zClwNgjETBR7nhbKI9EV+CxtuzM+MWD5LGKtOuJwQc2vg=="

padding = 0

class LFSR:
    def __init__(self, register, branches):
        self.register = register
        self.branches = branches
        self.n = len(register)

    def next_bit(self):
        ret = self.register[self.n - 1]
        new = 0
        for i in self.branches:
            new ^^= self.register[i - 1]
        self.register = [new] + self.register[:-1]

        return ret

def getMask(data,n):
    A = Matrix(GF(2),n,n,lambda x,y: data[x+y])
    Y = Matrix(GF(2),data[n:n+n])
    X = A.solve_right(Y.T)
    return X

def checkMask(data,n,X):
    A = Matrix(GF(2),n,n,lambda x,y: data[x+y+len(data)-2*n])
    Y = Matrix(GF(2),data[len(data)-n:len(data)])
    YY = A*X
    return A*X==Y.T

def complete(res,data,mask,n):
    m = []
    for i in range(n):
        if mask[i][0]==1:
            m.append(n-i)
    lfsr = LFSR(res[:n][::-1],m)
    ans = ""
    for i in range(len(data)):
        ans+=str(lfsr.next_bit()^^data[i])
    ans = hex(int(ans,2))[2:].strip("L")
    if len(ans)%2==1:
        ans="0"+ans
    #print ans
    aaa = binascii.unhexlify(ans)
    if "CTF" in aaa:
        print repr(aaa)
        return True
    return False

data = data.decode("base64")
data_text = bin(int(binascii.hexlify(data),16))[2:]


for offset in range(len(data_text)-72):
    data_text2 = data_text[offset:]
    data_bits = [int(i) for i in data_text2]
    print "enc",data_text2
    print len(data_text2)

    head_text = bin(int(binascii.hexlify(head),16))[2:]
    head_bits = [int(i) for i in head_text]
    print "plain",head_text
    print len(head_text)

    res = []

    for i in range(padding):
        res.append(head_bits[i])
    for i in range(padding,len(head_bits)):
        res.append(head_bits[i]^^data_bits[i])
    a = ""
    for i in res:
        a+=str(i)

    print "stream",a

    #complete(res,data_bits,[[1],[1],[0],[0],[0],[1],[0],[1],[1],[1],[0],[1],[1],[0],[1],[1]],16)
    #raw_input("aaaa")
    for i in range(1,len(res)/2):
        try:
            X = getMask(res,i)
            if checkMask(res,i,X):
                if complete(res,data_bits,X,i):
                    print i,X.T
                    raw_input("aaaaaaa")
        except:
            pass
