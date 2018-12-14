from pwn import *
from struct import pack, unpack
#context.log_level = "debug"
#p = remote("aes-128-tsb.hackable.software",1337)
p = remote("localhost",1337)

def xor(a, b):
    assert len(a) == len(b)
    return ''.join([chr(ord(ai)^ord(bi)) for ai, bi in zip(a,b)])

def pad(msg):
    byte = 16 - len(msg) % 16
    return msg + chr(byte) * byte

p.send(pack("<I",0))
#p.send("a"*0)
p.send(pack("<I",0))
#p.send("a"*16)
n = unpack("<I",p.recvn(4))[0]
print n
data = p.recvn(n)
print data

iv = data[:16]
msg = data[16:32]


def bruteforce(iv,msg):
    #step1
    ivv = iv[:15]
    c1 = xor(iv,msg)
    ddd = [0 for i in range(256)]
    for i in range(256):
        ivnew = ivv+chr(i)
        msgnew = xor(c1,ivnew)
        p.send(pack("<I",0))
        p.send(pack("<I",48))
        p.send(ivnew+msgnew+ivnew)
        temp = p.recvn(4)
        temp = unpack("<I",temp)[0]
        p.recvn(temp)
        if temp==50:
            print i,"true"
            ddd[i]=1
        else:
            print i,"false"
            ddd[i]=0
    
    #step2
    def getlast(d):
        for res in range(256):
            temp = [0 for i in range(256)]
            for i in range(256):
                if i^res in range(1,16):
                    temp[i]=1
            flag = True
            for i in range(256):
                if temp[i]!=d[i]:
                    flag = False
                    break
            if flag:
                return res

    lastbyte = getlast(ddd)
    print "get lastbyte   ",lastbyte

    #step3
    res = ""
    for i in range(15,0,-1):
        ivnew = ivv+chr(i^lastbyte)
        msgnew = xor(c1,ivnew)
        for guess in range(256):
            p.send(pack("<I",16-i))
            p.send(res+chr(guess))
            p.send(pack("<I",48))
            p.send(ivnew+msgnew+ivnew)
            temp = p.recvn(4)
            temp = unpack("<I",temp)[0]
            p.recvn(temp)
            if temp==50:
                print i,guess,"false"
            else:
                print i,guess,"true"
                res+=chr(guess)
                print repr(res)
                break
    res+=chr(lastbyte^ord(iv[-1]))
    return res


P1 = bruteforce(iv,msg)
print "===================================="
print P1
c1 = xor(iv,msg)
ivnew = xor(xor(P1,pad("gimme_flag")),iv)
msgnew = xor(c1,ivnew)
p.send(pack("<I",10))
p.send("gimme_flag")
p.send(pack("<I",48))
p.send(ivnew+msgnew+ivnew)

n = unpack("<I",p.recvn(4))[0]
data = p.recvn(n)
print data

iv = data[:16]
CC1 = data[16:32]
CC2 = data[32:48]
CC3 = data[48:64]
CC4 = data[64:80]
CCIV = data[80:96]


def bruteforce2(iv,msg):
    #step1
    ivv = iv[:15]
    c1 = xor(iv,msg)
    ddd = [0 for i in range(256)]
    for i in range(256):
        ivnew = ivv+chr(i)
        msgnew = xor(c1,ivnew)
        p.send(pack("<I",0))
        p.send(pack("<I",48))
        p.send(ivnew+msgnew+ivnew)
        temp = p.recvn(4)
        temp = unpack("<I",temp)[0]
        p.recvn(temp)
        if temp==50:
            print i,"true"
            ddd[i]=1
        else:
            print i,"false"
            ddd[i]=0
    
    #step2
    def getlast(d):
        for res in range(256):
            temp = [0 for i in range(256)]
            for i in range(256):
                if i^res in range(1,16):
                    temp[i]=1
            flag = True
            for i in range(256):
                if temp[i]!=d[i]:
                    flag = False
                    break
            if flag:
                return res

    lastbyte = getlast(ddd)
    print "get lastbyte   ",lastbyte

    #step3
    res = ""
    for i in range(15,0,-1):
        ivnew = ivv+chr(i^lastbyte)
        msgnew = xor(c1,ivnew)
        for guess in range(256):
            p.send(pack("<I",16-i))
            p.send(res+chr(guess))
            p.send(pack("<I",48))
            p.send(ivnew+msgnew+ivnew)
            temp = p.recvn(4)
            temp = unpack("<I",temp)[0]
            p.recvn(temp)
            if temp==50:
                print i,guess,"false"
            else:
                print i,guess,"true"
                res+=chr(guess)
                print repr(res)
                break
    res+=chr(lastbyte^ord(iv[-1]))
    return res


print bruteforce2(iv,CC1)