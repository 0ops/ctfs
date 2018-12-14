__author__ = "polaris"

from pwn import *
#context.log_level = "debug"


blocksize = 16
hmac_size = 20

def encrypt(prefix,suffix):
    r.sendline("1")
    r.recvuntil("prefix: ")
    r.sendline(prefix)
    r.recvuntil("suffix: ")
    r.sendline(suffix)
    data = r.recvline()
    r.recvuntil("3. quit")
    return data[:-1]

def decrypt(data):
    r.sendline("2")
    r.recvuntil("data: ")
    r.sendline(data)
    data = r.recvline()
    r.recvuntil("3. quit")
    return data[:-1]

def deal(data):
    #print data
    #print len(data)
    data = data.decode('hex')
    return (data[:blocksize],data[blocksize:])




"""
for i in range(16):
    (iv,data) = deal(encrypt("A"*i,""))
    print i,len(data)

data+mac : 84
data     : 64

11+xxxxx+1 = 96
(prefix+data+suffix)+hmac+padding 
"""


flag = "rmup;thankyou-and-"
for pos in range(48,64):
    i = 0
    while True:
        print "=============",pos,"===========",i,"=========="
        print "*******************",flag,"*******************"
        i+=1
        r = remote("206.189.92.209",54321)
        r.recvuntil("3. quit")
        (iv,data) = deal(encrypt("A"*12+(64-pos)*"A","A"*pos))
        #print (iv+data).encode("hex")
        new_data = data[:-blocksize]+data[4*blocksize:5*blocksize]
        #print (iv+new_data).encode("hex")
        #res = decrypt((iv+data).encode("hex"))
        #assert("OK" in res)
        res = decrypt((iv+new_data).encode("hex"))
        if "KO" not in res:
            aaa = 15^ord(data[-2*blocksize:-blocksize][-1])^ord(data[3*blocksize:4*blocksize][-1])
            print chr(aaa)
            flag+=chr(aaa)
            print "*******************",flag,"*******************"
            r.close()
            break
        r.close()

    #print i,decrypt((iv+data).encode("hex"))