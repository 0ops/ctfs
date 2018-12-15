__author__ = "polaris"

from Crypto.Util.number import long_to_bytes,GCD,bytes_to_long
from pwn import *

#context.log_level = "debug"

#p = remote("18.179.251.168",21700)
p = remote("127.0.0.1",8889)
p.recvline()
flag = p.recvline().strip()
nn = int(p.recvline().strip())
e = int(p.recvline().strip())
d = int(p.recvline().strip())
fff = p.recvline().strip()

print "e",e
print "d",d
print "fff",fff

def enc(data):
    p.recvuntil("cmd: ")
    p.sendline("A")
    p.recvuntil("input: ")
    p.sendline(long_to_bytes(data).encode('hex'))
    return int(p.recvline().strip(),16)

def dec(data):
    p.recvuntil("cmd: ")
    p.sendline("B")
    p.recvuntil("input: ")
    p.sendline(long_to_bytes(data).encode('hex'))
    return int(p.recvline().strip(),16)

c2 = enc(2)
c5 = enc(5)
c4 = enc(4)
c25 = enc(25)
n1 = c2*c2-c4
n2 = c5*c5-c25
n = GCD(n1,n2)
while n%2==0:
    n=n/2
#c123 = enc(123)
print "n",n
print "nn",nn
#assert(pow(123,))
print("get n ok")

c256 = enc(256)

#low = bytes_to_long("\xff"*118)
#high = bytes_to_long("\xff"*128)
flag = int(flag,16)

cccc = n&0xff
mmap = []
for i in range(256):
    for k in range(256):
        if ((i+k*cccc)&0xff)==0x00:
            mmap.append(k)
            break
print mmap
#0x00-kn=b
xdd = 0
bit = 0
print flag
raw_input()
#flag = pow(int("929e5ca2efdfff05d8c096b95eacb7b30575eb7e154369fcc842b7dcbc4c033ef87964240a8c2d0c7c9a00348bd8f79887c2fdb28a10d9398314f9e778da8566cff486d56161616161616161616161616161616161616161616161616161616161616363636363636363636364646464646464646161",16),e,n)

while n>>bit:
    flag = (c256*flag)%n
    b = dec(flag)
    k = mmap[b]
    print k
    xdd = 256*xdd+k
    bit += 8
    #kn/256<flag<(k+1)n/256 
    
    #a = pow(((c256*tmp)%n),d,n)&0xff
    #print a,b
    #print k
    #print (256*high)/n%256
    
    #print pow(int(fff,16),e,n)
    #print pow(int(fff,16),e,nn)
print hex(xdd)


print long_to_bytes((xdd+1)*n//2**bit)
print hex(bytes_to_long('a'*128)*(2**bit)//n)