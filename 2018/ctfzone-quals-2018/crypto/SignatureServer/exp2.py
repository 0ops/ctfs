__author__ = "polaris"

from pwn import *
import base64
import hashlib
import time
HASH_LENGTH=32
CHECKSUM_LENGTH=4
MESSAGE_LENGTH=32
CHANGED_MESSAGE_LENGTH=MESSAGE_LENGTH+CHECKSUM_LENGTH
BITS_PER_BYTE=8
show_flag_command="show flag"+(MESSAGE_LENGTH-9)*"\xff"
admin_command="su admin"+(MESSAGE_LENGTH-8)*"\x00"

r = remote("crypto-02.v7frkwrfyhsjtbpfcppnu.ctfz.one",1337)
context.log_level = "debug"

print r.recvline()
print r.recvline()

def sign(data):
    payload = "sign:"
    payload += base64.b64encode(data)
    r.sendline(payload)
    a = r.recvline()[:-1]
    a = a.split(",")
    a1 = base64.b64decode(a[0])
    a2 = base64.b64decode(a[1])
    return a1,a2

def eeee(data,sig):
    payload = "execute_command:"
    payload += base64.b64encode(data)
    payload += ","
    payload += base64.b64encode(sig)
    r.sendline(payload)
    return r.recvline()
"""
full_sign_key = [["" for pos in range(36)] for data in range(256)]
#first 32bytes
payload = "\x00"*32
a1,a2 = sign(payload)
for i in range(32):
    full_sign_key[0][i] = a2[i*32:(i+1)*32]
#full
for i in range(1,256):
    for j in range(32):
        full_sign_key[i][j] = hashlib.sha256(full_sign_key[i-1][j]).digest()
#test
payload = "\x01"*32
a1,a2 = sign(payload)
assert(a2[0:32*32]=="".join(full_sign_key[1][:32]))

print "32 bytes ok"

full_sign_key[0][34] = a2[-64:-32]
full_sign_key[0][35] = a2[-32:]

byte2 = []
min_byte1 = 255
for i in range(1,256):
    a1,a2 = sign("su admin"+"\x00"*23+chr(i))
    a10 = a1[-4]
    a11 = a1[-3]
    byte2.append(a11)
    a20 = a2[-4*32:-3*32]
    a21 = a2[-3*32:-2*32]
    full_sign_key[ord(a10)][32] = a20
    full_sign_key[ord(a11)][33] = a21
    min_byte1 = min(min_byte1,ord(a10))
    print i,repr(a10),repr(a20),repr(a11),repr(a21)
print "min:",min_byte1

#for i in range(256):

for i in range(min_byte1+1,256):
    #print full_sign_key[i][32]
    #print hashlib.sha256(full_sign_key[i-1][32]).digest()
    if full_sign_key[i][32]=="":
        full_sign_key[i][32] = hashlib.sha256(full_sign_key[i-1][32]).digest()
    else:
        assert(full_sign_key[i][32]==hashlib.sha256(full_sign_key[i-1][32]).digest())
byte2 = set(byte2)

i=min_byte1
for j in byte2:
    while i<256:
        print i,repr(j)
        payload = "su admin"+"\x00"*24
        sig = ""
        payload+=(chr(i)+j+"\x00\x00")
        for d in range(36):
            sig+=full_sign_key[ord(payload[d])][d]
        time.sleep(1)
        assert(len(payload)==36)
        assert(len(sig)==32*36)
        print repr(payload)
        res = eeee(payload,sig)
        print res
        if "admin" in res:
            payload = "sign:"
            payload += base64.b64encode("show flag")
            r.sendline(payload)
            aaa = r.recvline()
            r.sendline("execute_command:"+aaa)
            r.interactive()
        if "sum" in res:
            i+=1
        else:
            r.recvline()
"""
payload = "sign:"
payload += base64.b64encode("show flag")
r.sendline(payload)
aaa = r.recvline()
r.sendline("execute_command:"+aaa)
r.interactive()