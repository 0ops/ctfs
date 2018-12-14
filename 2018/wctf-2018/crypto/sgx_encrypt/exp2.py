from pwn import *
#context.log_level = 'debug'
ccc = [0 for i in range(13)]
#alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
#alpha += "abcdefghijklmnopqrstuvwxyz"
#alpha += "_1234567890"
alpha = "0123456789"
alpha += "abcdef"

def enc_one(r,data):
    r.recvuntil("option:\n")
    r.sendline("1")
    r.recvuntil("text:\n")
    r.send(data)
    r.recvline()
    return r.recvline(keepends=False)

def enc_batch(r,data):
    r.recvuntil("option:\n")
    r.sendline("2")
    r.recvuntil("text:\n")
    r.send(data)
    r.recvline()
    return r.recvn(768)

def privilege(r,data):
    r.recvuntil("option:\n")
    r.sendline("3")
    r.recvuntil("interesting:\n")
    r.send(data)

def format(s):
    post = s[-3:]
    return s[:s.index(post)]


def get_flag(data):
    r = remote("172.16.21.241",9909)
    r.recvline()
    flag = r.recvn(768)
    a = flag[:39]
    b = enc_batch(r,data)
    r.close()
    a = [a[i:i+3] for i in range(0,len(a),3)]
    b = [b[i:i+3] for i in range(0,len(b),3)]
    data = [data[i:i+3] for i in range(0,len(data),3)]
    for i in range(len(a)):
        if a[i] in b:
            print i,b.index(a[i]),data[b.index(a[i])]
            if ccc[i]==0:
                ccc[i]=data[b.index(a[i])]
            else:
                print "error"

"""
res = []
for a in alpha:
    for b in alpha:
        for c in alpha:
            res.append(a+b+c)

for i in range(16):
    tmp = res[i*256:(i+1)*256]
    tmp = "".join(tmp)
    get_flag(tmp)
print "".join(ccc[2:12])
#6c238fef7770914059dd7b52c474b6
#flag{26c238fef7770914059dd7b52c474b60}
"""

def get_flag2(data):
    r = remote("172.16.21.241",9909)
    r.recvline()
    flag = r.recvn(768)
    a = flag[36:39]
    b = enc_batch(r,data)[:3]
    r.close()
    print a
    print b
    if a==b:
        raw_input()

res = []
for a in alpha:
    res.append(a+'}'+'\n')

for tmp in res:
    print tmp
    get_flag2(tmp)

